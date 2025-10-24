from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import time
from datetime import timedelta
from typing import Any, Dict, List, Tuple

from aiohttp.client_exceptions import ClientResponseError
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import aiohttp_client, event as ha_event

from .api import AdGuardAPI
from .const import (
    DOMAIN,
    CONF_BASE_URL,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_VERIFY_SSL,
    CONF_DEVICES_JSON,
    CONF_RULES_TEXT,
    CONF_ALLOWED_GROUPS,
    CONF_APPEND_DYNAMIC_RULES,
    CONF_SCAN_RANGE,       # kept for options parity; no longer used for scanning
    CONF_AUTO_ONBOARD,
    CONF_GUEST_GROUP,
    DEFAULT_RULES,
    DEFAULT_ALLOWED_GROUPS,
    CTAG_MAPPING,
    SAFESEARCH_GROUPS, SAFESEARCH_CTAGS,
    SAFEBROWSING_GROUPS, SAFEBROWSING_CTAGS,
    PARENTAL_GROUPS, PARENTAL_CTAGS,
    BLOCKED_SERVICES_PRESETS,
    KNOWN_CTAGS,
    CONF_ALLOW_RENAME,
)

DHCP_TTL = 90  # seconds to reuse DHCP cache

_LOGGER = logging.getLogger(__name__)
PLATFORMS: list[str] = []

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
MAC_RE  = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


def _is_ipv4(s: str) -> bool:
    return isinstance(s, str) and bool(IPV4_RE.match(s))


def _norm_mac(s: str | None) -> str | None:
    """
    Normalise to lower-case AA:BB:CC:DD:EE:FF.
    Accepts AABBCCDDEEFF, AA-BB-..., AA:BB:...
    """
    if not s:
        return None
    raw = re.sub(r"[^0-9A-Fa-f]", "", s)
    if len(raw) == 12:
        mac = ":".join(raw[i:i+2] for i in range(0, 12, 2)).lower()
        return mac
    s2 = s.replace("-", ":").lower()
    return s2 if MAC_RE.match(s2) else None


def _format_mac_upper(s: str) -> str:
    """For logs/UI: AA:BB:CC:DD:EE:FF (upper)."""
    m = _norm_mac(s)
    return m.upper() if m else (s or "").upper()


def _normalise_id(idv: str) -> str | None:
    s = str(idv or "").strip()
    if not s:
        return None
    mac = _norm_mac(s)
    if mac:
        return mac
    return s  # IPs / custom IDs passed through


def _parse_groups(groups_str: str | None) -> set[str]:
    if not groups_str:
        return set(DEFAULT_ALLOWED_GROUPS)
    parts = [p.strip().lower() for p in groups_str.split(",")]
    return {p for p in parts if p}


def _derive_short_id(idv: str) -> str:
    if ":" in idv:
        parts = idv.split(":")
        return parts[-2] + parts[-1] if len(parts) == 6 else parts[-1]
    if "." in idv:
        return idv.split(".")[-1]
    return idv[-4:] if len(idv) >= 4 else idv


def _unique_name(base_name: str, ids: List[str], existing_names: set) -> str:
    if base_name not in existing_names:
        existing_names.add(base_name)
        return base_name
    sid = _derive_short_id(ids[0])
    candidate = f"{base_name} [{sid}]"
    name = candidate
    i = 2
    while name in existing_names:
        name = f"{candidate} #{i}"
        i += 1
    existing_names.add(name)
    return name


def _groups_for_device(d: dict[str, Any], allowed_groups: set[str]) -> list[str]:
    tags = [str(t).lower() for t in d.get("tags", []) if t]
    return [g for g in tags if g in allowed_groups]


def _ctags_from_json(d: dict[str, Any]) -> list[str]:
    raw = [str(t).strip().lower() for t in d.get("tags", []) if t]
    out: list[str] = []
    seen: set[str] = set()
    for t in raw:
        if t in KNOWN_CTAGS and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _map_groups_to_ctags(groups: list[str]) -> list[str]:
    mapped = [c for g in groups for c in CTAG_MAPPING.get(g, [])]
    out: list[str] = []
    seen: set[str] = set()
    for t in mapped:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _infer_groups_from_ctags(ctags: list[str], allowed_groups: set[str]) -> list[str]:
    rev: dict[str, str] = {}
    for grp, ct_list in CTAG_MAPPING.items():
        for ct in ct_list:
            rev[ct] = grp
    inferred: list[str] = []
    for t in ctags:
        g = rev.get(t)
        if g and g in allowed_groups:
            inferred.append(g)
    if "user_regular" in ctags and "guest" in allowed_groups:
        inferred.append("guest")
    if "user_admin" in ctags and "adult" in allowed_groups:
        inferred.append("adult")
    out: list[str] = []
    seen: set[str] = set()
    for g in inferred:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out


async def async_setup(hass: HomeAssistant, config) -> bool:
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    session = aiohttp_client.async_get_clientsession(hass)
    base_url = entry.data[CONF_BASE_URL]
    username = (entry.data.get(CONF_USERNAME) or "").strip()
    password = (entry.data.get(CONF_PASSWORD) or "").strip()
    verify_ssl = entry.data.get(CONF_VERIFY_SSL, True)

    devices_json = entry.data.get(CONF_DEVICES_JSON)
    rules_text = entry.data.get(CONF_RULES_TEXT) or DEFAULT_RULES
    allowed_groups = _parse_groups(entry.data.get(CONF_ALLOWED_GROUPS))
    append_dyn = bool(entry.data.get(CONF_APPEND_DYNAMIC_RULES, True))
    default_scan_range = (entry.data.get(CONF_SCAN_RANGE) or "").strip()  # unused now; kept for options
    default_auto_on = bool(entry.data.get(CONF_AUTO_ONBOARD, False))
    default_guest_grp = (entry.data.get(CONF_GUEST_GROUP) or "guest").strip().lower()
    allow_rename = bool(entry.data.get(CONF_ALLOW_RENAME, True))
    
    api = AdGuardAPI(
        session,
        base_url,
        username=username or None,
        password=password or None,
        verify_ssl=verify_ssl,
    )

    try:
        await api.get_version()
        _LOGGER.info("Connected to AdGuard Home at %s", base_url)
    except Exception as e:
        _LOGGER.warning("Cannot reach %s yet: %s (services still registered)", base_url, e)

    try:
        catalog = await api.list_blocked_services_catalog()
        valid_slugs = set(catalog.keys())
        _LOGGER.info("Loaded %d blocked services", len(valid_slugs))
    except Exception as e:
        _LOGGER.warning("Could not load blocked services catalog: %s", e)
        valid_slugs = set()

    hass.data[DOMAIN][entry.entry_id] = {
        "api": api,
        "devices_json": devices_json,
        "rules_text": rules_text,
        "valid_service_slugs": valid_slugs,
        "allowed_groups": allowed_groups,
        "append_dynamic_rules": append_dyn,
        "default_scan_range": default_scan_range,   # legacy; ignored for scanning
        "default_auto_onboard": default_auto_on,
        "default_guest_group": default_guest_grp,
        "_pause_state": {},
        "_dhcp_cache": {},  # mac->ip cache with ts
        "allow_rename": allow_rename,
    }

    # --------------------------
    # DHCP helper (cached)
    # --------------------------

    async def _mac_to_ipv4_from_dhcp_cached() -> dict[str, str]:
        """
        Build {mac -> ipv4} from AdGuard DHCP leases + static leases, cached briefly.
        """
        store = hass.data[DOMAIN][entry.entry_id]
        cache = store.get("_dhcp_cache") or {}
        now = time.monotonic()
        if cache and (now - cache.get("ts", 0)) < DHCP_TTL:
            return cache.get("map", {})

        mapping: dict[str, str] = {}
        try:
            st = await api.dhcp_status()
            leases = st.get("leases", []) if isinstance(st, dict) else []
            for it in leases or []:
                mac = _norm_mac(it.get("mac"))
                ip = str(it.get("ip", "")).strip()
                if mac and _is_ipv4(ip):
                    mapping.setdefault(mac, ip)
            stat = st.get("static_leases", [])
            for it in stat or []:
                mac = _norm_mac(it.get("mac"))
                ip = str(it.get("ip", "")).strip()
                if mac and _is_ipv4(ip):
                    mapping.setdefault(mac, ip)
        except Exception as e:
            _LOGGER.warning("DHCP status read failed: %s", e)

        store["_dhcp_cache"] = {"ts": now, "map": mapping}
        return mapping

    # --------------------------
    # Services
    # --------------------------

    async def _service_discover(call: ServiceCall) -> None:
        """
        No network scan. Purely use DHCP to:
        - update existing clients so ids contain [MAC, IP],
        - optionally add Guests for unknown devices.
        """
        data = hass.data[DOMAIN][entry.entry_id]
        valid_slugs: set[str] = data.get("valid_service_slugs", set())
        
        guest_tags_try = ["user_child", "device_other"]

        guest_group = (call.data.get("guest_group") or data.get("default_guest_group") or "guest").strip().lower()
        create_clients = bool(call.data.get("create_clients", True))

        dhcp_map = await _mac_to_ipv4_from_dhcp_cached()
        pairs = [(ip, mac) for mac, ip in dhcp_map.items()]

        guest_block = BLOCKED_SERVICES_PRESETS.get(guest_group, [])
        if valid_slugs:
            guest_block = [s for s in guest_block if s in valid_slugs]

        try:
            status = await api.clients_status()
            existing = status.get("clients", []) if isinstance(status, dict) else (status if isinstance(status, list) else [])
        except Exception:
            existing = []
        existing_names = {c.get("name", "") for c in existing if isinstance(c, dict)}

        created = 0
        updated = 0

        for ip, mac in pairs:
            mac_disp = _format_mac_upper(mac)

            try:
                matched = await api.clients_search([mac, ip])
            except Exception:
                matched = []

            if matched:
                name = matched[0].get("name")
                ids = matched[0].get("ids") or []
                have_mac = any(_norm_mac(i) == mac for i in ids if isinstance(i, str))
                have_ip = any(i == ip for i in ids if isinstance(i, str))
                if not (have_mac and have_ip):
                    new_ids = list(dict.fromkeys([*(ids or []), mac, ip]))
                    try:
                        await api.clients_update(name, {"ids": new_ids})
                        updated += 1
                        hass.bus.async_fire(f"{DOMAIN}.guest_identifiers_updated", {"name": name, "ip": ip, "mac": mac})
                        _LOGGER.info("discover: updated ids for '%s' → [%s, %s]", name, mac_disp, ip)
                    except Exception as e:
                        _LOGGER.error("discover: update ids failed for '%s': %s", name, e)

                hass.bus.async_fire(f"{DOMAIN}.guest_discovered", {"ip": ip, "mac": mac, "persistent": True})
                continue

            # Unknown → optionally add as Guest
            hass.bus.async_fire(f"{DOMAIN}.guest_discovered", {"ip": ip, "mac": mac, "persistent": False})
            if not create_clients:
                continue

            suffix = (mac.replace(":", "")[-4:].upper()) if mac else ip.split(".")[-1]
            name = f"Guest [{suffix}]"
            base = name
            i = 2
            while name in existing_names:
                name = f"{base} #{i}"
                i += 1
            existing_names.add(name)

            payload = {
                "name": name,
                "ids": [mac, ip],
                "use_global_settings": False,
                "filtering_enabled": True,
                "safebrowsing_enabled": True,
                "safesearch_enabled": True,
                "parental_enabled": True,
                "use_global_blocked_services": False,
                "blocked_services": guest_block,
                "tags": guest_tags_try,  # valid AGH ctag
            }

            try:
                await api.clients_add(payload)
                created += 1
                hass.bus.async_fire(f"{DOMAIN}.guest_onboarded", {"name": name, "ip": ip, "mac": mac})
                _LOGGER.info("discover: onboarded Guest '%s' ids=[%s, %s] (ctags=%s)", name, mac_disp, ip, guest_tags_try)
            except ClientResponseError as cre:
                # If AGH rejects a tag for any reason, retry with device_only
                if "invalid tag" in str(cre).lower():
                    payload["tags"] = ["device_other"]
                    _LOGGER.warning("AGH rejected a guest ctag; retrying Guest '%s' with device_other only", name)
                    await api.clients_add(payload)
                    created += 1
                    hass.bus.async_fire(f"{DOMAIN}.guest_onboarded", {"name": name, "ip": ip, "mac": mac})
                    _LOGGER.info("discover: onboarded Guest '%s' ids=[%s, %s] (ctag=device_other)", name, mac_disp, ip)
                else:
                    # …keep your duplicate-MAC recovery path here…
                    m = re.search(r'another client "([^"]+)" uses the same', str(cre))
                    if m:
                        exist_name = m.group(1)
                        await api.clients_update(exist_name, {"ids": list(dict.fromkeys([mac, ip]))})
                        updated += 1
                        hass.bus.async_fire(f"{DOMAIN}.guest_identifiers_updated", {"name": exist_name, "ip": ip, "mac": mac})
                        _LOGGER.info("discover: recovered by updating '%s' ids=[%s, %s]", exist_name, mac_disp, ip)
                    else:
                        _LOGGER.error("discover: add failed for %s/%s: %s", ip, mac_disp, cre)
            
    async def _service_sync(call: ServiceCall) -> None:
        data = hass.data[DOMAIN][entry.entry_id]
        api: AdGuardAPI = data["api"]
        valid_slugs: set[str] = data.get("valid_service_slugs", set())
        allowed_groups: set[str] = data.get("allowed_groups", set(DEFAULT_ALLOWED_GROUPS))
        append_dynamic: bool = data.get("append_dynamic_rules", True)
        allow_rename: bool = data.get("allow_rename", False)

        json_path = call.data.get("devices_json") or data.get("devices_json")
        rules_text_base = call.data.get("rules_text") or data.get("rules_text") or DEFAULT_RULES

        # Auto-onboard unknowns (DHCP-only now)
        auto_onboard = bool(call.data.get("auto_onboard_unknowns", data.get("default_auto_onboard", False)))
        guest_group = (call.data.get("guest_group") or data.get("default_guest_group") or "guest").strip().lower()
        if auto_onboard:
            await _service_discover(ServiceCall(DOMAIN, "discover", {"guest_group": guest_group, "create_clients": True}))

        # MAC->IPv4 enrichment map from DHCP (cached) + existing clients
        mac_to_ipv4: dict[str, str] = {}
        dhcp_map = await _mac_to_ipv4_from_dhcp_cached()
        mac_to_ipv4.update(dhcp_map)

        try:
            status_now = await api.clients_status()
            existing_now = status_now.get("clients", []) if isinstance(status_now, dict) else (status_now if isinstance(status_now, list) else [])
        except Exception:
            existing_now = []
        existing_names = {c.get("name", "") for c in existing_now if isinstance(c, dict)}

        for c in existing_now:
            if not isinstance(c, dict):
                continue
            ids = c.get("ids") or []
            ips = [i for i in ids if isinstance(i, str) and _is_ipv4(i)]
            macs = [_norm_mac(i) for i in ids if isinstance(i, str)]
            macs = [m for m in macs if m]
            if ips:
                for m in macs:
                    mac_to_ipv4.setdefault(m, ips[0])

        # Read devices JSON (non-blocking)
        devices: list[dict[str, Any]] | None = None
        if json_path:
            if not os.path.isabs(json_path):
                json_path = os.path.join(hass.config.path(), json_path)

            def _read_json(path: str):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)

            try:
                devices = await hass.async_add_executor_job(_read_json, json_path)
            except Exception as e:
                _LOGGER.error("Failed to read devices JSON from %s: %s", json_path, e)
                raise

        # Plan
        plan: List[Tuple[str, dict, bool]] = []
        groups_to_clients: Dict[str, List[str]] = {}
        if devices:
            plan, groups_to_clients = await _plan_clients(api, devices, valid_slugs, allowed_groups)

        # Reverse index id->name for deciding add/update
        id_to_name: dict[str, str] = {}
        for c in existing_now:
            if not isinstance(c, dict):
                continue
            nm = c.get("name")
            for i in (c.get("ids") or []):
                if isinstance(i, str):
                    id_to_name[i] = nm

        def _existing_name_for_ids(ids: list[str]) -> str | None:
            for i in ids or []:
                nm = id_to_name.get(i)
                if nm:
                    return nm
            return None

        # Dynamic rules
        rules_text = rules_text_base
        if append_dynamic and groups_to_clients:
            dyn = _generate_dynamic_rules(groups_to_clients)
            rules_text = rules_text.rstrip() + "\n\n" + dyn + "\n"

        try:
            await api.set_custom_rules(rules_text)
        except Exception as e:
            _LOGGER.error("Failed to set custom rules: %s", e)
        # Apply plan
        for final_name, client_payload, should_update in plan:
            # Ensure MAC + IP in ids
            ids = list(client_payload.get("ids") or [])
            macs = [_norm_mac(i) for i in ids]
            macs = [m for m in macs if m]
            has_v4 = any(_is_ipv4(i) for i in ids)
            if macs and not has_v4:
                live = mac_to_ipv4.get(macs[0])
                if live and live not in ids:
                    ids.append(live)
            client_payload["ids"] = ids
        
            # Decide add vs update
            target_name = final_name
            action_update = bool(should_update)
            if not action_update:
                existing_for_ids = _existing_name_for_ids(ids)
                if existing_for_ids:
                    target_name = existing_for_ids
                    action_update = True
        
            # JSON source-of-truth name (carried from _plan_clients)
            desired_name = client_payload.pop("_desired_name", final_name)
        
            # ------- Rename-by-recreate (opt-in) -------
            if action_update and allow_rename and desired_name != target_name:
                _LOGGER.info("Renaming client '%s' → '%s' by recreate (ids=%s)", target_name, desired_name, ids)
        
                # Optional: pre-clear any stale record with desired_name
                try:
                    await api.clients_delete(desired_name)
                except Exception:
                    pass
        
                # Delete the old record
                try:
                    await api.clients_delete(target_name)
                    _LOGGER.debug("Rename: deleted old '%s'", target_name)
                except Exception as e:
                    _LOGGER.warning("Rename: delete old '%s' failed, continuing: %s", target_name, e)
        
                # Re-add with desired JSON name
                payload_new = dict(client_payload)
                payload_new["name"] = desired_name
                try:
                    await api.clients_add(payload_new)
                    for i in payload_new.get("ids", []):
                        if isinstance(i, str):
                            id_to_name[i] = desired_name
                    _LOGGER.info("Rename complete: '%s' → '%s'", target_name, desired_name)
                    continue  # handled; next client
                except ClientResponseError as cre:
                    # If a different client still owns these IDs, purge and retry once
                    m = re.search(r'another client "([^"]+)" uses the same', str(cre))
                    if m:
                        other = m.group(1)
                        try:
                            await api.clients_delete(other)
                            await api.clients_add(payload_new)
                            for i in payload_new.get("ids", []):
                                if isinstance(i, str):
                                    id_to_name[i] = desired_name
                            _LOGGER.info("Rename complete after purging '%s': '%s' → '%s'", other, target_name, desired_name)
                            continue
                        except Exception as e2:
                            _LOGGER.error("Rename purge retry failed for '%s': %s", desired_name, e2)
                    _LOGGER.error("Rename: add '%s' failed: %s; updating old name instead", desired_name, cre)
                except Exception as e:
                    _LOGGER.error("Rename: add '%s' failed: %s; updating old name instead", desired_name, e)
        
            # ------- Normal add/update path -------
            client_payload["name"] = target_name
            try:
                if action_update:
                    await api.clients_update(target_name, client_payload)
                else:
                    await api.clients_add(client_payload)
        
                # Learn ids→name for later items
                final_applied_name = target_name if action_update else client_payload["name"]
                for i in ids:
                    if isinstance(i, str):
                        id_to_name[i] = final_applied_name
        
            except ClientResponseError as cre:
                # Duplicate on add → retry as update against server-reported owner
                if not action_update:
                    m = re.search(r'another client "([^"]+)" uses the same', str(cre))
                    if m:
                        owner = m.group(1)
                        client_payload["name"] = owner
                        try:
                            await api.clients_update(owner, client_payload)
                            for i in ids:
                                if isinstance(i, str):
                                    id_to_name[i] = owner
                            continue
                        except Exception as e2:
                            _LOGGER.error(
                                "Retry as update failed for %s → %s: %s | Payload=%s",
                                final_name, owner, e2,
                                {k: client_payload.get(k) for k in ("name","ids","tags","blocked_services","use_global_blocked_services")}
                            )
                            continue
                _LOGGER.error(
                    "Client push failed for %s: %s | Payload=%s",
                    final_name, cre,
                    {k: client_payload.get(k) for k in ("name","ids","tags","use_global_settings",
                                                        "blocked_services","use_global_blocked_services",
                                                        "safesearch_enabled","safebrowsing_enabled","parental_enabled")}
                )
                continue
        
            except Exception as e:
                _LOGGER.error(
                    "Client push failed for %s: %s | Payload=%s",
                    final_name, e,
                    {k: client_payload.get(k) for k in ("name","ids","tags","use_global_blocked_services","blocked_services")}
                )
                continue

    async def _service_pause(call: ServiceCall) -> None:
        data = hass.data[DOMAIN][entry.entry_id]
        api: AdGuardAPI = data["api"]
        minutes = int(call.data.get("minutes", 15))
        scope = str(call.data.get("scope", "filtering_only")).lower()
        clients = call.data.get("clients") or []
        if not clients:
            _LOGGER.error("pause: no clients provided")
            return

        try:
            status = await api.clients_status()
            existing = status.get("clients", []) if isinstance(status, dict) else (status if isinstance(status, list) else [])
        except Exception as e:
            _LOGGER.error("pause: failed to list clients: %s", e)
            return

        indexed = {c.get("name"): c for c in existing if isinstance(c, dict) and c.get("name")}
        for name in clients:
            c = indexed.get(name)
            if not c:
                _LOGGER.warning("pause: client '%s' not found", name)
                continue

            prev = {
                "filtering_enabled": bool(c.get("filtering_enabled", True)),
                "safebrowsing_enabled": bool(c.get("safebrowsing_enabled", False)),
                "parental_enabled": bool(c.get("parental_enabled", False)),
                "use_global_blocked_services": bool(c.get("use_global_blocked_services", True)),
                "blocked_services": c.get("blocked_services", []),
            }
            hass.data[DOMAIN][entry.entry_id]["_pause_state"][name] = prev

            payload = {"filtering_enabled": False}
            if scope == "all":
                payload.update(
                    {
                        "safebrowsing_enabled": False,
                        "parental_enabled": False,
                        "use_global_blocked_services": False,
                        "blocked_services": [],
                    }
                )
            try:
                await api.clients_update(name, payload)
                _LOGGER.info("pause: paused '%s' for %d minutes (scope=%s)", name, minutes, scope)
            except Exception as e:
                _LOGGER.error("pause: update failed for '%s': %s", name, e)
                continue

            async def _restore_cb(now):
                snap = hass.data[DOMAIN][entry.entry_id]["_pause_state"].pop(name, None)
                if not snap:
                    return
                try:
                    await api.clients_update(name, snap)
                    _LOGGER.info("pause: restored '%s'", name)
                except Exception as e:
                    _LOGGER.error("pause: restore failed for '%s': %s", name, e)

            ha_event.async_call_later(hass, timedelta(minutes=minutes), _restore_cb)

    hass.services.async_register(DOMAIN, "discover", _service_discover)
    hass.services.async_register(DOMAIN, "sync", _service_sync)
    hass.services.async_register(DOMAIN, "pause", _service_pause)

    if devices_json:
        hass.async_create_task(hass.services.async_call(DOMAIN, "sync", {}, blocking=False))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    with contextlib.suppress(Exception):
        hass.services.async_remove(DOMAIN, "discover")
    with contextlib.suppress(Exception):
        hass.services.async_remove(DOMAIN, "sync")
    with contextlib.suppress(Exception):
        hass.services.async_remove(DOMAIN, "pause")
    hass.data[DOMAIN].pop(entry.entry_id, None)
    return True


async def _plan_clients(
    api: AdGuardAPI, devices: list[dict[str, Any]], valid_slugs: set[str], allowed_groups: set[str]
) -> Tuple[List[Tuple[str, dict, bool]], Dict[str, List[str]]]:
    try:
        status = await api.clients_status()
        existing = status.get("clients", []) if isinstance(status, dict) else (status if isinstance(status, list) else [])
    except Exception:
        existing = []
    existing_names = {c.get("name", "") for c in existing if isinstance(c, dict)}

    plan: List[Tuple[str, dict, bool]] = []
    groups_to_clients: Dict[str, List[str]] = {}

    for d in devices:
        desired_name = d.get("name") or "unnamed"
        explicit_groups = _groups_for_device(d, allowed_groups)
        passthrough_ctags = _ctags_from_json(d)
        mapped_ctags = _map_groups_to_ctags(explicit_groups)
        ctags = list(dict.fromkeys(passthrough_ctags + mapped_ctags))
        inferred_groups = _infer_groups_from_ctags(ctags, allowed_groups)
        groups = list(dict.fromkeys(explicit_groups + inferred_groups))

        # Build ids from JSON (we’ll append IPs later in _service_sync)
        raw_ids: list[str] = []
        for v in (d.get("ip"), d.get("mac"), d.get("id")):
            if v:
                nid = _normalise_id(v)
                if nid:
                    raw_ids.append(nid)
        ids: list[str] = []
        seen: set[str] = set()
        for v in raw_ids:
            if v not in seen:
                seen.add(v)
                ids.append(v)

        if not ids:
            _LOGGER.warning("Skipping '%s': no ids provided", desired_name)
            continue

        # Decide add vs update using persistent search
        try:
            matched = await api.clients_search(ids)
        except Exception:
            matched = []
        if matched:
            final_name = matched[0].get("name") or desired_name
            should_update = True
        else:
            final_name = _unique_name(desired_name, ids, existing_names)
            should_update = False

        for g in groups:
            groups_to_clients.setdefault(g, []).append(final_name)

        # Features with cohort defaults (overridable per device)
        safesearch = (
            True if d.get("safesearch") is True else
            False if d.get("safesearch") is False else
            (any(g in SAFESEARCH_GROUPS for g in groups) or any(t in SAFESEARCH_CTAGS for t in ctags))
        )
        safebrowsing = (
            True if d.get("safebrowsing") is True else
            False if d.get("safebrowsing") is False else
            (any(g in SAFEBROWSING_GROUPS for g in groups) or any(t in SAFEBROWSING_CTAGS for t in ctags))
        )
        parental = (
            True if d.get("parental") is True else
            False if d.get("parental") is False else
            (any(g in PARENTAL_GROUPS for g in groups) or any(t in PARENTAL_CTAGS for t in ctags))
        )

        # Blocked services: per-device override or cohort preset
        if "blocked_services" in d:
            blocked = [s for s in (d.get("blocked_services") or [])]
            if valid_slugs:
                blocked = [s for s in blocked if s in valid_slugs]
            use_global_bs = bool(d.get("use_global_blocked_services", False))
        else:
            wanted = [slug for g in groups for slug in BLOCKED_SERVICES_PRESETS.get(g, [])]
            if valid_slugs:
                wanted = [s for s in wanted if s in valid_slugs]
            blocked = sorted(set(wanted))
            use_global_bs = False

        client_payload: dict[str, Any] = {
            "name": final_name,
            "ids": ids,
            "use_global_settings": False,
            "filtering_enabled": True,
            "parental_enabled": bool(parental),
            "safebrowsing_enabled": bool(safebrowsing),
            "safesearch_enabled": bool(safesearch),
            "use_global_blocked_services": use_global_bs,
            "blocked_services": blocked,
        }
        if ctags:
            client_payload["tags"] = ctags
        client_payload["_desired_name"] = desired_name
        
        _LOGGER.info(
            "Plan '%s': tags=%s, safebrowsing=%s, parental=%s, safesearch=%s, blocked=%s (global_bs=%s)",
            final_name,
            ctags,
            safebrowsing,
            parental,
            safesearch,
            blocked,
            use_global_bs,
        )

        plan.append((final_name, client_payload, should_update))

    return plan, groups_to_clients


def _fmt_client_union(names: List[str]) -> str:
    quoted = ["'" + n.replace("'", "\\'") + "'" for n in names]
    return "|".join(quoted)


def _generate_dynamic_rules(groups_to_clients: Dict[str, List[str]]) -> str:
    lines = ["! ---- Dynamically generated $client rules ----"]
    if "child" in groups_to_clients and groups_to_clients["child"]:
        union = _fmt_client_union(groups_to_clients["child"])
        for host in ("doh.cloudflare-dns.com", "dns.google", "dns.quad9.net"):
            lines.append(f"||{host}^$client={union}")
    if "media" in groups_to_clients and groups_to_clients["media"]:
        union = _fmt_client_union(groups_to_clients["media"])
        for host in ("facebook.com", "instagram.com", "tiktok.com", "discord.com", "reddit.com"):
            lines.append(f"||{host}^$client={union}")
    lines.append("! ---- End dynamic rules ----")
    return "\n".join(lines)
