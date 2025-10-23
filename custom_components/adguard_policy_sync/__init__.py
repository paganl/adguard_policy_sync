from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import re
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
    CONF_SCAN_RANGE,
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
)

_LOGGER = logging.getLogger(__name__)
PLATFORMS: list[str] = []

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
MAC_RE  = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _is_ipv4(s: str) -> bool: return bool(IPV4_RE.match(s))
def _is_mac(s: str)  -> bool: return bool(MAC_RE.match(s))

def _normalise_id(idv: str) -> str | None:
    s = str(idv).strip()
    if not s:
        return None
    if ":" in s and all(c in "0123456789abcdefABCDEF:" for c in s):
        s2 = s.lower()
        return s2 if MAC_RE.match(s2) else s2
    return s

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
        existing_names.add(base_name); return base_name
    sid = _derive_short_id(ids[0]); candidate = f"{base_name} [{sid}]"; name = candidate; i = 2
    while name in existing_names:
        name = f"{candidate} #{i}"; i += 1
    existing_names.add(name); return name

def _groups_for_device(d: dict[str, Any], allowed_groups: set[str]) -> list[str]:
    tags = [str(t).lower() for t in d.get("tags", []) if t]
    return [g for g in tags if g in allowed_groups]

def _ctags_from_json(d: dict[str, Any]) -> list[str]:
    raw = [str(t).strip().lower() for t in d.get("tags", []) if t]
    out: list[str] = []; seen: set[str] = set()
    for t in raw:
        if t in KNOWN_CTAGS and t not in seen:
            seen.add(t); out.append(t)
    return out

def _map_groups_to_ctags(groups: list[str]) -> list[str]:
    mapped = [c for g in groups for c in CTAG_MAPPING.get(g, [])]
    out: list[str] = []; seen: set[str] = set()
    for t in mapped:
        if t not in seen: seen.add(t); out.append(t)
    return out

def _infer_groups_from_ctags(ctags: list[str], allowed_groups: set[str]) -> list[str]:
    rev: dict[str, str] = {}
    for grp, ct_list in CTAG_MAPPING.items():
        for ct in ct_list: rev[ct] = grp
    inferred: list[str] = []
    for t in ctags:
        g = rev.get(t)
        if g and g in allowed_groups: inferred.append(g)
    if "user_regular" in ctags and "guest" in allowed_groups: inferred.append("guest")
    if "user_admin" in ctags and "adult" in allowed_groups: inferred.append("adult")
    out: list[str] = []; seen: set[str] = set()
    for g in inferred:
        if g not in seen: seen.add(g); out.append(g)
    return out

async def async_setup(hass: HomeAssistant, config) -> bool:
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})
    session  = aiohttp_client.async_get_clientsession(hass)
    base_url = entry.data[CONF_BASE_URL]
    username = (entry.data.get(CONF_USERNAME) or "").strip()
    password = (entry.data.get(CONF_PASSWORD) or "").strip()
    verify_ssl = entry.data.get(CONF_VERIFY_SSL, True)

    devices_json       = entry.data.get(CONF_DEVICES_JSON)
    rules_text         = entry.data.get(CONF_RULES_TEXT) or DEFAULT_RULES
    allowed_groups     = _parse_groups(entry.data.get(CONF_ALLOWED_GROUPS))
    append_dyn         = bool(entry.data.get(CONF_APPEND_DYNAMIC_RULES, True))
    default_scan_range = (entry.data.get(CONF_SCAN_RANGE) or "").strip()
    default_auto_on    = bool(entry.data.get(CONF_AUTO_ONBOARD, False))
    default_guest_grp  = (entry.data.get(CONF_GUEST_GROUP) or "guest").strip().lower()

    api = AdGuardAPI(session, base_url,
                     username=username or None, password=password or None,
                     verify_ssl=verify_ssl)

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

    hass.data[DOMAIN][entry.entry_id] = dict(
        api=api, devices_json=devices_json, rules_text=rules_text,
        valid_service_slugs=valid_slugs, allowed_groups=allowed_groups,
        append_dynamic_rules=append_dyn,
        default_scan_range=default_scan_range,
        default_auto_onboard=default_auto_on,
        default_guest_group=default_guest_grp,
        _pause_state={},
    )

    # --------------------------
    # Discovery (nmap) helpers
    # --------------------------

    async def _nmap_scan(cidr: str) -> list[tuple[str, str]]:
        """
        Return [(ip, mac)] using `nmap -sn`. Works best with root/cap_net_raw.
        Falls back to empty list if nmap missing.
        """
        cmd = ["nmap", "-sn", "-PE", "-T4", "--host-timeout", "2s", cidr]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
        except FileNotFoundError:
            _LOGGER.warning("nmap not found; falling back to ping+ARP")
            return []

        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=90.0)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError): proc.kill()
            return []

        text = out.decode(errors="ignore").splitlines()
        pairs: list[tuple[str, str]] = []
        cur_ip: str | None = None
        for ln in text:
            # Nmap scan report for 10.2.0.77
            if "Nmap scan report for " in ln:
                cur_ip = ln.split()[-1]
                continue
            # MAC Address: aa:bb:cc:dd:ee:ff (Vendor)
            if "MAC Address:" in ln and cur_ip and _is_ipv4(cur_ip):
                parts = ln.split("MAC Address:")[-1].strip().split()
                mac = parts[0].lower()
                if _is_mac(mac):
                    pairs.append((cur_ip, mac))
                    cur_ip = None
        return pairs

    async def _ping_sweep_and_arp(cidr: str) -> list[tuple[str, str]]:
        """Fallback: ping all hosts (best-effort), then read /proc/net/arp."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception as e:
            _LOGGER.error("discover: invalid scan_range '%s': %s", cidr, e)
            return []
        hosts = [str(ip) for ip in net.hosts()]
        sem = asyncio.Semaphore(64)

        async def _ping(ip: str):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ping", "-c", "1", "-W", "1", ip,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(proc.communicate(), timeout=2.0)
            except FileNotFoundError:
                return
            except Exception:
                return

        await asyncio.gather(*(_ping(ip) for ip in hosts), return_exceptions=True)

        def _read_arp():
            table: dict[str, str] = {}
            try:
                with open("/proc/net/arp", "r", encoding="utf-8") as f:
                    lines = f.read().strip().splitlines()[1:]
                for ln in lines:
                    parts = ln.split()
                    if len(parts) >= 4:
                        ip, mac = parts[0], parts[3].lower()
                        if _is_ipv4(ip) and _is_mac(mac):
                            table[ip] = mac
            except Exception as e:
                _LOGGER.debug("ARP read failed: %s", e)
            return table

        arp = await hass.async_add_executor_job(_read_arp)
        return [(ip, mac) for ip, mac in arp.items() if ip in hosts]

    # --------------------------
    # Services
    # --------------------------

    async def _service_discover(call: ServiceCall) -> None:
        data = hass.data[DOMAIN][entry.entry_id]
        api: AdGuardAPI = data["api"]
        valid_slugs: set[str] = data.get("valid_service_slugs", set())

        scan_range = (call.data.get("scan_range") or data.get("default_scan_range") or "").strip()
        guest_group = (call.data.get("guest_group") or data.get("default_guest_group") or "guest").strip().lower()
        create_clients = bool(call.data.get("create_clients", True))
        if not scan_range:
            _LOGGER.error("discover: scan_range is required")
            return

        # 1) nmap first, then fallback
        pairs = await _nmap_scan(scan_range)
        if not pairs:
            pairs = await _ping_sweep_and_arp(scan_range)

        # 2) Build guest preset (filtered)
        guest_block = BLOCKED_SERVICES_PRESETS.get(guest_group, [])
        if valid_slugs:
            guest_block = [s for s in guest_block if s in valid_slugs]

        # 3) Check existing persistent matches
        try:
            status = await api.clients_status()
            existing = status.get("clients", []) if isinstance(status, dict) else (status if isinstance(status, list) else [])
        except Exception:
            existing = []
        existing_names = {c.get("name","") for c in existing if isinstance(c, dict)}

        created = 0
        for ip, mac in pairs:
            try:
                matched = await api.clients_search([mac, ip])
            except Exception:
                matched = []

            if matched:
                hass.bus.async_fire(f"{DOMAIN}.guest_discovered", {"ip": ip, "mac": mac, "persistent": True})
                continue

            hass.bus.async_fire(f"{DOMAIN}.guest_discovered", {"ip": ip, "mac": mac, "persistent": False})
            if not create_clients:
                continue

            # unique Guest name
            suffix = (mac.split(":")[-2] + mac.split(":")[-1]) if mac else ip.split(".")[-1]
            name = f"Guest [{suffix}]"
            base = name; i = 2
            while name in existing_names:
                name = f"{base} #{i}"; i += 1
            existing_names.add(name)

            payload = {
                "name": name,
                "ids": [mac, ip],
                "use_global_settings": False,
                "filtering_enabled": True,
                "safebrowsing_enabled": True,
                "safesearch_enabled": True,
                "parental_enabled": False,
                "use_global_blocked_services": False,
                "blocked_services": guest_block,
                "tags": ["user_regular"],  # valid AGH ctag
            }
            try:
                await api.clients_add(payload)
                created += 1
                hass.bus.async_fire(f"{DOMAIN}.guest_onboarded", {"name": name, "ip": ip, "mac": mac})
                _LOGGER.info("discover: onboarded Guest '%s' ids=%s", name, [mac, ip])
            except Exception as e:
                _LOGGER.error("discover: add failed for %s/%s: %s", ip, mac, e)

        _LOGGER.info("discover: created %d Guest clients (range %s)", created, scan_range)

    async def _service_sync(call: ServiceCall) -> None:
        data = hass.data[DOMAIN][entry.entry_id]
        api: AdGuardAPI = data["api"]
        valid_slugs: set[str] = data.get("valid_service_slugs", set())
        allowed_groups: set[str] = data.get("allowed_groups", set(DEFAULT_ALLOWED_GROUPS))
        append_dynamic: bool = data.get("append_dynamic_rules", True)

        json_path = call.data.get("devices_json") or data.get("devices_json")
        rules_text_base = call.data.get("rules_text") or data.get("rules_text") or DEFAULT_RULES

        # Optional pre-scan & auto-onboard
        scan_range = (call.data.get("scan_range") or data.get("default_scan_range") or "").strip()
        auto_onboard = bool(call.data.get("auto_onboard_unknowns", data.get("default_auto_onboard", False)))
        guest_group = (call.data.get("guest_group") or data.get("default_guest_group") or "guest").strip().lower()

        discovered_pairs: list[tuple[str,str]] = []
        if scan_range:
            discovered_pairs = await _nmap_scan(scan_range)
            if not discovered_pairs:
                discovered_pairs = await _ping_sweep_and_arp(scan_range)
            if auto_onboard:
                await _service_discover(ServiceCall(DOMAIN, "discover",
                    {"scan_range": scan_range, "guest_group": guest_group, "create_clients": True}))

        # Build MAC->IP map from scan
        mac_to_ipv4: dict[str,str] = {}
        for ip, mac in discovered_pairs:
            if _is_mac(mac) and _is_ipv4(ip):
                mac_to_ipv4.setdefault(mac, ip)

        # Load existing clients for name/index and additional MAC->IP learning
        try:
            status_now = await api.clients_status()
            existing_now = status_now.get("clients", []) if isinstance(status_now, dict) else (status_now if isinstance(status_now, list) else [])
        except Exception:
            existing_now = []
        existing_names = {c.get("name","") for c in existing_now if isinstance(c, dict)}

        # Learn extra MAC->IP from AGH
        for c in existing_now:
            if not isinstance(c, dict): continue
            ids = c.get("ids") or []
            ips  = [i for i in ids if isinstance(i,str) and _is_ipv4(i)]
            macs = [i for i in ids if isinstance(i,str) and _is_mac(i)]
            if ips:
                for m in macs:
                    mac_to_ipv4.setdefault(m, ips[0])

        # Read devices JSON (non-blocking)
        devices: list[dict[str, Any]] | None = None
        if json_path:
            if not os.path.isabs(json_path):
                json_path = os.path.join(hass.config.path(), json_path)
            def _read_json(path: str):
                with open(path, "r", encoding="utf-8") as f: return json.load(f)
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

        # Ensure every payload has both MAC and IP if we know them
        # Also flip add->update if any id already belongs to an existing client
        # Build id->name reverse index once
        id_to_name: dict[str,str] = {}
        for c in existing_now:
            if not isinstance(c, dict): continue
            nm = c.get("name")
            for i in (c.get("ids") or []):
                if isinstance(i,str): id_to_name[i] = nm

        def _existing_name_for_ids(ids: list[str]) -> str | None:
            for i in ids or []:
                nm = id_to_name.get(i)
                if nm: return nm
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

        for final_name, client_payload, should_update in plan:
            # Union MAC + IP
            ids = list(client_payload.get("ids") or [])
            macs = [i for i in ids if _is_mac(i)]
            has_v4 = any(_is_ipv4(i) for i in ids)
            if macs and not has_v4:
                live = mac_to_ipv4.get(macs[0])
                if live and live not in ids:
                    ids.append(live)
            client_payload["ids"] = ids

            # Decide add/update (persistent) and recover duplicate adds
            target_name = final_name
            action_update = bool(should_update)
            if not action_update:
                existing_for_ids = _existing_name_for_ids(ids)
                if existing_for_ids:
                    target_name = existing_for_ids
                    action_update = True
                    client_payload["name"] = existing_for_ids

            try:
                if action_update:
                    await api.clients_update(target_name, client_payload)
                else:
                    await api.clients_add(client_payload)
                # success: learn ids→name for later items
                for i in ids: id_to_name[i] = target_name

            except ClientResponseError as cre:
                msg = f"{cre}"
                m = re.search(r'another client "([^"]+)" uses the same', msg)
                if not action_update and m:
                    existing_for_ids = m.group(1)
                    client_payload["name"] = existing_for_ids
                    try:
                        await api.clients_update(existing_for_ids, client_payload)
                        for i in ids: id_to_name[i] = existing_for_ids
                        continue
                    except Exception as e2:
                        _LOGGER.error("Retry as update failed for %s → %s: %s | Payload=%s",
                                      final_name, existing_for_ids, e2,
                                      {k: client_payload.get(k) for k in ("name","ids","tags","blocked_services","use_global_blocked_services")})
                        continue

                _LOGGER.error("Client push failed for %s: %s | Payload=%s",
                              final_name, cre,
                              {k: client_payload.get(k) for k in ("name","ids","tags","use_global_settings",
                                                                   "blocked_services","use_global_blocked_services",
                                                                   "safesearch_enabled","safebrowsing_enabled","parental_enabled")})
                continue

            except Exception as e:
                _LOGGER.error("Client push failed for %s: %s | Payload=%s", final_name, e,
                              {k: client_payload.get(k) for k in ("name","ids","tags","use_global_blocked_services","blocked_services")})
                continue

    async def _service_pause(call: ServiceCall) -> None:
        data = hass.data[DOMAIN][entry.entry_id]
        api: AdGuardAPI = data["api"]
        minutes = int(call.data.get("minutes", 15))
        scope = str(call.data.get("scope", "filtering_only")).lower()
        clients = call.data.get("clients") or []
        if not clients:
            _LOGGER.error("pause: no clients provided"); return

        try:
            status = await api.clients_status()
            existing = status.get("clients", []) if isinstance(status, dict) else (status if isinstance(status, list) else [])
        except Exception as e:
            _LOGGER.error("pause: failed to list clients: %s", e); return

        indexed = {c.get("name"): c for c in existing if isinstance(c, dict) and c.get("name")}
        for name in clients:
            c = indexed.get(name)
            if not c:
                _LOGGER.warning("pause: client '%s' not found", name); continue

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
                payload.update({"safebrowsing_enabled": False, "parental_enabled": False,
                                "use_global_blocked_services": False, "blocked_services": []})
            try:
                await api.clients_update(name, payload)
                _LOGGER.info("pause: paused '%s' for %d minutes (scope=%s)", name, minutes, scope)
            except Exception as e:
                _LOGGER.error("pause: update failed for '%s': %s", name, e); continue

            async def _restore_cb(now):
                snap = hass.data[DOMAIN][entry.entry_id]["_pause_state"].pop(name, None)
                if not snap: return
                try:
                    await api.clients_update(name, snap)
                    _LOGGER.info("pause: restored '%s'", name)
                except Exception as e:
                    _LOGGER.error("pause: restore failed for '%s': %s", name, e)

            ha_event.async_call_later(hass, timedelta(minutes=minutes), _restore_cb)

    hass.services.async_register(DOMAIN, "discover", _service_discover)
    hass.services.async_register(DOMAIN, "sync", _service_sync)
    hass.services.async_register(DOMAIN, "pause", _service_pause)

    # Kick off an initial sync if a JSON path is configured
    if devices_json:
        hass.async_create_task(hass.services.async_call(DOMAIN, "sync", {}, blocking=False))
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    with contextlib.suppress(Exception): hass.services.async_remove(DOMAIN, "discover")
    with contextlib.suppress(Exception): hass.services.async_remove(DOMAIN, "sync")
    with contextlib.suppress(Exception): hass.services.async_remove(DOMAIN, "pause")
    hass.data[DOMAIN].pop(entry.entry_id, None)
    return True

async def _plan_clients(api: AdGuardAPI, devices: list[dict[str, Any]], valid_slugs: set[str],
                        allowed_groups: set[str]) -> Tuple[List[Tuple[str, dict, bool]], Dict[str, List[str]]]:
    # Use clients_status for names/index; clients_search decides add vs update
    try:
        status = await api.clients_status()
        existing = status.get("clients", []) if isinstance(status, dict) else (status if isinstance(status, list) else [])
    except Exception:
        existing = []
    existing_names = {c.get("name","") for c in existing if isinstance(c, dict)}

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
                seen.add(v); ids.append(v)

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

        # Features with sensible cohort defaults (overridable per device)
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

        # Blocked services: device override or cohort presets (filtered)
        if "blocked_services" in d:
            blocked = [s for s in (d.get("blocked_services") or [])]
            if valid_slugs: blocked = [s for s in blocked if s in valid_slugs]
            use_global_bs = bool(d.get("use_global_blocked_services", False))
        else:
            wanted = [slug for g in groups for slug in BLOCKED_SERVICES_PRESETS.get(g, [])]
            if valid_slugs: wanted = [s for s in wanted if s in valid_slugs]
            blocked = sorted(set(wanted))
            use_global_bs = False

        client_payload: dict[str, Any] = {
            "name": final_name, "ids": ids, "use_global_settings": False,
            "filtering_enabled": True,
            "parental_enabled": bool(parental),
            "safebrowsing_enabled": bool(safebrowsing),
            "safesearch_enabled": bool(safesearch),
            "use_global_blocked_services": use_global_bs,
            "blocked_services": blocked,
        }
        if ctags:
            client_payload["tags"] = ctags

        _LOGGER.info("Plan '%s': tags=%s, safebrowsing=%s, parental=%s, safesearch=%s, blocked=%s (global_bs=%s)",
                     final_name, ctags, safebrowsing, parental, safesearch, blocked, use_global_bs)

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
