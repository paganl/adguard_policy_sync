from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
from datetime import timedelta
from typing import Any, Dict, List, Tuple

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
    SAFESEARCH_GROUPS,
    SAFESEARCH_CTAGS,
    SAFEBROWSING_GROUPS,
    SAFEBROWSING_CTAGS,
    PARENTAL_GROUPS,
    PARENTAL_CTAGS,
    BLOCKED_SERVICES_PRESETS,
    KNOWN_CTAGS,
)

_LOGGER = logging.getLogger(__name__)
PLATFORMS: list[str] = []

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _normalise_id(idv: str) -> str | None:
    s = str(idv).strip()
    if not s:
        return None
    if ":" in s and all(c in "0123456789abcdefABCDEF:" for c in s):
        s2 = s.lower()
        if MAC_RE.match(s2):
            return s2
        return s2
    return s


def _parse_groups(groups_str: str | None) -> set[str]:
    if not groups_str:
        return set(DEFAULT_ALLOWED_GROUPS)
    parts = [p.strip().lower() for p in groups_str.split(",")]
    return {p for p in parts if p}


def _derive_short_id(idv: str) -> str:
    if ":" in idv:
        parts = idv.split(":")
        if len(parts) == 6:
            return parts[-2] + parts[-1]
        return parts[-1]
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


def _infer_groups_from_ctags(ctags: list[str], allowed_groups: set[str]) -> list[str]:
    # reverse map from CTAG_MAPPING
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
    seen: set[str] = set()
    out: list[str] = []
    for g in inferred:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out


def _ctags_from_json(d: dict[str, Any]) -> list[str]:
    """Only pass real AGH ctags; drop friendly groups like 'media', 'adult', 'lan'."""
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
    seen: set[str] = set()
    out: list[str] = []
    for t in mapped:
        if t not in seen:
            seen.add(t)
            out.append(t)
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
    append_dynamic_rules = bool(entry.data.get(CONF_APPEND_DYNAMIC_RULES, True))
    default_scan_range = (entry.data.get(CONF_SCAN_RANGE) or "").strip()
    default_auto_onboard = bool(entry.data.get(CONF_AUTO_ONBOARD, False))
    default_guest_group = (entry.data.get(CONF_GUEST_GROUP) or "guest").strip().lower()

    api = AdGuardAPI(
        session,
        base_url,
        username=username or None,
        password=password or None,
        verify_ssl=verify_ssl,
    )

    try:
        await api.get_version()
        _LOGGER.info("AdGuard Policy Sync: connected to %s", base_url)
    except Exception as e:
        _LOGGER.warning(
            "AdGuard Policy Sync: cannot reach %s yet: %s (services still registered)",
            base_url,
            e,
        )

    try:
        catalog = await api.list_blocked_services_catalog()
        valid_slugs = set(catalog.keys())
        _LOGGER.info("Loaded %d blocked services from AdGuard", len(valid_slugs))
    except Exception as e:
        _LOGGER.warning("Could not load blocked services catalog: %s", e)
        valid_slugs = set()

    hass.data[DOMAIN][entry.entry_id] = {
        "api": api,
        "devices_json": devices_json,
        "rules_text": rules_text,
        "valid_service_slugs": valid_slugs,
        "allowed_groups": allowed_groups,
        "append_dynamic_rules": append_dynamic_rules,
        "default_scan_range": default_scan_range,
        "default_auto_onboard": default_auto_onboard,
        "default_guest_group": default_guest_group,
        "_pause_state": {},
    }

    # --------------------------
    # Helpers: discovery & ARP
    # --------------------------

    async def _ping_once(ip: str) -> None:
        """Non-blocking 1-probe ping to warm neighbour table; ignore result."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "1", ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=2.0)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
        except FileNotFoundError:
            # ping not available; nothing we can do
            return
        except Exception:
            return

    def _read_arp_table() -> dict[str, str]:
        """Read /proc/net/arp → {ip: mac}."""
        table: dict[str, str] = {}
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                lines = f.read().strip().splitlines()[1:]
            for ln in lines:
                parts = ln.split()
                if len(parts) >= 4:
                    ip, _, _, mac = parts[0], parts[1], parts[2], parts[3]
                    mac = mac.lower()
                    if MAC_RE.match(mac) and IPV4_RE.match(ip):
                        table[ip] = mac
        except Exception as e:
            _LOGGER.debug("ARP read failed: %s", e)
        return table

    async def _arp_scan_range(cidr: str) -> list[tuple[str, str]]:
        """Ping-sweep a CIDR (non-blocking) then read ARP; return list of (ip, mac)."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception as e:
            _LOGGER.error("discover: invalid scan_range '%s': %s", cidr, e)
            return []

        hosts = [str(ip) for ip in net.hosts()]
        # Limit concurrency to be kind to HA
        sem = asyncio.Semaphore(64)

        async def _worker(ip: str):
            async with sem:
                await _ping_once(ip)

        # Fire & wait (best-effort; ping might not be present)
        await asyncio.gather(*(_worker(ip) for ip in hosts), return_exceptions=True)
        arp = await hass.async_add_executor_job(_read_arp_table)
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

        # Build guest preset (filtered)
        guest_block = BLOCKED_SERVICES_PRESETS.get(guest_group, [])
        if valid_slugs:
            guest_block = [s for s in guest_block if s in valid_slugs]

        # Get current clients for faster decisions
        try:
            status = await api.clients_status()
            existing_clients = status.get("clients", []) if isinstance(status, dict) else (status if isinstance(status, list) else [])
        except Exception:
            existing_clients = []

        # Index existing persistent names to avoid collisions
        existing_names = {c.get("name", "") for c in existing_clients if isinstance(c, dict)}

        discovered = await _arp_scan_range(scan_range)
        if not discovered:
            _LOGGER.warning("discover: no devices found in %s (ping may be unavailable)", scan_range)

        created_count = 0
        for ip, mac in discovered:
            # If AGH already has a persistent match, skip onboarding
            try:
                matched = await api.clients_search([mac, ip])
            except Exception:
                matched = []
            if matched:
                hass.bus.async_fire(f"{DOMAIN}.guest_discovered", {"ip": ip, "mac": mac, "persistent": True})
                continue

            # Unknown → optionally onboard as Guest
            hass.bus.async_fire(f"{DOMAIN}.guest_discovered", {"ip": ip, "mac": mac, "persistent": False})

            if not create_clients:
                continue

            suffix = (mac.split(":")[-2] + mac.split(":")[-1]) if mac else ip.split(".")[-1]
            name = f"Guest [{suffix}]"
            # ensure unique
            if name in existing_names:
                i = 2
                base = name
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
                "parental_enabled": False,
                "use_global_blocked_services": False,
                "blocked_services": guest_block,
                "tags": ["user_regular"],  # valid ctag
            }
            try:
                await api.clients_add(payload)
                created_count += 1
                hass.bus.async_fire(f"{DOMAIN}.guest_onboarded", {"name": name, "ip": ip, "mac": mac})
                _LOGGER.info("discover: onboarded Guest '%s' ids=%s", name, [mac, ip])
            except Exception as e:
                _LOGGER.error("discover: add failed for %s/%s: %s", ip, mac, e)

        _LOGGER.info("discover: created %d Guest clients in %s", created_count, scan_range)

    async def _service_sync(call: ServiceCall) -> None:
        data = hass.data[DOMAIN][entry.entry_id]
        api: AdGuardAPI = data["api"]
        valid_slugs: set[str] = data.get("valid_service_slugs", set())
        allowed_groups: set[str] = data.get("allowed_groups", set(DEFAULT_ALLOWED_GROUPS))
        append_dynamic_rules: bool = data.get("append_dynamic_rules", True)

        json_path = call.data.get("devices_json") or data.get("devices_json")
        rules_text_base = call.data.get("rules_text") or data.get("rules_text") or DEFAULT_RULES

        # Optional pre-scan + auto-onboard
        scan_range = (call.data.get("scan_range") or data.get("default_scan_range") or "").strip()
        auto_onboard = bool(call.data.get("auto_onboard_unknowns", data.get("default_auto_onboard", False)))
        guest_group = (call.data.get("guest_group") or data.get("default_guest_group") or "guest").strip().lower()
        if scan_range and auto_onboard:
            await _service_discover(ServiceCall(
                DOMAIN, "discover", {"scan_range": scan_range, "guest_group": guest_group, "create_clients": True}
            ))

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

        groups_to_clients: dict[str, list[str]] = {}
        plan: List[Tuple[str, dict, bool]] = []

        if devices:
            plan, groups_to_clients = await _plan_clients(api, devices, valid_slugs, allowed_groups)

        rules_text = rules_text_base
        if append_dynamic_rules and groups_to_clients:
            dyn = _generate_dynamic_rules(groups_to_clients)
            rules_text = rules_text.rstrip() + "\n\n" + dyn + "\n"

        try:
            await api.set_custom_rules(rules_text)
        except Exception as e:
            _LOGGER.error("Failed to set custom rules: %s", e)

        for final_name, client_payload, should_update in plan:
            try:
                if should_update:
                    await api.clients_update(final_name, client_payload)
                else:
                    await api.clients_add(client_payload)
            except Exception as e:
                _LOGGER.error(
                    "Client push failed for %s: %s | Payload=%s",
                    final_name,
                    e,
                    {
                        k: client_payload.get(k)
                        for k in (
                            "name", "ids", "tags", "use_global_settings",
                            "blocked_services", "use_global_blocked_services",
                            "safesearch_enabled", "safebrowsing_enabled", "parental_enabled",
                        )
                    },
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
            if isinstance(status, dict):
                existing_clients = status.get("clients", [])
            elif isinstance(status, list):
                existing_clients = status
            else:
                existing_clients = []
        except Exception as e:
            _LOGGER.error("pause: failed to list clients: %s", e)
            return

        indexed = {
            c.get("name"): c for c in existing_clients if isinstance(c, dict) and c.get("name")
        }

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
                payload.update({
                    "safebrowsing_enabled": False,
                    "parental_enabled": False,
                    "use_global_blocked_services": False,
                    "blocked_services": [],
                })
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
    for svc in ("discover", "sync", "pause"):
        with contextlib.suppress(Exception):
            hass.services.async_remove(DOMAIN, svc)
    hass.data[DOMAIN].pop(entry.entry_id, None)
    return True


async def _plan_clients(
    api: AdGuardAPI,
    devices: list[dict[str, Any]],
    valid_slugs: set[str],
    allowed_groups: set[str],
) -> Tuple[List[Tuple[str, dict, bool]], Dict[str, List[str]]]:
    # Use clients_status for names/index only (search decides add vs update)
    try:
        status = await api.clients_status()
        if isinstance(status, dict):
            existing_clients = status.get("clients", [])
        elif isinstance(status, list):
            existing_clients = status
        else:
            existing_clients = []
    except Exception:
        existing_clients = []

    existing_names = {c.get("name", "") for c in existing_clients if isinstance(c, dict)}

    plan: List[Tuple[str, dict, bool]] = []
    groups_to_clients: Dict[str, List[str]] = {}

    for d in devices:
        desired_name = d.get("name") or "unnamed"
        explicit_groups = _groups_for_device(d, allowed_groups)
        passthrough_ctags = _ctags_from_json(d)
        mapped_ctags = _map_groups_to_ctags(explicit_groups)
        ctags = list(dict.fromkeys(passthrough_ctags + mapped_ctags))

        # Infer friendly groups from ctags and union with explicit groups
        inferred_groups = _infer_groups_from_ctags(ctags, allowed_groups)
        groups = list(dict.fromkeys(explicit_groups + inferred_groups))

        # Build ids: include MAC/IP/custom id from JSON
        raw_ids: list[str] = []
        for v in (d.get("ip"), d.get("mac"), d.get("id")):
            if v:
                nid = _normalise_id(v)
                if nid:
                    raw_ids.append(nid)

        # De-dup while preserving order
        ids: list[str] = []
        seen: set[str] = set()
        for v in raw_ids:
            if v not in seen:
                seen.add(v)
                ids.append(v)

        if not ids:
            _LOGGER.warning("Skipping '%s': no ids provided", desired_name)
            continue

        # Decide add vs update *only* via clients_search (persistent match)
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

        # Feature flags (explicit override > cohort defaults)
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

        # Blocked services: per-device override or presets (filtered)
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

        _LOGGER.info(
            "Plan '%s': tags=%s, safebrowsing=%s, parental=%s, safesearch=%s, blocked=%s (global_bs=%s)",
            final_name, ctags, safebrowsing, parental, safesearch, blocked, use_global_bs,
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
