from __future__ import annotations

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
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[str] = []

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

    api = AdGuardAPI(
        session,
        base_url,
        username=username or None,
        password=password or None,
        verify_ssl=verify_ssl,
    )

    # Best-effort connectivity; still register services
    try:
        await api.get_version()
        _LOGGER.info("AdGuard Policy Sync: connected to %s", base_url)
    except Exception as e:
        _LOGGER.warning(
            "AdGuard Policy Sync: cannot reach %s yet: %s (services still registered)",
            base_url,
            e,
        )

    # Blocked services catalog is optional
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
        "_pause_state": {},
    }

    async def _service_sync(call: ServiceCall) -> None:
        data = hass.data[DOMAIN][entry.entry_id]
        api: AdGuardAPI = data["api"]
        valid_slugs: set[str] = data.get("valid_service_slugs", set())
        allowed_groups: set[str] = data.get(
            "allowed_groups", set(DEFAULT_ALLOWED_GROUPS)
        )
        append_dynamic_rules: bool = data.get("append_dynamic_rules", True)
        json_path = call.data.get("devices_json") or data.get("devices_json")
        rules_text_base = (
            call.data.get("rules_text") or data.get("rules_text") or DEFAULT_RULES
        )

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
            plan, groups_to_clients = await _plan_clients(
                api, devices, valid_slugs, allowed_groups
            )

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
                            "name",
                            "ids",
                            "tags",
                            "use_global_settings",
                            "blocked_services",
                            "use_global_blocked_services",
                            "safesearch_enabled",
                            "safebrowsing_enabled",
                            "parental_enabled",
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
            c.get("name"): c
            for c in existing_clients
            if isinstance(c, dict) and c.get("name")
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
                "use_global_blocked_services": bool(
                    c.get("use_global_blocked_services", True)
                ),
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
                _LOGGER.info(
                    "pause: paused '%s' for %d minutes (scope=%s)",
                    name,
                    minutes,
                    scope,
                )
            except Exception as e:
                _LOGGER.error("pause: update failed for '%s': %s", name, e)
                continue

            async def _restore_cb(now):
                snap = hass.data[DOMAIN][entry.entry_id]["_pause_state"].pop(
                    name, None
                )
                if not snap:
                    return
                try:
                    await api.clients_update(name, snap)
                    _LOGGER.info("pause: restored '%s'", name)
                except Exception as e:
                    _LOGGER.error("pause: restore failed for '%s': %s", name, e)

            ha_event.async_call_later(hass, timedelta(minutes=minutes), _restore_cb)

    hass.services.async_register(DOMAIN, "sync", _service_sync)
    hass.services.async_register(DOMAIN, "pause", _service_pause)

    if devices_json:
        hass.async_create_task(
            hass.services.async_call(DOMAIN, "sync", {}, blocking=False)
        )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.services.async_remove(DOMAIN, "sync")
    hass.services.async_remove(DOMAIN, "pause")
    hass.data[DOMAIN].pop(entry.entry_id, None)
    return True


def _groups_for_device(d: dict[str, Any], allowed_groups: set[str]) -> list[str]:
    tags = [str(t).lower() for t in d.get("tags", []) if t]
    return [g for g in tags if g in allowed_groups]


def _infer_groups_from_ctags(ctags: list[str], allowed_groups: set[str]) -> list[str]:
    """
    Map known AGH ctags back to our friendly groups so cohort defaults apply
    even when the JSON uses only ctags.
    """
    # Build a reverse map once from CTAG_MAPPING
    rev: dict[str, str] = {}
    for grp, ct_list in CTAG_MAPPING.items():
        for ct in ct_list:
            rev[ct] = grp

    inferred: list[str] = []
    for t in ctags:
        g = rev.get(t)
        if g and g in allowed_groups:
            inferred.append(g)

    # User cohorts if only user_* ctags are present
    if "user_regular" in ctags and "guest" in allowed_groups:
        inferred.append("guest")
    if "user_admin" in ctags and "adult" in allowed_groups:
        inferred.append("adult")

    # De-dup while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for g in inferred:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out


def _ctags_passthrough_unfiltered(d: dict[str, Any]) -> list[str]:
    raw = [str(t).strip().lower() for t in d.get("tags", []) if t]
    out: list[str] = []
    seen: set[str] = set()
    for t in raw:
        if not t:
            continue
        if all(c.isalnum() or c == "_" for c in t):
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out


def _map_groups_to_ctags(groups: list[str]) -> list[str]:
    mapped = [c for g in groups for c in CTAG_MAPPING.get(g, [])]
    # De-dup while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for t in mapped:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


async def _plan_clients(
    api: AdGuardAPI,
    devices: list[dict[str, Any]],
    valid_slugs: set[str],
    allowed_groups: set[str],
) -> Tuple[List[Tuple[str, dict, bool]], Dict[str, List[str]]]:
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
    existing_ids: set[str] = set()
    for c in existing_clients:
        ids_list = c.get("ids") if isinstance(c, dict) else None
        if isinstance(ids_list, list):
            for idv in ids_list:
                existing_ids.add(str(idv))

    plan: List[Tuple[str, dict, bool]] = []
    groups_to_clients: Dict[str, List[str]] = {}

    for d in devices:
        desired_name = d.get("name") or "unnamed"
        explicit_groups = _groups_for_device(d, allowed_groups)
        passthrough_ctags = _ctags_passthrough_unfiltered(d)
        mapped_ctags = _map_groups_to_ctags(explicit_groups)
        ctags = list(dict.fromkeys(passthrough_ctags + mapped_ctags))

        # Infer groups from ctags and union with explicit groups
        inferred_groups = _infer_groups_from_ctags(ctags, allowed_groups)
        groups = list(dict.fromkeys(explicit_groups + inferred_groups))

        ip = d.get("ip")
        mac = d.get("mac")
        arbitrary_id = d.get("id")
        raw_ids: list[str] = []
        for v in (ip, mac, arbitrary_id):
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

        should_update = any(idv in existing_ids for idv in ids)
        final_name = desired_name
        if should_update:
            try:
                matched = await api.clients_search(ids)
                if matched:
                    final_name = matched[0].get("name") or desired_name
            except Exception:
                pass
        else:
            final_name = _unique_name(desired_name, ids, existing_names)

        for g in groups:
            groups_to_clients.setdefault(g, []).append(final_name)

        # Feature flags with overrides (honour explicit booleans; else cohort defaults/ctags)
        safesearch = (
            True
            if d.get("safesearch") is True
            else False
            if d.get("safesearch") is False
            else (any(g in SAFESEARCH_GROUPS for g in groups) or any(t in SAFESEARCH_CTAGS for t in ctags))
        )

        safebrowsing = (
            True
            if d.get("safebrowsing") is True
            else False
            if d.get("safebrowsing") is False
            else (any(g in SAFEBROWSING_GROUPS for g in groups) or any(t in SAFEBROWSING_CTAGS for t in ctags))
        )

        parental = (
            True
            if d.get("parental") is True
            else False
            if d.get("parental") is False
            else (any(g in PARENTAL_GROUPS for g in groups) or any(t in PARENTAL_CTAGS for t in ctags))
        )

        # Blocked services: per-device override or preset union (filter invalid slugs)
        if "blocked_services" in d:
            blocked = [s for s in (d.get("blocked_services") or [])]
            if valid_slugs:
                blocked = [s for s in blocked if s in valid_slugs]
            use_global_bs = bool(d.get("use_global_blocked_services", False))
        else:
            # Presets apply even when groups were inferred from ctags
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
        # Only set tags if non-empty (avoid wiping on AGH)
        if ctags:
            client_payload["tags"] = ctags

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
