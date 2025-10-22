from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Tuple

from homeassistant.const import CONF_USERNAME, CONF_PASSWORD, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers import aiohttp_client
from homeassistant.exceptions import ConfigEntryNotReady

from .const import (
    DOMAIN, CONF_BASE_URL, CONF_DEVICES_JSON, CONF_RULES_TEXT, CONF_ALLOWED_GROUPS, CONF_APPEND_DYNAMIC_RULES,
    DEFAULT_RULES, DEFAULT_ALLOWED_GROUPS, ALLOWED_CTAGS, CTAG_MAPPING, SAFESEARCH_GROUPS, SAFESEARCH_CTAGS, BLOCKED_SERVICES_PRESETS
)
from .api import AdGuardAPI

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

    api = AdGuardAPI(session, base_url, username=username or None, password=password or None, verify_ssl=verify_ssl)

    try:
        status = await api.get_version()
        _LOGGER.info("Connected to AdGuard Home at %s — status: %s", base_url, status)
    except Exception as e:
        _LOGGER.exception("AdGuard Policy Sync: connectivity check failed to %s", base_url)
        raise ConfigEntryNotReady(f"Cannot reach AdGuard Home at {base_url}: {e}") from e

    try:
        catalog = await api.list_blocked_services_catalog()
        valid_slugs = set(catalog.keys())
        _LOGGER.info("Loaded %d blocked services from AdGuard", len(valid_slugs))
    except Exception as e:
        _LOGGER.warning("Could not load blocked services catalog: %s", e)
        valid_slugs = set()

    hass.data[DOMAIN][entry.entry_id] = {
        "api": api, "devices_json": devices_json, "rules_text": rules_text,
        "valid_service_slugs": valid_slugs, "allowed_groups": allowed_groups,
        "append_dynamic_rules": append_dynamic_rules,
    }

    async def _service_sync(call: ServiceCall) -> None:
        data = hass.data[DOMAIN][entry.entry_id]
        api: AdGuardAPI = data["api"]
        valid_slugs: set[str] = data.get("valid_service_slugs", set())
        allowed_groups: set[str] = data.get("allowed_groups", set(DEFAULT_ALLOWED_GROUPS))
        append_dynamic_rules: bool = data.get("append_dynamic_rules", True)
        json_path = call.data.get("devices_json") or data.get("devices_json")
        rules_text_base = call.data.get("rules_text") or data.get("rules_text") or DEFAULT_RULES

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
            rules_text = rules_text.rstrip() + "\\n\\n" + dyn + "\\n"

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
                import logging
                logging.getLogger(__name__).error("Client push failed for %s: %s | Payload=%s", final_name, e, {k: client_payload[k] for k in ("name","ids","tags","use_global_settings","blocked_services","use_global_blocked_services","safesearch_enabled")})
                continue

    hass.services.async_register(DOMAIN, "sync", _service_sync)

    if devices_json:
        hass.async_create_task(hass.services.async_call(DOMAIN, "sync", {}, blocking=False))

    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.services.async_remove(DOMAIN, "sync")
    hass.data[DOMAIN].pop(entry.entry_id, None)
    return True

def _groups_for_device(d: dict[str, Any], allowed_groups: set[str]) -> list[str]:
    tags = [str(t).lower() for t in d.get("tags", []) if t]
    return [g for g in tags if g in allowed_groups]

def _ctags_passthrough_unfiltered(d: dict[str, Any]) -> list[str]:
    raw = [str(t).strip().lower() for t in d.get("tags", []) if t]
    out = []
    seen = set()
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
    return list(dict.fromkeys(mapped))

async def _plan_clients(api: AdGuardAPI, devices: list[dict[str, Any]], valid_slugs: set[str],
                        allowed_groups: set[str]) -> Tuple[List[Tuple[str, dict, bool]], Dict[str, List[str]]]:
    try:
        status = await api.clients_status()
        if isinstance(status, dict):
            existing_clients = status.get("clients") or []
        elif isinstance(status, list):
            existing_clients = status
        else:
            existing_clients = []
    except Exception:
        existing_clients = []

    existing_names = {c.get("name","") for c in existing_clients if isinstance(c, dict)}
    existing_ids = set()
    for c in existing_clients:
        ids_list = c.get("ids") if isinstance(c, dict) else None
        if isinstance(ids_list, list):
            for idv in ids_list:
                existing_ids.add(str(idv))

    plan: List[Tuple[str, dict, bool]] = []
    groups_to_clients: Dict[str, List[str]] = {}

    for d in devices:
        desired_name = d.get("name") or "unnamed"
        groups = _groups_for_device(d, allowed_groups)
        passthrough_ctags = _ctags_passthrough_unfiltered(d)
        mapped_ctags = _map_groups_to_ctags(groups)
        ctags = list(dict.fromkeys(passthrough_ctags + mapped_ctags))

        ip = d.get("ip")
        mac = d.get("mac")
        arbitrary_id = d.get("id")
        raw_ids = []
        for v in (ip, mac, arbitrary_id):
            if v:
                nid = _normalise_id(v)
                if nid:
                    raw_ids.append(nid)
        ids = []
        seen = set()
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
            matched = await api.clients_search(ids)
            if matched:
                final_name = matched[0].get("name") or desired_name
        else:
            final_name = _unique_name(desired_name, ids, existing_names)

        for g in groups:
            groups_to_clients.setdefault(g, []).append(final_name)

        safesearch_explicit = bool(d.get("safesearch", False))
        safesearch = safesearch_explicit or any(g in SAFESEARCH_GROUPS for g in groups) or any(t in {"user_child"} for t in ctags)

        wanted = [slug for g in groups for slug in BLOCKED_SERVICES_PRESETS.get(g, [])]
        blocked = sorted({s for s in wanted if not valid_slugs or s in valid_slugs})

        client_payload = {
            "name": final_name,
            "ids": ids,
            "upstreams": [],
            "use_global_settings": False,
            "filtering_enabled": True,
            "parental_enabled": False,
            "safebrowsing_enabled": False,
            "safesearch_enabled": bool(safesearch),
            "use_global_blocked_services": False,
            "blocked_services": blocked,
        }
        if ctags:
            client_payload["tags"] = ctags  # only set when non-empty

        _LOGGER.info("Plan for '%s': from_json_tags=%s -> final_tags=%s safesearch=%s blocked_services=%s",
                     final_name, d.get("tags", []), ctags, safesearch, blocked)

        plan.append((final_name, client_payload, should_update))

    return plan, groups_to_clients

def _fmt_client_union(names: List[str]) -> str:
    quoted = ["'" + n.replace("'", "\\'") + "'" for n in names]
    return "|".join(quoted)

def _generate_dynamic_rules(groups_to_clients: Dict[str, List[str]]) -> str:
    lines = ["! ---- Dynamically generated $client rules ----"]
    if "child" in groups_to_clients and groups_to_clients["child"]:
        union = _fmt_client_union(groups_to_clients["child"])
        for host in ("doh.cloudflare-dns.com","dns.google","dns.quad9.net"):
            lines.append(f"||{host}^$client={union}")
    if "media" in groups_to_clients and groups_to_clients["media"]:
        union = _fmt_client_union(groups_to_clients["media"])
        for host in ("facebook.com","instagram.com","tiktok.com","discord.com","reddit.com"):
            lines.append(f"||{host}^$client={union}")
    lines.append("! ---- End dynamic rules ----")
    return "\\n".join(lines)