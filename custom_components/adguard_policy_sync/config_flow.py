from __future__ import annotations

import logging
from urllib.parse import urlparse, urlunparse
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession  # <-- correct import

from .const import (
    DOMAIN,
    CONF_BASE_URL, CONF_USERNAME, CONF_PASSWORD, CONF_VERIFY_SSL,
    CONF_DEVICES_JSON, CONF_RULES_TEXT,
    CONF_SCAN_RANGE, CONF_AUTO_ONBOARD, CONF_GUEST_GROUP,
)
from .api import AdGuardAPI

_LOGGER = logging.getLogger(__name__)

def _normalise_base(s: str) -> str:
    s = (s or "").strip().rstrip("/")
    if not s:
        return s
    if not s.startswith(("http://", "https://")):
        s = "http://" + s  # default to http if user omitted scheme
    return s

def _ensure_port(base: str, default_port: int = 3000) -> str:
    """If user omitted a port, append :3000."""
    try:
        p = urlparse(base)
        if p.port is not None:
            return base
        netloc = p.hostname if p.hostname else p.netloc
        if not netloc:
            return base
        netloc = f"{netloc}:{default_port}"
        return urlunparse((p.scheme, netloc, p.path or "", p.params, p.query, p.fragment))
    except Exception:
        return base

USER_SCHEMA = vol.Schema({
    vol.Required(CONF_BASE_URL): str,   # e.g. http://10.2.0.3:3000  (port optional; we default to :3000)
    vol.Optional(CONF_USERNAME, default=""): str,
    vol.Optional(CONF_PASSWORD, default=""): str,
    vol.Optional(CONF_VERIFY_SSL, default=False): bool,
    vol.Optional(CONF_DEVICES_JSON, default="adguard_devices.json"): str,
    vol.Optional(CONF_RULES_TEXT, default=""): str,
    vol.Optional(CONF_SCAN_RANGE, default=""): str,      # e.g. 10.2.0.0/24
    vol.Optional(CONF_AUTO_ONBOARD, default=False): bool,
    vol.Optional(CONF_GUEST_GROUP, default="guest"): str,
})

class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            raw = user_input.get(CONF_BASE_URL, "")
            base = _ensure_port(_normalise_base(raw))
            user = (user_input.get(CONF_USERNAME) or "").strip()
            pwd  = (user_input.get(CONF_PASSWORD) or "").strip()
            verify = bool(user_input.get(CONF_VERIFY_SSL, False))

            if not base:
                errors["base"] = "invalid_url"
                return self.async_show_form(step_id="user", data_schema=USER_SCHEMA, errors=errors)

            _LOGGER.info("Config flow: connectivity test to %s (verify_ssl=%s)", base, verify)
            try:
                session = async_get_clientsession(self.hass)  # <-- correct usage
                api = AdGuardAPI(session, base, username=user or None, password=pwd or None, verify_ssl=verify)
                await api.get_version()
            except Exception as e:
                _LOGGER.exception("Connectivity test failed during config flow to %s", base)
                msg = str(e).lower()
                if any(tok in msg for tok in ("401", "unauthorized", "forbidden")):
                    errors["base"] = "invalid_auth"
                else:
                    errors["base"] = "cannot_connect"
                return self.async_show_form(step_id="user", data_schema=USER_SCHEMA, errors=errors)

            # Use netloc as unique id to prevent dupes
            netloc = urlparse(base).netloc or base
            await self.async_set_unique_id(netloc)
            self._abort_if_unique_id_configured()

            data = {
                CONF_BASE_URL: base,
                CONF_USERNAME: user,
                CONF_PASSWORD: pwd,
                CONF_VERIFY_SSL: verify,
                CONF_DEVICES_JSON: user_input.get(CONF_DEVICES_JSON, ""),
                CONF_RULES_TEXT: user_input.get(CONF_RULES_TEXT, ""),
                CONF_SCAN_RANGE: user_input.get(CONF_SCAN_RANGE, ""),
                CONF_AUTO_ONBOARD: bool(user_input.get(CONF_AUTO_ONBOARD, False)),
                CONF_GUEST_GROUP: (user_input.get(CONF_GUEST_GROUP) or "guest").strip().lower(),
            }
            return self.async_create_entry(title="AdGuard Policy Sync", data=data)

        # First render
        return self.async_show_form(step_id="user", data_schema=USER_SCHEMA, errors=errors)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return OptionsFlow(config_entry)


class OptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry):
        self.entry = entry

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        data = {**self.entry.data, **(self.entry.options or {})}
        schema = vol.Schema({
            vol.Optional(CONF_DEVICES_JSON, default=data.get(CONF_DEVICES_JSON, "")): str,
            vol.Optional(CONF_RULES_TEXT, default=data.get(CONF_RULES_TEXT, "")): str,
            vol.Optional(CONF_SCAN_RANGE, default=data.get(CONF_SCAN_RANGE, "")): str,
            vol.Optional(CONF_AUTO_ONBOARD, default=data.get(CONF_AUTO_ONBOARD, False)): bool,
            vol.Optional(CONF_GUEST_GROUP, default=data.get(CONF_GUEST_GROUP, "guest")): str,
        })
        return self.async_show_form(step_id="init", data_schema=schema)
