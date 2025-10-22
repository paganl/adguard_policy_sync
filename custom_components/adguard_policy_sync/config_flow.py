from __future__ import annotations

import logging
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_USERNAME, CONF_PASSWORD, CONF_VERIFY_SSL
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import aiohttp_client

from .const import DOMAIN, CONF_BASE_URL, CONF_DEVICES_JSON, CONF_RULES_TEXT, CONF_SKIP_TEST, CONF_ALLOWED_GROUPS, CONF_APPEND_DYNAMIC_RULES
from .api import AdGuardAPI

_LOGGER = logging.getLogger(__name__)

def _clean(s: str | None) -> str:
    return (s or "").strip()

class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            base = user_input[CONF_BASE_URL]
            user = _clean(user_input.get(CONF_USERNAME))
            pwd = _clean(user_input.get(CONF_PASSWORD))
            verify = user_input.get(CONF_VERIFY_SSL, True)
            skip = user_input.get(CONF_SKIP_TEST, False)

            if user and not pwd:
                errors["password"] = "password_required"

            session = aiohttp_client.async_get_clientsession(self.hass)
            api = AdGuardAPI(session, base, username=user or None, password=pwd or None, verify_ssl=verify)

            if not errors and not skip:
                try:
                    await api.get_version()
                except Exception as e:
                    _LOGGER.exception("Connectivity test failed during config flow to %s", base)
                    errors["base"] = "cannot_connect"

            if not errors:
                return self.async_create_entry(title="AdGuard Policy Sync", data=user_input)

        data_schema = vol.Schema({
            vol.Required(CONF_BASE_URL, default="http://10.2.0.10:3000"): str,
            vol.Optional(CONF_USERNAME): str,
            vol.Optional(CONF_PASSWORD): str,
            vol.Optional(CONF_VERIFY_SSL, default=True): bool,
            vol.Optional(CONF_SKIP_TEST, default=False): bool,
            vol.Optional(CONF_DEVICES_JSON, description={"suggested_value": "adguard_devices.json"}): str,
            vol.Optional(CONF_RULES_TEXT): str,
            vol.Optional(CONF_ALLOWED_GROUPS, description={"suggested_value": "iot,media,child,adult,guest"}): str,
            vol.Optional(CONF_APPEND_DYNAMIC_RULES, default=True): bool,
        })
        return self.async_show_form(step_id="user", data_schema=data_schema, errors=errors)
