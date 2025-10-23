from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple

from aiohttp import ClientSession, ClientResponseError, BasicAuth

def _join(base: str, path: str) -> str:
    if base.endswith('/'):
        base = base[:-1]
    if not path.startswith('/'):
        path = '/' + path
    return base + path

class AdGuardAPI:
    def __init__(
        self,
        session: ClientSession,
        base_url: str,
        auth: Optional[BasicAuth | Tuple[str, str]] = None,
        verify_ssl: bool = True,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        self._session = session
        self._base = base_url
        if username and password:
            self._auth = BasicAuth(username, password)
        else:
            if isinstance(auth, tuple) and len(auth) == 2:
                self._auth = BasicAuth(auth[0], auth[1])
            elif isinstance(auth, BasicAuth):
                self._auth = auth
            else:
                self._auth = None
        self._ssl = verify_ssl
        
    async def dhcp_status(self) -> dict:
        """Return DHCP status (leases + static leases)."""
        return await self._req("GET", "/control/dhcp/status")

    async def _req(self, method: str, path: str, json_body: Any=None) -> Any:
        url = _join(self._base, path)
        async with self._session.request(
            method, url, json=json_body, auth=self._auth, ssl=self._ssl, timeout=30
        ) as resp:
            detail = None
            try:
                detail = await resp.text()
            except Exception:
                pass
            if resp.status >= 400:
                raise ClientResponseError(
                    request_info=resp.request_info,
                    history=resp.history,
                    status=resp.status,
                    message=f"{resp.reason}; body={detail!r}",
                    headers=resp.headers,
                )
            ctype = resp.headers.get("content-type","")
            if "application/json" in ctype:
                return await resp.json()
            return detail

    async def get_version(self) -> Any:
        try:
            return await self._req("GET", "/control/status")
        except ClientResponseError:
            return await self._req("GET", "/control/version")

    async def list_blocked_services_catalog(self):
        data = await self._req("GET", "/control/blocked_services/services")
        if isinstance(data, dict) and "services" in data:
            return {s["id"]: s for s in data["services"]}
        if isinstance(data, list):
            return {s.get("id",""): s for s in data if isinstance(s, dict) and s.get("id")}
        return {}

    async def clients_status(self):
        return await self._req("GET", "/control/clients")

    async def clients_search(self, ids: List[str]) -> List[Dict[str, Any]]:
        try:
            res = await self._req("POST", "/control/clients/search", {"ids": ids})
            if isinstance(res, dict):
                clients = res.get("clients")
                if isinstance(clients, list):
                    return clients
            return []
        except Exception:
            return []

    async def clients_update(self, name: str, data: Dict[str, Any]) -> Any:
        payload = {"name": name, "data": {"name": name, **data}}
        return await self._req("POST", "/control/clients/update", payload)

    async def clients_add(self, data: Dict[str, Any]) -> Any:
        return await self._req("POST", "/control/clients/add", data)

    async def set_custom_rules(self, rules_text: str) -> Any:
        lines = [ln.rstrip("\r") for ln in rules_text.split("\n")]
        payload_list = [ln for ln in lines if ln.strip() or ln.startswith("!")]
        try:
            return await self._req("POST", "/control/filtering/set_rules", {"rules": payload_list})
        except ClientResponseError as e:
            msg = str(e)
            if "cannot unmarshal array" in msg or ("[]string" in msg and "string" in msg):
                return await self._req("POST", "/control/filtering/set_rules", {"rules": rules_text})
            raise
