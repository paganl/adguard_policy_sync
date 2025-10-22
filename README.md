# AdGuard Policy Sync (Home Assistant custom integration)

**What it does:**  
- Reads a JSON list of devices and assigns AdGuard **client tags**, **SafeSearch**, and **blocked services** per device.  
- Pushes a single block of **custom rules** that use `$ctag` and `denyallow` so you can run **default‑deny** for `iot`/`guest` and targeted blocks for `child`/`media`.  
- Exposes a **service** `adguard_policy_sync.sync` so you can trigger a resync from automations.

## Install

1. Download and extract this folder into `/config/custom_components/adguard_policy_sync`.
2. Restart Home Assistant.
3. Go to *Settings → Devices & services → Add integration* and pick **AdGuard Policy Sync**.
4. Enter your AdGuard Home base URL (avoid Ingress; use the add‑on host/port), username/password if set, and (optionally) the file name of your devices JSON in `/config` (e.g. `adguard_devices.json`).

## Devices JSON format

```json
[
  {"name": "LR-TV", "ip": "10.2.0.15", "mac": "AA:BB:CC:DD:EE:01", "tags": ["media"]},
  {"name": "Nest-Thermostat", "mac": "AA:BB:CC:DD:EE:02", "tags": ["iot"]},
  {"name": "Kid-iPad", "ip": "10.2.0.42", "mac": "AA:BB:CC:DD:EE:03", "tags": ["child"]},
  {"name": "Mum-iPhone", "ip": "10.2.0.51", "tags": ["adult"]},
  {"name": "Guest-Laptop", "mac": "AA:BB:CC:DD:EE:05", "tags": ["guest"]}
]
```

*Tip:* include both `ip` and `mac` when possible so the persistent client survives DHCP changes.

## Service

**`adguard_policy_sync.sync`**  
- `devices_json` (optional): override the file path (relative to `/config` or absolute).  
- `rules_text` (optional): provide custom rules to apply instead of the defaults.

## Default rules shipped

- `iot`: `*$ctag=iot,denyallow=pool.ntp.org|time.google.com|ntp.ubuntu.com|time.windows.com`  
- `guest`: `*$ctag=guest,denyallow=google.com|gstatic.com|googleapis.com|microsoft.com|apple.com|icloud.com|bing.com`  
- `child`: blocks common DoH resolvers; rely on per‑client SafeSearch + blocked services.  
- `media`: blocks social/chat.

Adjust them in the integration options (edit entry) or pass `rules_text` in the service call.

## Notes

- The integration talks directly to the AdGuard Home **HTTP API** (Basic Auth).  
- If you installed AdGuard Home as a Home Assistant add‑on, point the URL at the add‑on host/port (not the Ingress URL).  
- On first setup, if you set a `devices_json` path, it runs an initial sync and then exposes the service for future runs.
- For hardened setups, add global anti‑DoH/Proxy blocklists and firewall rules in your gateway to prevent DNS bypass.
