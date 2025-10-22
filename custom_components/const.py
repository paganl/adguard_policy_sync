DOMAIN = "adguard_policy_sync"
CONF_BASE_URL = "base_url"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_VERIFY_SSL = "verify_ssl"
CONF_DEVICES_JSON = "devices_json"
CONF_RULES_TEXT = "rules_text"
CONF_SKIP_TEST = "skip_test"
CONF_ALLOWED_GROUPS = "allowed_groups"
CONF_APPEND_DYNAMIC_RULES = "append_dynamic_rules"

DEFAULT_ALLOWED_GROUPS = {"iot","media","child","adult","guest","lan"}

ALLOWED_CTAGS = {
  "device_audio","device_camera","device_gameconsole","device_laptop","device_nas",
  "device_pc","device_phone","device_printer","device_securityalarm","device_tablet",
  "device_tv","device_other",
  "os_android","os_ios","os_linux","os_macos","os_windows","os_other",
  "user_admin","user_regular","user_child"
}

CTAG_MAPPING = {
    "child": ["user_child"],
    "adult": ["user_admin"],
    "media": ["device_tv"],
    "iot":   ["device_other"],
    "guest": ["user_regular"],
}

SAFESEARCH_GROUPS = {"child","guest"}
SAFESEARCH_CTAGS  = {"user_child"}

BLOCKED_SERVICES_PRESETS = {
    "child":  ["youtube","tiktok","snapchat","discord","reddit","steam","roblox","whatsapp"],
    "guest":  ["tiktok","snapchat","discord","reddit","steam","roblox"],
    "media":  ["facebook","instagram","tiktok","discord","reddit"],
    "iot":    [],
    "adult":  [],
    "lan":    []
}

DEFAULT_RULES = """
! ---------- STATIC RULES (ctag-based, only valid ctags) ----------

! CHILD (user_child): block common DoH to reduce DNS bypass
||doh.cloudflare-dns.com^$ctag=user_child
||dns.quad9.net^$ctag=user_child
||dns.google^$ctag=user_child

! MEDIA (device_tv): keep social off TVs/streamers
||facebook.com^$ctag=device_tv
||instagram.com^$ctag=device_tv
||tiktok.com^$ctag=device_tv
||discord.com^$ctag=device_tv
||reddit.com^$ctag=device_tv

! GUEST (user_regular): optional lightweight social clamp
||tiktok.com^$ctag=user_regular
||snapchat.com^$ctag=user_regular
||discord.com^$ctag=user_regular
||reddit.com^$ctag=user_regular

! IOT (device_other): default-deny with small allow list of essentials
*$ctag=device_other,denyallow=pool.ntp.org|time.google.com|connectivitycheck.gstatic.com|time.windows.com|time.apple.com

! ---------- DYNAMIC RULES (client-based) ----------
! These are appended automatically if 'append_dynamic_rules' is enabled and your JSON has those groups.
! Example patterns that may be emitted:
!   ||dns.google^$client='Kid iPad'|'Switch'                 (for group=child)
!   ||facebook.com^$client='Living Room TV'|'Apple TV'       (for group=media)
"""