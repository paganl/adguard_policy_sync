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
CONF_SCAN_RANGE = "scan_range"                     # e.g. "10.2.0.0/24"
CONF_AUTO_ONBOARD = "auto_onboard_unknowns"        # bool
CONF_GUEST_GROUP = "guest_group"                   # friendly group to use for unknowns (default "guest")
CONF_ALLOW_RENAME = "allow_rename"
DEFAULT_ALLOW_RENAME = False

DEFAULT_ALLOWED_GROUPS = {"iot","media","child","adult","guest","other","blocked"}

CTAG_MAPPING = {
    "child": ["user_child"],
    "adult": ["user_admin"],
    "media": ["device_tv"],
    "iot":   ["device_other"],
    "guest": ["user_child","device_other"],
    "blocked": [],
    "other": ["device_other"],
}

SAFESEARCH_GROUPS = {"child","guest"}
SAFESEARCH_CTAGS  = {"user_child"}

SAFEBROWSING_GROUPS = {"child","adult","guest"}
SAFEBROWSING_CTAGS  = {"user_child"}

PARENTAL_GROUPS = {"child"}
PARENTAL_CTAGS  = {"user_child"}

BLOCKED_SERVICES_PRESETS = {
    "child":  ["youtube","tiktok","snapchat","discord","reddit","steam","roblox","whatsapp"],
    "guest":  ["tiktok","snapchat","discord","reddit","steam","roblox"],
    "media":  ["facebook","instagram","tiktok","discord","reddit"],
    "iot":    [],
    "adult":  ["facebook"]
}

KNOWN_CTAGS = {
    # user roles
    "user_child", "user_regular", "user_admin",
    # device types (AGH’s built-in set)
    "device_computer", "device_phone", "device_tablet",
    "device_tv", "device_audio", "device_watch", "device_other",
    # operating systems
    "os_windows", "os_macos", "os_ios", "os_android", "os_linux", "os_other",
}

DEFAULT_RULES = """
||doh.cloudflare-dns.com^$ctag=user_child
||dns.quad9.net^$ctag=user_child
||dns.google^$ctag=user_child

||facebook.com^$ctag=device_tv
||instagram.com^$ctag=device_tv
||tiktok.com^$ctag=device_tv
||discord.com^$ctag=device_tv
||reddit.com^$ctag=device_tv

||tiktok.com^$ctag=user_regular
||snapchat.com^$ctag=user_regular
||discord.com^$ctag=user_regular
||reddit.com^$ctag=user_regular
@@||prod.zpath.net^$client='ABN AMRO Dell Laptop'

*$ctag=device_other,denyallow=pool.ntp.org|time.google.com|connectivitycheck.gstatic.com|time.windows.com|time.apple.com
"""
