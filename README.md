<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>

<h1>AdGuard Policy Sync (Home Assistant)</h1>

<p>
AdGuard Policy Sync is a Home Assistant custom integration that pushes per-client policy into <strong>AdGuard Home</strong> (AGH) from a simple devices JSON, and manages custom filter rules. It keeps things honest: only AGH’s native features are used — persistent clients, built-in tags (<code>ctag</code>), Safe Search, Browsing Security, Parental Control, blocked services, and <code>$client</code>/<code>$ctag</code> rules. No gimmicks.
</p>

<h2>Features</h2>
<ul>
  <li><strong>Client sync:</strong> create/update persistent clients with IDs (IP/MAC/custom), names, and tags.</li>
  <li><strong>Tag handling:</strong> passes through valid AGH tags (<code>user_child</code>, <code>device_tv</code>, <code>os_ios</code>, etc.). Friendly groups (<code>child</code>, <code>media</code>, <code>guest</code>, <code>adult</code>, <code>iot</code>) are optional and are mapped to real <code>ctag</code>s.</li>
  <li><strong>Safety flags:</strong> SafeSearch, Browsing Security, and Parental Control per client (with sensible defaults and JSON overrides).</li>
  <li><strong>Blocked services:</strong> per-client lists or presets by group; no need to touch AGH UI.</li>
  <li><strong>Rules-first:</strong> custom rules are applied before clients, compiled to AGH’s <code>[]string</code> API format.</li>
  <li><strong>Dynamic cohort rules (optional):</strong> generates <code>$client=</code> rules from friendly groups.</li>
  <li><strong>Pause service:</strong> temporarily relax a client (filtering only or everything) and auto-restore.</li>
  <li><strong>Robust updates:</strong> unique-name strategy, non-destructive tag updates (never wipes tags with an empty list), detailed logs.</li>
</ul>

<h2>Requirements</h2>
<ul>
  <li>Home Assistant (Supervised/Container/Core) with access to your AGH instance.</li>
  <li>AdGuard Home reachable via HTTP(S) with credentials (Basic Auth).</li>
  <li>Optional: a JSON file of devices in your HA config directory (e.g. <code>/config/adguard_devices.json</code>).</li>
</ul>

<h2>Install</h2>
<ol>
  <li>Copy this folder to <code>/config/custom_components/adguard_policy_sync/</code>.</li>
  <li>Restart Home Assistant.</li>
  <li>In HA: <em>Settings → Devices &amp; Services → Add Integration → AdGuard Policy Sync</em>.</li>
  <li>Enter:
    <ul>
      <li><code>base_url</code> (e.g. <code>http://10.2.0.3:3000</code>)</li>
      <li>Optional: <code>username</code> / <code>password</code></li>
      <li>Optional: <code>devices_json</code> (relative to <code>/config</code>)</li>
      <li>Optional: <code>rules_text</code> (inline rules to push on sync)</li>
      <li>Optional: <code>allowed_groups</code> (comma list, default: <code>iot,media,child,adult,guest</code>)</li>
      <li>Optional: <code>append_dynamic_rules</code> (default: on)</li>
    </ul>
  </li>
</ol>

<h2>Devices JSON schema</h2>
<p>File is an array of device objects:</p>
<pre><code>[
  {
    "name": "Kid iPad",
    "ip": "10.2.0.42",
    "mac": "aa:bb:cc:dd:ee:ff",
    "id": "optional-custom-id",
    "tags": ["user_child","os_ios","media"], 
    "safesearch": true,
    "safebrowsing": true,
    "parental": true,
    "blocked_services": ["tiktok","discord","reddit"],
    "use_global_blocked_services": false
  }
]
</code></pre>
<ul>
  <li><strong>name</strong>: client display name in AGH (the integration ensures uniqueness).</li>
  <li><strong>ip</strong> / <strong>mac</strong> / <strong>id</strong>: any mix; at least one required.</li>
  <li><strong>tags</strong>:
    <ul>
      <li>Prefer AGH <code>ctag</code>s: <code>user_child</code>, <code>user_regular</code>, <code>user_admin</code>, <code>device_tv</code>, <code>device_other</code>, <code>os_ios</code>, etc.</li>
      <li>Optional friendly groups: <code>child</code>, <code>media</code>, <code>guest</code>, <code>adult</code>, <code>iot</code>. These are mapped to real <code>ctag</code>s server-side.</li>
    </ul>
  </li>
  <li><strong>safesearch / safebrowsing / parental</strong>: booleans; if omitted, reasonable defaults are derived from groups/ctags.</li>
  <li><strong>blocked_services</strong>: list of AGH service IDs; omit to use group presets.</li>
  <li><strong>use_global_blocked_services</strong>: false by default; set true to inherit AGH’s global list.</li>
</ul>

<h2>How tags &amp; groups are applied</h2>
<ul>
  <li><strong>AGH tags</strong> in your JSON are passed through unchanged (lower-cased and de-duplicated).</li>
  <li><strong>Friendly groups</strong> (if present) are mapped to <code>ctag</code>s and unioned with your tags:
    <ul>
      <li><code>child → user_child</code></li>
      <li><code>media → device_tv</code></li>
      <li><code>guest → user_regular</code></li>
      <li><code>adult → user_admin</code></li>
      <li><code>iot → device_other</code></li>
    </ul>
  </li>
  <li>If the final tag list is empty, the integration omits the <code>tags</code> field to avoid wiping tags in AGH.</li>
</ul>

<h2>Services</h2>
<p><strong>adguard_policy_sync.sync</strong> — apply rules, then sync clients.</p>
<pre><code>service: adguard_policy_sync.sync
data:
  devices_json: adguard_devices.json   # optional; overrides config entry
  rules_text: |                        # optional; overrides default rules
    ||dns.google^$ctag=user_child
</code></pre>
<ul>
  <li>Uploads custom rules (and appends dynamic rules if enabled).</li>
  <li>Creates or updates clients with tags, safety flags, and blocked services.</li>
</ul>

<p><strong>adguard_policy_sync.pause</strong> — temporarily relax protection for named clients and restore automatically.</p>
<pre><code>service: adguard_policy_sync.pause
data:
  clients: ["Kid iPad","My Laptop"]
  minutes: 20
  scope: filtering_only   # or "all"
</code></pre>
<ul>
  <li><em>filtering_only</em>: disables filtering rules only.</li>
  <li><em>all</em>: also disables Browsing Security &amp; Parental, and clears blocked services during the pause.</li>
</ul>

<h2>Custom rules</h2>
<ul>
  <li><strong>Static</strong> example rules target <code>$ctag</code> (e.g. block DoH for <code>user_child</code>, keep socials off <code>device_tv</code>).</li>
  <li><strong>Dynamic</strong> rules target <code>$client='Name'|'Name2'</code> and are generated only if you use friendly groups in JSON.</li>
  <li>Rules are sent as an array of strings (AGH’s preferred format). Comment lines starting with <code>!</code> are preserved.</li>
</ul>

<h2>Defaults and presets</h2>
<ul>
  <li><strong>SafeSearch</strong>: on for <code>child</code> and <code>guest</code> cohorts (or if <code>user_child</code> tag is present).</li>
  <li><strong>Browsing Security</strong>: on by default for <code>child</code>, <code>adult</code>, and <code>guest</code> unless you override.</li>
  <li><strong>Parental</strong>: on by default for <code>child</code> unless you override.</li>
  <li><strong>Blocked services</strong>:
    <ul>
      <li><em>child</em>: curated set (e.g. tiktok/discord/reddit/…)</li>
      <li><em>media</em>: social on TVs/streamers off by default</li>
      <li><em>guest</em>: light social clamp</li>
    </ul>
  </li>
</ul>

<h2>Troubleshooting</h2>
<ul>
  <li><strong>Service not visible:</strong> confirm the folder name is exactly <code>adguard_policy_sync</code>, restart HA; the integration registers services even if AGH is temporarily down.</li>
  <li><strong>400 Bad Request (invalid tag):</strong> use only AGH’s fixed <code>ctag</code>s (e.g. <code>user_child</code>, not <code>child_user</code>).</li>
  <li><strong>No tags applied:</strong> check logs for <em>from_json_tags → final_tags</em>; ensure your JSON tags are valid and lower-case; friendly groups are optional but must match the allowed list.</li>
  <li><strong>Client not found for pause:</strong> names must match exactly what AGH shows under “Clients”.</li>
</ul>

<h2>Verification</h2>
<pre><code># inspect server truth after a sync
curl -s -u USER:PASS http://AGH_HOST:PORT/control/clients \
 | jq '.clients[] | {name, ids, tags, safesearch_enabled, safebrowsing_enabled, parental_enabled, blocked_services}'
</code></pre>

<h2>Security notes</h2>
<ul>
  <li>Use HTTPS to AGH or keep traffic on a trusted LAN. Credentials are stored in HA; protect your HA config.</li>
  <li>Pause is emulated by flipping client flags and restoring later; if you rename a client during a pause, restore may miss.</li>
</ul>

</body>
</html>
