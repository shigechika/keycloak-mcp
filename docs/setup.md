# Setup

## Install

```bash
uv pip install keycloak-mcp
# or
pip install keycloak-mcp
```

From source:

```bash
git clone https://github.com/shigechika/keycloak-mcp.git
cd keycloak-mcp
uv sync          # or: pip install -e .
```

## KeyCloak client setup

1. Create a new client in the KeyCloak admin console.
2. Turn on **Client authentication** and **Service account roles**.
3. Grant the service account `view-users`, `view-events`, `view-clients`, and
   — only if you intend to use `reset_password` or `reset_passwords_batch` —
   `manage-users`.

!!! tip "Read-only deployment"
    If password reset is not something you want this server able to do,
    simply omit `manage-users`. The four write tools
    (`reset_password`, `reset_passwords_batch`, `logout_user`,
    `set_user_enabled`) will fail against the KeyCloak API rather than the
    server refusing to start, so the permission grant is the actual security
    boundary.

## Environment variables

| Variable | Description | Default |
|---|---|---|
| `KEYCLOAK_URL` | Base URL, e.g. `https://keycloak.example.com` | *required* |
| `KEYCLOAK_REALM` | Realm name | `master` |
| `KEYCLOAK_CLIENT_ID` | Service account client ID | *required* |
| `KEYCLOAK_CLIENT_SECRET` | Client secret | *required* |
| `KEYCLOAK_SITES_INI` | INI file for IP-to-site labeling | unset |
| `KEYCLOAK_DEFAULT_DATE_FROM_HOURS` | Default look-back window for event tools when `date_from` is omitted. `0` scans full history (can hang on a large realm) | `24` |
| `KEYCLOAK_DEADLINE` | Wall-clock budget (seconds) per call for the heavy event/TOTP tools; `0` or negative disables | `45` |
| `KEYCLOAK_MAX_EVENTS` | Cap on events fetched per call; `0` or negative disables | `200000` |
| `KEYCLOAK_MAX_USERS` | Default cap on users scanned by `get_totp_users` when its `max_users` argument is `0`; `0` or negative disables | `5000` |
| `KEYCLOAK_USER_ATTRIBUTE_WHITELIST` | Comma-separated custom attribute keys `get_user` may surface; unset means `get_user` never fetches or shows `attributes` at all. A whitelisted key that looks credential-shaped is blocked rather than shown (safety net, not a guarantee) | *unset* |

## Verify before wiring it into anything

```bash
export KEYCLOAK_URL=https://keycloak.example.com
export KEYCLOAK_REALM=my-realm
export KEYCLOAK_CLIENT_ID=keycloak-mcp
export KEYCLOAK_CLIENT_SECRET=your-secret
keycloak-mcp --check
```

Exit `0` means authentication succeeded; `1` is a missing environment
variable, `2` an authentication error. Running this once turns "the tool
returns nothing" into a question you have already answered.

## IP-to-site labeling (optional)

Point `KEYCLOAK_SITES_INI` at an INI file to have IP addresses in tool output
tagged with your own site names. `get_user_sessions`, `get_events`, and
`get_login_failures_by_ip` pick it up automatically; anything outside your
declared ranges is labeled `external`. Leave the variable unset and IPs are
shown as-is — nothing breaks either way.

```ini
[hq]
name = HQ (Tokyo)
ipv4 = 192.0.2.0/24, 198.51.100.0/24
ipv6 = 2001:db8:1::/48

[vpn]
name = VPN
ipv4 = 10.0.0.0/8, 172.16.0.0/12
```

See [`sites.ini.example`](https://github.com/shigechika/keycloak-mcp/blob/main/sites.ini.example)
in the repository. One site per `[section]`; `name` is the display label
(falls back to the section name); `ipv4` / `ipv6` take comma-separated CIDRs
(a single host is `/32` or `/128`). Matching is first-match in file order —
put specific ranges before broad ones.

## Register with an MCP client

### Claude Code (plugin)

This repository doubles as a single-plugin marketplace:

```
/plugin marketplace add shigechika/keycloak-mcp
/plugin install keycloak-mcp@keycloak-mcp
```

The plugin launches `uvx keycloak-mcp` and reads the same [environment
variables](#environment-variables) as every other transport; export them
before starting Claude Code.

`uvx` must be on the `PATH` of the process that runs Claude Code — a login
shell usually has it, but a GUI-launched app may not; install
[uv](https://docs.astral.sh/uv/) system-wide if the plugin fails to start.

### Claude Code (manual)

`.mcp.json`:

```json
{
  "mcpServers": {
    "keycloak-mcp": {
      "type": "stdio",
      "command": "keycloak-mcp",
      "env": {
        "KEYCLOAK_URL": "https://keycloak.example.com",
        "KEYCLOAK_REALM": "my-realm",
        "KEYCLOAK_CLIENT_ID": "keycloak-mcp",
        "KEYCLOAK_CLIENT_SECRET": ""
      }
    }
  }
}
```

### Claude Desktop

`claude_desktop_config.json` takes the same `env` block under `command`
without the `type` field. See the repository README for the full example.

### Direct execution

```bash
export KEYCLOAK_URL=https://keycloak.example.com
export KEYCLOAK_REALM=my-realm
export KEYCLOAK_CLIENT_ID=keycloak-mcp
export KEYCLOAK_CLIENT_SECRET=your-secret
keycloak-mcp
```

No-argument mode is the normal one — that is how MCP clients launch it.

## Next

[Security investigation](investigation.md) covers the brute-force workflow
and what each write tool does.
