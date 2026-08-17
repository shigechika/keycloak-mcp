<!-- mcp-name: io.github.shigechika/keycloak-mcp -->

# keycloak-mcp

English | [日本語](README.ja.md)

An MCP (Model Context Protocol) server for the [KeyCloak](https://www.keycloak.org/) Admin REST API.

Documentation: <https://shigechika.github.io/keycloak-mcp/>

Authenticates via a Service Account (**Client Credentials Grant**), so no human password or TOTP is involved. Also Infinispan-safe — it never creates user sessions and never hits the userinfo endpoint.

## Features

### Users

| Tool | Description |
|------|-------------|
| `count_users` | Total user count in the realm |
| `search_users` | Partial-match search (username / email / name) |
| `get_user` | Full detail for an exact username |
| `reset_password` | Reset one user's password |
| `reset_passwords_batch` | Bulk reset from CSV (`username,password` per line; blank password is generated) |
| `get_user_sessions` | Active sessions for one user, timestamps in local time |
| `logout_user` | Kill all active sessions for one user |
| `set_user_enabled` | Enable or disable one user; disabling blocks all logins (custom attributes preserved) |

### MFA / Credentials

| Tool | Description |
|------|-------------|
| `get_user_credentials` | Credential types configured for one user; an `otp` entry means TOTP/HOTP is set up |
| `get_totp_users` | Realm-wide TOTP adoption: how many users have an `otp` credential, with percentage and (optionally) the user list. Enumerates users and reads each one's credentials (N+1; bound with `max_users`) |

### Groups

| Tool | Description |
|------|-------------|
| `list_user_groups` | Which groups a user belongs to |
| `list_users_by_group` | Members of a group |

### Security

| Tool | Description |
|------|-------------|
| `get_brute_force_status` | Whether a user is currently locked by brute-force detection |
| `get_realm_security_defenses` | Realm-level security policy: whether brute-force detection is enabled and its thresholds, the password policy, and browser security headers |
| `get_login_failures_by_ip` | Failure breakdown by source IP (site-labeled when `KEYCLOAK_SITES_INI` is set) |
| `get_ip_activity` | Exhaustive investigation of one source IP: success/failure counts, affected users/clients, timeline. Returns structured JSON. |
| `detect_login_loops` | Flag users who logged in too many times in a short window (redirect loops) |

### Events

| Tool | Description |
|------|-------------|
| `get_events` | Filter by type, username, client, IP, and date range. Username is resolved to user ID internally. Failure events include KeyCloak's `error` field (e.g. `invalid_user_credentials`). |
| `get_login_stats` | Login success/failure totals, paginated across all results |
| `get_login_stats_by_hour` | Logins bucketed by hour of day (local time) |
| `get_login_stats_by_client` | Logins bucketed by client / SP |
| `get_password_update_events` | `UPDATE_PASSWORD` history |

### Admin Events

`get_events` only sees *user* events. Actions driven by an admin — or by a service account writing custom attributes — don't show up there. The admin-event endpoint fills that gap.

| Tool | Description |
|------|-------------|
| `get_admin_events` | Filter by operation (CREATE / UPDATE / DELETE / ACTION), resource type (USER / CLIENT / ROLE / GROUP / …), resource path, and date range |
| `get_user_attribute_history` | UPDATE/ACTION events scoped to one user — handy for tracking when a custom attribute (e.g. `provisioning_flag`) was written by an automated pipeline |

Both tools accept `max_repr` to control the representation payload: positive = truncate to N chars (default 500), `0` = omit, negative = include in full.

### Sessions & Clients

| Tool | Description |
|------|-------------|
| `get_session_stats` | Active session count per client |
| `get_client_sessions` | Active sessions for one client (SP) |
| `list_clients` | SAML and OIDC clients in the realm |
| `get_realm_roles` | Realm-level roles |

### Morning Patrol

| Tool | Description |
|------|-------------|
| `health_check` | Report the running server version and verify the KeyCloak backend is reachable and the service account can authenticate. Lightweight (one token request; no user/event/session scans). Returns a fixed-shape dict with `status`, `auth`, and the configured URL/realm. The tool's own description enumerates the values those fields can take, and is the one place that does. |
| `daily_brief` | One-shot morning health check: login stats, brute-force IPs, active sessions, password updates, and admin events in a single Markdown summary. IPs exceeding `ip_failure_threshold` failures (default 50) are flagged **WARNING**; API errors surface as **CRITICAL**. `since_hours` controls the look-back window (default 18 h). |

## Setup

```bash
# uv
uv pip install keycloak-mcp

# pip
pip install keycloak-mcp
```

From source:

```bash
git clone https://github.com/shigechika/keycloak-mcp.git
cd keycloak-mcp

# uv
uv sync

# pip
pip install -e .
```

## Configuration

| Variable | Description | Default |
|---|---|---|
| `KEYCLOAK_URL` | Base URL, e.g. `https://keycloak.example.com` | *required* |
| `KEYCLOAK_REALM` | Realm name | `master` |
| `KEYCLOAK_CLIENT_ID` | Service Account client ID | *required* |
| `KEYCLOAK_CLIENT_SECRET` | Client secret | *required* |
| `KEYCLOAK_SITES_INI` | INI file for IP-to-site labeling (see below) | *unset* |
| `KEYCLOAK_DEFAULT_DATE_FROM_HOURS` | Default look-back window for event tools when `date_from` is omitted. Set to `0` to scan full history (can hang on large realms). | `24` |
| `KEYCLOAK_DEADLINE` | Per-call wall-clock budget (seconds) for the heavy event/TOTP tools. When a wide window / large realm would exceed it, the tool stops and returns a **disclosed partial** (⚠️ warning) instead of running past the client's ~60s gateway timeout and hammering KeyCloak. `0` or negative disables. | `45` |
| `KEYCLOAK_MAX_EVENTS` | Per-pagination cap on events fetched by the event tools (also bounds how deep the slow high-offset pagination goes). Over the cap the result is a disclosed partial. `0` or negative disables. | `200000` |
| `KEYCLOAK_MAX_USERS` | Default cap on users scanned by `get_totp_users` when its `max_users` argument is `0` (each user costs one credential call). `0` or negative disables (whole realm, bounded only by `KEYCLOAK_DEADLINE`). | `5000` |
| `KEYCLOAK_USER_ATTRIBUTE_WHITELIST` | Comma-separated custom user-attribute keys that `get_user` is allowed to surface. Unset by default: `get_user` only ever returns username/name/email/enabled/created, since the search endpoint it resolves the username through returns a brief representation with no `attributes` at all. Opting a key in makes `get_user` do one extra by-ID lookup and append that attribute's value when present. Everything else stays out of tool output. | *unset* |

### KeyCloak client setup

1. Create a new client in the KeyCloak admin console.
2. Turn on **Client authentication** and **Service account roles**.
3. Give it `view-users`, `view-events`, `view-clients`, and — only if you need password reset — `manage-users`.

### Write operations

Four tools change state. Everything else only reads.

| Tool | Admin API call |
|---|---|
| `reset_password` | `PUT /users/{id}/reset-password` |
| `reset_passwords_batch` | the same call, once per CSV row |
| `set_user_enabled` | `PUT /users/{id}` with `enabled` toggled |
| `logout_user` | `POST /users/{id}/logout` |

All four need `manage-users` on the Service Account. **Leave that role off and the
server is read-only**: those four tools fail with `403` and every other tool keeps
working, so a realm can be handed to Claude for investigation without granting any
ability to modify it. Grant `manage-users` only when account recovery or
containment is part of the job.

### Verify your setup

After setting the environment variables, run `--check` to confirm authentication works before wiring it into an MCP client:

```bash
export KEYCLOAK_URL=https://keycloak.example.com
export KEYCLOAK_REALM=my-realm
export KEYCLOAK_CLIENT_ID=keycloak-mcp
export KEYCLOAK_CLIENT_SECRET=your-secret
keycloak-mcp --check
# HTTP Request: POST https://keycloak.example.com/realms/my-realm/protocol/openid-connect/token "HTTP/1.1 200 OK"
# OK: authenticated to https://keycloak.example.com/admin/realms/my-realm
```

Exit codes: `0` success, `1` configuration error (missing variable), `2` authentication error.

### IP-to-site labeling (optional)

Point `KEYCLOAK_SITES_INI` at an INI file if you want IP addresses in tool output to be tagged with your site names. Tools like `get_user_sessions`, `get_events`, and `get_login_failures_by_ip` pick it up automatically; anything outside your declared ranges is labeled `external`. Leave the variable unset and IPs are shown as-is.

See [`sites.ini.example`](sites.ini.example). A minimal file:

```ini
[hq]
name = HQ (Tokyo)
ipv4 = 192.0.2.0/24, 198.51.100.0/24
ipv6 = 2001:db8:1::/48

[vpn]
name = VPN
ipv4 = 10.0.0.0/8, 172.16.0.0/12
```

One site per `[section]`. `name` is the display label (falls back to the section name). `ipv4` / `ipv6` take comma-separated CIDRs; a single host is `/32` or `/128`. Matching is first-match in file order — put specific ranges before broad ones.

## Usage

### Claude Code (plugin)

This repository doubles as a single-plugin marketplace, so Claude Code can install
the server for you:

```
/plugin marketplace add shigechika/keycloak-mcp
/plugin install keycloak-mcp@keycloak-mcp
```

The plugin launches `uvx keycloak-mcp` and reads the same environment variables
described in [Configuration](#configuration); export them before starting Claude
Code. `KEYCLOAK_REALM` falls back to `master` and `KEYCLOAK_SITES_INI` may stay
unset.

`uvx` must be on the `PATH` of the process that runs Claude Code — a login
shell usually has it, but a GUI-launched app may not; install
[uv](https://docs.astral.sh/uv/) system-wide if the plugin fails to start.

### Claude Code (manual)

In `.mcp.json`:

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

In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "keycloak-mcp": {
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

### From a shell

```bash
export KEYCLOAK_URL=https://keycloak.example.com
export KEYCLOAK_REALM=my-realm
export KEYCLOAK_CLIENT_ID=keycloak-mcp
export KEYCLOAK_CLIENT_SECRET=your-secret
keycloak-mcp
```

### CLI

```bash
keycloak-mcp --version   # Print version and exit
keycloak-mcp --help      # Show usage and required environment variables
keycloak-mcp --check     # Verify env vars and authentication, then exit
keycloak-mcp             # Run the MCP STDIO server (default)
```

No-argument mode is the normal one — that's how MCP clients launch it.

## Development

```bash
git clone https://github.com/shigechika/keycloak-mcp.git
cd keycloak-mcp

# uv
uv sync --dev
uv run pytest -v
uv run ruff check .

# pip
python3 -m venv .venv
.venv/bin/pip install -e . && .venv/bin/pip install pytest pytest-cov respx ruff
.venv/bin/pytest -v
.venv/bin/ruff check .
```

### Live smoke test

`pytest` checks logic against fixtures; it cannot tell you that a tool has
stopped returning real data. `scripts/smoke_test.py` runs **every registered
tool** against the configured realm and fails on empty, malformed or error
answers:

```bash
# needs KEYCLOAK_URL / KEYCLOAK_CLIENT_ID / KEYCLOAK_CLIENT_SECRET
uv run python scripts/smoke_test.py
uv run python scripts/smoke_test.py --only login_stats --traceback
```

- **Read-only.** Every state-changing tool (`reset_password`, `logout_user`,
  `set_user_enabled`, `reset_passwords_batch`) is skipped by name, and a test
  enforces that. The report prints tool names and statuses only — never
  payloads, and server-authored error text is redacted too (KeyCloak quotes the
  username it was asked about); `--traceback` still shows the full text on the
  operator's own terminal.
- Arguments that would identify real users, groups or IPs are **discovered at
  run time**, never written into `scripts/smoke_probes.py`.
- CI enforces the cheap half: a tool registered without a probe spec fails the
  build (`tests/test_smoke_probes.py`), so adding a tool forces the question
  "how would we know it works?".
- `scripts/smoke_harness.py` is the engine and holds no KeyCloak knowledge:
  it is kept identical across the servers that share it, so fix engine bugs
  once and sync the file rather than patching this copy.

## License

MIT
