<!-- mcp-name: io.github.shigechika/keycloak-mcp -->

# keycloak-mcp

English | [日本語](README.ja.md)

MCP (Model Context Protocol) server for [KeyCloak](https://www.keycloak.org/) Admin REST API.

Uses **Client Credentials Grant** (Service Account) — no user password or TOTP required.
Infinispan-safe: does not create user sessions or use the userinfo endpoint.

## Features

### User Management

| Tool | Description |
|------|-------------|
| `count_users` | Get total user count in the realm |
| `search_users` | Search users by username, email, or name |
| `get_user` | Get detailed user information by username |
| `reset_password` | Reset a user's password |
| `reset_passwords_batch` | Reset passwords for multiple users from CSV |
| `get_user_sessions` | Get active sessions for a user (local time) |
| `logout_user` | Force logout a user by removing all sessions |

### Group Management

| Tool | Description |
|------|-------------|
| `list_user_groups` | List groups a user belongs to |
| `list_users_by_group` | List all members of a group |

### Security Monitoring

| Tool | Description |
|------|-------------|
| `get_brute_force_status` | Check if a user is locked by brute force detection |
| `get_login_failures_by_ip` | Login failure statistics by source IP (with site labels) |
| `detect_login_loops` | Detect users with rapid repeated logins (redirect loop detection) |

### Event Analytics

| Tool | Description |
|------|-------------|
| `get_events` | Get events with filters (type, username, client, IP, date). Resolves username to user ID automatically. Shows KeyCloak's ``error`` field for failure events (e.g. ``invalid_user_credentials``, ``user_temporarily_disabled``) |
| `get_login_stats` | Login success/failure statistics with full pagination |
| `get_login_stats_by_hour` | Login statistics by hour (local time) |
| `get_login_stats_by_client` | Login statistics by client (SP) |
| `get_password_update_events` | Password update event history |

### Session & Client

| Tool | Description |
|------|-------------|
| `get_session_stats` | Active session count per client |
| `get_client_sessions` | Active sessions for a specific client |
| `list_clients` | List all SAML/OIDC clients |
| `get_realm_roles` | List all realm-level roles |

## Setup

```bash
# uv
uv pip install keycloak-mcp

# pip
pip install keycloak-mcp
```

Or from source:

```bash
git clone https://github.com/shigechika/keycloak-mcp.git
cd keycloak-mcp

# uv
uv sync

# pip
pip install -e .
```

## Configuration

Set the following environment variables:

| Variable | Description | Default |
|---|---|---|
| `KEYCLOAK_URL` | KeyCloak base URL (e.g., `https://sso.example.com`) | *required* |
| `KEYCLOAK_REALM` | Realm name | `master` |
| `KEYCLOAK_CLIENT_ID` | Service Account client ID | *required* |
| `KEYCLOAK_CLIENT_SECRET` | Client secret | *required* |
| `KEYCLOAK_SITES_INI` | Path to INI file for IP-to-site classification (optional) | — |

### KeyCloak Client Setup

1. Create a new client in KeyCloak Admin Console
2. Enable **Client authentication** and **Service account roles**
3. Assign realm roles: `view-users`, `view-events`, `view-clients`, `manage-users` (for password reset)

### IP-to-Site Classification (optional)

Set `KEYCLOAK_SITES_INI` to the path of an INI file that maps CIDR ranges to
site names. When configured, tools that display IP addresses
(`get_user_sessions`, `get_events`, `get_login_failures_by_ip`, etc.) annotate
each IP with its site; unmatched IPs are labeled `external`. If the variable is
unset or the file is missing, IPs are shown without labels.

See [`sites.ini.example`](sites.ini.example) for the format:

```ini
[hq]
name = HQ (Tokyo)
ipv4 = 192.0.2.0/24, 198.51.100.0/24
ipv6 = 2001:db8:1::/48

[vpn]
name = VPN
ipv4 = 10.0.0.0/8, 172.16.0.0/12
```

Each `[section]` defines one site. `name` is the display label (defaults to the
section name). `ipv4` and `ipv6` take comma-separated CIDRs; a single host is
`/32` or `/128`. Ranges are matched in file order, so list more specific
entries first.

## Usage

### Claude Code

Add to `.mcp.json`:

```json
{
  "mcpServers": {
    "keycloak-mcp": {
      "type": "stdio",
      "command": "keycloak-mcp",
      "env": {
        "KEYCLOAK_URL": "https://sso.example.com",
        "KEYCLOAK_CLIENT_ID": "keycloak-mcp",
        "KEYCLOAK_CLIENT_SECRET": ""
      }
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "keycloak-mcp": {
      "command": "keycloak-mcp",
      "env": {
        "KEYCLOAK_URL": "https://sso.example.com",
        "KEYCLOAK_CLIENT_ID": "keycloak-mcp",
        "KEYCLOAK_CLIENT_SECRET": ""
      }
    }
  }
}
```

### Direct Execution

```bash
export KEYCLOAK_URL=https://sso.example.com
export KEYCLOAK_CLIENT_ID=keycloak-mcp
export KEYCLOAK_CLIENT_SECRET=your-secret
keycloak-mcp
```

### CLI Options

```bash
keycloak-mcp --version   # Print version and exit
keycloak-mcp --help      # Show usage and required environment variables
keycloak-mcp --check     # Verify environment variables and authentication, then exit
keycloak-mcp             # Start MCP server (STDIO, default)
```

With no options, the process runs as an MCP STDIO server (the mode used by MCP clients).

`--check` exit codes: `0` success, `1` config error, `2` auth error.

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

## License

MIT
