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
| `get_user_sessions` | Get active sessions for a user |

### Group Management

| Tool | Description |
|------|-------------|
| `list_user_groups` | List groups a user belongs to |
| `list_users_by_group` | List all members of a group |

### Security Monitoring

| Tool | Description |
|------|-------------|
| `get_brute_force_status` | Check if a user is locked by brute force detection |
| `get_login_failures_by_ip` | Login failure statistics by source IP |

### Event Analytics

| Tool | Description |
|------|-------------|
| `get_events` | Get KeyCloak events with filters (type, user, date) |
| `get_login_stats` | Login success/failure statistics with pagination |
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
pip install keycloak-mcp
```

Or from source:

```bash
git clone https://github.com/shigechika/keycloak-mcp.git
cd keycloak-mcp
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

### KeyCloak Client Setup

1. Create a new client in KeyCloak Admin Console
2. Enable **Client authentication** and **Service account roles**
3. Assign realm roles: `view-users`, `view-events`, `view-clients`, `manage-users` (for password reset)

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

## Development

```bash
git clone https://github.com/shigechika/keycloak-mcp.git
cd keycloak-mcp
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -v
.venv/bin/ruff check .
```

## License

MIT
