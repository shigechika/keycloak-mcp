# keycloak-mcp

[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for KeyCloak Admin REST API.

Uses **Client Credentials Grant** (Service Account) — no user password or TOTP required.
Infinispan-safe: does not create user sessions or use the userinfo endpoint.

## Features

- User management (search, get, reset password, batch reset)
- Event queries (login stats, password updates, filtered events)
- Session monitoring (per-client stats, user sessions)
- Client and role listing

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Configuration

Set the following environment variables:

| Variable | Description | Example |
|---|---|---|
| `KEYCLOAK_URL` | KeyCloak base URL | `https://sso.example.com` |
| `KEYCLOAK_REALM` | Realm name (default: `master`) | `sso` |
| `KEYCLOAK_CLIENT_ID` | Service Account client ID | `keycloak-mcp` |
| `KEYCLOAK_CLIENT_SECRET` | Client secret | |

### KeyCloak Client Setup

1. Create a new client in KeyCloak Admin Console
2. Enable **Client authentication** and **Service account roles**
3. Assign realm roles: `view-users`, `view-events`, `view-clients`, `manage-users` (for password reset)

## Usage with Claude Code

Add to `.mcp.json`:

```json
{
  "mcpServers": {
    "keycloak-mcp": {
      "type": "stdio",
      "command": "/path/to/.venv/bin/python3",
      "args": ["-m", "keycloak_mcp"],
      "env": {
        "KEYCLOAK_URL": "https://sso.example.com",
        "KEYCLOAK_CLIENT_ID": "keycloak-mcp",
        "KEYCLOAK_CLIENT_SECRET": ""
      }
    }
  }
}
```

## License

MIT
