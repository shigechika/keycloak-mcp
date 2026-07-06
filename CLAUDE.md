# CLAUDE.md

## Overview

MCP server for the KeyCloak Admin REST API. Authenticates as a Service
Account (OIDC Client Credentials Grant — no human password or TOTP);
never calls the `userinfo` endpoint and never creates user sessions
(the project describes this as "Infinispan-safe" — see README.md).
Exposes 29 tools (users, MFA/credentials, groups, brute-force/security,
events, admin events, sessions/clients, and a `daily_brief` morning
report) over stdio transport.

## Commands

```bash
uv sync --dev
uv run pytest -v                  # all tests
uv run ruff check .               # lint
uv run ruff format --check .      # format check
```

This mirrors `.github/workflows/ci.yml` (matrix: Python 3.10–3.14 on
Ubuntu, plus one Windows 3.12 job to catch stdio newline regressions).
Plain-`pip` equivalents are documented in README.md's Development section.

## Architecture

- `keycloak_mcp/auth.py` — `TokenManager`: Client Credentials Grant token
  fetch/cache, refreshed 30s before expiry.
- `keycloak_mcp/client.py` — `KeyCloakClient`: thin `httpx` wrapper over
  the Admin REST API; retries 429/502/503/504 and transport errors with
  exponential backoff; `_paginate` pages list endpoints.
- `keycloak_mcp/sites.py` — `SiteClassifier`: labels IPs with a site name
  from an optional `KEYCLOAK_SITES_INI` file.
- `keycloak_mcp/server.py` — `FastMCP` server; all `@mcp.tool()` functions.
- `keycloak_mcp/__main__.py` — CLI entry point (`--check`, `--version`)
  plus a Windows-only stdout wrapper that strips CRLF back to LF.

Required env vars: `KEYCLOAK_URL`, `KEYCLOAK_CLIENT_ID`,
`KEYCLOAK_CLIENT_SECRET`. Optional: `KEYCLOAK_REALM` (default `master`),
`KEYCLOAK_SITES_INI`, `KEYCLOAK_DEFAULT_DATE_FROM_HOURS` (default 24).

## Conventions

- Public repository: comments, commit messages, and docs in English.
  README.md / README.ja.md is a maintained bilingual pair.
- Docstrings in English.
- Python 3.10+ (`requires-python = ">=3.10"` in pyproject.toml).
- Tests: `tests/test_client.py` mocks HTTP with `respx`; `tests/test_server.py`
  exercises tool functions directly with `unittest.mock`/`monkeypatch`;
  `tests/test_stdio_smoke.py` spawns the server as a subprocess to guard
  against CRLF line-ending regressions on stdio.
