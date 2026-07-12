# Repository overview

`keycloak-mcp` is an MCP (Model Context Protocol) server exposing the
KeyCloak Admin REST API — users, sessions, events, security settings —
to AI assistants over **stdio transport**. It authenticates as a Service
Account (Client Credentials Grant, `keycloak_mcp/auth.py`) and talks to
the Admin API via `KeyCloakClient` (`keycloak_mcp/client.py`). Built on
the official `mcp` Python SDK's `FastMCP` (`keycloak_mcp/server.py`).

See `CLAUDE.md` for the authoritative command list and architecture
notes — read it before reviewing changes to `client.py`, `auth.py`, or
`server.py`.

# Build & validate

```bash
uv sync --dev
uv run ruff check .
uv run ruff format --check .
uv run pytest -v
```

This mirrors `.github/workflows/ci.yml`: a `lint` job (ruff check +
format check) and a `test` job matrixed over Python 3.10–3.14 on Ubuntu,
plus one Windows 3.12 job specifically to catch stdio newline
regressions (`modelcontextprotocol/python-sdk#2433`). Ruff **does** run
in CI here — don't hand-flag formatting/import-order issues it already
enforces; focus review comments on things CI can't catch.

# What to focus review on in this repo

## 1. This is a stdio MCP server — stdout is a JSON-RPC channel, not a log

Any `print()` or library logging that writes to stdout instead of
stderr corrupts the protocol stream for the connected client. The
existing convention in `server.py` and `__main__.py` is to route
diagnostics to stderr explicitly (`print(..., file=sys.stderr)`) in
tool error paths (`reset_passwords_batch`, `get_totp_users`,
`daily_brief`). The one exception is `__main__.py`'s `_check_config()`,
which prints a plain confirmation line to stdout on `--check` — that
path calls `sys.exit()` before `mcp.run()` ever starts, so it never
shares the stream with JSON-RPC traffic. Flag any *new* code path that
writes to stdout on the `mcp.run(transport="stdio")` side, or that lets
a dependency's default logging config leak through.

## 2. FastMCP already wraps tool returns — don't ask for manual envelope code

`server.py`'s `@mcp.tool()` functions return plain `str`/`dict` values;
FastMCP handles the MCP content-envelope wrapping and derives `isError`
from raised exceptions. Do **not** suggest a tool handler manually
build `{"content": [...], "isError": ...}`. Broad `except Exception`
blocks that catch-and-continue (`get_totp_users` skipping a user whose
credential lookup fails, `daily_brief` reporting `CRITICAL` instead of
raising) are deliberate patterns for partial-result/summary tools, not
bugs — don't flag them as swallowed errors unless the new code silently
drops a failure with no visible trace at all (not even a stderr log).

## 3. Service Account credentials and tokens are the sensitive surface

- `KEYCLOAK_CLIENT_SECRET` and the cached access token
  (`TokenManager._token`) must never be logged or printed, including at
  a hypothetical DEBUG level — flag any diff that logs request/response
  headers, the token response body, or `Authorization` headers in
  `auth.py` or `client.py`'s `_send`.
- `reset_password` / `reset_passwords_batch` take a plaintext password
  argument. `reset_passwords_batch` intentionally echoes back
  **generated** passwords in its result (the caller has no other way to
  recover them) but never echoes a caller-**supplied** password — this
  asymmetry is deliberate, not a leak; don't flag it.
- Tool inputs (usernames, group names, CSV text, IP addresses) come
  from an LLM acting on a user's behalf — treat them as adversarial.
  The existing pattern passes raw input to the KeyCloak API via
  `httpx`'s `params` dict (safely encoded), and any ID interpolated
  into a URL path (e.g. `f"/users/{user_id}/..."`) is one already
  resolved from a prior lookup (`get_user_by_username`), never a raw
  argument. Flag any new endpoint call that drops a raw tool argument
  directly into an f-string URL path instead of going through `params`
  or a resolved ID first.
- A new `@mcp.tool()`'s name and docstring are what the calling model
  uses to decide whether/how to invoke it — flag a vague name or a
  docstring that omits an expected format (e.g. the `username,password`
  CSV shape `reset_passwords_batch` expects, or the `YYYY-MM-DD` date
  format used throughout the event tools).

## 4. Test conventions

- `tests/test_client.py` mocks HTTP with `respx` against the fixtures
  in `tests/conftest.py`; `tests/test_server.py` exercises tool
  functions directly via `unittest.mock`/`monkeypatch`. A new
  `client.py` method that hand-mocks `httpx` instead of using `respx`
  is inconsistent with the existing suite.
- New tools/client methods need a test covering both a normal response
  and at least one edge case (not-found, empty list, a paginated
  multi-page response for anything using `_paginate`).
- `tests/test_stdio_smoke.py` is a real regression guard (CRLF on
  Windows) — don't suggest removing or "simplifying" it as redundant
  with the unit tests.

## 5. Heavy event/scan tools must be bounded and disclose partial results

Keycloak's `events?first=N` pagination degrades badly at deep offsets, so a
wide window (e.g. a week of a busy realm) can blow past the ~60s tool-call
gateway and — worse — keep hammering the IdP after the client has given up.
Every heavy event/enumeration tool is therefore bounded and discloses when it
stopped early (PR #37):

- `_paginate` (`client.py`) returns `(items, truncated)`, stopping on a
  per-pagination count cap (`max_total`) or a shared wall-clock `deadline`
  (`deadline_after` / `past_deadline`). `get_events_all` /
  `get_admin_events_all` / `list_users_all` propagate that tuple — a caller
  that throws the `truncated` bool away is a bug.
- Policy lives in `server.py`: `KEYCLOAK_DEADLINE` (default 45s, the wall-clock
  budget), `KEYCLOAK_MAX_EVENTS` (per-pagination event cap), `KEYCLOAK_MAX_USERS`
  (enumeration cap for `get_totp_users`). A tool that runs several paginations
  in one call must compute **one** deadline
  (`deadline_after(_deadline_seconds())`) and share it across all of them (see
  `daily_brief`, `get_ip_activity`, `_fetch_login_events`) — not restart the
  budget per pagination.
- Partial results must be disclosed, never presented as complete:
  string-returning tools prepend `_PARTIAL_WARNING` via
  `_with_warning(text, truncated)`; dict-returning tools expose a key (e.g.
  `get_ip_activity`'s `events_capped`). `get_totp_users`'s N+1 credential loop
  also checks the deadline and discloses when it stops short.

So a new tool that paginates events/users — or a new probe added to
`daily_brief` — must be deadline+cap bounded, must share the call's single
deadline, and must surface truncation to the caller. Flag one that doesn't.

# Out of scope for review comments

- `release-please.yml` using `secrets.RELEASE_PLEASE_TOKEN` instead of
  `GITHUB_TOKEN` is intentional (tags/releases authored by
  `GITHUB_TOKEN` don't trigger downstream workflows, which would leave
  the PyPI / MCP Registry publish pipeline dormant) — don't suggest
  reverting it.
