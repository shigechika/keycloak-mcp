# Review rules for this repository

Review rules on top of the reviewer's default focus. Three things:
which findings are blocking here, which classes to report that the
default focus would otherwise skip, and which are noise. The reasoning
behind the rules lives in `.github/copilot-instructions.md` (its
numbered focus items are cited below) and `CLAUDE.md`, which the
reviewer also receives.

## Always blocking

- **A credential or token reaching a log line or a tool response
  (§3).** `KEYCLOAK_CLIENT_SECRET`, the cached access token, request or
  response headers, an `Authorization` header, or the token response
  body — in `auth.py` or `client.py`'s `_send`, at any level including
  a hypothetical DEBUG.
- **A raw tool argument interpolated into a URL path (§3).** Inputs
  arrive from an LLM acting on a user's behalf. The existing pattern
  passes them through `httpx`'s `params` dict, and any id appearing in
  an f-string path is one already resolved by a prior lookup such as
  `get_user_by_username` — never a raw argument.
- **Dropping the `truncated` half of a `_paginate` result (§5).**
  `_paginate` returns `(items, truncated)`, and `get_events_all` /
  `get_admin_events_all` / `list_users_all` propagate it. A caller that
  throws the bool away turns a partial scan into an apparently complete
  one.
- **Presenting a bounded scan as complete (§5).** A string-returning
  tool that omits `_PARTIAL_WARNING` via `_with_warning(text,
  truncated)`, or a dict-returning tool with no truncation key of its
  own (`get_ip_activity`'s `events_capped` is the pattern).
- **Restarting the time budget per pagination (§5).** A tool running
  several paginations in one call must compute **one** deadline with
  `deadline_after(_deadline_seconds())` and share it across all of
  them, as `daily_brief`, `get_ip_activity` and `_fetch_login_events`
  do. Keycloak's `events?first=N` degrades badly at deep offsets, so an
  unbounded or per-pagination budget keeps hammering the IdP after the
  client has already given up on the call.
- **A new event or user pagination that is not deadline- and
  cap-bounded (§5)**, whether a new tool or a new probe inside
  `daily_brief`. Policy lives in `server.py`: `KEYCLOAK_DEADLINE`,
  `KEYCLOAK_MAX_EVENTS`, `KEYCLOAK_MAX_USERS`.

## Report even though the default focus would not

- **A new `@mcp.tool()`'s name and docstring (§3).** The calling model
  decides whether and how to invoke a tool by reading them, so a vague
  name, or a docstring omitting an expected format — the
  `username,password` CSV shape `reset_passwords_batch` takes, or the
  `YYYY-MM-DD` dates the event tools use — is a functional defect here.
  Report it even though docstring accuracy is normally out of scope
  when reviewing code.
- **A diff that adds a tool or `client.py` method and also touches
  `tests/` without covering an edge case (§4)**, as advisory:
  not-found, empty list, or a multi-page response for anything using
  `_paginate`. Judge it from the diff only — you receive changed files,
  so a pull request that leaves `tests/` alone may well be covered by
  tests you were not given.
- **A test departing from this suite's conventions (§4)**, as
  advisory. `tests/test_client.py` mocks HTTP with `respx` against the
  `tests/conftest.py` fixtures; `tests/test_server.py` exercises tools
  directly with `unittest.mock` / `monkeypatch`. A new `client.py` test
  that hand-mocks `httpx` is inconsistent with that.

## Never report

- `reset_passwords_batch` echoing back the passwords it **generated**.
  The caller has no other way to recover them, and the asymmetry is
  deliberate: a caller-**supplied** password is never echoed. That
  asymmetry itself is still worth checking — a change that started
  echoing a supplied password would be the blocking credential-leak
  rule above.
- Suggestions to remove or "simplify" `tests/test_stdio_smoke.py` as
  redundant with the unit tests. It is a real regression guard for CRLF
  handling on Windows.
- Suggestions to hand-build an MCP content envelope
  (`{"content": [...], "isError": ...}`) inside a tool handler. FastMCP
  wraps returned values already.
- A finding that does nothing but restate one of the two gates CI
  already enforces: `ruff check .` and `ruff format --check .` both gate this
  repository, and `tests/test_smoke_probes.py`
  already fails the build for a registered tool with no probe spec.
  This covers those two and nothing further. It never applies to a
  rule listed under **Always blocking** above, even when the same
  diff happens to fail a test as well, and it does not cover that
  same file's realm-specific-literal assertion — a leak
  reaching a public repository is worth catching twice.
- Suggestions to *replace* `release-please.yml`'s
  `secrets.RELEASE_PLEASE_TOKEN` with `GITHUB_TOKEN`. Preferring the
  dedicated token is deliberate: a `GITHUB_TOKEN`-authored tag or
  release does not trigger downstream workflows, which would leave the
  PyPI and MCP Registry publish pipeline dormant.
