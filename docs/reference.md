# Reference

## `health_check()`

Seven keys are present on every call:

| Key | Meaning |
|---|---|
| `status` | `healthy` / `degraded` / `error` |
| `service` | Always `keycloak-mcp` |
| `version` | Package version |
| `keycloak_url` | Configured URL (empty string when unset) |
| `realm` | Configured realm (empty string when unset) |
| `keycloak_version` | `null` until a token request succeeds |
| `auth` | `unknown` / `ok` / `missing-env` / `error` |

`detail` is added only on `degraded` or `error`, with the reason: a missing
environment variable, or the exception type (and HTTP status, when the
backend returned one) for a genuine authentication failure. Internal URLs and
raw HTTP payloads are deliberately kept out of it.

Lightweight by design: it acquires one Client Credentials token — the
lightest possible proof the service account can talk to the realm — and
scans nothing else. Safe to call at session start or after a tool-call
timeout.

## Tool index

| Tool | Purpose |
|---|---|
| `count_users` | Total user count in the realm |
| `search_users(query, max_results=20)` | Partial-match search: username, email, first/last name |
| `get_user(username)` | Full detail for an exact username |
| `get_user_sessions(username)` | Active sessions, timestamps in local time |
| `logout_user(username)` | **Writes.** Ends all active sessions for one user |
| `set_user_enabled(username, enabled)` | **Writes.** Enable/disable; disabling does not end existing sessions |
| `reset_password(username, password, temporary=False)` | **Writes.** Reset one user's password |
| `reset_passwords_batch(csv_text, temporary=False)` | **Writes.** Bulk reset from `username,password` CSV |
| `get_user_credentials(username)` | Configured credential types; an `otp` entry means TOTP/HOTP is set up |
| `get_totp_users(max_users=0)` | Realm-wide TOTP adoption. N+1 (one call per user); bounded by `max_users` or `KEYCLOAK_MAX_USERS` |
| `list_user_groups(username)` | Groups a user belongs to |
| `list_users_by_group(group)` | Members of a group |
| `get_brute_force_status(username)` | Whether a user is currently locked by brute-force detection |
| `get_realm_security_defenses()` | Brute-force policy and thresholds, password policy, browser security headers |
| `get_login_failures_by_ip(date_from, date_to, top=20)` | Failure counts ranked by source IP |
| `get_ip_activity(ip_address, event_types, date_from, date_to, max_timeline=200)` | Exhaustive per-IP investigation (structured JSON) |
| `detect_login_loops(date_from, date_to, threshold=10, window_seconds=60, top=20)` | Users logging in faster than `threshold` per `window_seconds` |
| `get_events(event_type, username, client_id, ip_address, date_from, date_to)` | Filtered event search; username resolved to user ID internally |
| `get_login_stats(date_from, date_to)` | Success/failure totals, fully paginated |
| `get_login_stats_by_hour(date_from, date_to)` | Logins bucketed by hour of day, local time |
| `get_login_stats_by_client(date_from, date_to)` | Logins bucketed by client (SP) |
| `get_password_update_events(date_from, date_to)` | `UPDATE_PASSWORD` history |
| `get_admin_events(operation_types, resource_types, resource_path, date_from, date_to, max_repr=500)` | Admin-driven changes; `get_events` never sees these |
| `get_user_attribute_history(username, date_from, date_to, max_repr=500)` | Admin events scoped to one user |
| `get_session_stats()` | Active session count per client |
| `get_client_sessions(client_id)` | Active sessions for one client |
| `list_clients()` | SAML and OIDC clients in the realm |
| `get_realm_roles()` | Realm-level roles |
| `daily_brief(since_hours=18, ip_failure_threshold=50)` | Morning summary: login stats, brute-force IPs, sessions, password updates, admin events |

See [Security investigation](investigation.md) for what the write tools
actually do, how to read `get_ip_activity`'s output, and the deadline /
partial-result mechanism shared by the heavy scans.

## `daily_brief`

One Markdown report covering login stats, IPs over `ip_failure_threshold`
failures (flagged `WARNING`), active sessions, password updates, and admin
events, all within `since_hours` (default 18 — roughly the previous afternoon
for a 09:00 morning run). A backend connection failure renders the whole
report as `## CRITICAL — <ExceptionType>` rather than a partial brief with
gaps unaccounted for.

`get_admin_events` and `get_user_attribute_history` accept `max_repr`, which
controls how much of the KeyCloak "representation" payload (the changed
object, as JSON text) is included: positive truncates to that many characters
(default 500), `0` omits it, negative includes it in full.

## `get_events` vs. `get_admin_events`

`get_events` sees *user* events — logins, logouts, password changes performed
by the user themself. Actions performed by an administrator, or by a service
account writing a custom attribute, do not appear there at all;
`get_admin_events` is the endpoint that does. `get_user_attribute_history` is
`get_admin_events` pre-scoped to one user, useful for confirming when an
automated pipeline last wrote something like a `temp_password` attribute.

## CLI

```bash
keycloak-mcp            # start the MCP server (stdio; default, no arguments)
keycloak-mcp --version  # print version and exit
keycloak-mcp --help     # show usage and required environment variables
keycloak-mcp --check    # verify environment and authentication, then exit
```

Exit codes for `--check`: `0` success, `1` a required environment variable is
missing, `2` authentication failed.
