# keycloak-mcp

MCP server for the [KeyCloak](https://www.keycloak.org/) Admin REST API.

Built for two things: a morning `daily_brief` that flags brute-force IPs and
API trouble in one call, and a set of investigation tools for the moment a
brief (or an alert) says something is wrong and you need the full picture for
one user, one IP, or one client.

## Tools by area

| Area | Tools |
|---|---|
| Users | `count_users`, `search_users`, `get_user`, `get_user_sessions`, `logout_user`, `set_user_enabled` |
| Passwords | `reset_password`, `reset_passwords_batch` |
| MFA | `get_user_credentials`, `get_totp_users` |
| Groups | `list_user_groups`, `list_users_by_group` |
| Security | `get_brute_force_status`, `get_realm_security_defenses`, `get_login_failures_by_ip`, `get_ip_activity`, `detect_login_loops` |
| Events | `get_events`, `get_login_stats`, `get_login_stats_by_hour`, `get_login_stats_by_client`, `get_password_update_events` |
| Admin events | `get_admin_events`, `get_user_attribute_history` |
| Sessions & clients | `get_session_stats`, `get_client_sessions`, `list_clients`, `get_realm_roles` |
| Morning patrol | `health_check`, `daily_brief` |

**Four tools write:** `reset_password`, `reset_passwords_batch`, `logout_user`,
`set_user_enabled`. Everything else is read-only. See
[Security investigation](investigation.md) for what each write tool actually
does and when it is the right response.

## Design notes

**Service-account auth, and that choice is load-bearing.** The server
authenticates with a Client Credentials Grant, not a human password or TOTP.
No user session is ever created and the `userinfo` endpoint is never called —
which matters specifically on deployments where Infinispan (KeyCloak's
distributed session cache) is not clustered, where session-based auth can
produce inconsistent state across nodes. A server that only ever requests
service-account tokens sidesteps that class of problem entirely, by
construction rather than by care taken at call sites.

**A capped scan discloses that it is capped.** `KEYCLOAK_DEADLINE` bounds how
long the heavy event/TOTP tools run, and `KEYCLOAK_MAX_EVENTS` bounds how much
they fetch. When either limit stops a scan early, the response is prefixed
with an explicit `⚠️ PARTIAL RESULT` warning rather than silently returning
what happened to be fetched. A partial result that looks complete is worse
than a slow one, and worse still than an error.

**Everything resolves against your site.** `get_events`, `get_user_sessions`
and `get_login_failures_by_ip` label IP addresses with the site names you
declare in an INI file, so investigation output reads in your own topology
instead of raw addresses you would otherwise have to look up by hand.

## Next steps

- [Setup](setup.md) — service account, permissions, environment, IP-to-site labeling
- [Security investigation](investigation.md) — brute-force / credential-stuffing workflow, the write tools, deadlines and partial results
- [Reference](reference.md) — every tool, the `health_check` contract, CLI, exit codes
