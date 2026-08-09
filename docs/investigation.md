# Security investigation

Two tools narrow "something is wrong" down to "what, exactly" — `get_login_failures_by_ip`
finds candidate IPs, `get_ip_activity` gives the full picture for one of them.
Four more tools act on what you find.

## From candidate IPs to a full picture

**`get_login_failures_by_ip(date_from, date_to, top=20)`** ranks source IPs by
login-failure count over a window. This is the starting point, not the
verdict — a high failure count from a single IP is exactly what a shared NAT
exit or a corporate proxy produces on an ordinary day, and a spray attack
distributed across residential proxies can produce a *low* per-IP count while
still succeeding. Failure count alone under- and over-flags in both
directions.

**`get_ip_activity(ip_address, event_types="LOGIN,LOGIN_ERROR", date_from, date_to, max_timeline=200)`**
is what actually answers the question, for one IP. It fully paginates every
matching event before filtering — unlike filtering `get_events` client-side on
a single page, which can miss activity outside the most recent results — so
the summary is exhaustive over the requested window, not a sample. It returns
structured data:

- `summary`: total events, success/failure counts, unique users, unique
  clients, first/last seen
- `users`: per-user success/failure breakdown with distinct KeyCloak error
  codes (`invalid_user_credentials`, `user_temporarily_disabled`, …)
- `clients`: per-client (SP) success/failure breakdown
- `timeline`: chronological events, capped at `max_timeline`

## Reading the numbers: spray vs. one person's typo

The distinguishing signal is **success rate across distinct users**, not raw
failure count:

- **Many users, low success rate** (rule of thumb: ≥10 distinct users, <20%
  success) from one IP is the shape of a password-spray or
  credential-stuffing run. Any user with `success > 0` in that IP's breakdown
  is a compromised account — this is where you stop reading and act.
- **One user, many failures, eventual success** — especially from a
  residential or mobile IP, at human intervals of tens of seconds to minutes,
  often trying an ID variant (a personal email address, a typo'd username) —
  is ordinary password amnesia. It is not an incident.
- Widening the lens to **known shared egress ranges** (a corporate VPN, a
  remote-desktop farm) can turn "many users, one IP" from suspicious into
  routine — and, symmetrically, a *low* per-IP success rate spread across many
  IPs that all belong to one hosting or VPS provider is worth the same
  scrutiny a single noisy IP would get, because that is what a distributed
  spray looks like from this vantage point.

`get_realm_security_defenses` shows whether brute-force detection is on and
its thresholds — useful context for judging whether KeyCloak's own defenses
already caught what you are looking at, and `get_brute_force_status` confirms
whether one specific user is currently locked.

## Responding: the four write tools

Once `get_ip_activity` names a compromised account, three tools do the actual
containment, in the order that matters:

1. **`set_user_enabled(username, enabled=False)`** blocks all future logins.
   It changes only the `enabled` flag — custom attributes are untouched. It
   **does not end existing sessions**: a token already issued stays valid
   until it expires on its own. When it disables a user with active sessions,
   the response reports the session count and says to run `logout_user` next
   — the tool tells you the follow-up step rather than assuming you know it.
2. **`logout_user(username)`** removes all of that user's active sessions,
   forcing re-authentication everywhere. Reports how many sessions it removed;
   a call against a user with none is a no-op that says so rather than
   erroring.
3. **`reset_password(username, password, temporary=False)`** sets a new
   password. `temporary=True` forces a change on next login — the right choice
   for a reset you are handing to the user, not one you intend to use yourself.

**`reset_passwords_batch(csv_text, temporary=False)`** takes `username,password`
per line (CSV) for bulk resets; an empty password field generates one. Built
for a spray incident with several compromised accounts at once, not for
routine use.

None of the four are exercised by the live smoke test (`scripts/smoke_test.py`)
— they mutate real accounts, and a scheduled test run is not the place for
that. A unit test enforces that they stay skipped there.

## Login loops

**`detect_login_loops(date_from, date_to, threshold=10, window_seconds=60, top=20)`**
flags users who logged in more than `threshold` times within `window_seconds`
— the signature of a broken redirect between KeyCloak and a service provider,
not an attack. It scans `LOGIN` events only, so it is a separate lens from the
failure-based spray detection above.

## Deadlines and partial results

`get_ip_activity`, `get_login_failures_by_ip`, `detect_login_loops`, and
`get_totp_users` all pull potentially large amounts of data — a wide date
range or a large realm can mean many pages of events. Two independent limits
protect against that:

- `KEYCLOAK_DEADLINE` (default 45s) bounds wall-clock time per call
- `KEYCLOAK_MAX_EVENTS` (default 200,000) bounds how much a single call fetches

How the cutoff is disclosed depends on the tool's return type:

- The text-returning tools (`get_login_failures_by_ip`, `detect_login_loops`,
  `get_login_stats`, and others) prefix their output with
  `⚠️ PARTIAL RESULT — stopped early (window too wide / realm too large): the
  data below is INCOMPLETE.`
- `get_ip_activity` returns structured JSON instead of formatted text, so it
  signals the same condition through a boolean field, **`events_capped`**.
  When `true`, the whole result — `summary`, `users`, `clients`, and
  `timeline` alike — is incomplete. This is a separate concern from
  `truncated`, which only means the `timeline` list itself was capped at
  `max_timeline` while `summary`/`users`/`clients` (computed from the full
  matched set) stayed accurate.

Either way, the data returned is real, just not exhaustive — narrow
`date_from` to get full coverage instead of a partial one. A tool that
quietly returned a partial result formatted identically to a complete one
would be worse than useless during an investigation: it would look like
"nothing more happened" when the truth is "we stopped looking".
