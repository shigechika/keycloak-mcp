"""Probe specs for this server's tools — the KeyCloak-specific half of the smoke test.

Every registered tool needs an entry here (the harness fails on a tool with no
spec), so adding a tool forces a decision: how would we know it works?

Two constraints shape everything below.

**Read-only.** These tools drive a production identity provider. Anything that
mutates state — password resets, forced logout, enable/disable — is skipped by
name and must stay skipped.

**No site-specific values in this file.** This repository is public, so a probe
may not hardcode a username, a client ID, a group, or a hostname from the realm
it happens to run against. Where a tool needs such an argument, an
``args_factory`` discovers one at run time from a listing tool; the only literal
identifiers used are KeyCloak's own built-in clients, which exist in every realm.

Assertions are shape-first. Most tools answer with formatted text whose empty
case is a sentence ("No events found"), not an error, so a probe pins the header
line it must produce. Where an empty answer would be pathological rather than
quiet — a realm reporting zero users, zero clients, zero roles — the probe says
so explicitly with ``must_not_match``.

**Bound anything that scans.** A probe runs on a schedule, so a tool whose
default arguments walk the whole realm must be called with an explicit cap. The
first live run of this file learned that the hard way: ``get_totp_users`` with
no arguments enumerated thousands of accounts and issued one credential request
each. Passing a small sample proves the tool works; measuring the realm is a
separate, deliberate operation.
"""

from __future__ import annotations

import re
from typing import Any

from smoke_harness import Caller, Probe, SkipProbe

#: KeyCloak ships these clients in every realm, so naming them here reveals
#: nothing about the deployment while still exercising the code path.
BUILTIN_CLIENT = "account"

#: A short, common substring to search users by. Kept generic on purpose: the
#: point is to find *a* user, not a particular one.
USER_QUERY = "a"


async def _first_username(call: Caller) -> dict[str, Any]:
    """Discover a username at run time for the per-user tools."""
    payload = await call("search_users", {"query": USER_QUERY, "max_results": 1})
    text = payload if isinstance(payload, str) else str(payload)
    # "Found 1 user(s):\n  <username>  id=<uuid>  name=... enabled=..."
    # The name runs to the "id=" field rather than to the first space: KeyCloak
    # permits a space in a username, and a truncated one would be looked up as
    # a different account (or as nobody).
    match = re.search(r"^\s{2}(\S.*?)\s+id=", text, re.MULTILINE)
    if not match:
        raise SkipProbe("search_users returned no user to probe with")
    return {"username": match.group(1)}


async def _first_group(call: Caller) -> dict[str, Any]:
    """Discover a group name from whichever user the search finds."""
    args = await _first_username(call)
    payload = await call("list_user_groups", args)
    text = payload if isinstance(payload, str) else str(payload)
    # "Groups for <user> (N):\n  <group>  path=..."
    match = re.search(r"^\s{2}(\S+)", text, re.MULTILINE)
    if "belongs to no groups" in text or not match:
        raise SkipProbe("no group membership available to probe with")
    return {"group_name": match.group(1)}


#: Source addresses as the failure report renders them. IPv6 is included
#: because the server normalises and prints it, and on a dual-stack network the
#: top offender may well be v6 — matching v4 only would quietly skip
#: get_ip_activity on exactly the days worth investigating.
_SOURCE_ADDRESS = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    r"|(?i:\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}\b"
    r"|\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?)"
)


async def _first_failing_ip(call: Caller) -> dict[str, Any]:
    """Discover a source address from the recent login-failure report."""
    payload = await call("get_login_failures_by_ip", {"top": 1})
    text = payload if isinstance(payload, str) else str(payload)
    match = _SOURCE_ADDRESS.search(text)
    if not match:
        raise SkipProbe("no login failures in the window to trace an address from")
    return {"ip_address": match.group(0)}


#: Header lines that prove a tool rendered its report. Empty windows are
#: tolerated by alternation because event retention and quiet hours are real.
PROBES: dict[str, Probe] = {
    # -- server / realm health --------------------------------------------
    "health_check": Probe(
        require_keys=("status", "service", "auth"),
        must_match=(r'"auth": "ok"', r'"status": "(healthy|degraded)"'),
        allow_empty=True,
    ),
    "get_realm_security_defenses": Probe(must_match=(r"^Security defenses for realm",), min_chars=40),
    "get_realm_roles": Probe(
        must_match=(r"^Realm roles \(\d+\):",),
        # Every realm has built-in roles; zero means the read failed, not that
        # the realm is empty.
        must_not_match=(r"^Realm roles \(0\):",),
    ),
    "list_clients": Probe(
        must_match=(r"^Clients \(\d+\):",),
        must_not_match=(r"^Clients \(0\):",),
    ),
    "count_users": Probe(
        must_match=(r"^Total users: \d+",),
        must_not_match=(r"^Total users: 0$",),
    ),
    "get_session_stats": Probe(
        must_match=(r"^(Active sessions: \d+ total, \d+ clients|No active sessions)",),
    ),
    "daily_brief": Probe(
        must_match=(r"^## daily_brief",),
        # The tool renders its own crash into the report rather than raising.
        must_not_match=(r"^## CRITICAL",),
        timeout=300,
    ),
    # -- user lookups (arguments discovered at run time) -------------------
    "search_users": Probe(
        args={"query": USER_QUERY, "max_results": 5},
        must_match=(r"^(Found \d+ user\(s\):|No users found)",),
    ),
    "get_user": Probe(
        args_factory=_first_username,
        must_match=(r"^# \S+", r"^ID: "),
    ),
    "get_user_sessions": Probe(
        args_factory=_first_username,
        must_match=(r"^(Active sessions for \S+: \d+|No active sessions for )",),
    ),
    "get_user_credentials": Probe(
        args_factory=_first_username,
        must_match=(r"^(Credentials for \S+:|\S+: no credentials configured)",),
    ),
    "get_brute_force_status": Probe(
        args_factory=_first_username,
        must_match=(r"(no brute force events detected|[Ff]ailure|[Ll]ocked)",),
        min_chars=5,
    ),
    "list_user_groups": Probe(
        args_factory=_first_username,
        must_match=(r"^(Groups for \S+ \(\d+\):|User '\S+' belongs to no groups)",),
    ),
    "list_users_by_group": Probe(
        args_factory=_first_group,
        must_match=(r"(members|No members in group|No group matching)",),
        min_chars=5,
    ),
    "get_user_attribute_history": Probe(
        args_factory=_first_username,
        must_match=(r"(No attribute change events|attribute)",),
        min_chars=5,
        timeout=300,
    ),
    # Bounded on purpose. Called bare, this tool enumerates up to
    # KEYCLOAK_MAX_USERS (5000) accounts and then issues ONE credential request
    # per user — thousands of admin calls against a live IdP, which a probe run
    # regularly has no business doing. A small sample proves the tool works;
    # measuring realm-wide TOTP coverage is a separate, deliberate operation.
    "get_totp_users": Probe(
        args={"max_users": 25, "list_users": False},
        must_match=(r"^TOTP \(OTP\) usage \(scanned \d+|^No users found",),
        min_chars=5,
        timeout=300,
    ),
    # -- clients / sessions ------------------------------------------------
    "get_client_sessions": Probe(
        args={"client_id": BUILTIN_CLIENT, "max_results": 10},
        must_match=(r"(sessions|not found)",),
        min_chars=5,
    ),
    # -- event windows -----------------------------------------------------
    # An empty window is a legitimate observation (retention settings, quiet
    # hours), so these pin the rendered shape rather than a row count.
    "get_events": Probe(must_match=(r"(No events found|[Ee]vent)",), min_chars=5, timeout=300),
    "get_admin_events": Probe(must_match=(r"(No admin events found|[Ee]vent)",), min_chars=5, timeout=300),
    "get_login_stats": Probe(
        must_match=(r"^Login statistics:", r"^\s+Success: \d+", r"^\s+Total:\s+\d+"),
        timeout=300,
    ),
    "get_login_stats_by_hour": Probe(must_match=(r"^Login statistics by hour",), timeout=300),
    "get_login_stats_by_client": Probe(must_match=(r"^Login statistics by client:",), timeout=300),
    "get_login_failures_by_ip": Probe(
        must_match=(r"^Login failures by IP \(\d+ total, \d+ unique IPs\):|No ",),
        timeout=300,
    ),
    "get_password_update_events": Probe(
        must_match=(r"(No password update events found|UPDATE_PASSWORD|\d)",),
        min_chars=5,
        timeout=300,
    ),
    "detect_login_loops": Probe(must_match=(r"(No LOGIN events found|loop|LOGIN)",), min_chars=5, timeout=300),
    "get_ip_activity": Probe(
        args_factory=_first_failing_ip,
        must_match=(r"\d",),
        min_chars=5,
        timeout=300,
    ),
    # -- state-changing tools: never exercised ----------------------------
    "reset_password": Probe(skip="destructive: would change a user's password"),
    "reset_passwords_batch": Probe(skip="destructive: would change passwords in bulk"),
    "logout_user": Probe(skip="destructive: would terminate a user's sessions"),
    "set_user_enabled": Probe(skip="destructive: would enable/disable an account"),
}
