"""MCP server exposing KeyCloak Admin operations via Service Account.

Uses Client Credentials Grant — no user password or TOTP required.
Infinispan-safe: does not create user sessions or use userinfo endpoint.
"""

import ipaddress
import math
import os
import secrets
import string
import sys
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from mcp.server.fastmcp import FastMCP

from .client import KeyCloakClient, deadline_after, past_deadline
from .sites import SiteClassifier


def _epoch_to_local_dt(epoch_ms: int | str) -> datetime:
    """Convert epoch milliseconds to an aware local datetime. Raises ValueError/TypeError on bad input."""
    return datetime.fromtimestamp(int(epoch_ms) / 1000, tz=timezone.utc).astimezone()


def _format_ts(epoch_ms: int | str) -> str:
    """Convert epoch milliseconds to local datetime string."""
    try:
        return _epoch_to_local_dt(epoch_ms).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return str(epoch_ms)


def _format_iso(epoch_ms: int | str) -> str:
    """Convert epoch milliseconds to a local ISO 8601 datetime string with offset."""
    try:
        return _epoch_to_local_dt(epoch_ms).isoformat()
    except (ValueError, TypeError):
        return str(epoch_ms)


def _normalize_ip(ip: str) -> str:
    """Return a canonical string form of an IP address, or the input unchanged if unparseable."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def _default_date_from(date_from: str) -> str | None:
    """Return date_from if given; otherwise compute a default lookback window.

    The default window is controlled by KEYCLOAK_DEFAULT_DATE_FROM_HOURS
    (default 24).  Set it to 0 or a negative value to disable the default
    and fall back to the original "scan all history" behaviour.
    """
    if date_from:
        return date_from
    try:
        hours = int(os.environ.get("KEYCLOAK_DEFAULT_DATE_FROM_HOURS", "24"))
    except ValueError:
        hours = 24
    if hours <= 0:
        return None
    return (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d")


# Bounds for heavy read tools so a wide date window / big realm can't page unbounded, blow the
# ~60s tool-call gateway, and keep hammering KeyCloak after the caller has given up. All read
# fresh from the env (0/negative disables), matching _default_date_from's idiom.
_DEADLINE_DEFAULT = 45.0
_MAX_EVENTS_DEFAULT = 200000
_MAX_USERS_DEFAULT = 5000

# Prepended to a tool's output when its data was cut short by the deadline or a cap, so a
# partial result is never silently mistaken for the whole picture.
_PARTIAL_WARNING = (
    "⚠️ PARTIAL RESULT — stopped early (window too wide / realm too large): the data below "
    "is INCOMPLETE. Narrow date_from (or set a smaller window) for full coverage."
)


def _deadline_seconds() -> float | None:
    """Per-call wall-clock budget (seconds) for heavy paginating/fan-out tools.

    From KEYCLOAK_DEADLINE (default 45); 0 or negative disables the deadline.
    """
    try:
        secs = float(os.environ.get("KEYCLOAK_DEADLINE", str(_DEADLINE_DEFAULT)))
    except ValueError:
        secs = _DEADLINE_DEFAULT
    if not math.isfinite(secs):  # "nan"/"inf" parse fine but would silently disable the deadline
        secs = _DEADLINE_DEFAULT
    return secs if secs > 0 else None


def _positive_int_env(name: str, default: int) -> int | None:
    """A positive-int bound from env var ``name`` (unparseable falls back to ``default``);
    0 or negative disables it (returns ``None``). Shared body behind the count caps."""
    try:
        val = int(os.environ.get(name, str(default)))
    except ValueError:
        val = default
    return val if val > 0 else None


def _max_events() -> int | None:
    """Per-pagination cap on events fetched (KEYCLOAK_MAX_EVENTS, default 200000; 0/negative
    disables the count cap and relies on the deadline alone)."""
    return _positive_int_env("KEYCLOAK_MAX_EVENTS", _MAX_EVENTS_DEFAULT)


def _max_users() -> int | None:
    """Default cap on users enumerated by get_totp_users (KEYCLOAK_MAX_USERS, default 5000;
    0/negative scans the whole realm, bounded only by the deadline). Used only when the tool's
    ``max_users`` argument is 0."""
    return _positive_int_env("KEYCLOAK_MAX_USERS", _MAX_USERS_DEFAULT)


def _user_attribute_whitelist() -> list[str]:
    """Custom user-attribute keys get_user is allowed to surface, from
    KEYCLOAK_USER_ATTRIBUTE_WHITELIST (comma-separated attribute keys). Empty/unset by
    default, so get_user's output — and the extra by-ID lookup needed to see attributes at
    all (see get_user_by_id) — is unchanged unless an operator opts specific keys in. This
    keeps arbitrary custom attributes (internal provisioning state, SSO/Shibboleth extension
    attributes, other site-specific fields, …) out of LLM context by default; only
    realm-specific deployments that need one attribute surfaced (e.g. an enrollment-status
    field for account lifecycle decisions) should set this."""
    raw = os.environ.get("KEYCLOAK_USER_ATTRIBUTE_WHITELIST", "")
    return [key.strip() for key in raw.split(",") if key.strip()]


def _with_warning(text: str, truncated: bool) -> str:
    """Prepend the partial-result warning to a tool's text output when it was cut short."""
    return f"{_PARTIAL_WARNING}\n\n{text}" if truncated else text


mcp = FastMCP("keycloak-mcp")
_client: KeyCloakClient | None = None
_sites: SiteClassifier | None = None


def _kc() -> KeyCloakClient:
    """Lazy-initialize the KeyCloak client."""
    global _client
    if _client is None:
        _client = KeyCloakClient()
    return _client


def reset_client() -> None:
    """Drop the cached client so the next call rebuilds and re-authenticates."""
    global _client
    _client = None


def _site_classifier() -> SiteClassifier:
    """Lazy-initialize the site classifier."""
    global _sites
    if _sites is None:
        _sites = SiteClassifier()
    return _sites


def _label_ip(ip: str) -> str:
    """Return IP with site label if available."""
    sc = _site_classifier()
    if not sc.available:
        return ip
    site = sc.classify(ip)
    return f"{ip} ({site})" if site else f"{ip} (external)"


def _format_event_list(header: str, events: list[dict], formatter: Callable[[dict], str]) -> str:
    """Render a header followed by one formatted line per event."""
    return "\n".join([header, *(formatter(e) for e in events)])


def _format_user_event(e: dict) -> str:
    """Format a single user-side event from `/events`."""
    details = e.get("details", {})
    error = e.get("error", "")
    error_part = f"  error={error}" if error else ""
    return (
        f"  {_format_ts(e.get('time', 0))}  {e['type']}  "
        f"user={details.get('username', e.get('userId', ''))}  "
        f"ip={_label_ip(e.get('ipAddress', ''))}  "
        f"client={e.get('clientId', '')}{error_part}"
    )


def _format_password_event(e: dict) -> str:
    """Format a single UPDATE_PASSWORD event."""
    details = e.get("details", {})
    return (
        f"  {_format_ts(e.get('time', ''))}  {details.get('username', '')}  "
        f"ip={_label_ip(e.get('ipAddress', ''))}  client={e.get('clientId', '')}"
    )


def _resolve_user(username: str) -> tuple[dict | None, str]:
    """Look up a user by exact username. Returns (user, error_message).

    ``error_message`` is the ready-to-return string when the user is missing,
    and is empty otherwise. Every MCP tool that takes a username starts with
    the same check, so this keeps the wording (and the lookup call) in one
    place.
    """
    user = _kc().get_user_by_username(username)
    if not user:
        return None, f"User '{username}' not found"
    return user, ""


# ---- Health ----


@mcp.tool()
def health_check() -> dict:
    """Report server version and KeyCloak backend connectivity / authentication.

    Call this at session start (or after a tool-call timeout) to confirm the MCP
    is up, see which version is running, and verify the KeyCloak Admin API is
    reachable and the service account can authenticate. Lightweight: it acquires
    an admin access token via the Client Credentials Grant (reusing the cached
    client) and does NOT enumerate users, events, or sessions.

    Always returns the same keys: ``status`` (healthy / degraded / error),
    ``service``, ``version``, ``keycloak_url`` (configured base URL, empty if
    unset), ``realm`` (configured realm), ``keycloak_version`` (None — not exposed
    by a cheap call), and ``auth`` (ok / error / missing-env). On a degraded or
    error result, ``detail`` carries the reason.

    This description is the only place those value sets are written down. The
    READMEs used to repeat them, which is three copies to keep in step and two
    that an LLM never reads — it is handed this text.
    """
    from keycloak_mcp import __version__

    # Fixed shape: every key is present regardless of outcome, so callers can
    # read it uniformly and rely on `status` to judge health.
    result: dict = {
        "status": "healthy",
        "service": "keycloak-mcp",
        "version": __version__,
        "keycloak_url": os.environ.get("KEYCLOAK_URL", ""),
        "realm": os.environ.get("KEYCLOAK_REALM", ""),
        "keycloak_version": None,
        "auth": "unknown",
    }

    # Backend: build the client (reads required env in TokenManager) and acquire
    # a token via Client Credentials Grant. A single token request is the lightest
    # proof that the service account can talk to the realm — no user/event scans.
    try:
        client = _kc()
        client.auth.get_token()
        result["auth"] = "ok"
    except KeyError as e:
        result["status"] = "error"
        result["auth"] = "missing-env"
        result["detail"] = f"Missing environment variable: {e}"
    except Exception as e:  # noqa: BLE001 — surface any backend failure, never raise
        reset_client()
        result["status"] = "degraded"
        result["auth"] = "error"
        # Keep internal URLs / httpx payloads out of the response; report the type.
        status = getattr(getattr(e, "response", None), "status_code", None)
        result["detail"] = f"{type(e).__name__} {status}" if status else type(e).__name__

    return result


# ---- User tools ----


@mcp.tool()
def count_users() -> str:
    """Get total user count in the realm."""
    count = _kc().count_users()
    return f"Total users: {count}"


@mcp.tool()
def search_users(query: str, max_results: int = 20) -> str:
    """Search users by username, email, first name, or last name.

    Args:
        query: Search string (partial match).
        max_results: Maximum results to return (default 20).
    """
    users = _kc().search_users(query, max_results)
    if not users:
        return f"No users found for '{query}'"
    lines = [f"Found {len(users)} user(s):"]
    for u in users:
        lines.append(
            f"  {u['username']}  id={u['id']}  "
            f"name={u.get('firstName', '')} {u.get('lastName', '')}  "
            f"enabled={u.get('enabled', '')}"
        )
    return "\n".join(lines)


@mcp.tool()
def get_user(username: str) -> str:
    """Get detailed user information by exact username (email).

    If KEYCLOAK_USER_ATTRIBUTE_WHITELIST names any custom attribute keys, this
    also does one extra by-ID lookup and appends whichever of those keys are
    present on the user (the search endpoint used to resolve the username
    returns a brief representation that omits ``attributes`` entirely).

    Args:
        username: Exact username (e.g., user@example.com).
    """
    u, err = _resolve_user(username)
    if err:
        return err
    lines = [
        f"# {u['username']}",
        f"ID: {u['id']}",
        f"Name: {u.get('firstName', '')} {u.get('lastName', '')}",
        f"Email: {u.get('email', '')}",
        f"Enabled: {u.get('enabled', '')}",
        f"Created: {_format_ts(u.get('createdTimestamp', ''))}",
    ]
    whitelist = _user_attribute_whitelist()
    if whitelist:
        full = _kc().get_user_by_id(u["id"])
        attributes = full.get("attributes") or {}
        for key in whitelist:
            if key not in attributes:
                continue
            values = attributes[key]
            value = ", ".join(values) if isinstance(values, list) else str(values)
            lines.append(f"Attribute[{key}]: {value}")
    return "\n".join(lines)


@mcp.tool()
def reset_password(username: str, password: str, temporary: bool = False) -> str:
    """Reset a user's password.

    Args:
        username: Exact username (email).
        password: New password to set.
        temporary: If True, user must change password on next login.
    """
    u, err = _resolve_user(username)
    if err:
        return err
    _kc().reset_password(u["id"], password, temporary)
    return f"Password reset for {username} (temporary={temporary})"


@mcp.tool()
def reset_passwords_batch(csv_text: str, temporary: bool = False) -> str:
    """Reset passwords for multiple users from CSV text.

    Each line should be: username,password
    If password column is empty, a random 12-char password is generated and
    included in the response (the caller cannot recover it otherwise).
    Caller-supplied passwords are never echoed back.

    Args:
        csv_text: CSV text with username,password per line (header optional).
        temporary: If True, users must change password on next login.
    """
    results = []
    for line in csv_text.strip().split("\n"):
        line = line.strip()
        if not line or line.lower().startswith("email") or line.lower().startswith("username"):
            continue
        parts = line.split(",")
        username = parts[0].strip()
        supplied = parts[1].strip() if len(parts) > 1 and parts[1].strip() else ""
        password = supplied or _random_password()
        generated = not supplied
        u = _kc().get_user_by_username(username)
        if not u:
            results.append(f"  NG  {username} — not found")
            continue
        try:
            _kc().reset_password(u["id"], password, temporary)
        except Exception as e:
            # Log details to stderr for operator diagnostics; keep the
            # tool response free of internal URLs or httpx repr payloads.
            print(f"reset_passwords_batch: {username}: {type(e).__name__}: {e}", file=sys.stderr)
            status = getattr(getattr(e, "response", None), "status_code", None)
            label = f"{type(e).__name__} {status}" if status else type(e).__name__
            results.append(f"  NG  {username} — request failed ({label})")
            continue
        if generated:
            results.append(f"  OK  {username} — reset (generated: {password})")
        else:
            results.append(f"  OK  {username} — reset (supplied)")
    return f"Batch reset ({len(results)} users):\n" + "\n".join(results)


def _random_password(length: int = 12) -> str:
    """Generate a random password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


@mcp.tool()
def get_user_sessions(username: str) -> str:
    """Get active sessions for a user.

    Args:
        username: Exact username (email).
    """
    u, err = _resolve_user(username)
    if err:
        return err
    sessions = _kc().get_user_sessions(u["id"])
    if not sessions:
        return f"No active sessions for {username}"
    lines = [f"Active sessions for {username}: {len(sessions)}"]
    for s in sessions:
        clients = s.get("clients", {})
        client_names = ", ".join(clients.values()) if clients else "none"
        lines.append(
            f"  clients=[{client_names}]  "
            f"started={_format_ts(s.get('start', 0) * 1000)}  "
            f"ip={_label_ip(s.get('ipAddress', ''))}"
        )
    return "\n".join(lines)


@mcp.tool()
def logout_user(username: str) -> str:
    """Force logout a user by removing all their active sessions.

    Args:
        username: Exact username (email).
    """
    u, err = _resolve_user(username)
    if err:
        return err
    sessions = _kc().get_user_sessions(u["id"])
    if not sessions:
        return f"No active sessions for {username} — nothing to do"
    _kc().logout_user(u["id"])
    return f"Logged out {username} ({len(sessions)} session(s) removed)"


@mcp.tool()
def set_user_enabled(username: str, enabled: bool) -> str:
    """Enable or disable a user account.

    Disabling blocks all authentication (SSO logins) for the user — the
    containment action for a compromised or decommissioned account. Only the
    ``enabled`` flag is changed; custom attributes are preserved.

    Disabling does not terminate existing sessions (an already-issued token
    stays valid until it expires), so when disabling this reports how many
    sessions remain and to run ``logout_user`` to end them immediately.

    Args:
        username: Exact username (email).
        enabled: True to enable, False to disable.
    """
    u, err = _resolve_user(username)
    if err:
        return err
    if u.get("enabled") == enabled:
        return f"{username} already enabled={enabled} — no change"
    _kc().set_user_enabled(u["id"], enabled)
    msg = f"Set {username} enabled={enabled}"
    if not enabled:
        sessions = _kc().get_user_sessions(u["id"])
        if sessions:
            msg += f"; {len(sessions)} active session(s) remain — run logout_user to terminate them"
    return msg


# ---- MFA / credential tools ----

# KeyCloak credential `type` value for TOTP/HOTP authenticators.
_OTP_TYPE = "otp"


def _format_credential(c: dict) -> str:
    """Format a single credential record from `/users/{id}/credentials`."""
    label = c.get("userLabel", "")
    label_part = f"  label={label}" if label else ""
    return f"  {c.get('type', '?'):24s}  created={_format_ts(c.get('createdDate', ''))}{label_part}"


@mcp.tool()
def get_user_credentials(username: str) -> str:
    """List the credential types configured for one user (password, otp, webauthn, …).

    Use this to check a single user's MFA status: an ``otp`` credential means
    TOTP/HOTP is configured. Reads ``/users/{id}/credentials`` (read-only; does
    not create a session).

    Args:
        username: Exact username (email).
    """
    u, err = _resolve_user(username)
    if err:
        return err
    creds = _kc().get_user_credentials(u["id"])
    if not creds:
        return f"{username}: no credentials configured"
    types = sorted({c.get("type", "?") for c in creds})
    has_otp = "yes" if any(c.get("type") == _OTP_TYPE for c in creds) else "no"
    lines = [
        f"Credentials for {username}:",
        f"  TOTP (otp): {has_otp}",
        f"  Types: {', '.join(types)}",
        "",
        *(_format_credential(c) for c in creds),
    ]
    return "\n".join(lines)


@mcp.tool()
def get_totp_users(
    enabled_only: bool = True,
    list_users: bool = True,
    max_users: int = 0,
) -> str:
    """Report how many users have TOTP (OTP) configured across the realm.

    Enumerates users and inspects each one's credentials for an ``otp`` entry.
    KeyCloak has no bulk credential endpoint, so this makes one credential
    request per user (N+1) — expect it to be slow on large realms; bound it with
    ``max_users`` (which also short-circuits the user enumeration). Users whose
    credential lookup fails are counted separately and skipped, so a single
    transient error does not abort the whole scan.

    Args:
        enabled_only: Only scan enabled users (default True).
        list_users: Include the list of usernames with TOTP (default True).
        max_users: Cap the number of users scanned. ``0`` (default) falls back to
                   KEYCLOAK_MAX_USERS (default 5000) rather than the whole realm.
                   The N+1 credential loop is also bounded by KEYCLOAK_DEADLINE, so
                   a large realm returns a disclosed sample. When capped, the
                   percentage covers only the sample, not the realm.
    """
    # Explicit max_users wins; otherwise fall back to the KEYCLOAK_MAX_USERS default so a
    # bare call can't try to enumerate the whole realm. The deadline additionally bounds the
    # N+1 credential loop — the real time sink — so a big realm returns a disclosed sample
    # instead of running past the tool-call gateway and hammering KeyCloak after it gives up.
    limit = max_users if max_users > 0 else _max_users()
    deadline = deadline_after(_deadline_seconds())
    users, enum_trunc = _kc().list_users_all(enabled_only=enabled_only, limit=limit, deadline=deadline)
    if not users:
        note = " (enumeration cut short by the time/user limit; realm may contain more)" if enum_trunc else ""
        return f"No users found{note}"

    otp_users: list[str] = []
    errors = 0
    scanned = 0
    loop_trunc = False
    for u in users:
        if past_deadline(deadline):
            loop_trunc = True
            break
        scanned += 1
        try:
            creds = _kc().get_user_credentials(u["id"])
        except Exception as exc:  # noqa: BLE001 — skip the user, keep scanning
            print(f"get_totp_users: {u.get('username', u['id'])}: {type(exc).__name__}: {exc}", file=sys.stderr)
            errors += 1
            continue
        if any(c.get("type") == _OTP_TYPE for c in creds):
            otp_users.append(u.get("username", u["id"]))

    capped = enum_trunc or loop_trunc
    succeeded = scanned - errors
    with_otp = len(otp_users)
    pct = (with_otp / succeeded * 100) if succeeded else 0.0
    scope = "enabled users" if enabled_only else "users"
    header = f"TOTP (OTP) usage (scanned {scanned} {scope}"
    if capped:
        if loop_trunc:
            reason = "the time budget (KEYCLOAK_DEADLINE)"
        elif max_users > 0:
            reason = f"max_users={max_users}"
        else:
            reason = "KEYCLOAK_MAX_USERS"
        header += f"; capped by {reason}, realm may contain more"
    header += "):"
    lines = [
        header,
        f"  With TOTP:    {with_otp} ({pct:.1f}%)",
        f"  Without TOTP: {succeeded - with_otp}",
    ]
    if errors:
        lines.append(f"  Errors:       {errors} (credential lookup failed; see stderr)")
    if list_users and otp_users:
        lines.append("")
        lines.append("Users with TOTP:")
        lines.extend(f"  {name}" for name in sorted(otp_users))
    return "\n".join(lines)


# ---- Brute force tools ----


@mcp.tool()
def get_brute_force_status(username: str) -> str:
    """Check if a user is temporarily locked due to brute force detection.

    Args:
        username: Exact username (email).
    """
    u, err = _resolve_user(username)
    if err:
        return err
    status = _kc().get_brute_force_status(u["id"])
    if not status or not status.get("numFailures"):
        return f"User '{username}': no brute force events detected"
    lines = [
        f"Brute force status for {username}:",
        f"  Failures: {status.get('numFailures', 0)}",
        f"  Disabled: {status.get('disabled', False)}",
        f"  Last failure: {_format_ts(status.get('lastFailure', 0))}",
        f"  Last IP: {_label_ip(status.get('lastIPFailure', ''))}",
    ]
    return "\n".join(lines)


# ---- Group tools ----


@mcp.tool()
def list_user_groups(username: str) -> str:
    """List groups a user belongs to.

    Args:
        username: Exact username (email).
    """
    u, err = _resolve_user(username)
    if err:
        return err
    groups = _kc().get_user_groups(u["id"])
    if not groups:
        return f"User '{username}' belongs to no groups"
    lines = [f"Groups for {username} ({len(groups)}):"]
    for g in groups:
        lines.append(f"  {g['name']}  path={g.get('path', '')}")
    return "\n".join(lines)


@mcp.tool()
def list_users_by_group(group_name: str, max_results: int = 100) -> str:
    """List all users in a group.

    Args:
        group_name: Group name (partial match).
        max_results: Maximum results (default 100).
    """
    groups = _kc().list_groups()
    matched = [g for g in groups if group_name.lower() in g.get("name", "").lower()]
    if not matched:
        return f"No group matching '{group_name}'"
    group = matched[0]
    members = _kc().get_group_members(group["id"], max_results)
    if not members:
        return f"No members in group '{group['name']}'"
    lines = [f"Members of '{group['name']}' ({len(members)}):"]
    for u in members:
        lines.append(
            f"  {u['username']:<40s}  {u.get('firstName', '')} {u.get('lastName', '')}  enabled={u.get('enabled', '')}"
        )
    return "\n".join(lines)


# ---- Event tools ----


@mcp.tool()
def get_events(
    event_type: str = "",
    username: str = "",
    client_id: str = "",
    ip_address: str = "",
    date_from: str = "",
    date_to: str = "",
    max_results: int = 50,
) -> str:
    """Get KeyCloak events with optional filters.

    Args:
        event_type: Event type filter (e.g., LOGIN, LOGIN_ERROR, UPDATE_PASSWORD).
        username: Filter by exact username (email). Resolved to user ID internally.
        client_id: Filter by client ID (SP name).
        ip_address: Filter events by source IP (client-side filter).
        date_from: Start date (YYYY-MM-DD). Defaults to last 24h when omitted (KEYCLOAK_DEFAULT_DATE_FROM_HOURS).
        date_to: End date (YYYY-MM-DD).
        max_results: Maximum results (default 50).
    """
    # Resolve username to user ID for the KeyCloak API
    user_id = None
    if username:
        u, err = _resolve_user(username)
        if err:
            return err
        user_id = u["id"]

    events = _kc().get_events(
        event_type=event_type or None,
        user=user_id,
        client_id=client_id or None,
        date_from=_default_date_from(date_from),
        date_to=date_to or None,
        max_results=max_results,
    )

    # Client-side IP filter (normalized so equivalent notations, e.g. IPv6
    # "::1" vs "0:0:0:0:0:0:0:1", still match)
    if ip_address:
        target_ip = _normalize_ip(ip_address)
        events = [e for e in events if _normalize_ip(e.get("ipAddress", "")) == target_ip]

    if not events:
        return "No events found"
    return _format_event_list(f"Events ({len(events)}):", events, _format_user_event)


def _fetch_login_events(
    date_from: str = "", date_to: str = "", deadline: float | None = None
) -> tuple[list[dict], list[dict], bool]:
    """Fetch all LOGIN and LOGIN_ERROR events with bounded pagination.

    A single wall-clock ``deadline`` (computed here from KEYCLOAK_DEADLINE when not
    supplied) is SHARED across both paginations, so the pair together stays under the
    tool-call gateway timeout; the KEYCLOAK_MAX_EVENTS cap applies per pagination (each of
    LOGIN / LOGIN_ERROR may collect up to the cap). When a caller (e.g. ``daily_brief``)
    already runs several paginations, it passes its own shared ``deadline``.

    Returns ``(success, failure, truncated)`` — ``truncated`` True if either pagination was
    cut short (results incomplete).
    """
    if deadline is None:
        deadline = deadline_after(_deadline_seconds())
    cap = _max_events()
    resolved_from = _default_date_from(date_from)
    resolved_to = date_to or None
    success, s_trunc = _kc().get_events_all(
        "LOGIN", date_from=resolved_from, date_to=resolved_to, max_events=cap, deadline=deadline
    )
    failure, f_trunc = _kc().get_events_all(
        "LOGIN_ERROR", date_from=resolved_from, date_to=resolved_to, max_events=cap, deadline=deadline
    )
    return success, failure, s_trunc or f_trunc


@mcp.tool()
def get_login_stats(date_from: str = "", date_to: str = "") -> str:
    """Get login success/failure statistics with full pagination.

    Args:
        date_from: Start date (YYYY-MM-DD). Defaults to last 24h when omitted (KEYCLOAK_DEFAULT_DATE_FROM_HOURS).
        date_to: End date (YYYY-MM-DD). Empty for all.
    """
    success, failure, truncated = _fetch_login_events(date_from, date_to)

    lines = [
        "Login statistics:",
        f"  Success: {len(success)}",
        f"  Failure: {len(failure)}",
        f"  Total:   {len(success) + len(failure)}",
    ]

    if failure:
        fail_users = Counter(e.get("details", {}).get("username", "unknown") for e in failure)
        lines.append("\nTop failing users:")
        for user, count in fail_users.most_common(10):
            lines.append(f"  {count:5d}  {user}")

    return _with_warning("\n".join(lines), truncated)


@mcp.tool()
def get_login_stats_by_hour(date_from: str = "", date_to: str = "") -> str:
    """Get login statistics broken down by hour (local time).

    Args:
        date_from: Start date (YYYY-MM-DD). Defaults to last 24h when omitted (KEYCLOAK_DEFAULT_DATE_FROM_HOURS).
        date_to: End date (YYYY-MM-DD). Empty for all.
    """
    success, failure, truncated = _fetch_login_events(date_from, date_to)

    success_by_hour: Counter[int] = Counter()
    failure_by_hour: Counter[int] = Counter()
    for e in success:
        try:
            hour = datetime.fromtimestamp(int(e["time"]) / 1000, tz=timezone.utc).astimezone().hour
            success_by_hour[hour] += 1
        except (KeyError, ValueError, TypeError):
            pass
    for e in failure:
        try:
            hour = datetime.fromtimestamp(int(e["time"]) / 1000, tz=timezone.utc).astimezone().hour
            failure_by_hour[hour] += 1
        except (KeyError, ValueError, TypeError):
            pass

    tz_name = datetime.now().astimezone().strftime("%Z")
    lines = [f"Login statistics by hour ({tz_name}):", f"{'Hour':>6s}  {'Success':>8s}  {'Failure':>8s}  {'Total':>8s}"]
    for h in range(24):
        s, f = success_by_hour[h], failure_by_hour[h]
        if s or f:
            lines.append(f"  {h:02d}:00  {s:8d}  {f:8d}  {s + f:8d}")
    total_s = sum(success_by_hour.values())
    total_f = sum(failure_by_hour.values())
    lines.append(f"  Total  {total_s:8d}  {total_f:8d}  {total_s + total_f:8d}")
    return _with_warning("\n".join(lines), truncated)


@mcp.tool()
def get_login_failures_by_ip(date_from: str = "", date_to: str = "", top: int = 20) -> str:
    """Get login failure statistics broken down by source IP.

    Args:
        date_from: Start date (YYYY-MM-DD). Defaults to last 24h when omitted (KEYCLOAK_DEFAULT_DATE_FROM_HOURS).
        date_to: End date (YYYY-MM-DD). Empty for all.
        top: Number of top IPs to show (default 20).
    """
    failure, truncated = _kc().get_events_all(
        "LOGIN_ERROR",
        date_from=_default_date_from(date_from),
        date_to=date_to or None,
        max_events=_max_events(),
        deadline=deadline_after(_deadline_seconds()),
    )
    if not failure:
        return _with_warning("No login failures found", truncated)

    # Group by normalized IP so equivalent notations (e.g. IPv6 "::1" vs
    # "0:0:0:0:0:0:0:1") aren't fragmented into separate rows.
    by_ip: Counter[str] = Counter(_normalize_ip(e.get("ipAddress", "unknown")) for e in failure)
    lines = [f"Login failures by IP ({len(failure)} total, {len(by_ip)} unique IPs):"]
    lines.append(f"  {'Count':>6s}  {'IP':<40s}  {'Site':<16s}  {'Last seen'}")
    for ip, count in by_ip.most_common(top):
        last = max(
            (e.get("time", 0) for e in failure if _normalize_ip(e.get("ipAddress", "unknown")) == ip),
            default=0,
        )
        site = _site_classifier().classify(ip) or "external"
        lines.append(f"  {count:6d}  {ip:<40s}  {site:<16s}  {_format_ts(last)}")
    return _with_warning("\n".join(lines), truncated)


@mcp.tool()
def get_ip_activity(
    ip_address: str,
    event_types: str = "LOGIN,LOGIN_ERROR",
    date_from: str = "",
    date_to: str = "",
    max_timeline: int = 200,
) -> dict:
    """Exhaustive investigation of all activity from one source IP address.

    Unlike `get_events(ip_address=...)`, which filters a single page and can
    miss activity outside the most recent `max_results` events, this tool
    fully paginates every requested event type (via `get_events_all`) before
    filtering by IP, so the result is exhaustive over the requested date
    range. Use this for brute-force / credential-stuffing / shared-workstation
    investigations where `get_login_failures_by_ip` told you *which* IP to
    look at and you now need the full picture for that one IP.

    Returns a fixed-shape dict (JSON), not formatted text — every key below is
    always present, even when zero events match.

    Returns:
        error: None on success. Set to a descriptive message if event_types
            resolved to no event types (e.g. empty or all-whitespace/commas);
            every other key is still present, with an empty/zero result in
            that case (no data was fetched).
        ip_address: Echoes the input.
        site: Site name from KEYCLOAK_SITES_INI, or null if unmatched or
            unconfigured (see sites_configured to tell those apart).
        sites_configured: True if KEYCLOAK_SITES_INI was loaded at all.
        date_from / date_to: The resolved date range actually scanned.
        event_types: The event types scanned (echoes the input, split).
        summary: total_events, login_success, login_failure, unique_users,
            unique_clients, first_seen/last_seen (ISO 8601, null if no match).
            login_success/login_failure classify EVERY scanned event type by
            whether its type ends in "_ERROR" (matching the users/clients
            breakdown below), not just literal LOGIN/LOGIN_ERROR — so widening
            event_types always keeps these numbers reconciled with the
            per-user/per-client totals. Always computed over the FULL matched
            set, unaffected by max_timeline truncation.
        users: Per-user breakdown (success/failure counts, distinct error
            codes), sorted by total activity descending. Note: successful
            LOGIN events often carry only a userId (UUID) while LOGIN_ERROR
            carries details.username — this tool keys on
            username-or-userId-or-"unknown", so the same human can
            legitimately appear under two different keys across success vs.
            failure events.
        clients: Per-client (SP) breakdown, same shape, sorted descending.
        timeline: Chronological event list, capped at max_timeline (most
            recent kept on overflow — see truncated). max_timeline<=0 returns
            an empty timeline.
        truncated: True if timeline was capped; summary/users/clients are
            never affected by this cap.
        events_capped: True if event pagination itself was cut short by the
            wall-clock deadline (KEYCLOAK_DEADLINE) or the per-type cap
            (KEYCLOAK_MAX_EVENTS) — i.e. the window was too wide and the WHOLE
            result (summary/users/clients/timeline) is incomplete. Distinct from
            ``truncated``, which only trims the timeline of an otherwise-complete
            scan. Narrow date_from when this is true.

    Args:
        ip_address: Source IP to investigate. Compared against KeyCloak's
            recorded ipAddress field after normalizing both sides through
            Python's ipaddress module (so equivalent IPv6 notations like
            "::1" and "0:0:0:0:0:0:0:1" match); falls back to a raw string
            compare if either side doesn't parse as an IP.
        event_types: Comma-separated KeyCloak event types to scan (default
            "LOGIN,LOGIN_ERROR"). Widen with e.g.
            "LOGIN,LOGIN_ERROR,LOGOUT,UPDATE_PASSWORD,CLIENT_LOGIN,CLIENT_LOGIN_ERROR"
            for a broader sweep. Must resolve to at least one type.
        date_from: Start date (YYYY-MM-DD). Defaults to last 24h when omitted
            (KEYCLOAK_DEFAULT_DATE_FROM_HOURS). Widening the window means
            fully paginating every event type over that window before
            filtering — expect it to be slower on large realms.
        date_to: End date (YYYY-MM-DD). Empty for open-ended.
        max_timeline: Cap on the number of most-recent timeline entries
            returned (default 200; <=0 means no timeline entries). Does not
            affect summary/users/clients.
    """
    resolved_date_from = _default_date_from(date_from)
    types = [t.strip() for t in event_types.split(",") if t.strip()]
    error = None if types else f"event_types must contain at least one event type, got {event_types!r}"

    all_events: list[dict] = []
    events_capped = False
    if error is None:
        # One deadline SHARED across every event type's pagination (the cap applies per
        # type), so widening event_types or the window can't page unbounded past the
        # tool-call timeout.
        deadline = deadline_after(_deadline_seconds())
        cap = _max_events()
        for et in types:
            ev, trunc = _kc().get_events_all(
                et, date_from=resolved_date_from, date_to=date_to or None, max_events=cap, deadline=deadline
            )
            all_events.extend(ev)
            events_capped = events_capped or trunc

    target_ip = _normalize_ip(ip_address)
    matched = [e for e in all_events if _normalize_ip(e.get("ipAddress", "")) == target_ip]

    def _time_key(e: dict) -> int:
        return e.get("time") or 0

    def _user_key(e: dict) -> str:
        return (e.get("details") or {}).get("username") or e.get("userId") or "unknown"

    def _client_key(e: dict) -> str:
        return e.get("clientId") or "unknown"

    matched.sort(key=_time_key)

    users: dict[str, dict] = {}
    clients: dict[str, dict] = {}
    login_success = login_failure = 0

    for e in matched:
        is_failure = e.get("type", "").endswith("_ERROR")
        if is_failure:
            login_failure += 1
        else:
            login_success += 1

        uname = _user_key(e)
        u = users.setdefault(uname, {"username": uname, "success": 0, "failure": 0, "errors": []})
        cid = _client_key(e)
        c = clients.setdefault(cid, {"client_id": cid, "success": 0, "failure": 0})
        if is_failure:
            u["failure"] += 1
            c["failure"] += 1
            err = e.get("error")
            if err and err not in u["errors"]:
                u["errors"].append(err)
        else:
            u["success"] += 1
            c["success"] += 1

    if max_timeline > 0:
        timeline_src = matched[-max_timeline:]
    else:
        timeline_src = []
    truncated = len(matched) > len(timeline_src)
    timeline = [
        {
            "time": _format_iso(_time_key(e)),
            "type": e.get("type", ""),
            "username": _user_key(e),
            "client_id": _client_key(e),
            "error": e.get("error") or None,
        }
        for e in timeline_src
    ]

    sc = _site_classifier()
    return {
        "error": error,
        "ip_address": ip_address,
        "site": sc.classify(ip_address),
        "sites_configured": sc.available,
        "date_from": resolved_date_from,
        "date_to": date_to or None,
        "event_types": types,
        "summary": {
            "total_events": len(matched),
            "login_success": login_success,
            "login_failure": login_failure,
            "unique_users": len(users),
            "unique_clients": len(clients),
            "first_seen": _format_iso(_time_key(matched[0])) if matched else None,
            "last_seen": _format_iso(_time_key(matched[-1])) if matched else None,
        },
        "users": sorted(users.values(), key=lambda u: u["success"] + u["failure"], reverse=True),
        "clients": sorted(clients.values(), key=lambda c: c["success"] + c["failure"], reverse=True),
        "timeline": timeline,
        "truncated": truncated,
        "events_capped": events_capped,
    }


@mcp.tool()
def get_login_stats_by_client(date_from: str = "", date_to: str = "") -> str:
    """Get login statistics broken down by client (SP).

    Args:
        date_from: Start date (YYYY-MM-DD). Defaults to last 24h when omitted (KEYCLOAK_DEFAULT_DATE_FROM_HOURS).
        date_to: End date (YYYY-MM-DD). Empty for all.
    """
    success, failure, truncated = _fetch_login_events(date_from, date_to)

    success_by_client: Counter[str] = Counter(e.get("clientId", "unknown") for e in success)
    failure_by_client: Counter[str] = Counter(e.get("clientId", "unknown") for e in failure)

    all_clients = sorted(set(success_by_client) | set(failure_by_client))
    lines = ["Login statistics by client:", f"{'Client':<50s}  {'Success':>8s}  {'Failure':>8s}  {'Total':>8s}"]
    for client in all_clients:
        s, f = success_by_client[client], failure_by_client[client]
        lines.append(f"  {client:<48s}  {s:8d}  {f:8d}  {s + f:8d}")
    total_s = sum(success_by_client.values())
    total_f = sum(failure_by_client.values())
    lines.append(f"  {'Total':<48s}  {total_s:8d}  {total_f:8d}  {total_s + total_f:8d}")
    return _with_warning("\n".join(lines), truncated)


@mcp.tool()
def detect_login_loops(
    date_from: str = "",
    date_to: str = "",
    threshold: int = 10,
    window_seconds: int = 60,
    top: int = 20,
) -> str:
    """Detect users with rapid repeated logins (possible redirect loops).

    Scans all LOGIN events and finds users who logged in more than `threshold`
    times within `window_seconds`.

    Args:
        date_from: Start date (YYYY-MM-DD). Defaults to last 24h when omitted (KEYCLOAK_DEFAULT_DATE_FROM_HOURS).
        date_to: End date (YYYY-MM-DD). Empty for all.
        threshold: Minimum logins within the window to flag (default 10).
        window_seconds: Time window in seconds (default 60).
        top: Number of top users to show (default 20). Use 0 for all.
    """
    events, truncated = _kc().get_events_all(
        "LOGIN",
        date_from=_default_date_from(date_from),
        date_to=date_to or None,
        max_events=_max_events(),
        deadline=deadline_after(_deadline_seconds()),
    )
    if not events:
        return _with_warning("No LOGIN events found", truncated)

    # Group events by username
    by_user: dict[str, list[dict]] = {}
    for e in events:
        username = e.get("details", {}).get("username", "")
        if username:
            by_user.setdefault(username, []).append(e)

    # Detect loops: sliding window
    loops: list[tuple[str, int, float, float, str, str]] = []
    for username, user_events in by_user.items():
        timestamps = sorted(int(e.get("time", 0)) for e in user_events)
        if len(timestamps) < threshold:
            continue

        # Find the densest window
        max_count = 0
        best_start = 0
        best_end = 0
        window_ms = window_seconds * 1000
        j = 0
        for i in range(len(timestamps)):
            while j < len(timestamps) and timestamps[j] - timestamps[i] <= window_ms:
                j += 1
            count = j - i
            if count > max_count:
                max_count = count
                best_start = timestamps[i]
                best_end = timestamps[j - 1]

        if max_count >= threshold:
            duration_s = (best_end - best_start) / 1000
            avg_interval = duration_s / (max_count - 1) if max_count > 1 else 0
            # Find most common IP and client for this user
            ips = Counter(e.get("ipAddress", "") for e in user_events)
            clients = Counter(e.get("clientId", "") for e in user_events)
            loops.append(
                (
                    username,
                    max_count,
                    duration_s,
                    avg_interval,
                    ips.most_common(1)[0][0],
                    clients.most_common(1)[0][0],
                )
            )

    if not loops:
        return _with_warning(f"No login loops detected (threshold={threshold}, window={window_seconds}s)", truncated)

    loops.sort(key=lambda x: -x[1])
    total_loop_users = len(loops)
    if top > 0:
        loops = loops[:top]
    lines = [
        f"Login loops detected: {total_loop_users} user(s) "
        f"(threshold={threshold}, window={window_seconds}s, showing top {len(loops)})",
        "",
        f"  {'User':<40s}  {'Count':>5s}  {'Duration':>10s}  {'Avg interval':>12s}  {'IP':<40s}  {'Client'}",
    ]
    for username, count, duration, avg_interval, ip, client in loops:
        lines.append(
            f"  {username:<40s}  {count:5d}  {duration:8.1f}s  {avg_interval:10.2f}s  {_label_ip(ip):<40s}  {client}"
        )
    return _with_warning("\n".join(lines), truncated)


@mcp.tool()
def get_password_update_events(date_from: str = "", date_to: str = "", max_results: int = 100) -> str:
    """Get password update events.

    Args:
        date_from: Start date (YYYY-MM-DD). Defaults to last 24h when omitted (KEYCLOAK_DEFAULT_DATE_FROM_HOURS).
        date_to: End date (YYYY-MM-DD).
        max_results: Maximum results (default 100).
    """
    events = _kc().get_events(
        "UPDATE_PASSWORD",
        date_from=_default_date_from(date_from),
        date_to=date_to or None,
        max_results=max_results,
    )
    if not events:
        return "No password update events found"
    return _format_event_list(
        f"Password updates ({len(events)}):",
        events,
        _format_password_event,
    )


# ---- Admin event tools ----


def _format_admin_event(e: dict, max_repr: int = 500) -> str:
    """Format a single admin event record.

    :param e: the raw admin event.
    :param max_repr: max chars of the ``representation`` field to include.
        Use ``0`` to omit the representation entirely, or a negative value
        to include it in full without truncation.
    """
    auth = e.get("authDetails", {}) or {}
    auth_user = auth.get("userId", "")
    auth_ip = auth.get("ipAddress", "")
    parts = [
        _format_ts(e.get("time", 0)),
        e.get("operationType", ""),
        e.get("resourceType", ""),
        f"path={e.get('resourcePath', '')}",
        f"admin={auth_user}",
        f"ip={_label_ip(auth_ip)}" if auth_ip else "ip=-",
    ]
    error = e.get("error")
    if error:
        parts.append(f"error={error}")
    if max_repr != 0:
        rep = e.get("representation")
        if rep:
            if max_repr < 0 or len(rep) <= max_repr:
                rep_short = rep
            else:
                rep_short = rep[: max_repr - 3] + "..."
            parts.append(f"repr={rep_short}")
    return "  " + "  ".join(parts)


@mcp.tool()
def get_admin_events(
    operation_types: str = "",
    resource_types: str = "",
    resource_path: str = "",
    date_from: str = "",
    date_to: str = "",
    max_results: int = 50,
    max_repr: int = 500,
) -> str:
    """Get KeyCloak admin events (changes performed via the Admin REST API).

    Admin events record operations performed by service accounts or admin users
    — e.g. custom user attribute updates (``provisioning_flag``), role / group
    assignments, client configuration changes. These are distinct from user
    events (login / password change). Use this when ``UPDATE_PROFILE`` in
    ``get_events`` is empty but an attribute is known to have changed.

    Args:
        operation_types: Comma-separated list of CREATE, UPDATE, DELETE, ACTION.
        resource_types: Comma-separated list of USER, CLIENT, ROLE, GROUP, REALM_ROLE, etc.
        resource_path: Filter by resource path (e.g. "users/{userId}").
        date_from: Start date (YYYY-MM-DD). Defaults to last 24h when omitted (KEYCLOAK_DEFAULT_DATE_FROM_HOURS).
        date_to: End date (YYYY-MM-DD).
        max_results: Maximum results (default 50).
        max_repr: Max chars of the representation field. 0 = omit, -1 = full.
    """
    op_list = [s.strip() for s in operation_types.split(",") if s.strip()] or None
    rt_list = [s.strip() for s in resource_types.split(",") if s.strip()] or None
    events = _kc().get_admin_events(
        operation_types=op_list,
        resource_types=rt_list,
        resource_path=resource_path or None,
        date_from=_default_date_from(date_from),
        date_to=date_to or None,
        max_results=max_results,
    )
    if not events:
        return "No admin events found"
    return _format_event_list(
        f"Admin events ({len(events)}):",
        events,
        lambda e: _format_admin_event(e, max_repr=max_repr),
    )


@mcp.tool()
def get_user_attribute_history(
    username: str,
    date_from: str = "",
    date_to: str = "",
    max_results: int = 100,
    max_repr: int = 500,
) -> str:
    """Get admin-side attribute change history for a single user.

    Queries admin events scoped to ``users/{userId}`` with UPDATE / ACTION
    operations. Intended for tracking custom attribute changes such as
    ``provisioning_flag`` which are written by admin API and do **not** surface in
    ``get_events`` (which only shows user-driven events like LOGIN /
    UPDATE_PASSWORD).

    Args:
        username: Exact username (email).
        date_from: Start date (YYYY-MM-DD). Defaults to last 24h when omitted (KEYCLOAK_DEFAULT_DATE_FROM_HOURS).
        date_to: End date (YYYY-MM-DD).
        max_results: Maximum results (default 100).
        max_repr: Max chars of the representation field. 0 = omit, -1 = full.
    """
    user, err = _resolve_user(username)
    if err:
        return err
    user_id = user["id"]
    events = _kc().get_admin_events(
        operation_types=["UPDATE", "ACTION"],
        resource_types=["USER"],
        resource_path=f"users/{user_id}",
        date_from=_default_date_from(date_from),
        date_to=date_to or None,
        max_results=max_results,
    )
    if not events:
        return f"No attribute change events for {username}"
    return _format_event_list(
        f"Attribute history for {username} ({len(events)}):",
        events,
        lambda e: _format_admin_event(e, max_repr=max_repr),
    )


# ---- Session tools ----


@mcp.tool()
def get_session_stats() -> str:
    """Get active session count per client."""
    stats = _kc().get_session_stats()
    if not stats:
        return "No active sessions"
    total = sum(int(s.get("active", 0)) for s in stats)
    lines = [f"Active sessions: {total} total, {len(stats)} clients"]
    for s in sorted(stats, key=lambda x: -int(x.get("active", 0))):
        lines.append(f"  {int(s.get('active', 0)):5d}  {s['clientId']}")
    return "\n".join(lines)


@mcp.tool()
def get_client_sessions(client_id: str, max_results: int = 100) -> str:
    """Get active sessions for a specific client (SP).

    Args:
        client_id: Client ID (e.g., 'xflow', 'shadowserver').
        max_results: Maximum results (default 100).
    """
    client = _kc().get_client_by_client_id(client_id)
    if not client:
        return f"Client '{client_id}' not found"
    sessions = _kc().get_client_sessions(client["id"], max_results)
    if not sessions:
        return f"No active sessions for '{client_id}'"
    lines = [f"Active sessions for '{client_id}' ({len(sessions)}):"]
    for s in sessions:
        lines.append(
            f"  {s.get('username', ''):<40s}  "
            f"ip={_label_ip(s.get('ipAddress', ''))}  "
            f"started={_format_ts(s.get('start', 0) * 1000)}"
        )
    return "\n".join(lines)


# ---- Client tools ----


@mcp.tool()
def list_clients() -> str:
    """List all SAML/OIDC clients in the realm."""
    clients = _kc().list_clients()
    lines = [f"Clients ({len(clients)}):"]
    for c in clients:
        protocol = c.get("protocol", "")
        lines.append(f"  {c['clientId']:50s}  {protocol:10s}  enabled={c.get('enabled', '')}")
    return "\n".join(lines)


@mcp.tool()
def get_realm_roles() -> str:
    """List all realm-level roles."""
    roles = _kc().get_realm_roles()
    lines = [f"Realm roles ({len(roles)}):"]
    for r in roles:
        lines.append(f"  {r['name']:30s}  {r.get('description', '')}")
    return "\n".join(lines)


@mcp.tool()
def get_realm_security_defenses() -> str:
    """Show the realm's security-defense settings (read-only).

    Reports the realm-level security configuration that the admin console
    groups under "Security defenses":

    - Brute force detection: whether it is enabled, the lockout strategy,
      and the thresholds (max login failures, wait increments, reset window).
    - Password policy.
    - Browser security headers.

    Use this to verify that brute-force protection is actually turned on and
    how aggressively it locks accounts — the per-user ``get_brute_force_status``
    only reflects runtime state, not whether the policy itself is configured.
    """
    realm = _kc().get_realm()
    enabled = realm.get("bruteForceProtected", False)
    lines = [
        f"Security defenses for realm '{realm.get('realm', '?')}':",
        "",
        "## Brute force detection",
        f"  Enabled:                {enabled}",
    ]
    if enabled:
        lines += [
            f"  Strategy:               {realm.get('bruteForceStrategy', 'MULTIPLE')}",
            f"  Permanent lockout:      {realm.get('permanentLockout', False)}",
            f"  Max login failures:     {realm.get('failureFactor', '?')}",
            f"  Max temporary lockouts: {realm.get('maxTemporaryLockouts', 0)}",
            f"  Wait increment:         {realm.get('waitIncrementSeconds', '?')}s",
            f"  Max wait:               {realm.get('maxFailureWaitSeconds', '?')}s",
            f"  Failure reset after:    {realm.get('maxDeltaTimeSeconds', '?')}s",
            f"  Quick-login check:      {realm.get('quickLoginCheckMilliSeconds', '?')}ms",
            f"  Min quick-login wait:   {realm.get('minimumQuickLoginWaitSeconds', '?')}s",
        ]
    else:
        lines.append("  (brute-force protection is OFF — no lockout thresholds apply)")

    lines += [
        "",
        "## Password policy",
        f"  {realm.get('passwordPolicy') or '(none)'}",
    ]

    headers = realm.get("browserSecurityHeaders") or {}
    set_headers = {k: v for k, v in headers.items() if v}
    lines += ["", "## Browser security headers"]
    if set_headers:
        for k in sorted(set_headers):
            lines.append(f"  {k}: {set_headers[k]}")
    else:
        lines.append("  (none configured)")
    return "\n".join(lines)


@mcp.tool()
def daily_brief(
    since_hours: int = 18,
    ip_failure_threshold: int = 50,
) -> str:
    """Run a morning Keycloak health check.

    Checks (all scoped to the last ``since_hours`` hours):
    - Login statistics (success / failure totals, top failing IPs)
    - Active sessions by client
    - Password update events
    - Admin events (CREATE/UPDATE/DELETE on USER/CLIENT resources)

    A single IP with login failures >= ``ip_failure_threshold`` is flagged
    as WARNING (possible brute-force).

    ``since_hours`` defaults to 18 (≈ previous 15:00 for a 09:00 morning run).

    Output tiers:
    - CRITICAL — API connection failure
    - WARNING  — anomalies detected
    - OK       — clean

    Args:
        since_hours: Look-back window in hours (default 18).
        ip_failure_threshold: Login failures from a single IP that triggers a
                              WARNING (default 50).
    """
    now_str = datetime.now(tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z").strip()
    date_from = (datetime.now() - timedelta(hours=since_hours)).strftime("%Y-%m-%d")

    # One deadline SHARED across all four paginations so the whole brief stays under the
    # tool-call gateway timeout (the cap applies per pagination; a truncated section just
    # reports a lower bound).
    deadline = deadline_after(_deadline_seconds())
    cap = _max_events()
    try:
        success, failure, login_trunc = _fetch_login_events(date_from=date_from, deadline=deadline)
        pw_updates, pw_trunc = _kc().get_events_all(
            "UPDATE_PASSWORD", date_from=date_from, max_events=cap, deadline=deadline
        )
        admin_evts, admin_trunc = _kc().get_admin_events_all(
            operation_types=["CREATE", "UPDATE", "DELETE"],
            resource_types=["USER", "CLIENT"],
            date_from=date_from,
            max_events=cap,
            deadline=deadline,
        )
        session_stats = _kc().get_session_stats()
    except Exception as exc:
        print(f"daily_brief: {type(exc).__name__}: {exc}", file=sys.stderr)
        return f"## daily_brief — {now_str}\n## CRITICAL — {type(exc).__name__}"
    truncated = login_trunc or pw_trunc or admin_trunc

    by_ip: Counter[str] = Counter(e.get("ipAddress", "unknown") for e in failure)
    top_offenders = [(ip, cnt) for ip, cnt in by_ip.most_common() if cnt >= ip_failure_threshold][:5]
    warnings: list[str] = [f"[LOGIN_FAILURE] {cnt} failures from {_label_ip(ip)}" for ip, cnt in top_offenders]
    if truncated:
        warnings.append(
            "[PARTIAL] event data incomplete — the look-back window exceeded the time/size budget; "
            "counts are a lower bound (narrow since_hours or raise KEYCLOAK_DEADLINE)"
        )

    total_sessions = sum(int(s.get("active", 0)) for s in session_stats)

    lines: list[str] = [
        f"## daily_brief — {now_str} (since -{since_hours}h)",
        f"## {'WARNING' if warnings else 'OK'} — "
        f"login {len(success)} OK / {len(failure)} NG, "
        f"sessions {total_sessions}, "
        f"pw-updates {len(pw_updates)}, "
        f"admin-events {len(admin_evts)}",
        "",
    ]

    if warnings:
        lines.append("### WARNINGS")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")

    lines += [
        "### Login",
        f"- Success: {len(success)}",
        f"- Failure: {len(failure)} ({len(by_ip)} unique IPs)",
    ]
    if by_ip:
        lines.append("- Top failing IPs:")
        for ip, cnt in by_ip.most_common(5):
            lines.append(f"  - {cnt:5d}  {_label_ip(ip)}")
    lines.append("")

    lines.append("### Active sessions")
    if session_stats:
        lines.append(f"- Total: {total_sessions}")
        for s in sorted(session_stats, key=lambda x: -int(x.get("active", 0)))[:5]:
            lines.append(f"  - {int(s.get('active', 0)):5d}  {s['clientId']}")
    else:
        lines.append("- No active sessions")
    lines.append("")

    lines.append(f"### Password updates: {len(pw_updates)}")
    if pw_updates:
        for e in pw_updates[:10]:
            lines.append(f"- {_format_password_event(e)}")
    lines.append("")

    lines.append(f"### Admin events: {len(admin_evts)}")
    if admin_evts:
        for e in admin_evts[:10]:
            lines.append(f"- {_format_admin_event(e, max_repr=0)}")

    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
