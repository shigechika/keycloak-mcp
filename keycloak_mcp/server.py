"""MCP server exposing KeyCloak Admin operations via Service Account.

Uses Client Credentials Grant — no user password or TOTP required.
Infinispan-safe: does not create user sessions or use userinfo endpoint.
"""

import secrets
import string
import sys
from collections import Counter
from datetime import datetime

from mcp.server.fastmcp import FastMCP

from .client import KeyCloakClient
from .sites import SiteClassifier


def _format_ts(epoch_ms: int | str) -> str:
    """Convert epoch milliseconds to local datetime string."""
    try:
        ts = int(epoch_ms) / 1000
        return datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError):
        return str(epoch_ms)


mcp = FastMCP("keycloak-mcp")
_client: KeyCloakClient | None = None
_sites: SiteClassifier | None = None


def _kc() -> KeyCloakClient:
    """Lazy-initialize the KeyCloak client."""
    global _client
    if _client is None:
        _client = KeyCloakClient()
    return _client


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

    Args:
        username: Exact username (e.g., user@example.com).
    """
    u = _kc().get_user_by_username(username)
    if not u:
        return f"User '{username}' not found"
    lines = [
        f"# {u['username']}",
        f"ID: {u['id']}",
        f"Name: {u.get('firstName', '')} {u.get('lastName', '')}",
        f"Email: {u.get('email', '')}",
        f"Enabled: {u.get('enabled', '')}",
        f"Created: {_format_ts(u.get('createdTimestamp', ''))}",
    ]
    return "\n".join(lines)


@mcp.tool()
def reset_password(username: str, password: str, temporary: bool = False) -> str:
    """Reset a user's password.

    Args:
        username: Exact username (email).
        password: New password to set.
        temporary: If True, user must change password on next login.
    """
    u = _kc().get_user_by_username(username)
    if not u:
        return f"User '{username}' not found"
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
            results.append(f"  NG  {username} — request failed ({type(e).__name__})")
            continue
        if generated:
            results.append(f"  OK  {username} — generated: {password}")
        else:
            results.append(f"  OK  {username}")
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
    u = _kc().get_user_by_username(username)
    if not u:
        return f"User '{username}' not found"
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
    u = _kc().get_user_by_username(username)
    if not u:
        return f"User '{username}' not found"
    sessions = _kc().get_user_sessions(u["id"])
    if not sessions:
        return f"No active sessions for {username} — nothing to do"
    _kc().logout_user(u["id"])
    return f"Logged out {username} ({len(sessions)} session(s) removed)"


# ---- Brute force tools ----


@mcp.tool()
def get_brute_force_status(username: str) -> str:
    """Check if a user is temporarily locked due to brute force detection.

    Args:
        username: Exact username (email).
    """
    u = _kc().get_user_by_username(username)
    if not u:
        return f"User '{username}' not found"
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
    u = _kc().get_user_by_username(username)
    if not u:
        return f"User '{username}' not found"
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
        date_from: Start date (YYYY-MM-DD).
        date_to: End date (YYYY-MM-DD).
        max_results: Maximum results (default 50).
    """
    # Resolve username to user ID for the KeyCloak API
    user_id = None
    if username:
        u = _kc().get_user_by_username(username)
        if not u:
            return f"User '{username}' not found"
        user_id = u["id"]

    events = _kc().get_events(
        event_type=event_type or None,
        user=user_id,
        client_id=client_id or None,
        date_from=date_from or None,
        date_to=date_to or None,
        max_results=max_results,
    )

    # Client-side IP filter
    if ip_address:
        events = [e for e in events if e.get("ipAddress") == ip_address]

    if not events:
        return "No events found"
    lines = [f"Events ({len(events)}):"]
    for e in events:
        details = e.get("details", {})
        error = e.get("error", "")
        error_part = f"  error={error}" if error else ""
        lines.append(
            f"  {_format_ts(e.get('time', 0))}  {e['type']}  "
            f"user={details.get('username', e.get('userId', ''))}  "
            f"ip={_label_ip(e.get('ipAddress', ''))}  "
            f"client={e.get('clientId', '')}{error_part}"
        )
    return "\n".join(lines)


def _fetch_login_events(date_from: str = "", date_to: str = "") -> tuple[list[dict], list[dict]]:
    """Fetch all LOGIN and LOGIN_ERROR events with pagination."""
    success = _kc().get_events_all("LOGIN", date_from=date_from or None, date_to=date_to or None)
    failure = _kc().get_events_all("LOGIN_ERROR", date_from=date_from or None, date_to=date_to or None)
    return success, failure


@mcp.tool()
def get_login_stats(date_from: str = "", date_to: str = "") -> str:
    """Get login success/failure statistics with full pagination.

    Args:
        date_from: Start date (YYYY-MM-DD). Empty for all.
        date_to: End date (YYYY-MM-DD). Empty for all.
    """
    success, failure = _fetch_login_events(date_from, date_to)

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

    return "\n".join(lines)


@mcp.tool()
def get_login_stats_by_hour(date_from: str = "", date_to: str = "") -> str:
    """Get login statistics broken down by hour (local time).

    Args:
        date_from: Start date (YYYY-MM-DD). Empty for all.
        date_to: End date (YYYY-MM-DD). Empty for all.
    """
    success, failure = _fetch_login_events(date_from, date_to)

    success_by_hour: Counter[int] = Counter()
    failure_by_hour: Counter[int] = Counter()
    for e in success:
        try:
            hour = datetime.fromtimestamp(int(e["time"]) / 1000).astimezone().hour
            success_by_hour[hour] += 1
        except (KeyError, ValueError, TypeError):
            pass
    for e in failure:
        try:
            hour = datetime.fromtimestamp(int(e["time"]) / 1000).astimezone().hour
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
    return "\n".join(lines)


@mcp.tool()
def get_login_failures_by_ip(date_from: str = "", date_to: str = "", top: int = 20) -> str:
    """Get login failure statistics broken down by source IP.

    Args:
        date_from: Start date (YYYY-MM-DD). Empty for all.
        date_to: End date (YYYY-MM-DD). Empty for all.
        top: Number of top IPs to show (default 20).
    """
    failure = _kc().get_events_all("LOGIN_ERROR", date_from=date_from or None, date_to=date_to or None)
    if not failure:
        return "No login failures found"

    by_ip: Counter[str] = Counter(e.get("ipAddress", "unknown") for e in failure)
    lines = [f"Login failures by IP ({len(failure)} total, {len(by_ip)} unique IPs):"]
    lines.append(f"  {'Count':>6s}  {'IP':<40s}  {'Site':<16s}  {'Last seen'}")
    for ip, count in by_ip.most_common(top):
        last = max(
            (e.get("time", 0) for e in failure if e.get("ipAddress") == ip),
            default=0,
        )
        site = _site_classifier().classify(ip) or "external"
        lines.append(f"  {count:6d}  {ip:<40s}  {site:<16s}  {_format_ts(last)}")
    return "\n".join(lines)


@mcp.tool()
def get_login_stats_by_client(date_from: str = "", date_to: str = "") -> str:
    """Get login statistics broken down by client (SP).

    Args:
        date_from: Start date (YYYY-MM-DD). Empty for all.
        date_to: End date (YYYY-MM-DD). Empty for all.
    """
    success, failure = _fetch_login_events(date_from, date_to)

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
    return "\n".join(lines)


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
        date_from: Start date (YYYY-MM-DD). Empty for all.
        date_to: End date (YYYY-MM-DD). Empty for all.
        threshold: Minimum logins within the window to flag (default 10).
        window_seconds: Time window in seconds (default 60).
        top: Number of top users to show (default 20). Use 0 for all.
    """
    events = _kc().get_events_all("LOGIN", date_from=date_from or None, date_to=date_to or None)
    if not events:
        return "No LOGIN events found"

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
        return f"No login loops detected (threshold={threshold}, window={window_seconds}s)"

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
    return "\n".join(lines)


@mcp.tool()
def get_password_update_events(date_from: str = "", date_to: str = "", max_results: int = 100) -> str:
    """Get password update events.

    Args:
        date_from: Start date (YYYY-MM-DD).
        date_to: End date (YYYY-MM-DD). Empty for all.
        max_results: Maximum results (default 100).
    """
    events = _kc().get_events(
        "UPDATE_PASSWORD",
        date_from=date_from or None,
        date_to=date_to or None,
        max_results=max_results,
    )
    if not events:
        return "No password update events found"
    lines = [f"Password updates ({len(events)}):"]
    for e in events:
        details = e.get("details", {})
        lines.append(
            f"  {_format_ts(e.get('time', ''))}  {details.get('username', '')}  "
            f"ip={_label_ip(e.get('ipAddress', ''))}  client={e.get('clientId', '')}"
        )
    return "\n".join(lines)


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
    — e.g. custom user attribute updates (``temp_password``), role / group
    assignments, client configuration changes. These are distinct from user
    events (login / password change). Use this when ``UPDATE_PROFILE`` in
    ``get_events`` is empty but an attribute is known to have changed.

    Args:
        operation_types: Comma-separated list of CREATE, UPDATE, DELETE, ACTION.
        resource_types: Comma-separated list of USER, CLIENT, ROLE, GROUP, REALM_ROLE, etc.
        resource_path: Filter by resource path (e.g. "users/{userId}").
        date_from: Start date (YYYY-MM-DD).
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
        date_from=date_from or None,
        date_to=date_to or None,
        max_results=max_results,
    )
    if not events:
        return "No admin events found"
    lines = [f"Admin events ({len(events)}):"]
    for e in events:
        lines.append(_format_admin_event(e, max_repr=max_repr))
    return "\n".join(lines)


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
    ``temp_password`` which are written by admin API and do **not** surface in
    ``get_events`` (which only shows user-driven events like LOGIN /
    UPDATE_PASSWORD).

    Args:
        username: Exact username (email).
        date_from: Start date (YYYY-MM-DD).
        date_to: End date (YYYY-MM-DD).
        max_results: Maximum results (default 100).
        max_repr: Max chars of the representation field. 0 = omit, -1 = full.
    """
    user = _kc().get_user_by_username(username)
    if not user:
        return f"User '{username}' not found"
    user_id = user["id"]
    events = _kc().get_admin_events(
        operation_types=["UPDATE", "ACTION"],
        resource_types=["USER"],
        resource_path=f"users/{user_id}",
        date_from=date_from or None,
        date_to=date_to or None,
        max_results=max_results,
    )
    if not events:
        return f"No attribute change events for {username}"
    lines = [f"Attribute history for {username} ({len(events)}):"]
    for e in events:
        lines.append(_format_admin_event(e, max_repr=max_repr))
    return "\n".join(lines)


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


if __name__ == "__main__":
    mcp.run(transport="stdio")
