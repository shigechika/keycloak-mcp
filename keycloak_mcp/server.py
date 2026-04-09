"""MCP server exposing KeyCloak Admin operations via Service Account.

Uses Client Credentials Grant — no user password or TOTP required.
Infinispan-safe: does not create user sessions or use userinfo endpoint.
"""

import os
import secrets
import string
from collections import Counter

from mcp.server.fastmcp import FastMCP

from .client import KeyCloakClient

mcp = FastMCP("keycloak-mcp")
_client: KeyCloakClient | None = None


def _kc() -> KeyCloakClient:
    """Lazy-initialize the KeyCloak client."""
    global _client
    if _client is None:
        _client = KeyCloakClient()
    return _client


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
        f"Created: {u.get('createdTimestamp', '')}",
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
    If password column is empty, a random 12-char password is generated.

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
        password = parts[1].strip() if len(parts) > 1 and parts[1].strip() else _random_password()
        u = _kc().get_user_by_username(username)
        if not u:
            results.append(f"  NG  {username} — not found")
            continue
        try:
            _kc().reset_password(u["id"], password, temporary)
            results.append(f"  OK  {username} — {password}")
        except Exception as e:
            results.append(f"  NG  {username} — {e}")
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
        lines.append(
            f"  client={s.get('clients', {})}, started={s.get('start', '')}, "
            f"ip={s.get('ipAddress', '')}"
        )
    return "\n".join(lines)


# ---- Event tools ----


@mcp.tool()
def get_events(
    event_type: str = "",
    username: str = "",
    date_from: str = "",
    date_to: str = "",
    max_results: int = 50,
) -> str:
    """Get KeyCloak events with optional filters.

    Args:
        event_type: Event type filter (e.g., LOGIN, LOGIN_ERROR, UPDATE_PASSWORD, REGISTER).
        username: Filter by username.
        date_from: Start date (YYYY-MM-DD).
        date_to: End date (YYYY-MM-DD).
        max_results: Maximum results (default 50).
    """
    events = _kc().get_events(
        event_type=event_type or None,
        user=username or None,
        date_from=date_from or None,
        date_to=date_to or None,
        max_results=max_results,
    )
    if not events:
        return "No events found"
    lines = [f"Events ({len(events)}):"]
    for e in events:
        ts = e.get("time", 0)
        details = e.get("details", {})
        lines.append(
            f"  {ts}  {e['type']}  "
            f"user={details.get('username', e.get('userId', ''))}  "
            f"ip={e.get('ipAddress', '')}  "
            f"client={e.get('clientId', '')}"
        )
    return "\n".join(lines)


@mcp.tool()
def get_login_stats(date_from: str = "", date_to: str = "", max_results: int = 1000) -> str:
    """Get login success/failure statistics.

    Args:
        date_from: Start date (YYYY-MM-DD). Empty for today.
        date_to: End date (YYYY-MM-DD). Empty for today.
        max_results: Maximum events to scan (default 1000).
    """
    success = _kc().get_events("LOGIN", date_from=date_from or None, date_to=date_to or None, max_results=max_results)
    failure = _kc().get_events("LOGIN_ERROR", date_from=date_from or None, date_to=date_to or None, max_results=max_results)

    lines = [
        f"Login statistics:",
        f"  Success: {len(success)}",
        f"  Failure: {len(failure)}",
        f"  Total:   {len(success) + len(failure)}",
    ]

    if failure:
        # Top failing users
        fail_users = Counter(
            e.get("details", {}).get("username", "unknown") for e in failure
        )
        lines.append(f"\nTop failing users:")
        for user, count in fail_users.most_common(10):
            lines.append(f"  {count:5d}  {user}")

    return "\n".join(lines)


@mcp.tool()
def get_password_update_events(
    date_from: str = "", max_results: int = 100
) -> str:
    """Get password update events.

    Args:
        date_from: Start date (YYYY-MM-DD).
        max_results: Maximum results (default 100).
    """
    events = _kc().get_events(
        "UPDATE_PASSWORD",
        date_from=date_from or None,
        max_results=max_results,
    )
    if not events:
        return "No password update events found"
    lines = [f"Password updates ({len(events)}):"]
    for e in events:
        details = e.get("details", {})
        lines.append(
            f"  {e.get('time', '')}  {details.get('username', '')}  "
            f"ip={e.get('ipAddress', '')}  client={e.get('clientId', '')}"
        )
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
