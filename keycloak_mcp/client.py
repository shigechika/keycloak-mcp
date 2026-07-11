"""KeyCloak Admin REST API client."""

import time
from typing import Any

import httpx

from .auth import TokenManager

# HTTP status codes worth retrying: rate limiting and transient gateway/upstream
# failures. Everything else (400/401/403/404, …) is re-raised immediately.
_RETRYABLE_STATUS = {429, 502, 503, 504}
_MAX_ATTEMPTS = 5
_BACKOFF_BASE = 0.5


def deadline_after(seconds: float | None) -> float | None:
    """Absolute ``time.monotonic()`` deadline ``seconds`` from now, or ``None`` to disable.

    Centralizing the clock here lets one tool call compute a single wall-clock budget and
    share it across several paginations, and lets tests stub ``keycloak_mcp.client.time.monotonic``
    in exactly one place. A non-positive ``seconds`` returns ``None`` (deadline disabled).
    """
    if not seconds or seconds <= 0:
        return None
    return time.monotonic() + seconds


def past_deadline(deadline: float | None) -> bool:
    """True once ``deadline`` (an absolute monotonic timestamp) has passed; False if ``None``."""
    return deadline is not None and time.monotonic() >= deadline


class KeyCloakClient:
    """Thin wrapper around the KeyCloak Admin REST API."""

    def __init__(self):
        self.auth = TokenManager()
        self._http = httpx.Client(timeout=30)

    def _send(self, method: str, path: str, *, params: dict | None = None, json: dict | None = None) -> httpx.Response:
        """Send a request with retry on transient failures.

        Retries on ``httpx.TransportError`` (connection drops, timeouts,
        ``RemoteProtocolError`` from a server disconnecting mid-response, …) and
        on ``HTTPStatusError`` whose status is in :data:`_RETRYABLE_STATUS`
        (429/502/503/504). Other HTTP status errors are re-raised immediately.

        Token refresh (``self.auth.headers()`` → ``get_token()``) happens inside
        the retry loop, so a transient failure during token refresh is retried
        too; httpx auto-reconnects on the next request after a drop.

        Backoff is exponential: ``0.5 * 2**attempt`` seconds (0.5, 1, 2, 4).
        """
        url = f"{self.auth.admin_base}{path}"
        last_exc: Exception | None = None
        for attempt in range(_MAX_ATTEMPTS):
            try:
                resp = self._http.request(
                    method,
                    url,
                    headers=self.auth.headers(),
                    params=params or {},
                    json=json,
                )
                resp.raise_for_status()
                return resp
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in _RETRYABLE_STATUS:
                    raise
                last_exc = exc
            except httpx.TransportError as exc:
                last_exc = exc
            if attempt < _MAX_ATTEMPTS - 1:
                time.sleep(_BACKOFF_BASE * 2**attempt)
        assert last_exc is not None
        raise last_exc

    def _get(self, path: str, params: dict | None = None) -> Any:
        """GET request to Admin API."""
        return self._send("GET", path, params=params).json()

    def _put(self, path: str, json: dict | None = None) -> int:
        """PUT request to Admin API. Returns status code."""
        return self._send("PUT", path, json=json or {}).status_code

    def _delete(self, path: str) -> int:
        """DELETE request to Admin API. Returns status code."""
        return self._send("DELETE", path).status_code

    def _paginate(
        self,
        path: str,
        params: dict,
        page_size: int,
        max_total: int | None = None,
        deadline: float | None = None,
    ) -> tuple[list[dict], bool]:
        """Page through a GET list endpoint until a short page arrives.

        Assumes the endpoint returns a bare JSON array of items, which is the
        KeyCloak Admin API convention for list endpoints (``/events``,
        ``/admin-events``, ``/users``, …). Envelope-style responses like
        ``{"items": [...], "total": N}`` would need a separate helper.

        ``params`` is copied; this method sets ``max`` and ``first`` on the
        copy and leaves the caller's dict untouched.

        :param max_total: Stop once this many items are collected and return at
            most that many. ``None`` (default) does not cap on count.
        :param deadline: An absolute ``time.monotonic()`` timestamp (or ``None``).
            Checked between pages, so a wide date window can't page unbounded and
            keep hammering the server after the caller's tool-call gateway has
            already timed out — the caller gets a disclosed partial instead.
        :returns: ``(items, truncated)``. ``truncated`` is True when paging
            stopped early on ``max_total`` or ``deadline`` (more items likely
            exist); False when the endpoint was fully drained (a short page).
        """
        params = dict(params)
        params["max"] = page_size
        params["first"] = 0
        all_items: list[dict] = []
        while True:
            if past_deadline(deadline):
                return all_items, True
            page = self._get(path, params)
            all_items.extend(page)
            if max_total is not None and len(all_items) >= max_total:
                return all_items[:max_total], True
            if len(page) < page_size:
                return all_items, False
            params["first"] += page_size

    # --- Users ---

    def count_users(self) -> int:
        """Return total user count."""
        return self._get("/users/count")

    def search_users(self, query: str, max_results: int = 20) -> list[dict]:
        """Search users by username, email, or name."""
        return self._get("/users", {"search": query, "max": max_results})

    def list_users_all(
        self,
        enabled_only: bool = False,
        page_size: int = 100,
        limit: int | None = None,
        deadline: float | None = None,
    ) -> tuple[list[dict], bool]:
        """List every user in the realm with automatic pagination.

        :param enabled_only: When True, ask KeyCloak to return only enabled users.
        :param page_size: Users fetched per request.
        :param limit: Stop after collecting this many users (``None`` = all). The
            enumeration itself short-circuits, so a small limit does not page
            through the whole realm.
        :param deadline: Absolute ``time.monotonic()`` deadline (or ``None``); see
            :meth:`_paginate`.
        :returns: ``(users, truncated)`` — ``truncated`` True if capped by ``limit``
            or ``deadline`` before the realm was fully enumerated.
        """
        params: dict[str, Any] = {}
        if enabled_only:
            params["enabled"] = "true"
        return self._paginate("/users", params, page_size, max_total=limit, deadline=deadline)

    def get_user_credentials(self, user_id: str) -> list[dict]:
        """Get a user's configured credentials (password, otp, webauthn, …).

        Each entry has a ``type`` field; ``"otp"`` means TOTP/HOTP is configured.
        Read-only — does not create a user session.
        """
        return self._get(f"/users/{user_id}/credentials")

    def get_user_by_username(self, username: str) -> dict | None:
        """Get user by exact username. Returns None if not found."""
        users = self._get("/users", {"username": username, "exact": "true"})
        return users[0] if users else None

    def reset_password(self, user_id: str, password: str, temporary: bool = False) -> int:
        """Reset a user's password."""
        return self._put(
            f"/users/{user_id}/reset-password",
            {"type": "password", "value": password, "temporary": temporary},
        )

    def get_user_sessions(self, user_id: str) -> list[dict]:
        """Get active sessions for a user."""
        return self._get(f"/users/{user_id}/sessions")

    def logout_user(self, user_id: str) -> int:
        """Remove all sessions for a user (force logout)."""
        return self._delete(f"/users/{user_id}/sessions")

    def get_user_groups(self, user_id: str) -> list[dict]:
        """Get groups a user belongs to."""
        return self._get(f"/users/{user_id}/groups")

    # --- Brute Force ---

    def get_brute_force_status(self, user_id: str) -> dict:
        """Get brute force detection status for a user."""
        return self._get(f"/attack-detection/brute-force/users/{user_id}")

    # --- Groups ---

    def list_groups(self, max_results: int = 100) -> list[dict]:
        """List all groups."""
        return self._get("/groups", {"max": max_results})

    def get_group_by_path(self, path: str) -> dict:
        """Get a group by its path (e.g. ``"/教職員"``).

        A leading slash is accepted and stripped before building the URL, so
        both ``"/教職員"`` and ``"教職員"`` resolve the same group. Returns the
        group dict (``id``, ``name``, ``path``, possibly ``subGroups``).
        """
        return self._get(f"/group-by-path/{path.lstrip('/')}")

    def get_group_children(self, group_id: str, first: int = 0, max_results: int = 100) -> list[dict]:
        """Get the direct child (sub-)groups of a group (single page)."""
        return self._get(f"/groups/{group_id}/children", {"first": first, "max": max_results})

    def get_group_children_all(self, group_id: str, page_size: int = 100) -> list[dict]:
        """Get all child (sub-)groups of a group with automatic pagination."""
        return self._paginate(f"/groups/{group_id}/children", {}, page_size)[0]

    def get_group_members(self, group_id: str, first: int = 0, max_results: int = 100) -> list[dict]:
        """Get members of a group (single page)."""
        return self._get(f"/groups/{group_id}/members", {"first": first, "max": max_results})

    def get_group_members_all(self, group_id: str, page_size: int = 100) -> list[dict]:
        """Get all members of a group with automatic pagination."""
        return self._paginate(f"/groups/{group_id}/members", {}, page_size)[0]

    # --- Events ---

    def get_events(
        self,
        event_type: str | None = None,
        user: str | None = None,
        client_id: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        max_results: int = 100,
    ) -> list[dict]:
        """Get events with optional filters (single page)."""
        params: dict[str, Any] = {"max": max_results}
        if event_type:
            params["type"] = event_type
        if user:
            params["user"] = user
        if client_id:
            params["client"] = client_id
        if date_from:
            params["dateFrom"] = date_from
        if date_to:
            params["dateTo"] = date_to
        return self._get("/events", params)

    def get_events_all(
        self,
        event_type: str | None = None,
        user: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        page_size: int = 1000,
        max_events: int | None = None,
        deadline: float | None = None,
    ) -> tuple[list[dict], bool]:
        """Get all events with automatic pagination.

        :param max_events: Cap on events collected (``None`` = no count cap); also
            bounds how deep the offset (``first``) grows, since KeyCloak's offset
            pagination degrades badly at high offsets.
        :param deadline: Absolute ``time.monotonic()`` deadline (or ``None``); see
            :meth:`_paginate`.
        :returns: ``(events, truncated)`` — ``truncated`` True if the window was too
            wide and paging stopped on ``max_events``/``deadline``.
        """
        params: dict[str, Any] = {}
        if event_type:
            params["type"] = event_type
        if user:
            params["user"] = user
        if date_from:
            params["dateFrom"] = date_from
        if date_to:
            params["dateTo"] = date_to
        return self._paginate("/events", params, page_size, max_total=max_events, deadline=deadline)

    # --- Admin Events ---

    def get_admin_events(
        self,
        operation_types: list[str] | None = None,
        resource_types: list[str] | None = None,
        resource_path: str | None = None,
        auth_user: str | None = None,
        auth_ip: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        max_results: int = 100,
    ) -> list[dict]:
        """Get admin events (attribute / user profile / role changes by admins).

        Admin events are separate from user events. They record changes made via
        the Admin REST API, such as user attribute updates (e.g. custom
        ``temp_password``), role assignments, client config changes, etc.

        :param operation_types: Filter by operation (CREATE, UPDATE, DELETE, ACTION).
        :param resource_types: Filter by resource (USER, CLIENT, ROLE, GROUP, etc.).
        :param resource_path: Filter by resource path (e.g. ``users/{userId}``).
        :param auth_user: Filter by the admin user id who performed the operation.
        :param auth_ip: Filter by the IP of the admin performing the operation.
        :param date_from: Start date (YYYY-MM-DD).
        :param date_to: End date (YYYY-MM-DD).
        :param max_results: Maximum results per page.
        """
        params: dict[str, Any] = {"max": max_results}
        if operation_types:
            params["operationTypes"] = operation_types
        if resource_types:
            params["resourceTypes"] = resource_types
        if resource_path:
            params["resourcePath"] = resource_path
        if auth_user:
            params["authUser"] = auth_user
        if auth_ip:
            params["authIpAddress"] = auth_ip
        if date_from:
            params["dateFrom"] = date_from
        if date_to:
            params["dateTo"] = date_to
        return self._get("/admin-events", params)

    def get_admin_events_all(
        self,
        operation_types: list[str] | None = None,
        resource_types: list[str] | None = None,
        resource_path: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        page_size: int = 1000,
        max_events: int | None = None,
        deadline: float | None = None,
    ) -> tuple[list[dict], bool]:
        """Get all admin events with automatic pagination.

        :param max_events: Cap on events collected (``None`` = no count cap).
        :param deadline: Absolute ``time.monotonic()`` deadline (or ``None``); see
            :meth:`_paginate`.
        :returns: ``(events, truncated)`` — see :meth:`get_events_all`.
        """
        params: dict[str, Any] = {}
        if operation_types:
            params["operationTypes"] = operation_types
        if resource_types:
            params["resourceTypes"] = resource_types
        if resource_path:
            params["resourcePath"] = resource_path
        if date_from:
            params["dateFrom"] = date_from
        if date_to:
            params["dateTo"] = date_to
        return self._paginate("/admin-events", params, page_size, max_total=max_events, deadline=deadline)

    # --- Sessions ---

    def get_session_stats(self) -> list[dict]:
        """Get client session statistics."""
        return self._get("/client-session-stats")

    # --- Clients ---

    def list_clients(self, max_results: int = 100) -> list[dict]:
        """List all clients."""
        return self._get("/clients", {"max": max_results})

    def get_client(self, client_id: str) -> dict:
        """Get client by internal ID."""
        return self._get(f"/clients/{client_id}")

    def get_client_by_client_id(self, client_id: str) -> dict | None:
        """Get client by clientId (not internal UUID)."""
        clients = self._get("/clients", {"clientId": client_id})
        return clients[0] if clients else None

    def get_client_sessions(self, internal_id: str, max_results: int = 100) -> list[dict]:
        """Get active sessions for a client."""
        return self._get(f"/clients/{internal_id}/user-sessions", {"max": max_results})

    # --- Roles ---

    def get_realm_roles(self) -> list[dict]:
        """List realm roles."""
        return self._get("/roles")

    # --- Realm ---

    def get_realm(self) -> dict:
        """Get the realm representation (configuration).

        Read-only. The ``admin_base`` URL already points at the realm root
        (``/admin/realms/{realm}``), so an empty path GETs the realm itself.
        The returned ``RealmRepresentation`` carries the security-defense
        settings: brute-force fields (``bruteForceProtected``,
        ``failureFactor``, …), ``passwordPolicy``, and
        ``browserSecurityHeaders``.
        """
        return self._get("")
