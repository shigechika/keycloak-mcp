"""KeyCloak Admin REST API client."""

from typing import Any

import httpx

from .auth import TokenManager


class KeyCloakClient:
    """Thin wrapper around the KeyCloak Admin REST API."""

    def __init__(self):
        self.auth = TokenManager()
        self._http = httpx.Client(timeout=30)

    def _get(self, path: str, params: dict | None = None) -> Any:
        """GET request to Admin API."""
        url = f"{self.auth.admin_base}{path}"
        resp = self._http.get(url, headers=self.auth.headers(), params=params or {})
        resp.raise_for_status()
        return resp.json()

    def _put(self, path: str, json: dict | None = None) -> int:
        """PUT request to Admin API. Returns status code."""
        url = f"{self.auth.admin_base}{path}"
        resp = self._http.put(url, headers=self.auth.headers(), json=json or {})
        resp.raise_for_status()
        return resp.status_code

    def _delete(self, path: str) -> int:
        """DELETE request to Admin API. Returns status code."""
        url = f"{self.auth.admin_base}{path}"
        resp = self._http.delete(url, headers=self.auth.headers())
        resp.raise_for_status()
        return resp.status_code

    # --- Users ---

    def count_users(self) -> int:
        """Return total user count."""
        return self._get("/users/count")

    def search_users(self, query: str, max_results: int = 20) -> list[dict]:
        """Search users by username, email, or name."""
        return self._get("/users", {"search": query, "max": max_results})

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

    def get_group_members(self, group_id: str, max_results: int = 100) -> list[dict]:
        """Get members of a group."""
        return self._get(f"/groups/{group_id}/members", {"max": max_results})

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
    ) -> list[dict]:
        """Get all events with automatic pagination."""
        params: dict[str, Any] = {"max": page_size, "first": 0}
        if event_type:
            params["type"] = event_type
        if user:
            params["user"] = user
        if date_from:
            params["dateFrom"] = date_from
        if date_to:
            params["dateTo"] = date_to
        all_events: list[dict] = []
        while True:
            page = self._get("/events", params)
            all_events.extend(page)
            if len(page) < page_size:
                break
            params["first"] += page_size
        return all_events

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
    ) -> list[dict]:
        """Get all admin events with automatic pagination."""
        params: dict[str, Any] = {"max": page_size, "first": 0}
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
        all_events: list[dict] = []
        while True:
            page = self._get("/admin-events", params)
            all_events.extend(page)
            if len(page) < page_size:
                break
            params["first"] += page_size
        return all_events

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
