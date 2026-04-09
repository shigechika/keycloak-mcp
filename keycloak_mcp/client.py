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

    # --- Users ---

    def count_users(self) -> int:
        """Return total user count."""
        return self._get("/users/count")

    def search_users(self, query: str, max_results: int = 20) -> list[dict]:
        """Search users by username, email, or name."""
        return self._get("/users", {"search": query, "max": max_results})

    def get_user(self, user_id: str) -> dict:
        """Get user by ID."""
        return self._get(f"/users/{user_id}")

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

    def get_user_roles(self, user_id: str) -> dict:
        """Get role mappings for a user."""
        return self._get(f"/users/{user_id}/role-mappings")

    # --- Events ---

    def get_events(
        self,
        event_type: str | None = None,
        user: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        max_results: int = 100,
    ) -> list[dict]:
        """Get events with optional filters."""
        params: dict[str, Any] = {"max": max_results}
        if event_type:
            params["type"] = event_type
        if user:
            params["user"] = user
        if date_from:
            params["dateFrom"] = date_from
        if date_to:
            params["dateTo"] = date_to
        return self._get("/events", params)

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

    # --- Roles ---

    def get_realm_roles(self) -> list[dict]:
        """List realm roles."""
        return self._get("/roles")
