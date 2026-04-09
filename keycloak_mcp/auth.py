"""Token management for KeyCloak Service Account (Client Credentials Grant)."""

import os
import time

import httpx


class TokenManager:
    """Manage KeyCloak access tokens with automatic refresh.

    Tokens are refreshed 30 seconds before expiry to avoid mid-request failures.
    """

    def __init__(self):
        self.url = os.environ["KEYCLOAK_URL"].rstrip("/")
        self.realm = os.environ.get("KEYCLOAK_REALM", "master")
        self.client_id = os.environ["KEYCLOAK_CLIENT_ID"]
        self.client_secret = os.environ["KEYCLOAK_CLIENT_SECRET"]
        self._token = None
        self._expires_at = 0

    @property
    def token_endpoint(self) -> str:
        """Return the OIDC token endpoint URL."""
        return f"{self.url}/realms/{self.realm}/protocol/openid-connect/token"

    @property
    def admin_base(self) -> str:
        """Return the Admin REST API base URL."""
        return f"{self.url}/admin/realms/{self.realm}"

    def get_token(self) -> str:
        """Return a valid access token, refreshing if needed."""
        if self._token and time.time() < self._expires_at - 30:
            return self._token
        return self._refresh()

    def _refresh(self) -> str:
        """Fetch a new token via Client Credentials Grant."""
        resp = httpx.post(
            self.token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._expires_at = time.time() + data.get("expires_in", 300)
        return self._token

    def headers(self) -> dict:
        """Return Authorization headers with a valid Bearer token."""
        return {"Authorization": f"Bearer {self.get_token()}"}
