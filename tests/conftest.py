"""Shared fixtures for keycloak-mcp tests."""

import os

import httpx
import pytest
import respx

# Ensure environment variables are set for TokenManager
os.environ.setdefault("KEYCLOAK_URL", "https://sso.example.com")
os.environ.setdefault("KEYCLOAK_REALM", "test-realm")
os.environ.setdefault("KEYCLOAK_CLIENT_ID", "test-client")
os.environ.setdefault("KEYCLOAK_CLIENT_SECRET", "test-secret")

TOKEN_ENDPOINT = "https://sso.example.com/realms/test-realm/protocol/openid-connect/token"
ADMIN_BASE = "https://sso.example.com/admin/realms/test-realm"


@pytest.fixture()
def mock_api():
    """Provide a respx mock router with token endpoint pre-configured."""
    with respx.mock(assert_all_called=False) as router:
        router.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "fake-token", "expires_in": 300},
            )
        )
        yield router


SAMPLE_USER = {
    "id": "user-uuid-1",
    "username": "alice@example.com",
    "firstName": "Alice",
    "lastName": "Test",
    "email": "alice@example.com",
    "enabled": True,
    "createdTimestamp": 1700000000000,
}

SAMPLE_USER_2 = {
    "id": "user-uuid-2",
    "username": "bob@example.com",
    "firstName": "Bob",
    "lastName": "Test",
    "email": "bob@example.com",
    "enabled": True,
    "createdTimestamp": 1700000001000,
}
