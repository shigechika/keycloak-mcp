"""Tests for KeyCloakClient."""

import httpx

from keycloak_mcp.client import KeyCloakClient

from .conftest import ADMIN_BASE, SAMPLE_USER, SAMPLE_USER_2


class TestCountUsers:
    def test_returns_count(self, mock_api):
        mock_api.get(f"{ADMIN_BASE}/users/count").mock(return_value=httpx.Response(200, json=42))
        assert KeyCloakClient().count_users() == 42


class TestSearchUsers:
    def test_returns_list(self, mock_api):
        mock_api.get(f"{ADMIN_BASE}/users").mock(return_value=httpx.Response(200, json=[SAMPLE_USER]))
        result = KeyCloakClient().search_users("alice")
        assert len(result) == 1
        assert result[0]["username"] == "alice@example.com"


class TestGetUserByUsername:
    def test_found(self, mock_api):
        mock_api.get(f"{ADMIN_BASE}/users").mock(return_value=httpx.Response(200, json=[SAMPLE_USER]))
        result = KeyCloakClient().get_user_by_username("alice@example.com")
        assert result is not None
        assert result["id"] == "user-uuid-1"

    def test_not_found(self, mock_api):
        mock_api.get(f"{ADMIN_BASE}/users").mock(return_value=httpx.Response(200, json=[]))
        assert KeyCloakClient().get_user_by_username("nobody") is None


class TestResetPassword:
    def test_success(self, mock_api):
        mock_api.put(f"{ADMIN_BASE}/users/user-uuid-1/reset-password").mock(return_value=httpx.Response(204))
        status = KeyCloakClient().reset_password("user-uuid-1", "newpass")
        assert status == 204


class TestGetUserGroups:
    def test_returns_groups(self, mock_api):
        groups = [{"id": "g1", "name": "vpn-admin", "path": "/vpn-admin"}]
        mock_api.get(f"{ADMIN_BASE}/users/user-uuid-1/groups").mock(return_value=httpx.Response(200, json=groups))
        result = KeyCloakClient().get_user_groups("user-uuid-1")
        assert len(result) == 1
        assert result[0]["name"] == "vpn-admin"


class TestBruteForce:
    def test_returns_status(self, mock_api):
        status = {"numFailures": 5, "disabled": True, "lastFailure": 1700000000000, "lastIPFailure": "10.0.0.1"}
        mock_api.get(f"{ADMIN_BASE}/attack-detection/brute-force/users/user-uuid-1").mock(
            return_value=httpx.Response(200, json=status)
        )
        result = KeyCloakClient().get_brute_force_status("user-uuid-1")
        assert result["numFailures"] == 5
        assert result["disabled"] is True


class TestListGroups:
    def test_returns_groups(self, mock_api):
        groups = [{"id": "g1", "name": "admins"}, {"id": "g2", "name": "users"}]
        mock_api.get(f"{ADMIN_BASE}/groups").mock(return_value=httpx.Response(200, json=groups))
        result = KeyCloakClient().list_groups()
        assert len(result) == 2


class TestGetGroupMembers:
    def test_returns_members(self, mock_api):
        mock_api.get(f"{ADMIN_BASE}/groups/g1/members").mock(
            return_value=httpx.Response(200, json=[SAMPLE_USER, SAMPLE_USER_2])
        )
        result = KeyCloakClient().get_group_members("g1")
        assert len(result) == 2


class TestGetEvents:
    def test_with_filters(self, mock_api):
        events = [{"type": "LOGIN", "time": 1700000000000, "ipAddress": "10.0.0.1", "clientId": "app"}]
        mock_api.get(f"{ADMIN_BASE}/events").mock(return_value=httpx.Response(200, json=events))
        result = KeyCloakClient().get_events(event_type="LOGIN", date_from="2024-01-01")
        assert len(result) == 1
        assert result[0]["type"] == "LOGIN"


class TestGetEventsAll:
    def test_single_page(self, mock_api):
        events = [{"type": "LOGIN", "time": 1700000000000}]
        mock_api.get(f"{ADMIN_BASE}/events").mock(return_value=httpx.Response(200, json=events))
        result = KeyCloakClient().get_events_all("LOGIN", page_size=1000)
        assert len(result) == 1

    def test_pagination(self, mock_api):
        page1 = [{"type": "LOGIN", "time": i} for i in range(3)]
        page2 = [{"type": "LOGIN", "time": 99}]
        mock_api.get(f"{ADMIN_BASE}/events").mock(
            side_effect=[
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
            ]
        )
        result = KeyCloakClient().get_events_all("LOGIN", page_size=3)
        assert len(result) == 4


class TestGetAdminEvents:
    def test_with_filters(self, mock_api):
        events = [
            {
                "time": 1700000000000,
                "operationType": "UPDATE",
                "resourceType": "USER",
                "resourcePath": "users/user-uuid-1",
                "authDetails": {"userId": "admin-uuid", "ipAddress": "10.0.0.1"},
                "representation": '{"attributes":{"temp_password":["xxx"]}}',
            }
        ]
        route = mock_api.get(f"{ADMIN_BASE}/admin-events").mock(return_value=httpx.Response(200, json=events))
        result = KeyCloakClient().get_admin_events(
            operation_types=["UPDATE"],
            resource_types=["USER"],
            resource_path="users/user-uuid-1",
            date_from="2024-01-01",
        )
        assert len(result) == 1
        assert result[0]["operationType"] == "UPDATE"
        url = str(route.calls[0].request.url)
        assert "operationTypes=UPDATE" in url
        assert "resourceTypes=USER" in url
        assert "users%2Fuser-uuid-1" in url or "users/user-uuid-1" in url

    def test_empty(self, mock_api):
        mock_api.get(f"{ADMIN_BASE}/admin-events").mock(return_value=httpx.Response(200, json=[]))
        result = KeyCloakClient().get_admin_events()
        assert result == []


class TestGetAdminEventsAll:
    def test_pagination(self, mock_api):
        page1 = [{"time": i, "operationType": "UPDATE"} for i in range(3)]
        page2 = [{"time": 99, "operationType": "UPDATE"}]
        mock_api.get(f"{ADMIN_BASE}/admin-events").mock(
            side_effect=[
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
            ]
        )
        result = KeyCloakClient().get_admin_events_all(operation_types=["UPDATE"], page_size=3)
        assert len(result) == 4


class TestGetClientByClientId:
    def test_found(self, mock_api):
        client = {"id": "internal-uuid", "clientId": "xflow", "protocol": "saml"}
        mock_api.get(f"{ADMIN_BASE}/clients").mock(return_value=httpx.Response(200, json=[client]))
        result = KeyCloakClient().get_client_by_client_id("xflow")
        assert result is not None
        assert result["id"] == "internal-uuid"

    def test_not_found(self, mock_api):
        mock_api.get(f"{ADMIN_BASE}/clients").mock(return_value=httpx.Response(200, json=[]))
        assert KeyCloakClient().get_client_by_client_id("nonexistent") is None


class TestGetClientSessions:
    def test_returns_sessions(self, mock_api):
        sessions = [{"username": "alice@example.com", "ipAddress": "10.0.0.1", "start": 1700000}]
        mock_api.get(f"{ADMIN_BASE}/clients/internal-uuid/user-sessions").mock(
            return_value=httpx.Response(200, json=sessions)
        )
        result = KeyCloakClient().get_client_sessions("internal-uuid")
        assert len(result) == 1


class TestGetSessionStats:
    def test_returns_stats(self, mock_api):
        stats = [{"clientId": "xflow", "active": 5}, {"clientId": "zabbix", "active": 2}]
        mock_api.get(f"{ADMIN_BASE}/client-session-stats").mock(return_value=httpx.Response(200, json=stats))
        result = KeyCloakClient().get_session_stats()
        assert len(result) == 2


class TestListClients:
    def test_returns_clients(self, mock_api):
        clients = [{"clientId": "xflow", "protocol": "saml", "enabled": True}]
        mock_api.get(f"{ADMIN_BASE}/clients").mock(return_value=httpx.Response(200, json=clients))
        result = KeyCloakClient().list_clients()
        assert len(result) == 1


class TestLogoutUser:
    def test_success(self, mock_api):
        mock_api.delete(f"{ADMIN_BASE}/users/user-uuid-1/sessions").mock(return_value=httpx.Response(204))
        status = KeyCloakClient().logout_user("user-uuid-1")
        assert status == 204


class TestGetEventsWithClientId:
    def test_client_id_param(self, mock_api):
        events = [{"type": "LOGIN", "time": 1700000000000, "clientId": "xflow"}]
        route = mock_api.get(f"{ADMIN_BASE}/events").mock(return_value=httpx.Response(200, json=events))
        result = KeyCloakClient().get_events(event_type="LOGIN", client_id="xflow")
        assert len(result) == 1
        # Verify client param was sent
        assert "client" in str(route.calls[0].request.url)


class TestGetRealmRoles:
    def test_returns_roles(self, mock_api):
        roles = [{"name": "admin", "description": "Admin role"}]
        mock_api.get(f"{ADMIN_BASE}/roles").mock(return_value=httpx.Response(200, json=roles))
        result = KeyCloakClient().get_realm_roles()
        assert len(result) == 1
