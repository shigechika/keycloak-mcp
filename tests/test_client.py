"""Tests for KeyCloakClient."""

import json

import httpx
import pytest

import keycloak_mcp.client as client_mod
from keycloak_mcp.client import KeyCloakClient, deadline_after, past_deadline

from .conftest import ADMIN_BASE, SAMPLE_USER, SAMPLE_USER_2


class TestDeadlineHelpers:
    def test_deadline_after_disabled_when_non_positive(self):
        assert deadline_after(None) is None
        assert deadline_after(0) is None
        assert deadline_after(-5) is None

    def test_deadline_after_is_monotonic_plus_seconds(self, monkeypatch):
        monkeypatch.setattr("keycloak_mcp.client.time.monotonic", lambda: 100.0)
        assert deadline_after(30.0) == 130.0

    def test_past_deadline(self, monkeypatch):
        monkeypatch.setattr("keycloak_mcp.client.time.monotonic", lambda: 200.0)
        assert past_deadline(None) is False  # disabled
        assert past_deadline(199.0) is True  # already passed
        assert past_deadline(201.0) is False  # still in the future


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


class TestListUsersAll:
    def test_enabled_only_param(self, mock_api):
        route = mock_api.get(f"{ADMIN_BASE}/users").mock(return_value=httpx.Response(200, json=[SAMPLE_USER]))
        result, truncated = KeyCloakClient().list_users_all(enabled_only=True, page_size=100)
        assert len(result) == 1
        assert truncated is False
        assert "enabled=true" in str(route.calls[0].request.url)

    def test_pagination(self, mock_api):
        page1 = [{"id": str(i)} for i in range(3)]
        page2 = [{"id": "99"}]
        mock_api.get(f"{ADMIN_BASE}/users").mock(
            side_effect=[
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
            ]
        )
        result, truncated = KeyCloakClient().list_users_all(page_size=3)
        assert len(result) == 4
        assert truncated is False  # fully drained (short final page)

    def test_limit_short_circuits_enumeration(self, mock_api):
        # A full page would normally trigger another request; the limit must stop
        # enumeration and trim the result without fetching the next page.
        route = mock_api.get(f"{ADMIN_BASE}/users").mock(
            return_value=httpx.Response(200, json=[{"id": str(i)} for i in range(3)])
        )
        result, truncated = KeyCloakClient().list_users_all(page_size=3, limit=2)
        assert len(result) == 2
        assert truncated is True  # capped, so more likely exist
        assert route.call_count == 1


class TestGetUserCredentials:
    def test_returns_credentials(self, mock_api):
        creds = [
            {"id": "c1", "type": "password", "createdDate": 1700000000000},
            {"id": "c2", "type": "otp", "userLabel": "phone", "createdDate": 1700000001000},
        ]
        mock_api.get(f"{ADMIN_BASE}/users/user-uuid-1/credentials").mock(return_value=httpx.Response(200, json=creds))
        result = KeyCloakClient().get_user_credentials("user-uuid-1")
        assert len(result) == 2
        assert result[1]["type"] == "otp"


class TestGetUserByUsername:
    def test_found(self, mock_api):
        mock_api.get(f"{ADMIN_BASE}/users").mock(return_value=httpx.Response(200, json=[SAMPLE_USER]))
        result = KeyCloakClient().get_user_by_username("alice@example.com")
        assert result is not None
        assert result["id"] == "user-uuid-1"

    def test_not_found(self, mock_api):
        mock_api.get(f"{ADMIN_BASE}/users").mock(return_value=httpx.Response(200, json=[]))
        assert KeyCloakClient().get_user_by_username("nobody") is None


class TestGetUserById:
    def test_returns_full_representation(self, mock_api):
        rep = {
            "id": "user-uuid-1",
            "username": "alice@example.com",
            "enabled": True,
            "attributes": {"custom_key": ["value1"]},
        }
        mock_api.get(f"{ADMIN_BASE}/users/user-uuid-1").mock(return_value=httpx.Response(200, json=rep))
        result = KeyCloakClient().get_user_by_id("user-uuid-1")
        assert result["attributes"] == {"custom_key": ["value1"]}

    def test_not_found_raises(self, mock_api, monkeypatch):
        monkeypatch.setattr("keycloak_mcp.client.time.sleep", lambda *_: None)
        route = mock_api.get(f"{ADMIN_BASE}/users/missing-uuid").mock(return_value=httpx.Response(404))
        with pytest.raises(httpx.HTTPStatusError):
            KeyCloakClient().get_user_by_id("missing-uuid")
        assert route.call_count == 1


class TestResetPassword:
    def test_success(self, mock_api):
        mock_api.put(f"{ADMIN_BASE}/users/user-uuid-1/reset-password").mock(return_value=httpx.Response(204))
        status = KeyCloakClient().reset_password("user-uuid-1", "newpass")
        assert status == 204


class TestSetUserEnabled:
    def test_disable_preserves_attributes(self, mock_api):
        rep = {
            "id": "user-uuid-1",
            "username": "alice@example.com",
            "enabled": True,
            "attributes": {"provisioning_flag": ["x"], "sso_ext": ["y"]},
        }
        mock_api.get(f"{ADMIN_BASE}/users/user-uuid-1").mock(return_value=httpx.Response(200, json=rep))
        put_route = mock_api.put(f"{ADMIN_BASE}/users/user-uuid-1").mock(return_value=httpx.Response(204))
        status = KeyCloakClient().set_user_enabled("user-uuid-1", False)
        assert status == 204
        sent = json.loads(put_route.calls.last.request.content)
        assert sent["enabled"] is False
        # Custom attributes must survive the toggle, not be dropped.
        assert sent["attributes"] == {"provisioning_flag": ["x"], "sso_ext": ["y"]}


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


class TestGetGroupByPath:
    def test_strips_leading_slash(self, mock_api):
        group = {"id": "g-staff", "name": "教職員", "path": "/教職員"}
        route = mock_api.get(f"{ADMIN_BASE}/group-by-path/教職員").mock(return_value=httpx.Response(200, json=group))
        result = KeyCloakClient().get_group_by_path("/教職員")
        assert result["id"] == "g-staff"
        # Leading slash must be stripped: no '/group-by-path//' in the URL, and
        # the (percent-encoded) group name follows 'group-by-path/'.
        url = str(route.calls[0].request.url)
        assert "group-by-path/" in url
        assert "group-by-path//" not in url
        assert "%E6%95%99%E8%81%B7%E5%93%A1" in url or "教職員" in url


class TestGetGroupChildrenAll:
    def test_pagination(self, mock_api):
        page1 = [{"id": str(i)} for i in range(3)]
        page2 = [{"id": "99"}]
        mock_api.get(f"{ADMIN_BASE}/groups/g-staff/children").mock(
            side_effect=[
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
            ]
        )
        result = KeyCloakClient().get_group_children_all("g-staff", page_size=3)
        assert len(result) == 4


class TestGetGroupMembersAll:
    def test_pagination(self, mock_api):
        page1 = [{"id": str(i)} for i in range(3)]
        page2 = [{"id": "99"}]
        mock_api.get(f"{ADMIN_BASE}/groups/g-staff/members").mock(
            side_effect=[
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
            ]
        )
        result = KeyCloakClient().get_group_members_all("g-staff", page_size=3)
        assert len(result) == 4


class TestRetry:
    def test_retries_transient_disconnect(self, mock_api, monkeypatch):
        monkeypatch.setattr("keycloak_mcp.client.time.sleep", lambda *_: None)
        route = mock_api.get(f"{ADMIN_BASE}/users/count").mock(
            side_effect=[
                httpx.RemoteProtocolError("Server disconnected without sending a response"),
                httpx.Response(200, json=7),
            ]
        )
        assert KeyCloakClient().count_users() == 7
        assert route.call_count == 2

    def test_retries_on_503(self, mock_api, monkeypatch):
        monkeypatch.setattr("keycloak_mcp.client.time.sleep", lambda *_: None)
        route = mock_api.get(f"{ADMIN_BASE}/users/count").mock(
            side_effect=[
                httpx.Response(503),
                httpx.Response(200, json=7),
            ]
        )
        assert KeyCloakClient().count_users() == 7
        assert route.call_count == 2

    def test_does_not_retry_404(self, mock_api, monkeypatch):
        monkeypatch.setattr("keycloak_mcp.client.time.sleep", lambda *_: None)
        route = mock_api.get(f"{ADMIN_BASE}/users/count").mock(return_value=httpx.Response(404))
        with pytest.raises(httpx.HTTPStatusError):
            KeyCloakClient().count_users()
        assert route.call_count == 1


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
        result, truncated = KeyCloakClient().get_events_all("LOGIN", page_size=1000)
        assert len(result) == 1
        assert truncated is False

    def test_pagination(self, mock_api):
        page1 = [{"type": "LOGIN", "time": i} for i in range(3)]
        page2 = [{"type": "LOGIN", "time": 99}]
        mock_api.get(f"{ADMIN_BASE}/events").mock(
            side_effect=[
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
            ]
        )
        result, truncated = KeyCloakClient().get_events_all("LOGIN", page_size=3)
        assert len(result) == 4
        assert truncated is False

    def test_max_events_caps_and_reports_truncated(self, mock_api):
        # A full page would normally trigger another request; max_events must stop
        # paging early, trim to the cap, and report truncated=True.
        route = mock_api.get(f"{ADMIN_BASE}/events").mock(
            return_value=httpx.Response(200, json=[{"type": "LOGIN", "time": i} for i in range(3)])
        )
        result, truncated = KeyCloakClient().get_events_all("LOGIN", page_size=3, max_events=2)
        assert len(result) == 2
        assert truncated is True
        assert route.call_count == 1  # did not fetch the next page

    def test_short_final_page_hitting_cap_exactly_is_not_truncated(self, mock_api):
        # A short final page that reaches exactly max_events means the endpoint is
        # drained — an exact-fit complete result, not a partial. Must report truncated=False.
        page1 = [{"type": "LOGIN", "time": i} for i in range(3)]  # full page
        page2 = [{"type": "LOGIN", "time": 99}]  # short page -> drained; total 4 == max_events
        mock_api.get(f"{ADMIN_BASE}/events").mock(
            side_effect=[httpx.Response(200, json=page1), httpx.Response(200, json=page2)]
        )
        result, truncated = KeyCloakClient().get_events_all("LOGIN", page_size=3, max_events=4)
        assert len(result) == 4
        assert truncated is False

    def test_short_final_page_overshooting_cap_is_truncated(self, mock_api):
        # A short page (drained) that OVERSHOOTS max_events — more items than the cap, so
        # real data is trimmed away — must report truncated=True, not a complete exact-fit.
        page = [{"type": "LOGIN", "time": i} for i in range(5)]  # short (5<100) but 5 > cap 3
        mock_api.get(f"{ADMIN_BASE}/events").mock(return_value=httpx.Response(200, json=page))
        result, truncated = KeyCloakClient().get_events_all("LOGIN", page_size=100, max_events=3)
        assert len(result) == 3  # trimmed
        assert truncated is True  # 2 items dropped -> incomplete

    def test_deadline_stops_paging_between_pages(self, mock_api, monkeypatch):
        # Full pages would page forever; a deadline already in the past on the 2nd
        # loop iteration must stop paging and report a disclosed partial.
        clock = iter([1000.0, 1000.0, 9999.0])  # deadline_after start, 1st check, 2nd check (past)
        monkeypatch.setattr("keycloak_mcp.client.time.monotonic", lambda: next(clock, 9999.0))
        # A single full page via side_effect (not return_value): if the deadline guard were
        # removed the loop would try to fetch a 2nd page and raise StopIteration — a fast, clean
        # failure instead of an infinite hang on an unbounded full-page source.
        route = mock_api.get(f"{ADMIN_BASE}/events").mock(
            side_effect=[httpx.Response(200, json=[{"type": "LOGIN", "time": i} for i in range(3)])]
        )
        deadline = client_mod.deadline_after(30.0)  # start=1000 -> deadline 1030
        result, truncated = KeyCloakClient().get_events_all("LOGIN", page_size=3, deadline=deadline)
        assert truncated is True
        assert route.call_count == 1  # 1st check (1000<1030) fetched one page; 2nd check (9999>1030) stopped
        assert len(result) == 3


class TestGetAdminEvents:
    def test_with_filters(self, mock_api):
        events = [
            {
                "time": 1700000000000,
                "operationType": "UPDATE",
                "resourceType": "USER",
                "resourcePath": "users/user-uuid-1",
                "authDetails": {"userId": "admin-uuid", "ipAddress": "10.0.0.1"},
                "representation": '{"attributes":{"provisioning_flag":["xxx"]}}',
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
        result, truncated = KeyCloakClient().get_admin_events_all(operation_types=["UPDATE"], page_size=3)
        assert len(result) == 4
        assert truncated is False


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
        route = mock_api.post(f"{ADMIN_BASE}/users/user-uuid-1/logout").mock(return_value=httpx.Response(204))
        status = KeyCloakClient().logout_user("user-uuid-1")
        assert status == 204
        assert route.called


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


class TestGetRealm:
    def test_returns_realm_representation(self, mock_api):
        realm = {"realm": "test-realm", "bruteForceProtected": True, "failureFactor": 30}
        # admin_base already points at the realm root, so the GET path is empty.
        mock_api.get(ADMIN_BASE).mock(return_value=httpx.Response(200, json=realm))
        result = KeyCloakClient().get_realm()
        assert result["realm"] == "test-realm"
        assert result["bruteForceProtected"] is True
