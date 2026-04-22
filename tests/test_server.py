"""Tests for MCP server tools."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from keycloak_mcp import server


def _mock_kc():
    """Create a mock KeyCloakClient."""
    return MagicMock()


SAMPLE_USER = {
    "id": "user-uuid-1",
    "username": "alice@example.com",
    "firstName": "Alice",
    "lastName": "Test",
    "email": "alice@example.com",
    "enabled": True,
    "createdTimestamp": 1700000000000,
}


class TestFormatTs:
    def test_valid_epoch_ms(self):
        result = server._format_ts(1700000000000)
        assert "2023-11-1" in result  # Nov 14 or 15 depending on TZ

    def test_invalid_value(self):
        assert server._format_ts("invalid") == "invalid"

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Windows raises OSError on datetime.fromtimestamp(0); _format_ts falls back to str(0)",
    )
    def test_zero(self):
        result = server._format_ts(0)
        assert "1970" in result or "1969" in result  # depends on TZ


class TestCountUsers:
    @patch.object(server, "_kc")
    def test_output(self, mock):
        mock.return_value.count_users.return_value = 150
        result = server.count_users()
        assert "150" in result


class TestSearchUsers:
    @patch.object(server, "_kc")
    def test_found(self, mock):
        mock.return_value.search_users.return_value = [SAMPLE_USER]
        result = server.search_users("alice")
        assert "alice@example.com" in result
        assert "1 user(s)" in result

    @patch.object(server, "_kc")
    def test_not_found(self, mock):
        mock.return_value.search_users.return_value = []
        result = server.search_users("nobody")
        assert "No users found" in result


class TestGetUser:
    @patch.object(server, "_kc")
    def test_found(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        result = server.get_user("alice@example.com")
        assert "alice@example.com" in result
        assert "Alice" in result

    @patch.object(server, "_kc")
    def test_not_found(self, mock):
        mock.return_value.get_user_by_username.return_value = None
        result = server.get_user("nobody")
        assert "not found" in result


class TestResetPassword:
    @patch.object(server, "_kc")
    def test_success(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        result = server.reset_password("alice@example.com", "newpass")
        assert "Password reset" in result

    @patch.object(server, "_kc")
    def test_user_not_found(self, mock):
        mock.return_value.get_user_by_username.return_value = None
        result = server.reset_password("nobody", "pass")
        assert "not found" in result


class TestResetPasswordsBatch:
    @patch.object(server, "_kc")
    def test_mixed_results(self, mock):
        mock.return_value.get_user_by_username.side_effect = [SAMPLE_USER, None]
        csv = "alice@example.com,pass123\nnobody@example.com,pass456"
        result = server.reset_passwords_batch(csv)
        assert "OK" in result
        assert "NG" in result
        assert "2 users" in result

    @patch.object(server, "_kc")
    def test_skip_header(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        csv = "username,password\nalice@example.com,pass123"
        result = server.reset_passwords_batch(csv)
        assert "1 users" in result

    @patch.object(server, "_kc")
    def test_supplied_password_not_echoed(self, mock):
        """Caller-provided passwords must not appear in the response."""
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        secret = "s3cret-do-not-leak"
        result = server.reset_passwords_batch(f"alice@example.com,{secret}")
        assert secret not in result
        assert "OK" in result

    @patch.object(server, "_kc")
    def test_generated_password_is_returned(self, mock):
        """Auto-generated passwords are returned verbatim so the caller can distribute them."""
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        result = server.reset_passwords_batch("alice@example.com,")
        # The actual generated password passed to reset_password must appear in
        # the response — otherwise the caller has no way to recover it.
        generated = mock.return_value.reset_password.call_args.args[1]
        assert f"reset (generated: {generated})" in result

    @patch.object(server, "_kc")
    def test_supplied_is_labeled(self, mock):
        """Supplied-password rows are explicitly labeled so callers can't confuse them with generated ones."""
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        result = server.reset_passwords_batch("alice@example.com,mypass")
        assert "reset (supplied)" in result
        assert "generated" not in result

    @patch.object(server, "_kc")
    def test_exception_message_is_sanitized(self, mock, capsys):
        """httpx-style exception details must not reach the response."""
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        leak = "https://internal-sso.example.corp/admin/realms/foo"
        mock.return_value.reset_password.side_effect = RuntimeError(f"Connection failed: {leak}")
        result = server.reset_passwords_batch("alice@example.com,pw")
        assert leak not in result
        assert "RuntimeError" in result
        # Detailed error is logged to stderr for operators.
        assert leak in capsys.readouterr().err

    @patch.object(server, "_kc")
    def test_http_status_code_is_surfaced(self, mock):
        """If the underlying error carries an HTTP status, include it so callers can tell
        auth failures apart from network ones — but still no body or URL."""

        class FakeHTTPError(Exception):
            def __init__(self, status):
                super().__init__("boom")
                self.response = type("R", (), {"status_code": status})()

        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.reset_password.side_effect = FakeHTTPError(403)
        result = server.reset_passwords_batch("alice@example.com,pw")
        assert "FakeHTTPError 403" in result
        assert "boom" not in result


class TestGetBruteForceStatus:
    @patch.object(server, "_kc")
    def test_locked(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_brute_force_status.return_value = {
            "numFailures": 5,
            "disabled": True,
            "lastFailure": 1700000000000,
            "lastIPFailure": "10.0.0.1",
        }
        result = server.get_brute_force_status("alice@example.com")
        assert "Failures: 5" in result
        assert "Disabled: True" in result

    @patch.object(server, "_kc")
    def test_no_events(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_brute_force_status.return_value = {"numFailures": 0}
        result = server.get_brute_force_status("alice@example.com")
        assert "no brute force" in result


class TestListUserGroups:
    @patch.object(server, "_kc")
    def test_has_groups(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_user_groups.return_value = [{"name": "vpn-admin", "path": "/vpn-admin"}]
        result = server.list_user_groups("alice@example.com")
        assert "vpn-admin" in result

    @patch.object(server, "_kc")
    def test_no_groups(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_user_groups.return_value = []
        result = server.list_user_groups("alice@example.com")
        assert "no groups" in result


class TestListUsersByGroup:
    @patch.object(server, "_kc")
    def test_found(self, mock):
        mock.return_value.list_groups.return_value = [{"id": "g1", "name": "vpn-admin"}]
        mock.return_value.get_group_members.return_value = [SAMPLE_USER]
        result = server.list_users_by_group("vpn")
        assert "alice@example.com" in result

    @patch.object(server, "_kc")
    def test_no_match(self, mock):
        mock.return_value.list_groups.return_value = [{"id": "g1", "name": "admins"}]
        result = server.list_users_by_group("vpn")
        assert "No group matching" in result


class TestGetLoginStats:
    @patch.object(server, "_fetch_login_events")
    def test_stats(self, mock):
        success = [{"type": "LOGIN"}] * 10
        failure = [{"type": "LOGIN_ERROR", "details": {"username": "alice"}}] * 3
        mock.return_value = (success, failure)
        result = server.get_login_stats()
        assert "Success: 10" in result
        assert "Failure: 3" in result
        assert "Total:   13" in result


class TestGetLoginStatsByHour:
    @patch.object(server, "_fetch_login_events")
    def test_by_hour(self, mock):
        # Use a timestamp that maps to hour 10 in most timezones
        success = [{"type": "LOGIN", "time": 1700035200000}]  # 2023-11-15 10:00 UTC
        mock.return_value = (success, [])
        result = server.get_login_stats_by_hour()
        assert "Login statistics by hour" in result
        assert "Total" in result


class TestGetLoginFailuresByIp:
    @patch.object(server, "_kc")
    def test_by_ip(self, mock):
        failures = [
            {"type": "LOGIN_ERROR", "ipAddress": "10.0.0.1", "time": 1700000000000},
            {"type": "LOGIN_ERROR", "ipAddress": "10.0.0.1", "time": 1700000001000},
            {"type": "LOGIN_ERROR", "ipAddress": "10.0.0.2", "time": 1700000002000},
        ]
        mock.return_value.get_events_all.return_value = failures
        result = server.get_login_failures_by_ip()
        assert "3 total" in result
        assert "2 unique IPs" in result
        assert "10.0.0.1" in result


class TestGetLoginStatsByClient:
    @patch.object(server, "_fetch_login_events")
    def test_by_client(self, mock):
        success = [{"clientId": "xflow"}, {"clientId": "xflow"}, {"clientId": "zabbix"}]
        failure = [{"clientId": "xflow"}]
        mock.return_value = (success, failure)
        result = server.get_login_stats_by_client()
        assert "xflow" in result
        assert "zabbix" in result


class TestGetClientSessions:
    @patch.object(server, "_kc")
    def test_found(self, mock):
        mock.return_value.get_client_by_client_id.return_value = {"id": "uuid", "clientId": "xflow"}
        mock.return_value.get_client_sessions.return_value = [
            {"username": "alice@example.com", "ipAddress": "10.0.0.1", "start": 1700000}
        ]
        result = server.get_client_sessions("xflow")
        assert "alice@example.com" in result
        assert "1" in result

    @patch.object(server, "_kc")
    def test_client_not_found(self, mock):
        mock.return_value.get_client_by_client_id.return_value = None
        result = server.get_client_sessions("nonexistent")
        assert "not found" in result


class TestGetSessionStats:
    @patch.object(server, "_kc")
    def test_with_sessions(self, mock):
        mock.return_value.get_session_stats.return_value = [
            {"clientId": "xflow", "active": 5},
            {"clientId": "zabbix", "active": 2},
        ]
        result = server.get_session_stats()
        assert "7 total" in result
        assert "xflow" in result

    @patch.object(server, "_kc")
    def test_no_sessions(self, mock):
        mock.return_value.get_session_stats.return_value = []
        result = server.get_session_stats()
        assert "No active sessions" in result


class TestGetPasswordUpdateEvents:
    @patch.object(server, "_kc")
    def test_found(self, mock):
        mock.return_value.get_events.return_value = [
            {"time": 1700000000000, "details": {"username": "alice"}, "ipAddress": "10.0.0.1", "clientId": "app"}
        ]
        result = server.get_password_update_events()
        assert "Password updates (1)" in result
        assert "alice" in result

    @patch.object(server, "_kc")
    def test_empty(self, mock):
        mock.return_value.get_events.return_value = []
        result = server.get_password_update_events()
        assert "No password update events" in result


class TestListClients:
    @patch.object(server, "_kc")
    def test_output(self, mock):
        mock.return_value.list_clients.return_value = [{"clientId": "xflow", "protocol": "saml", "enabled": True}]
        result = server.list_clients()
        assert "xflow" in result
        assert "saml" in result


class TestGetRealmRoles:
    @patch.object(server, "_kc")
    def test_output(self, mock):
        mock.return_value.get_realm_roles.return_value = [{"name": "admin", "description": "Admin role"}]
        result = server.get_realm_roles()
        assert "admin" in result


class TestLogoutUser:
    @patch.object(server, "_kc")
    def test_success(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_user_sessions.return_value = [
            {"clients": {"c1": "xflow"}, "start": 1700000, "ipAddress": "10.0.0.1"}
        ]
        mock.return_value.logout_user.return_value = 204
        result = server.logout_user("alice@example.com")
        assert "Logged out" in result
        assert "1 session(s)" in result

    @patch.object(server, "_kc")
    def test_no_sessions(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_user_sessions.return_value = []
        result = server.logout_user("alice@example.com")
        assert "nothing to do" in result

    @patch.object(server, "_kc")
    def test_user_not_found(self, mock):
        mock.return_value.get_user_by_username.return_value = None
        result = server.logout_user("nobody")
        assert "not found" in result


class TestDetectLoginLoops:
    @patch.object(server, "_kc")
    def test_detects_loop(self, mock):
        # Simulate 20 logins in 10 seconds for one user
        base_ts = 1700000000000
        events = [
            {
                "type": "LOGIN",
                "time": base_ts + i * 500,
                "details": {"username": "looper@example.com"},
                "ipAddress": "10.0.0.1",
                "clientId": "app",
            }
            for i in range(20)
        ]
        mock.return_value.get_events_all.return_value = events
        result = server.detect_login_loops(threshold=10, window_seconds=60)
        assert "1 user(s)" in result
        assert "looper@example.com" in result

    @patch.object(server, "_kc")
    def test_no_loop(self, mock):
        # 5 logins spread out — below threshold
        events = [
            {
                "type": "LOGIN",
                "time": 1700000000000 + i * 60000,
                "details": {"username": "normal@example.com"},
                "ipAddress": "10.0.0.1",
                "clientId": "app",
            }
            for i in range(5)
        ]
        mock.return_value.get_events_all.return_value = events
        result = server.detect_login_loops(threshold=10, window_seconds=60)
        assert "No login loops" in result

    @patch.object(server, "_kc")
    def test_top_limit(self, mock):
        base_ts = 1700000000000
        events = []
        # 3 users with loops
        for u in range(3):
            for i in range(15):
                events.append(
                    {
                        "type": "LOGIN",
                        "time": base_ts + i * 500,
                        "details": {"username": f"user{u}@example.com"},
                        "ipAddress": "10.0.0.1",
                        "clientId": "app",
                    }
                )
        mock.return_value.get_events_all.return_value = events
        result = server.detect_login_loops(threshold=10, window_seconds=60, top=2)
        assert "3 user(s)" in result
        assert "showing top 2" in result

    @patch.object(server, "_kc")
    def test_empty_events(self, mock):
        mock.return_value.get_events_all.return_value = []
        result = server.detect_login_loops()
        assert "No LOGIN events" in result


class TestGetEventsUsernameFilter:
    @patch.object(server, "_kc")
    def test_resolves_username_to_id(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_events.return_value = [
            {
                "type": "LOGIN",
                "time": 1700000000000,
                "details": {"username": "alice@example.com"},
                "ipAddress": "10.0.0.1",
                "clientId": "app",
            }
        ]
        server.get_events(event_type="LOGIN", username="alice@example.com")
        # Verify get_events was called with user ID, not username
        mock.return_value.get_events.assert_called_once()
        call_kwargs = mock.return_value.get_events.call_args
        assert call_kwargs[1].get("user") == "user-uuid-1" or call_kwargs.kwargs.get("user") == "user-uuid-1"

    @patch.object(server, "_kc")
    def test_username_not_found(self, mock):
        mock.return_value.get_user_by_username.return_value = None
        result = server.get_events(username="nobody")
        assert "not found" in result


class TestGetEventsIpFilter:
    @patch.object(server, "_kc")
    def test_filters_by_ip(self, mock):
        mock.return_value.get_events.return_value = [
            {
                "type": "LOGIN",
                "time": 1700000000000,
                "details": {"username": "alice"},
                "ipAddress": "10.0.0.1",
                "clientId": "app",
            },
            {
                "type": "LOGIN",
                "time": 1700000001000,
                "details": {"username": "bob"},
                "ipAddress": "10.0.0.2",
                "clientId": "app",
            },
        ]
        result = server.get_events(ip_address="10.0.0.1")
        assert "alice" in result
        assert "bob" not in result


class TestGetUserSessionsFormatted:
    @patch.object(server, "_kc")
    def test_formatted_output(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_user_sessions.return_value = [
            {"clients": {"c1": "xflow", "c2": "zabbix"}, "start": 1700000, "ipAddress": "10.0.0.1"}
        ]
        result = server.get_user_sessions("alice@example.com")
        assert "xflow" in result
        assert "zabbix" in result
        # Should show formatted timestamp, not raw epoch
        assert "1700000000" not in result


class TestLabelIp:
    @patch.object(server, "_site_classifier")
    def test_with_site(self, mock_sc):
        mock_sc.return_value.available = True
        mock_sc.return_value.classify.return_value = "Faculty of Law"
        result = server._label_ip("10.0.1.5")
        assert "Faculty of Law" in result

    @patch.object(server, "_site_classifier")
    def test_external(self, mock_sc):
        mock_sc.return_value.available = True
        mock_sc.return_value.classify.return_value = None
        result = server._label_ip("8.8.8.8")
        assert "external" in result

    @patch.object(server, "_site_classifier")
    def test_no_classifier(self, mock_sc):
        mock_sc.return_value.available = False
        result = server._label_ip("10.0.1.5")
        assert result == "10.0.1.5"


SAMPLE_ADMIN_EVENT = {
    "time": 1700000000000,
    "operationType": "UPDATE",
    "resourceType": "USER",
    "resourcePath": "users/user-uuid-1",
    "authDetails": {
        "realmId": "nu-sso",
        "clientId": "admin-client",
        "userId": "admin-uuid",
        "ipAddress": "10.0.0.1",
    },
    "representation": '{"attributes":{"temp_password":["xxx"]}}',
}


class TestGetAdminEvents:
    @patch.object(server, "_kc")
    def test_returns_events(self, mock):
        mock.return_value.get_admin_events.return_value = [SAMPLE_ADMIN_EVENT]
        result = server.get_admin_events(operation_types="UPDATE", resource_types="USER")
        assert "Admin events (1)" in result
        assert "UPDATE" in result
        assert "path=users/user-uuid-1" in result
        assert "admin=admin-uuid" in result
        # Verify comma-separated parsing
        call = mock.return_value.get_admin_events.call_args
        assert call.kwargs["operation_types"] == ["UPDATE"]
        assert call.kwargs["resource_types"] == ["USER"]

    @patch.object(server, "_kc")
    def test_multi_op_types(self, mock):
        mock.return_value.get_admin_events.return_value = []
        server.get_admin_events(operation_types="UPDATE, CREATE, DELETE")
        call = mock.return_value.get_admin_events.call_args
        assert call.kwargs["operation_types"] == ["UPDATE", "CREATE", "DELETE"]

    @patch.object(server, "_kc")
    def test_empty(self, mock):
        mock.return_value.get_admin_events.return_value = []
        result = server.get_admin_events()
        assert "No admin events" in result

    @patch.object(server, "_kc")
    def test_representation_truncated(self, mock):
        big = {**SAMPLE_ADMIN_EVENT, "representation": "x" * 1000}
        mock.return_value.get_admin_events.return_value = [big]
        # Default max_repr is 500, so 1000 x's should be truncated
        result = server.get_admin_events()
        assert "..." in result
        assert "x" * 1000 not in result

    @patch.object(server, "_kc")
    def test_representation_full_when_negative(self, mock):
        big = {**SAMPLE_ADMIN_EVENT, "representation": "x" * 1000}
        mock.return_value.get_admin_events.return_value = [big]
        result = server.get_admin_events(max_repr=-1)
        assert "x" * 1000 in result
        assert "..." not in result

    @patch.object(server, "_kc")
    def test_representation_omitted_when_zero(self, mock):
        big = {**SAMPLE_ADMIN_EVENT, "representation": "x" * 100}
        mock.return_value.get_admin_events.return_value = [big]
        result = server.get_admin_events(max_repr=0)
        assert "repr=" not in result


class TestGetUserAttributeHistory:
    @patch.object(server, "_kc")
    def test_user_not_found(self, mock):
        mock.return_value.get_user_by_username.return_value = None
        result = server.get_user_attribute_history("ghost@example.com")
        assert "not found" in result

    @patch.object(server, "_kc")
    def test_no_history(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_admin_events.return_value = []
        result = server.get_user_attribute_history("alice@example.com")
        assert "No attribute change events" in result

    @patch.object(server, "_kc")
    def test_returns_history(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_admin_events.return_value = [SAMPLE_ADMIN_EVENT]
        result = server.get_user_attribute_history("alice@example.com")
        assert "Attribute history for alice@example.com (1)" in result
        assert "temp_password" in result
        # Verify the query was scoped to this user
        call = mock.return_value.get_admin_events.call_args
        assert call.kwargs["resource_path"] == "users/user-uuid-1"
        assert call.kwargs["operation_types"] == ["UPDATE", "ACTION"]
        assert call.kwargs["resource_types"] == ["USER"]
