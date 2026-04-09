"""Tests for MCP server tools."""

from unittest.mock import MagicMock, patch

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


class TestGetBruteForceStatus:
    @patch.object(server, "_kc")
    def test_locked(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_brute_force_status.return_value = {
            "numFailures": 5, "disabled": True, "lastFailure": 1700000000000, "lastIPFailure": "10.0.0.1"
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
        mock.return_value.list_clients.return_value = [
            {"clientId": "xflow", "protocol": "saml", "enabled": True}
        ]
        result = server.list_clients()
        assert "xflow" in result
        assert "saml" in result


class TestGetRealmRoles:
    @patch.object(server, "_kc")
    def test_output(self, mock):
        mock.return_value.get_realm_roles.return_value = [
            {"name": "admin", "description": "Admin role"}
        ]
        result = server.get_realm_roles()
        assert "admin" in result
