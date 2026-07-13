"""Tests for MCP server tools."""

from datetime import datetime, timedelta
from unittest.mock import ANY, patch

from keycloak_mcp import server


def _ev(items, truncated=False):
    """Shape a client events/users pagination mock: (items, truncated)."""
    return (items, truncated)


def _evs(lists):
    """Shape a client pagination mock's side_effect: each returned list -> (list, False)."""
    return [(items, False) for items in lists]


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


class TestDefaultDateFrom:
    def test_explicit_date_returned_unchanged(self):
        assert server._default_date_from("2026-01-01") == "2026-01-01"

    def test_empty_returns_date_string(self):
        result = server._default_date_from("")
        assert result is not None
        dt = datetime.strptime(result, "%Y-%m-%d")
        assert dt < datetime.now()

    def test_env_zero_returns_none(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_DEFAULT_DATE_FROM_HOURS", "0")
        assert server._default_date_from("") is None

    def test_env_negative_returns_none(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_DEFAULT_DATE_FROM_HOURS", "-1")
        assert server._default_date_from("") is None

    def test_env_custom_hours(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_DEFAULT_DATE_FROM_HOURS", "48")
        result = server._default_date_from("")
        assert result is not None
        dt = datetime.strptime(result, "%Y-%m-%d")
        expected = datetime.now() - timedelta(hours=48)
        assert abs((dt - expected).total_seconds()) < 86400  # within 1 day tolerance

    def test_env_invalid_falls_back_to_24h(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_DEFAULT_DATE_FROM_HOURS", "foo")
        result = server._default_date_from("")
        assert result is not None
        dt = datetime.strptime(result, "%Y-%m-%d")
        assert dt < datetime.now()


class TestFormatEventList:
    def test_header_plus_formatted_events(self):
        events = [{"n": 1}, {"n": 2}, {"n": 3}]
        result = server._format_event_list("Items (3):", events, lambda e: f"  row {e['n']}")
        assert result == "Items (3):\n  row 1\n  row 2\n  row 3"

    def test_empty_events(self):
        """Header-only is fine — this path is not hit in practice because callers
        short-circuit on empty lists, but the helper should still do the right thing."""
        assert server._format_event_list("Items (0):", [], lambda e: "x") == "Items (0):"


class TestFormatUserEvent:
    def test_has_all_fields(self):
        e = {
            "time": 1700000000000,
            "type": "LOGIN",
            "details": {"username": "alice@example.com"},
            "ipAddress": "192.0.2.1",
            "clientId": "shibboleth",
        }
        out = server._format_user_event(e)
        assert "LOGIN" in out
        assert "alice@example.com" in out
        assert "192.0.2.1" in out
        assert "shibboleth" in out
        assert "error=" not in out

    def test_error_field_surfaced(self):
        e = {
            "time": 1700000000000,
            "type": "LOGIN_ERROR",
            "details": {"username": "alice@example.com"},
            "ipAddress": "192.0.2.1",
            "clientId": "shibboleth",
            "error": "invalid_user_credentials",
        }
        assert "error=invalid_user_credentials" in server._format_user_event(e)

    def test_falls_back_to_userid_when_username_missing(self):
        e = {"time": 0, "type": "LOGIN", "details": {}, "userId": "uuid-1", "ipAddress": "", "clientId": ""}
        assert "user=uuid-1" in server._format_user_event(e)


class TestFormatPasswordEvent:
    def test_renders_key_fields(self):
        e = {
            "time": 1700000000000,
            "details": {"username": "alice@example.com"},
            "ipAddress": "192.0.2.1",
            "clientId": "shibboleth",
        }
        out = server._format_password_event(e)
        assert "alice@example.com" in out
        assert "192.0.2.1" in out
        assert "shibboleth" in out


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


class TestGetUserCredentials:
    @patch.object(server, "_kc")
    def test_with_otp(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_user_credentials.return_value = [
            {"type": "password", "createdDate": 1700000000000},
            {"type": "otp", "userLabel": "phone", "createdDate": 1700000001000},
        ]
        result = server.get_user_credentials("alice@example.com")
        assert "TOTP (otp): yes" in result
        assert "Types: otp, password" in result
        assert "label=phone" in result

    @patch.object(server, "_kc")
    def test_without_otp(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_user_credentials.return_value = [
            {"type": "password", "createdDate": 1700000000000},
        ]
        result = server.get_user_credentials("alice@example.com")
        assert "TOTP (otp): no" in result

    @patch.object(server, "_kc")
    def test_no_credentials(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_user_credentials.return_value = []
        result = server.get_user_credentials("alice@example.com")
        assert "no credentials configured" in result

    @patch.object(server, "_kc")
    def test_user_not_found(self, mock):
        mock.return_value.get_user_by_username.return_value = None
        result = server.get_user_credentials("nobody")
        assert "not found" in result


class TestGetTotpUsers:
    @patch.object(server, "_kc")
    def test_counts_and_percentage(self, mock):
        mock.return_value.list_users_all.return_value = _ev(
            [
                {"id": "1", "username": "alice@example.com"},
                {"id": "2", "username": "bob@example.com"},
            ]
        )
        mock.return_value.get_user_credentials.side_effect = [
            [{"type": "password"}, {"type": "otp"}],
            [{"type": "password"}],
        ]
        result = server.get_totp_users()
        assert "scanned 2 enabled users" in result
        assert "With TOTP:    1 (50.0%)" in result
        assert "Without TOTP: 1" in result
        assert "alice@example.com" in result
        assert "bob@example.com" not in result

    @patch.object(server, "_kc")
    def test_max_users_caps_scan(self, mock):
        # The client enforces the cap (via list_users_all limit=) and reports it via the
        # truncated flag; the tool must pass the limit + deadline through and disclose it.
        mock.return_value.list_users_all.return_value = _ev(
            [{"id": str(i), "username": f"u{i}"} for i in range(2)], truncated=True
        )
        mock.return_value.get_user_credentials.return_value = [{"type": "otp"}]
        result = server.get_totp_users(max_users=2)
        mock.return_value.list_users_all.assert_called_once_with(enabled_only=True, limit=2, deadline=ANY)
        assert "capped by max_users=2" in result  # explicit arg reported precisely, not the env vars
        assert mock.return_value.get_user_credentials.call_count == 2

    @patch.object(server, "_kc")
    def test_credential_lookup_error_is_counted(self, mock):
        # One user's credential fetch raises; the scan continues and reports it.
        mock.return_value.list_users_all.return_value = _ev(
            [
                {"id": "1", "username": "alice@example.com"},
                {"id": "2", "username": "bob@example.com"},
            ]
        )
        mock.return_value.get_user_credentials.side_effect = [
            [{"type": "otp"}],
            RuntimeError("boom"),
        ]
        result = server.get_totp_users()
        assert "With TOTP:    1 (100.0%)" in result  # percentage over the 1 successful scan
        assert "Without TOTP: 0" in result
        assert "Errors:       1" in result
        assert "alice@example.com" in result

    @patch.object(server, "_kc")
    def test_no_users(self, mock):
        mock.return_value.list_users_all.return_value = _ev([])
        result = server.get_totp_users()
        assert "No users found" in result

    @patch.object(server, "_kc")
    def test_list_users_suppressed(self, mock):
        mock.return_value.list_users_all.return_value = _ev([{"id": "1", "username": "alice@example.com"}])
        mock.return_value.get_user_credentials.return_value = [{"type": "otp"}]
        result = server.get_totp_users(list_users=False)
        assert "Users with TOTP:" not in result
        assert "With TOTP:    1" in result


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
        mock.return_value = (success, failure, False)
        result = server.get_login_stats()
        assert "Success: 10" in result
        assert "Failure: 3" in result
        assert "Total:   13" in result


class TestGetLoginStatsByHour:
    @patch.object(server, "_fetch_login_events")
    def test_by_hour(self, mock):
        # Use a timestamp that maps to hour 10 in most timezones
        success = [{"type": "LOGIN", "time": 1700035200000}]  # 2023-11-15 10:00 UTC
        mock.return_value = (success, [], False)
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
        mock.return_value.get_events_all.return_value = _ev(failures)
        result = server.get_login_failures_by_ip()
        assert "3 total" in result
        assert "2 unique IPs" in result
        assert "10.0.0.1" in result

    @patch.object(server, "_kc")
    def test_groups_equivalent_ipv6_forms_together(self, mock):
        failures = [
            {"type": "LOGIN_ERROR", "ipAddress": "::1", "time": 1000},
            {"type": "LOGIN_ERROR", "ipAddress": "0:0:0:0:0:0:0:1", "time": 2000},
        ]
        mock.return_value.get_events_all.return_value = _ev(failures)
        result = server.get_login_failures_by_ip()
        assert "2 total" in result
        assert "1 unique IPs" in result


class TestGetIpActivity:
    _FIXED_KEYS = (
        "error",
        "ip_address",
        "site",
        "sites_configured",
        "date_from",
        "date_to",
        "event_types",
        "summary",
        "users",
        "clients",
        "timeline",
        "truncated",
        "events_capped",
    )
    _SUMMARY_KEYS = (
        "total_events",
        "login_success",
        "login_failure",
        "unique_users",
        "unique_clients",
        "first_seen",
        "last_seen",
    )

    @patch.object(server, "_kc")
    def test_happy_path_mixed_success_and_failure(self, mock):
        login_events = [
            {
                "type": "LOGIN",
                "ipAddress": "10.0.0.1",
                "time": 1000,
                "details": {"username": "alice"},
                "clientId": "xflow",
            },
            {
                "type": "LOGIN",
                "ipAddress": "10.0.0.1",
                "time": 2000,
                "details": {"username": "bob"},
                "clientId": "zabbix",
            },
            {
                "type": "LOGIN",
                "ipAddress": "10.0.0.9",
                "time": 1500,
                "details": {"username": "eve"},
                "clientId": "xflow",
            },
        ]
        login_error_events = [
            {
                "type": "LOGIN_ERROR",
                "ipAddress": "10.0.0.1",
                "time": 3000,
                "details": {"username": "alice"},
                "clientId": "xflow",
                "error": "invalid_user_credentials",
            },
        ]
        mock.return_value.get_events_all.side_effect = _evs([login_events, login_error_events])
        result = server.get_ip_activity("10.0.0.1")

        assert result["summary"]["total_events"] == 3
        assert result["summary"]["login_success"] == 2
        assert result["summary"]["login_failure"] == 1
        assert result["summary"]["unique_users"] == 2
        assert result["summary"]["unique_clients"] == 2

        alice = next(u for u in result["users"] if u["username"] == "alice")
        assert alice == {"username": "alice", "success": 1, "failure": 1, "errors": ["invalid_user_credentials"]}
        bob = next(u for u in result["users"] if u["username"] == "bob")
        assert bob == {"username": "bob", "success": 1, "failure": 0, "errors": []}

        xflow = next(c for c in result["clients"] if c["client_id"] == "xflow")
        assert xflow == {"client_id": "xflow", "success": 1, "failure": 1}

    @patch.object(server, "_kc")
    def test_excludes_other_ips(self, mock):
        login_events = [
            {
                "type": "LOGIN",
                "ipAddress": "10.0.0.1",
                "time": 1000,
                "details": {"username": "alice"},
                "clientId": "app",
            },
            {
                "type": "LOGIN",
                "ipAddress": "10.0.0.2",
                "time": 1100,
                "details": {"username": "mallory"},
                "clientId": "app",
            },
        ]
        login_error_events = [
            {
                "type": "LOGIN_ERROR",
                "ipAddress": "10.0.0.2",
                "time": 1200,
                "details": {"username": "mallory"},
                "clientId": "app",
                "error": "invalid_user_credentials",
            },
        ]
        mock.return_value.get_events_all.side_effect = _evs([login_events, login_error_events])
        result = server.get_ip_activity("10.0.0.1")

        assert result["summary"]["total_events"] == 1
        assert len(result["timeline"]) == 1
        assert result["users"] == [{"username": "alice", "success": 1, "failure": 0, "errors": []}]

    @patch.object(server, "_kc")
    def test_no_match_returns_fixed_shape(self, mock):
        mock.return_value.get_events_all.side_effect = _evs([[], []])
        result = server.get_ip_activity("10.0.0.1")

        for key in self._FIXED_KEYS:
            assert key in result
        for key in self._SUMMARY_KEYS:
            assert key in result["summary"]

        assert result["summary"]["total_events"] == 0
        assert result["summary"]["first_seen"] is None
        assert result["summary"]["last_seen"] is None
        assert result["users"] == []
        assert result["clients"] == []
        assert result["timeline"] == []
        assert result["truncated"] is False

    @patch.object(server, "_kc")
    def test_timeline_truncation(self, mock):
        login_events = [
            {
                "type": "LOGIN",
                "ipAddress": "10.0.0.1",
                "time": i * 1000,
                "details": {"username": "alice"},
                "clientId": "app",
            }
            for i in range(5)
        ]
        mock.return_value.get_events_all.side_effect = _evs([login_events, []])
        result = server.get_ip_activity("10.0.0.1", max_timeline=2)

        assert len(result["timeline"]) == 2
        assert result["truncated"] is True
        assert result["summary"]["total_events"] == 5
        assert result["summary"]["last_seen"] == result["timeline"][-1]["time"]

    @patch.object(server, "_kc")
    def test_event_types_widening(self, mock):
        mock.return_value.get_events_all.side_effect = _evs([[], [], []])
        result = server.get_ip_activity("10.0.0.1", event_types="LOGIN,LOGIN_ERROR,LOGOUT")

        assert mock.return_value.get_events_all.call_count == 3
        assert result["event_types"] == ["LOGIN", "LOGIN_ERROR", "LOGOUT"]

    @patch.object(server, "_site_classifier")
    @patch.object(server, "_kc")
    def test_site_matched(self, mock_kc, mock_sc):
        mock_kc.return_value.get_events_all.side_effect = _evs([[], []])
        mock_sc.return_value.classify.return_value = "hq"
        mock_sc.return_value.available = True
        result = server.get_ip_activity("10.0.0.1")

        assert result["site"] == "hq"
        assert result["sites_configured"] is True

    @patch.object(server, "_site_classifier")
    @patch.object(server, "_kc")
    def test_site_unmatched_but_configured(self, mock_kc, mock_sc):
        mock_kc.return_value.get_events_all.side_effect = _evs([[], []])
        mock_sc.return_value.classify.return_value = None
        mock_sc.return_value.available = True
        result = server.get_ip_activity("203.0.113.5")

        assert result["site"] is None
        assert result["sites_configured"] is True

    @patch.object(server, "_site_classifier")
    @patch.object(server, "_kc")
    def test_site_unconfigured(self, mock_kc, mock_sc):
        mock_kc.return_value.get_events_all.side_effect = _evs([[], []])
        mock_sc.return_value.classify.return_value = None
        mock_sc.return_value.available = False
        result = server.get_ip_activity("203.0.113.5")

        assert result["site"] is None
        assert result["sites_configured"] is False

    @patch.object(server, "_kc")
    def test_fixed_shape(self, mock):
        login_events = [
            {
                "type": "LOGIN",
                "ipAddress": "10.0.0.1",
                "time": 1000,
                "details": {"username": "alice"},
                "clientId": "app",
            }
        ]
        mock.return_value.get_events_all.side_effect = _evs([login_events, []])
        result = server.get_ip_activity("10.0.0.1")

        for key in self._FIXED_KEYS:
            assert key in result
        for key in self._SUMMARY_KEYS:
            assert key in result["summary"]

    @patch.object(server, "_kc")
    def test_error_details_collected_per_user(self, mock):
        login_error_events = [
            {
                "type": "LOGIN_ERROR",
                "ipAddress": "10.0.0.1",
                "time": 1000,
                "details": {"username": "alice"},
                "clientId": "app",
                "error": "invalid_user_credentials",
            },
            {
                "type": "LOGIN_ERROR",
                "ipAddress": "10.0.0.1",
                "time": 2000,
                "details": {"username": "alice"},
                "clientId": "app",
                "error": "user_disabled",
            },
            {
                "type": "LOGIN_ERROR",
                "ipAddress": "10.0.0.1",
                "time": 3000,
                "details": {"username": "alice"},
                "clientId": "app",
                "error": "invalid_user_credentials",
            },
        ]
        mock.return_value.get_events_all.side_effect = _evs([[], login_error_events])
        result = server.get_ip_activity("10.0.0.1")

        alice = result["users"][0]
        assert alice["username"] == "alice"
        assert sorted(alice["errors"]) == ["invalid_user_credentials", "user_disabled"]

    @patch.object(server, "_kc")
    def test_default_date_from_applied(self, mock):
        mock.return_value.get_events_all.side_effect = _evs([[], []])
        server.get_ip_activity("10.0.0.1")

        first_call = mock.return_value.get_events_all.call_args_list[0]
        assert first_call.kwargs["date_from"] is not None

    @patch.object(server, "_kc")
    def test_summary_reconciles_with_widened_non_login_types(self, mock):
        logout_events = [
            {
                "type": "LOGOUT",
                "ipAddress": "10.0.0.1",
                "time": 1000,
                "details": {"username": "alice"},
                "clientId": "app",
            }
        ]
        mock.return_value.get_events_all.side_effect = _evs([[], [], logout_events])
        result = server.get_ip_activity("10.0.0.1", event_types="LOGIN,LOGIN_ERROR,LOGOUT")

        assert result["summary"]["login_success"] == 1
        assert result["summary"]["login_failure"] == 0
        alice = result["users"][0]
        assert alice["success"] == 1
        assert alice["failure"] == 0

    @patch.object(server, "_kc")
    def test_max_timeline_zero_returns_empty_timeline(self, mock):
        login_events = [
            {
                "type": "LOGIN",
                "ipAddress": "10.0.0.1",
                "time": 1000,
                "details": {"username": "alice"},
                "clientId": "app",
            }
        ]
        mock.return_value.get_events_all.side_effect = _evs([login_events, []])
        result = server.get_ip_activity("10.0.0.1", max_timeline=0)

        assert result["timeline"] == []
        assert result["truncated"] is True
        assert result["summary"]["total_events"] == 1

    @patch.object(server, "_kc")
    def test_empty_event_types_returns_error_key(self, mock):
        result = server.get_ip_activity("10.0.0.1", event_types=" , ,")

        assert result["error"] is not None
        assert "event_types" in result["error"]
        assert result["summary"]["total_events"] == 0
        assert result["timeline"] == []
        mock.return_value.get_events_all.assert_not_called()

    @patch.object(server, "_kc")
    def test_success_has_null_error(self, mock):
        mock.return_value.get_events_all.side_effect = _evs([[], []])
        result = server.get_ip_activity("10.0.0.1")

        assert result["error"] is None

    @patch.object(server, "_kc")
    def test_user_key_handles_null_details(self, mock):
        login_events = [
            {
                "type": "LOGIN",
                "ipAddress": "10.0.0.1",
                "time": 1000,
                "details": None,
                "userId": "uuid-1",
                "clientId": "app",
            }
        ]
        mock.return_value.get_events_all.side_effect = _evs([login_events, []])
        result = server.get_ip_activity("10.0.0.1")

        assert result["users"] == [{"username": "uuid-1", "success": 1, "failure": 0, "errors": []}]

    @patch.object(server, "_kc")
    def test_clientid_default_consistent_across_clients_and_timeline(self, mock):
        login_events = [{"type": "LOGIN", "ipAddress": "10.0.0.1", "time": 1000, "details": {"username": "alice"}}]
        mock.return_value.get_events_all.side_effect = _evs([login_events, []])
        result = server.get_ip_activity("10.0.0.1")

        assert result["clients"] == [{"client_id": "unknown", "success": 1, "failure": 0}]
        assert result["timeline"][0]["client_id"] == "unknown"

    @patch.object(server, "_kc")
    def test_null_time_does_not_crash_sort_or_summary(self, mock):
        login_events = [
            {
                "type": "LOGIN",
                "ipAddress": "10.0.0.1",
                "time": None,
                "details": {"username": "alice"},
                "clientId": "app",
            },
            {"type": "LOGIN", "ipAddress": "10.0.0.1", "time": 2000, "details": {"username": "bob"}, "clientId": "app"},
        ]
        mock.return_value.get_events_all.side_effect = _evs([login_events, []])
        result = server.get_ip_activity("10.0.0.1")

        assert result["summary"]["total_events"] == 2
        assert result["summary"]["first_seen"] is not None
        assert result["summary"]["last_seen"] is not None

    @patch.object(server, "_kc")
    def test_ip_normalization_matches_equivalent_ipv6_forms(self, mock):
        login_events = [
            {
                "type": "LOGIN",
                "ipAddress": "0:0:0:0:0:0:0:1",
                "time": 1000,
                "details": {"username": "alice"},
                "clientId": "app",
            }
        ]
        mock.return_value.get_events_all.side_effect = _evs([login_events, []])
        result = server.get_ip_activity("::1")

        assert result["summary"]["total_events"] == 1


class TestGetLoginStatsByClient:
    @patch.object(server, "_fetch_login_events")
    def test_by_client(self, mock):
        success = [{"clientId": "xflow"}, {"clientId": "xflow"}, {"clientId": "zabbix"}]
        failure = [{"clientId": "xflow"}]
        mock.return_value = (success, failure, False)
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


class TestGetRealmSecurityDefenses:
    @patch.object(server, "_kc")
    def test_brute_force_enabled(self, mock):
        mock.return_value.get_realm.return_value = {
            "realm": "nu-sso",
            "bruteForceProtected": True,
            "permanentLockout": False,
            "failureFactor": 30,
            "waitIncrementSeconds": 60,
            "maxFailureWaitSeconds": 900,
            "passwordPolicy": "length(8)",
            "browserSecurityHeaders": {
                "contentSecurityPolicy": "frame-src 'self'",
                "xFrameOptions": "SAMEORIGIN",
                "strictTransportSecurity": "",
            },
        }
        result = server.get_realm_security_defenses()
        assert "Enabled:" in result and "True" in result
        assert "Max login failures:     30" in result
        assert "length(8)" in result
        # Set headers are shown; empty ones are filtered out.
        assert "xFrameOptions: SAMEORIGIN" in result
        assert "strictTransportSecurity" not in result

    @patch.object(server, "_kc")
    def test_brute_force_disabled(self, mock):
        mock.return_value.get_realm.return_value = {
            "realm": "nu-sso",
            "bruteForceProtected": False,
        }
        result = server.get_realm_security_defenses()
        assert "OFF" in result
        # Thresholds must not be printed when protection is off.
        assert "Max login failures" not in result


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


class TestSetUserEnabled:
    @patch.object(server, "_kc")
    def test_disable(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_user_sessions.return_value = []
        result = server.set_user_enabled("alice@example.com", False)
        assert "enabled=False" in result
        mock.return_value.set_user_enabled.assert_called_once_with(SAMPLE_USER["id"], False)

    @patch.object(server, "_kc")
    def test_disable_warns_active_sessions(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER
        mock.return_value.get_user_sessions.return_value = [
            {"clients": {"c1": "app"}, "start": 1700000, "ipAddress": "10.0.0.1"}
        ]
        result = server.set_user_enabled("alice@example.com", False)
        assert "1 active session(s) remain" in result
        assert "logout_user" in result

    @patch.object(server, "_kc")
    def test_no_change_skips_write(self, mock):
        mock.return_value.get_user_by_username.return_value = SAMPLE_USER  # enabled=True
        result = server.set_user_enabled("alice@example.com", True)
        assert "no change" in result
        mock.return_value.set_user_enabled.assert_not_called()

    @patch.object(server, "_kc")
    def test_user_not_found(self, mock):
        mock.return_value.get_user_by_username.return_value = None
        result = server.set_user_enabled("nobody", False)
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
        mock.return_value.get_events_all.return_value = _ev(events)
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
        mock.return_value.get_events_all.return_value = _ev(events)
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
        mock.return_value.get_events_all.return_value = _ev(events)
        result = server.detect_login_loops(threshold=10, window_seconds=60, top=2)
        assert "3 user(s)" in result
        assert "showing top 2" in result

    @patch.object(server, "_kc")
    def test_empty_events(self, mock):
        mock.return_value.get_events_all.return_value = _ev([])
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

    @patch.object(server, "_kc")
    def test_filters_by_ip_normalizes_equivalent_ipv6_forms(self, mock):
        mock.return_value.get_events.return_value = [
            {
                "type": "LOGIN",
                "time": 1700000000000,
                "details": {"username": "alice"},
                "ipAddress": "0:0:0:0:0:0:0:1",
                "clientId": "app",
            }
        ]
        result = server.get_events(ip_address="::1")
        assert "alice" in result


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


_SAMPLE_LOGIN_EVENT = {
    "type": "LOGIN",
    "time": 1700000000000,
    "details": {"username": "u"},
    "ipAddress": "10.0.0.1",
    "clientId": "app",
}
_SAMPLE_FAILURE_EVENT = {
    "type": "LOGIN_ERROR",
    "time": 1700000000000,
    "details": {"username": "x"},
    "ipAddress": "1.2.3.4",
    "clientId": "app",
}


class TestDailyBrief:
    def _make_kc_mock(
        self,
        mock,
        *,
        success_count=5,
        failure_events=None,
        pw_updates=None,
        admin_evts=None,
        sessions=None,
    ):
        failure_events = failure_events or []
        pw_updates = pw_updates or []
        admin_evts = admin_evts or []
        sessions = sessions or [{"clientId": "xflow", "active": "3"}]
        mock.return_value.get_events_all.side_effect = _evs(
            [
                [_SAMPLE_LOGIN_EVENT] * success_count,
                failure_events,
                pw_updates,
            ]
        )
        mock.return_value.get_admin_events_all.return_value = _ev(admin_evts)
        mock.return_value.get_session_stats.return_value = sessions

    @patch.object(server, "_kc")
    def test_ok_status(self, mock):
        self._make_kc_mock(mock)
        result = server.daily_brief()
        assert "## OK" in result
        assert "daily_brief" in result
        assert "Login" in result
        assert "Active sessions" in result

    @patch.object(server, "_kc")
    def test_warning_brute_force(self, mock):
        failures = [_SAMPLE_FAILURE_EVENT] * 60
        self._make_kc_mock(mock, failure_events=failures)
        result = server.daily_brief(ip_failure_threshold=50)
        assert "## WARNING" in result
        assert "### WARNINGS" in result
        assert "1.2.3.4" in result

    @patch.object(server, "_kc")
    def test_at_threshold_is_warning(self, mock):
        """Exactly ip_failure_threshold failures (>=) should trigger WARNING."""
        failures = [_SAMPLE_FAILURE_EVENT] * 50
        self._make_kc_mock(mock, failure_events=failures)
        result = server.daily_brief(ip_failure_threshold=50)
        assert "## WARNING" in result

    @patch.object(server, "_kc")
    def test_below_threshold_is_ok(self, mock):
        failures = [_SAMPLE_FAILURE_EVENT] * 10
        self._make_kc_mock(mock, failure_events=failures)
        result = server.daily_brief(ip_failure_threshold=50)
        assert "## OK" in result
        assert "### WARNINGS" not in result

    @patch.object(server, "_kc")
    def test_critical_on_api_error(self, mock, capsys):
        mock.return_value.get_events_all.side_effect = RuntimeError("connection refused")
        result = server.daily_brief()
        assert "## CRITICAL" in result
        assert "RuntimeError" in result
        assert "connection refused" not in result
        assert "connection refused" in capsys.readouterr().err

    @patch.object(server, "_kc")
    def test_since_hours_uses_param_not_env(self, mock, monkeypatch):
        """since_hours must bypass _default_date_from (env var must not override)."""
        from datetime import datetime, timedelta

        monkeypatch.setenv("KEYCLOAK_DEFAULT_DATE_FROM_HOURS", "1")
        self._make_kc_mock(mock)
        server.daily_brief(since_hours=48)
        calls = mock.return_value.get_events_all.call_args_list
        expected_date = (datetime.now() - timedelta(hours=48)).strftime("%Y-%m-%d")
        # LOGIN and LOGIN_ERROR calls (first two) must carry the 48h date, not 1h
        for call in calls[:2]:
            assert call.kwargs.get("date_from") == expected_date

    @patch.object(server, "_kc")
    def test_password_updates_shown(self, mock):
        pw = [{"time": 1700000000000, "details": {"username": "alice"}, "ipAddress": "10.0.0.1", "clientId": "app"}]
        self._make_kc_mock(mock, pw_updates=pw)
        result = server.daily_brief()
        assert "Password updates: 1" in result
        assert "alice" in result

    @patch.object(server, "_kc")
    def test_admin_events_shown(self, mock):
        self._make_kc_mock(mock, admin_evts=[SAMPLE_ADMIN_EVENT])
        result = server.daily_brief()
        assert "Admin events: 1" in result

    @patch.object(server, "_kc")
    def test_warning_more_than_five_ips_above_threshold(self, mock):
        """7 IPs all above threshold must trigger WARNING; top 5 appear in WARNINGS."""
        failures = []
        for i in range(7):
            event = {**_SAMPLE_FAILURE_EVENT, "ipAddress": f"10.0.0.{i + 1}"}
            failures += [event] * (60 - i)  # 60, 59, …, 54 — all above threshold=50
        self._make_kc_mock(mock, failure_events=failures)
        result = server.daily_brief(ip_failure_threshold=50)
        assert "## WARNING" in result
        assert "10.0.0.1" in result  # top IP flagged
        assert "10.0.0.5" in result  # 5th IP flagged


class TestHealthCheck:
    def teardown_method(self):
        # health_check caches/clears the module client; keep tests isolated.
        server.reset_client()

    @patch.object(server, "_kc")
    def test_healthy_auth_ok(self, mock):
        mock.return_value.auth.get_token.return_value = "fake-token"
        result = server.health_check()
        assert result["status"] == "healthy"
        assert result["service"] == "keycloak-mcp"
        assert result["auth"] == "ok"
        assert "detail" not in result
        # Fixed shape: every documented key is always present.
        for key in ("status", "service", "version", "keycloak_url", "realm", "keycloak_version", "auth"):
            assert key in result
        assert result["keycloak_version"] is None

    @patch.object(server, "_kc")
    def test_surfaces_configured_url_and_realm(self, mock, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_URL", "https://sso.example.com")
        monkeypatch.setenv("KEYCLOAK_REALM", "test-realm")
        mock.return_value.auth.get_token.return_value = "fake-token"
        result = server.health_check()
        assert result["keycloak_url"] == "https://sso.example.com"
        assert result["realm"] == "test-realm"

    @patch.object(server, "_kc")
    def test_missing_env(self, mock):
        # TokenManager raises KeyError when a required env var is absent.
        mock.side_effect = KeyError("KEYCLOAK_CLIENT_SECRET")
        result = server.health_check()
        assert result["status"] == "error"
        assert result["auth"] == "missing-env"
        assert "KEYCLOAK_CLIENT_SECRET" in result["detail"]

    @patch.object(server, "_kc")
    def test_backend_error_degraded(self, mock):
        mock.return_value.auth.get_token.side_effect = RuntimeError("connection refused")
        result = server.health_check()
        assert result["status"] == "degraded"
        assert result["auth"] == "error"
        assert result["detail"] == "RuntimeError"

    @patch.object(server, "_kc")
    def test_backend_error_does_not_leak_internals(self, mock):
        """Backend failure detail must not echo internal URLs / httpx payloads."""
        leak = "https://internal-sso.example.corp/realms/foo/protocol/openid-connect/token"
        mock.return_value.auth.get_token.side_effect = RuntimeError(f"Connection failed: {leak}")
        result = server.health_check()
        assert leak not in result["detail"]
        assert result["detail"] == "RuntimeError"

    @patch.object(server, "_kc")
    def test_backend_error_includes_http_status(self, mock):
        """When the error carries an HTTP status, it's included (no body/URL)."""

        class FakeHTTPError(Exception):
            def __init__(self, status):
                super().__init__("boom")
                self.response = type("R", (), {"status_code": status})()

        mock.return_value.auth.get_token.side_effect = FakeHTTPError(401)
        result = server.health_check()
        assert result["status"] == "degraded"
        assert result["detail"] == "FakeHTTPError 401"
        assert "boom" not in result["detail"]


class TestBoundsEnvParsing:
    def test_deadline_default(self, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_DEADLINE", raising=False)
        assert server._deadline_seconds() == 45.0

    def test_deadline_custom(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_DEADLINE", "20")
        assert server._deadline_seconds() == 20.0

    def test_deadline_zero_and_negative_disable(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_DEADLINE", "0")
        assert server._deadline_seconds() is None
        monkeypatch.setenv("KEYCLOAK_DEADLINE", "-1")
        assert server._deadline_seconds() is None

    def test_deadline_invalid_falls_back(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_DEADLINE", "foo")
        assert server._deadline_seconds() == 45.0

    def test_deadline_non_finite_falls_back_not_disabled(self, monkeypatch):
        # "nan"/"inf" parse as floats but must NOT silently disable the deadline.
        monkeypatch.setenv("KEYCLOAK_DEADLINE", "nan")
        assert server._deadline_seconds() == 45.0
        monkeypatch.setenv("KEYCLOAK_DEADLINE", "inf")
        assert server._deadline_seconds() == 45.0

    def test_max_events(self, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_MAX_EVENTS", raising=False)
        assert server._max_events() == 200000
        monkeypatch.setenv("KEYCLOAK_MAX_EVENTS", "1000")
        assert server._max_events() == 1000
        monkeypatch.setenv("KEYCLOAK_MAX_EVENTS", "0")
        assert server._max_events() is None
        monkeypatch.setenv("KEYCLOAK_MAX_EVENTS", "-5")
        assert server._max_events() is None
        monkeypatch.setenv("KEYCLOAK_MAX_EVENTS", "foo")
        assert server._max_events() == 200000

    def test_max_users(self, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_MAX_USERS", raising=False)
        assert server._max_users() == 5000
        monkeypatch.setenv("KEYCLOAK_MAX_USERS", "10")
        assert server._max_users() == 10
        monkeypatch.setenv("KEYCLOAK_MAX_USERS", "0")
        assert server._max_users() is None
        monkeypatch.setenv("KEYCLOAK_MAX_USERS", "foo")
        assert server._max_users() == 5000


class TestPartialDisclosure:
    """A truncated (deadline/cap) fetch must be disclosed, never silently under-reported."""

    @patch.object(server, "_fetch_login_events")
    def test_login_stats_warns_when_truncated(self, mock):
        mock.return_value = ([{"type": "LOGIN"}], [], True)
        result = server.get_login_stats()
        assert result.startswith("⚠️ PARTIAL RESULT")
        assert "Success: 1" in result  # the partial data is still shown

    @patch.object(server, "_fetch_login_events")
    def test_login_stats_no_warning_when_complete(self, mock):
        mock.return_value = ([{"type": "LOGIN"}], [], False)
        assert "PARTIAL RESULT" not in server.get_login_stats()

    @patch.object(server, "_kc")
    def test_login_failures_by_ip_warns_when_truncated(self, mock):
        mock.return_value.get_events_all.return_value = _ev(
            [{"type": "LOGIN_ERROR", "ipAddress": "10.0.0.1", "time": 1}], truncated=True
        )
        assert server.get_login_failures_by_ip().startswith("⚠️ PARTIAL RESULT")

    @patch.object(server, "_kc")
    def test_detect_login_loops_warns_when_truncated(self, mock):
        # A truncated scan must not be trusted to conclude "no loops".
        mock.return_value.get_events_all.return_value = _ev(
            [{"type": "LOGIN", "details": {"username": "x"}, "time": 1}], truncated=True
        )
        result = server.detect_login_loops()
        assert result.startswith("⚠️ PARTIAL RESULT")
        assert "No login loops" in result

    @patch.object(server, "_kc")
    def test_ip_activity_sets_events_capped_distinct_from_timeline(self, mock):
        # events_capped reflects a truncated pagination; the timeline 'truncated' flag is separate.
        mock.return_value.get_events_all.side_effect = [
            _ev([{"type": "LOGIN", "ipAddress": "10.0.0.1", "time": 1}], truncated=True),
            _ev([]),
        ]
        result = server.get_ip_activity("10.0.0.1")
        assert result["events_capped"] is True
        assert result["truncated"] is False  # timeline not capped -> the two flags are independent

    @patch.object(server, "_kc")
    def test_ip_activity_events_capped_false_on_complete_scan(self, mock):
        # A fully-drained scan must report events_capped=False (no spurious partial signal).
        mock.return_value.get_events_all.side_effect = [
            _ev([{"type": "LOGIN", "ipAddress": "10.0.0.1", "time": 1}]),
            _ev([]),
        ]
        result = server.get_ip_activity("10.0.0.1")
        assert result["events_capped"] is False

    @patch.object(server, "_kc")
    def test_totp_users_deadline_truncates_n_plus_1_loop(self, mock, monkeypatch):
        # The deadline must stop the per-user credential loop and disclose the cap.
        mock.return_value.list_users_all.return_value = _ev([{"id": str(i), "username": f"u{i}"} for i in range(5)])
        mock.return_value.get_user_credentials.return_value = [{"type": "otp"}]
        calls = {"n": 0}

        def fake_past(_deadline):  # False for the first two iterations, then True
            calls["n"] += 1
            return calls["n"] > 2

        monkeypatch.setattr("keycloak_mcp.server.past_deadline", fake_past)
        result = server.get_totp_users()
        assert "capped by the time budget (KEYCLOAK_DEADLINE)" in result
        assert "scanned 2 enabled users" in result  # stopped after 2 of 5
        assert mock.return_value.get_user_credentials.call_count == 2

    @patch.object(server, "_fetch_login_events")
    def test_login_stats_by_hour_warns_when_truncated(self, mock):
        mock.return_value = ([{"type": "LOGIN", "time": 1700035200000}], [], True)
        assert server.get_login_stats_by_hour().startswith("⚠️ PARTIAL RESULT")

    @patch.object(server, "_fetch_login_events")
    def test_login_stats_by_client_warns_when_truncated(self, mock):
        mock.return_value = ([{"clientId": "x"}], [], True)
        assert server.get_login_stats_by_client().startswith("⚠️ PARTIAL RESULT")

    @patch.object(server, "_kc")
    def test_daily_brief_discloses_partial(self, mock):
        # A pagination that blew the deadline/cap must flip the brief to WARNING with a
        # [PARTIAL] note — the flagship tool must not under-report events silently.
        mock.return_value.get_events_all.side_effect = [
            _ev([{"type": "LOGIN", "time": 1, "ipAddress": "1.1.1.1"}], truncated=True),  # LOGIN
            _ev([]),  # LOGIN_ERROR
            _ev([]),  # UPDATE_PASSWORD
        ]
        mock.return_value.get_admin_events_all.return_value = _ev([])
        mock.return_value.get_session_stats.return_value = [{"clientId": "x", "active": "1"}]
        result = server.daily_brief()
        assert "## WARNING" in result
        assert "[PARTIAL]" in result
