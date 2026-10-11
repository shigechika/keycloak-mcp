"""Tests for daily configuration snapshots (collect / diff / storage) and their tools."""

import copy
import json
import os
import stat
import time
from datetime import date, timedelta
from unittest.mock import patch

import httpx
import pytest

from keycloak_mcp import config_snapshot as cs
from keycloak_mcp import server

PEM = "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----"
CERT = "MIIC" + "A" * 400


def _realm():
    return {
        "id": "realm-uuid",
        "realm": "test",
        "notBefore": 0,
        "bruteForceProtected": True,
        "failureFactor": 30,
        "passwordPolicy": "length(12)",
        "revokeRefreshToken": False,
        "requiredCredentials": ["password"],
        "smtpServer": {"host": "smtp.example.org", "password": "smtp-pass-value"},
        "roles": {"realm": [{"name": "should-not-be-here"}]},
        "browserFlow": "browser",
    }


class FakeKC:
    """Answers the Admin API reads that collect() makes."""

    def __init__(self):
        self.realm = _realm()
        self.clients = [
            {
                "id": "c-app",
                "clientId": "app",
                "secret": "client-secret-value",
                "enabled": True,
                "redirectUris": ["https://b.example/*", "https://a.example/*"],
                "authenticationFlowBindingOverrides": {"browser": "f-otp"},
                "attributes": {
                    "saml.signing.private.key": "MIIEshortkeybody",
                    "saml.encryption.private.key": "K" * 600,
                    "client.secret.creation.time": "1700000000",
                    "saml.signing.certificate": CERT,
                    "client_credentials.use_refresh_token": "false",
                },
                "protocolMappers": [{"id": "m1", "name": "groups", "protocolMapper": "group-mapper", "config": {}}],
            },
            {"id": "c-rm", "clientId": "realm-management", "enabled": True},
        ]
        self.flows = [
            {"id": "f-browser", "alias": "browser", "topLevel": True, "builtIn": True, "providerId": "basic-flow"},
            {"id": "f-otp", "alias": "browser otp", "topLevel": True, "builtIn": False, "providerId": "basic-flow"},
            {"id": "f-sub", "alias": "forms", "topLevel": False},
        ]
        self.executions = {
            "browser": [{"id": "e1", "level": 0, "index": 0, "displayName": "Cookie", "requirement": "ALTERNATIVE"}],
            "browser otp": [
                {"id": "e2", "level": 0, "index": 0, "displayName": "OTP Form", "requirement": "REQUIRED"},
                {
                    "id": "e3",
                    "level": 0,
                    "index": 1,
                    "displayName": "Condition - user role",
                    "requirement": "REQUIRED",
                    "authenticationConfig": "cfg-1",
                },
            ],
        }
        self.auth_configs = {"cfg-1": {"id": "cfg-1", "alias": "staff only", "config": {"condUserRole": "staff"}}}
        self.roles = [
            {"id": "r-admin", "name": "dept-admin", "composite": True, "description": "x"},
            {"id": "r-plain", "name": "plain", "composite": False},
        ]
        self.composites = {"r-admin": [{"name": "query-users", "clientRole": True, "containerId": "c-rm"}]}
        self.components = [
            {
                "id": "k1",
                "parentId": "realm-uuid",
                "name": "rsa-generated",
                "providerId": "rsa-generated",
                "providerType": "org.keycloak.keys.KeyProvider",
                "config": {"privateKey": [PEM], "certificate": [CERT], "priority": ["100"]},
            },
            {
                "id": "p1",
                "name": "Allowed Client Scopes",
                "providerType": "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
                "subType": "anonymous",
                "config": {},
            },
            {
                "id": "p2",
                "name": "Allowed Client Scopes",
                "providerType": "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
                "subType": "authenticated",
                "config": {},
            },
            {
                "id": "h1",
                "name": "hmac",
                "providerType": "org.keycloak.keys.KeyProvider",
                "config": {"secret": ["hmac-secret-value"], "kid": ["abc"]},
            },
        ]
        self.idp_status = 200
        self.idps = [{"alias": "google", "config": {"clientSecret": "idp-secret-value", "clientId": "g"}}]
        self.truncate = set()
        self.calls = 0

    def _get(self, path, params=None, deadline=None):
        self.calls += 1
        if path == "":
            return copy.deepcopy(self.realm)
        if path == "/events/config":
            return {"eventsEnabled": True, "adminEventsEnabled": True, "eventsExpiration": 2592000}
        if path == "/authentication/flows":
            return copy.deepcopy(self.flows)
        if path.startswith("/authentication/flows/") and path.endswith("/executions"):
            from urllib.parse import unquote

            alias = unquote(path[len("/authentication/flows/") : -len("/executions")])
            return copy.deepcopy(self.executions[alias])
        if path.startswith("/authentication/config/"):
            return copy.deepcopy(self.auth_configs[path.rsplit("/", 1)[1]])
        if path.startswith("/roles-by-id/"):
            return copy.deepcopy(self.composites[path.split("/")[2]])
        if path == "/authentication/required-actions":
            return [{"alias": "CONFIGURE_TOTP", "enabled": True, "defaultAction": False}]
        if path == "/client-scopes":
            return [{"id": "s1", "name": "profile", "protocol": "openid-connect", "protocolMappers": []}]
        if path == "/default-default-client-scopes":
            return [{"id": "s1", "name": "profile"}]
        if path == "/default-optional-client-scopes":
            return []
        if path == "/components":
            return copy.deepcopy(self.components)
        if path == "/identity-provider/instances":
            if self.idp_status != 200:
                raise httpx.HTTPStatusError(
                    "denied", request=httpx.Request("GET", "x"), response=httpx.Response(self.idp_status)
                )
            return copy.deepcopy(self.idps)
        raise AssertionError(f"unexpected GET {path}")

    def _paginate(self, path, params, page_size, max_total=None, deadline=None):
        self.calls += 1
        items = {"/clients": self.clients, "/roles": self.roles}[path]
        return copy.deepcopy(items), path in self.truncate


@pytest.fixture
def kc():
    return FakeKC()


class TestCollect:
    def test_secrets_never_reach_the_snapshot(self, kc):
        text = json.dumps(cs.collect(kc), ensure_ascii=False)
        for secret in (
            "client-secret-value",
            "smtp-pass-value",
            "hmac-secret-value",
            "idp-secret-value",
            "MIIabc",
            "MIIEshortkeybody",
        ):
            assert secret not in text
        attrs = cs.collect(kc)["sections"]["clients"]["app"]["attributes"]
        # SAML keys are named with dots; a long one must be redacted, not hashed.
        assert attrs["saml.signing.private.key"] == cs.REDACTED
        assert attrs["saml.encryption.private.key"] == cs.REDACTED
        assert cs.REDACTED in text

    def test_a_password_that_reads_like_a_flag_is_still_redacted(self, kc):
        kc.realm["smtpServer"]["password"] = "false"
        assert cs.collect(kc)["sections"]["realm"]["smtpServer"]["password"] == cs.REDACTED

    def test_secrets_named_with_other_words_are_redacted(self, kc):
        kc.clients[0]["attributes"].update(
            {
                "client.secret.rotated": "old-secret-value",
                "client.secret.expiration": "1800000000",
                "apiKey": "api-key-value",
                "awsSecretKey": "aws-secret-value",
                "access.token.claim": "true",
            }
        )
        attrs = cs.collect(kc)["sections"]["clients"]["app"]["attributes"]
        for k in ("client.secret.rotated", "apiKey", "awsSecretKey"):
            assert attrs[k] == cs.REDACTED, k
        assert attrs["client.secret.expiration"] == "1800000000"
        assert attrs["access.token.claim"] == "true"

    def test_settings_named_like_secrets_stay_visible(self, kc):
        realm = cs.collect(kc)["sections"]["realm"]
        assert realm["passwordPolicy"] == "length(12)"
        assert realm["revokeRefreshToken"] is False
        assert realm["requiredCredentials"] == ["password"]
        kc.realm.update({"resetCredentialsFlow": "reset credentials", "webAuthnPolicyPasswordlessRpEntityName": "x"})
        realm = cs.collect(kc)["sections"]["realm"]
        assert realm["resetCredentialsFlow"] == "reset credentials"
        assert realm["webAuthnPolicyPasswordlessRpEntityName"] == "x"
        attrs = cs.collect(kc)["sections"]["clients"]["app"]["attributes"]
        assert attrs["client_credentials.use_refresh_token"] == "false"

    def test_long_values_are_hashed_and_volatile_ones_dropped(self, kc):
        snap = cs.collect(kc)["sections"]
        attrs = snap["clients"]["app"]["attributes"]
        assert attrs["saml.signing.certificate"].startswith("sha256:")
        assert "client.secret.creation.time" not in attrs
        assert "notBefore" not in snap["realm"] and "id" not in snap["realm"]
        assert "roles" not in snap["realm"]  # covered by its own section

    def test_shape(self, kc):
        snap = cs.collect(kc)["sections"]
        assert snap["clients"]["app"]["redirectUris"] == ["https://a.example/*", "https://b.example/*"]
        assert snap["clients"]["app"]["authenticationFlowBindingOverrides"] == {"browser": "browser otp"}
        assert "groups" in snap["clients"]["app"]["protocolMappers"]
        assert snap["roles"]["dept-admin"]["composites"] == ["realm-management:query-users"]
        assert "composites" not in snap["roles"]["plain"]
        assert set(snap["flows"]) == {"browser", "browser otp"}  # sub-flows come with their parent
        assert snap["flows"]["browser otp"]["steps"]["OTP Form"]["requirement"] == "REQUIRED"
        assert snap["flows"]["browser otp"]["order"] == ["OTP Form", "Condition - user role"]
        # The same component name under two subTypes stays two entries.
        assert {
            "ClientRegistrationPolicy/anonymous/Allowed Client Scopes",
            "ClientRegistrationPolicy/authenticated/Allowed Client Scopes",
        } <= set(snap["components"])

    def test_two_reads_of_an_unchanged_realm_are_equal(self, kc):
        a = cs.collect(kc)
        kc.realm["notBefore"] = 1800000000  # changes on "sign out all", not a setting
        kc.clients[0]["attributes"]["client.secret.creation.time"] = "1800000000"
        assert cs.diff(a, cs.collect(kc)) == []

    def test_unreadable_identity_providers_are_left_out(self, kc):
        kc.idp_status = 403
        snap = cs.collect(kc)
        assert "identity_providers" not in snap["sections"]
        assert snap["unavailable"] == ["identity_providers"]

    def test_a_section_that_went_away_is_left_out_not_fatal(self, kc):
        orig = kc._get

        def gone(path, params=None, deadline=None):
            if path == "/events/config":
                raise httpx.HTTPStatusError("x", request=httpx.Request("GET", "x"), response=httpx.Response(404))
            return orig(path, params, deadline)

        kc._get = gone
        snap = cs.collect(kc)
        assert "events" not in snap["sections"] and "events" in snap["unavailable"]

    def test_a_step_pointing_at_a_deleted_config(self, kc):
        del kc.auth_configs["cfg-1"]
        orig = kc._get

        def missing(path, params=None, deadline=None):
            if path.startswith("/authentication/config/"):
                raise httpx.HTTPStatusError("x", request=httpx.Request("GET", "x"), response=httpx.Response(404))
            return orig(path, params, deadline)

        kc._get = missing
        steps = cs.collect(kc)["sections"]["flows"]["browser otp"]["steps"]
        assert steps["Condition - user role"]["authenticationConfig"] == "<missing>"

    def test_components_with_the_same_name_under_different_parents(self, kc):
        kc.components += [
            {"id": "ldap-a", "name": "ldap-a", "providerType": "org.keycloak.storage.UserStorageProvider"},
            {"id": "ldap-b", "name": "ldap-b", "providerType": "org.keycloak.storage.UserStorageProvider"},
            {"id": "m-a", "parentId": "ldap-a", "name": "email", "providerType": "org.keycloak.storage.ldap.mappers.X"},
            {"id": "m-b", "parentId": "ldap-b", "name": "email", "providerType": "org.keycloak.storage.ldap.mappers.X"},
        ]
        comps = cs.collect(kc)["sections"]["components"]
        assert {"X/ldap-a/email", "X/ldap-b/email"} <= set(comps)

    def test_other_identity_provider_errors_propagate(self, kc):
        kc.idp_status = 500
        with pytest.raises(httpx.HTTPStatusError):
            cs.collect(kc)

    def test_truncated_list_is_incomplete(self, kc):
        kc.truncate = {"/clients"}
        with pytest.raises(cs.SnapshotIncomplete):
            cs.collect(kc)

    def test_past_deadline_is_incomplete(self, kc):
        with pytest.raises(cs.SnapshotIncomplete):
            cs.collect(kc, deadline=time.monotonic() - 1)


class TestDiff:
    def test_changes_are_listed_by_section_and_field(self, kc):
        a = cs.collect(kc)
        kc.clients[0]["redirectUris"].append("https://evil.example/*")
        kc.composites["r-admin"].append({"name": "realm-admin", "clientRole": True, "containerId": "c-rm"})
        kc.executions["browser otp"][0]["requirement"] = "DISABLED"
        kc.realm["failureFactor"] = 1000
        kc.clients.append({"id": "c-new", "clientId": "new-app"})
        rows = cs.diff(a, cs.collect(kc))
        where = {(r["section"], r["key"], r["change"]) for r in rows}
        assert ("clients", "app", "changed") in where
        assert ("clients", "new-app", "added") in where
        assert ("roles", "dept-admin", "changed") in where
        assert ("flows", "browser otp", "changed") in where
        assert ("realm", "", "changed") in where
        text = "\n".join(cs.format_diff(rows))
        assert "https://evil.example/*" in text
        assert "realm-management:realm-admin" in text
        assert "realm.failureFactor: 30 -> 1000" in text

    def test_authenticator_setting_change_is_seen(self, kc):
        a = cs.collect(kc)
        kc.auth_configs["cfg-1"]["config"]["condUserRole"] = "realm-admin"
        rows = cs.diff(a, cs.collect(kc))
        assert [(r["section"], r["key"]) for r in rows] == [("flows", "browser otp")]
        text = "\n".join(cs.format_diff(rows))
        assert (
            "flows/browser otp.steps.Condition - user role.authenticationConfig.config.condUserRole: "
            "staff -> realm-admin"
        ) in text

    def test_inserting_a_step_shows_only_that_step(self, kc):
        a = cs.collect(kc)
        kc.executions["browser otp"].insert(
            0, {"id": "e9", "level": 0, "index": 0, "displayName": "Cookie", "requirement": "ALTERNATIVE"}
        )
        lines = cs.format_diff(cs.diff(a, cs.collect(kc)))
        assert lines[0] == '- flows/browser otp.order: added ["Cookie"]'
        assert lines[1:] == [
            "- flows/browser otp.steps.Cookie.level: (absent) -> 0",
            "- flows/browser otp.steps.Cookie.requirement: (absent) -> ALTERNATIVE",
        ]

    def test_an_addition_to_a_long_list_is_visible(self, kc):
        kc.clients[0]["redirectUris"] = [f"https://host{i:02d}.example.org/callback/*" for i in range(20)]
        a = cs.collect(kc)
        kc.clients[0]["redirectUris"].append("https://zz.attacker.example/*")
        lines = cs.format_diff(cs.diff(a, cs.collect(kc)))
        assert lines == ['- clients/app.redirectUris: added ["https://zz.attacker.example/*"]']

    def test_removed_entry(self, kc):
        a = cs.collect(kc)
        kc.roles = kc.roles[:1]
        rows = cs.diff(a, cs.collect(kc))
        assert rows == [{"section": "roles", "key": "plain", "change": "removed", "fields": []}]

    def test_section_missing_on_one_side_is_not_compared(self, kc):
        a = cs.collect(kc)
        kc.idp_status = 403
        assert cs.diff(a, cs.collect(kc)) == []

    def test_long_diffs_are_capped(self):
        rows = [{"section": "roles", "key": f"r{i}", "change": "added", "fields": []} for i in range(50)]
        lines = cs.format_diff(rows, max_lines=5)
        assert len(lines) == 6 and "45 more" in lines[-1]


class TestStorage:
    def test_first_snapshot_of_the_day_is_kept(self, tmp_path, kc):
        today = date(2026, 10, 11)
        snap = cs.collect(kc)
        assert cs.save_if_first_today(str(tmp_path), today, snap) is True
        later = copy.deepcopy(snap)
        later["sections"]["realm"]["failureFactor"] = 1
        assert cs.save_if_first_today(str(tmp_path), today, later) is False
        stored = json.loads((tmp_path / cs.SNAPSHOT_DIR / "2026-10-11.json").read_text())
        assert stored["sections"]["realm"]["failureFactor"] == 30

    def test_a_racing_second_writer_does_not_replace_the_first(self, tmp_path, kc, monkeypatch):
        today = date(2026, 10, 11)
        snap = cs.collect(kc)
        assert cs.save_if_first_today(str(tmp_path), today, snap)
        later = copy.deepcopy(snap)
        later["sections"]["realm"]["failureFactor"] = 1
        # The second run checked before the first one published.
        monkeypatch.setattr(cs.Path, "exists", lambda self: False)
        assert cs.save_if_first_today(str(tmp_path), today, later) is False
        stored = json.loads((tmp_path / cs.SNAPSHOT_DIR / "2026-10-11.json").read_text())
        assert stored["sections"]["realm"]["failureFactor"] == 30
        assert not list((tmp_path / cs.SNAPSHOT_DIR).glob(".tmp-*"))

    def test_files_are_private(self, tmp_path, kc):
        cs.save_if_first_today(str(tmp_path), date(2026, 10, 11), cs.collect(kc))
        d = tmp_path / cs.SNAPSHOT_DIR
        assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(d / "2026-10-11.json").st_mode) == 0o600

    def test_baseline_is_the_latest_before_today(self, tmp_path, kc):
        snap = cs.collect(kc)
        for day in (1, 5, 11):
            cs.save_if_first_today(str(tmp_path), date(2026, 10, day), snap)
        d, _ = cs.load_baseline(str(tmp_path), date(2026, 10, 11))
        assert d == date(2026, 10, 5)
        d, _ = cs.load_baseline(str(tmp_path), date(2026, 10, 11), on=date(2026, 10, 1))
        assert d == date(2026, 10, 1)
        assert cs.load_baseline(str(tmp_path), date(2026, 10, 11), on=date(2026, 10, 2)) is None
        assert cs.load_baseline(str(tmp_path), date(2026, 10, 1)) is None

    def test_old_snapshots_are_pruned(self, tmp_path, kc):
        snap = cs.collect(kc)
        start = date(2026, 1, 1)
        for i in range(cs.KEEP_SNAPSHOTS + 3):
            cs.save_if_first_today(str(tmp_path), start + timedelta(days=i), snap)
        files = sorted(p.name for p in (tmp_path / cs.SNAPSHOT_DIR).glob("*.json"))
        assert len(files) == cs.KEEP_SNAPSHOTS and files[0] == "2026-01-04.json"

    def test_snapshot_of_another_format_is_not_a_baseline(self, tmp_path, kc):
        snap = {**cs.collect(kc), "version": cs.SNAPSHOT_VERSION + 1}
        cs.save_if_first_today(str(tmp_path), date(2026, 10, 10), snap)
        assert cs.load_baseline(str(tmp_path), date(2026, 10, 11)) is None


# ---- tools ----


def _brief_mocks(mock, kc, config_events=()):
    m = mock.return_value
    m.get_events_all.return_value = ([], False)
    m.get_session_stats.return_value = []

    def admin_events(**kw):
        return (list(config_events), False) if "REALM" in (kw.get("resource_types") or []) else ([], False)

    m.get_admin_events_all.side_effect = admin_events
    m._get.side_effect = kc._get
    m._paginate.side_effect = kc._paginate


class TestDailyBriefConfig:
    @patch.object(server, "_kc")
    def test_without_state_dir_only_admin_events(self, mock, kc, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_STATE_DIR", raising=False)
        _brief_mocks(mock, kc)
        out = server.daily_brief()
        assert "### Configuration" in out and "KEYCLOAK_STATE_DIR is not set" in out
        assert "## OK" in out

    @patch.object(server, "_kc")
    def test_first_run_records_a_baseline(self, mock, kc, tmp_path, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_STATE_DIR", str(tmp_path))
        _brief_mocks(mock, kc)
        out = server.daily_brief()
        assert "Baseline recorded today" in out and "## OK" in out
        assert list((tmp_path / cs.SNAPSHOT_DIR).glob("*.json"))

    @patch.object(server, "_kc")
    def test_change_since_yesterday_is_a_warning(self, mock, kc, tmp_path, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_STATE_DIR", str(tmp_path))
        yesterday = server._local_today() - timedelta(days=1)
        cs.save_if_first_today(str(tmp_path), yesterday, cs.collect(kc))
        kc.realm["bruteForceProtected"] = False
        _brief_mocks(mock, kc)
        out = server.daily_brief()
        assert "## WARNING" in out
        assert f"[CONFIG] 1 configuration item(s) changed since {yesterday.isoformat()} (realm)" in out
        assert "realm.bruteForceProtected: true -> false" in out

    @patch.object(server, "_kc")
    def test_unchanged(self, mock, kc, tmp_path, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_STATE_DIR", str(tmp_path))
        cs.save_if_first_today(str(tmp_path), server._local_today() - timedelta(days=1), cs.collect(kc))
        _brief_mocks(mock, kc)
        out = server.daily_brief()
        assert "No change since the snapshot of" in out and "## OK" in out

    @patch.object(server, "_kc")
    def test_config_admin_events_are_a_warning(self, mock, kc, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_STATE_DIR", raising=False)
        evt = {
            "time": int(time.time() * 1000) - 60_000,
            "operationType": "CREATE",
            "resourceType": "REALM_ROLE_MAPPING",
            "resourcePath": "users/u1/role-mappings/realm",
            "authDetails": {"userId": "admin-1", "ipAddress": "10.0.0.1"},
        }
        _brief_mocks(mock, kc, config_events=[evt])
        out = server.daily_brief()
        assert "[CONFIG] 1 configuration admin event(s)" in out
        assert "REALM_ROLE_MAPPING" in out

    @patch.object(server, "_kc")
    def test_section_unreadable_in_the_baseline_is_disclosed(self, mock, kc, tmp_path, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_STATE_DIR", str(tmp_path))
        kc.idp_status = 403
        cs.save_if_first_today(str(tmp_path), server._local_today() - timedelta(days=1), cs.collect(kc))
        kc.idp_status = 200  # readable today, but there is nothing to compare it with
        _brief_mocks(mock, kc)
        out = server.daily_brief()
        assert "Not compared (not readable then or now): identity_providers" in out

    @patch.object(server, "_kc")
    def test_configuration_is_read_before_the_events_under_one_deadline(self, mock, kc, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_STATE_DIR", raising=False)
        _brief_mocks(mock, kc)
        order = []
        m = mock.return_value
        admin = m.get_admin_events_all.side_effect
        m.get_admin_events_all.side_effect = lambda **kw: (order.append(("admin", kw["deadline"])), admin(**kw))[1]
        m.get_events_all.side_effect = lambda *a, **kw: (order.append(("events", kw["deadline"])), ([], False))[1]
        server.daily_brief()
        assert order[0][0] == "admin" and "REALM" in m.get_admin_events_all.call_args_list[0].kwargs["resource_types"]
        config_deadline = order[0][1]
        event_deadlines = {d for kind, d in order[1:]}
        # The events share one deadline; the configuration part stops earlier, within it.
        assert len(event_deadlines) == 1
        assert config_deadline <= min(event_deadlines)
        assert config_deadline <= time.monotonic() + server._CONFIG_BUDGET_SECONDS

    @patch.object(server, "_kc")
    def test_config_events_before_the_window_are_not_repeated(self, mock, kc, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_STATE_DIR", raising=False)
        old = {
            "time": int(time.time() * 1000) - 20 * 3600 * 1000,  # yesterday, before the 18 h window
            "operationType": "UPDATE",
            "resourceType": "REALM",
            "resourcePath": "",
            "authDetails": {"userId": "admin-1", "ipAddress": "10.0.0.1"},
        }
        _brief_mocks(mock, kc, config_events=[old])
        out = server.daily_brief(since_hours=18)
        assert "Configuration admin events: 0" in out and "[CONFIG]" not in out

    @patch.object(server, "_kc")
    def test_partial_read_keeps_the_previous_baseline(self, mock, kc, tmp_path, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_STATE_DIR", str(tmp_path))
        kc.truncate = {"/roles"}
        _brief_mocks(mock, kc)
        out = server.daily_brief()
        assert "[PARTIAL] configuration not compared" in out
        assert not list((tmp_path / cs.SNAPSHOT_DIR).glob("*.json"))

    @patch.object(server, "_kc")
    def test_config_failure_does_not_make_the_brief_critical(self, mock, kc, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("KEYCLOAK_STATE_DIR", str(tmp_path))
        _brief_mocks(mock, kc)
        mock.return_value._get.side_effect = RuntimeError("boom")
        out = server.daily_brief()
        assert "## CRITICAL" not in out
        assert "configuration check failed (RuntimeError)" in out
        assert "boom" not in out and "boom" in capsys.readouterr().err


class TestGetConfigChanges:
    def test_not_enabled(self, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_STATE_DIR", raising=False)
        assert "not enabled" in server.get_config_changes()

    def test_no_baseline_yet(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_STATE_DIR", str(tmp_path))
        assert server.get_config_changes().startswith("No configuration snapshot before today yet")

    def test_bad_date(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_STATE_DIR", str(tmp_path))
        assert "Invalid baseline_date" in server.get_config_changes("2026/10/01")

    @patch.object(server, "_kc")
    def test_lists_changes_and_never_writes(self, mock, kc, tmp_path, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_STATE_DIR", str(tmp_path))
        yesterday = server._local_today() - timedelta(days=1)
        cs.save_if_first_today(str(tmp_path), yesterday, cs.collect(kc))
        kc.clients[0]["enabled"] = False
        mock.return_value._get.side_effect = kc._get
        mock.return_value._paginate.side_effect = kc._paginate
        out = server.get_config_changes()
        assert out.startswith(f"Configuration changes since the snapshot of {yesterday.isoformat()}: 1")
        assert "clients/app.enabled: true -> false" in out
        assert len(list((tmp_path / cs.SNAPSHOT_DIR).glob("*.json"))) == 1

    @patch.object(server, "_kc")
    def test_lists_every_change_without_a_cap(self, mock, kc, tmp_path, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_STATE_DIR", str(tmp_path))
        cs.save_if_first_today(str(tmp_path), server._local_today() - timedelta(days=1), cs.collect(kc))
        kc.roles += [{"id": f"n{i}", "name": f"new-{i:03d}", "composite": False} for i in range(120)]
        mock.return_value._get.side_effect = kc._get
        mock.return_value._paginate.side_effect = kc._paginate
        out = server.get_config_changes()
        assert "roles/new-119: added" in out and "more" not in out
