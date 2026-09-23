"""Tests for the day-window batch report (spray_report / `keycloak-mcp spray-report`)."""

import json
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from keycloak_mcp import __main__ as cli
from keycloak_mcp import server

TOKYO = ZoneInfo("Asia/Tokyo")


def ms(y, mo, d, h=0, mi=0, s=0, milli=0, tz=TOKYO):
    return int(datetime(y, mo, d, h, mi, s, milli * 1000, tzinfo=tz).timestamp() * 1000)


class FakeSites:
    def __init__(self, available=True):
        self.available = available

    def classify(self, ip):
        return "campus" if ip.startswith("10.") else None


class FakeKC:
    def __init__(self, success, failure, truncated=False, users=None):
        self.events = {"LOGIN": success, "LOGIN_ERROR": failure}
        self.truncated = truncated
        self.users = users or {}
        self.calls = []

    def get_events_all(self, event_type, **kw):
        self.calls.append((event_type, kw))
        return list(self.events[event_type]), self.truncated

    def get_user_by_id(self, uid):
        return {"username": self.users[uid]} if uid in self.users else None


def fail(ip, user, t, error="invalid_user_credentials"):
    e = {"type": "LOGIN_ERROR", "ipAddress": ip, "time": t, "error": error}
    if user is not None:
        e["details"] = {"username": user}
    return e


def ok(ip, t, uid="u-1"):
    return {"type": "LOGIN", "ipAddress": ip, "time": t, "userId": uid, "clientId": "portal"}


@pytest.fixture()
def fake(monkeypatch):
    def install(success=(), failure=(), truncated=False, users=None, sites=True):
        kc = FakeKC(list(success), list(failure), truncated, users)
        monkeypatch.setattr(server, "_kc", lambda: kc)
        monkeypatch.setattr(server, "_site_classifier", lambda: FakeSites(sites))
        monkeypatch.delenv("KEYCLOAK_KNOWN_EGRESS", raising=False)
        return kc

    return install


def test_window_is_half_open_on_both_ends(fake):
    kc = fake(
        failure=[
            fail("203.0.113.1", "a", ms(2026, 9, 16, 23, 59, 59, 999)),  # previous day: out
            fail("203.0.113.1", "b", ms(2026, 9, 17, 0, 0, 0, 0)),  # first instant: in
            fail("203.0.113.1", "c", ms(2026, 9, 17, 23, 59, 59, 999)),  # last instant: in
            fail("203.0.113.1", "d", ms(2026, 9, 18, 0, 0, 0, 0)),  # next day: out
        ]
    )
    r = server.spray_report("2026-09-17", tz="Asia/Tokyo")
    assert r["coverage"]["failure_events"] == 2
    assert r["coverage"]["dropped_outside_window"] == 2
    assert r["external_totals"] == {"203.0.113.1": {"successes": 0, "failures": 2}}
    assert r["window"]["since"] == "2026-09-17T00:00:00+09:00"
    assert r["window"]["until"] == "2026-09-18T00:00:00+09:00"
    assert r["coverage"]["tail_gap_seconds"] == 0
    # KeyCloak is asked for the day and the next one, exclusive end
    assert kc.calls[0][1]["date_from"] == "2026-09-17"
    assert kc.calls[0][1]["date_to"] == "2026-09-18"


def test_window_follows_tz_not_host_zone(fake):
    # 2026-09-17 00:30 JST is still 09-16 in UTC: the UTC report must not include it.
    fake(failure=[fail("203.0.113.1", "a", ms(2026, 9, 17, 0, 30))])
    assert server.spray_report("2026-09-17", tz="UTC")["coverage"]["failure_events"] == 0
    assert server.spray_report("2026-09-16", tz="UTC")["coverage"]["failure_events"] == 1


def test_totals_count_failures_without_username(fake):
    t = ms(2026, 9, 17, 12)
    fake(failure=[fail("203.0.113.9", None, t), fail("203.0.113.9", None, t + 1), fail("10.0.0.1", None, t)])
    r = server.spray_report("2026-09-17", tz="Asia/Tokyo")
    # the per-user rows cannot see these, the totals must
    assert all(row["ip"] != "203.0.113.9" for row in r["external_ips"])
    assert r["external_totals"] == {"203.0.113.9": {"successes": 0, "failures": 2}}


def test_rows_include_single_user_ips(fake):
    t = ms(2026, 9, 17, 12)
    fake(failure=[fail("203.0.113.2", "solo", t)])
    r = server.spray_report("2026-09-17", tz="Asia/Tokyo")
    assert [row["ip"] for row in r["external_ips"]] == ["203.0.113.2"]


def test_spray_verdict_matches_rolling_analysis(fake):
    t = ms(2026, 9, 17, 3)
    failure = [fail("203.0.113.5", f"user{i}", t + i) for i in range(12)]
    success = [ok("203.0.113.5", t + 100, uid="u-1")]
    fake(success=success, failure=failure, users={"u-1": "Victim"})
    r = server.spray_report("2026-09-17", tz="Asia/Tokyo")
    assert [row["ip"] for row in r["spray"]] == ["203.0.113.5"]
    assert r["spray"][0]["breached"][0]["username"] == "victim"
    assert r["fetch_complete"] is True and r["resolve_complete"] is True
    assert r["schema"] == server.SPRAY_REPORT_SCHEMA


def test_truncated_fetch_is_not_complete(fake):
    fake(failure=[fail("203.0.113.1", "a", ms(2026, 9, 17, 1))], truncated=True)
    assert server.spray_report("2026-09-17", tz="Asia/Tokyo")["fetch_complete"] is False


def test_unresolved_flagged_success_is_not_resolve_complete(fake):
    t = ms(2026, 9, 17, 3)
    failure = [fail("203.0.113.5", f"user{i}", t + i) for i in range(12)]
    fake(success=[ok("203.0.113.5", t + 100, uid="u-gone")], failure=failure)
    assert server.spray_report("2026-09-17", tz="Asia/Tokyo")["resolve_complete"] is False


def test_missing_sites_is_an_error(fake):
    fake(sites=False)
    with pytest.raises(server.SprayReportConfigError):
        server.spray_report("2026-09-17", tz="Asia/Tokyo")
    assert server.spray_report("2026-09-17", tz="Asia/Tokyo", require_sites=False)["sites_configured"] is False


def test_tz_day_across_dst_is_not_24_hours(fake):
    fake()
    r = server.spray_report("2026-03-08", tz="America/New_York")
    assert r["window"]["since"] == "2026-03-08T00:00:00-05:00"
    assert r["window"]["until"] == "2026-03-09T00:00:00-04:00"


def test_local_zone_uses_rules_for_that_date(fake, monkeypatch):
    import time

    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset is POSIX-only")
    monkeypatch.setenv("TZ", "America/New_York")
    time.tzset()
    try:
        fake()
        # reporting a January day from any season must use EST (-05:00)
        assert server.spray_report("2026-01-15")["window"]["since"] == "2026-01-15T00:00:00-05:00"
        assert server.spray_report("2026-03-08")["window"]["until"] == "2026-03-09T00:00:00-04:00"
    finally:
        monkeypatch.undo()
        time.tzset()


def test_bad_known_egress_is_an_error(fake, monkeypatch):
    fake()
    monkeypatch.setenv("KEYCLOAK_KNOWN_EGRESS", "192.0.2.0/24,not-a-cidr")
    with pytest.raises(server.SprayReportConfigError, match="not-a-cidr"):
        server.spray_report("2026-09-17", tz="Asia/Tokyo")


@pytest.mark.parametrize("day,tz", [("2026-13-01", "Asia/Tokyo"), ("2026-09-17", "Mars/Olympus")])
def test_bad_inputs_are_errors(fake, day, tz):
    fake()
    with pytest.raises(server.SprayReportConfigError):
        server.spray_report(day, tz=tz)


def test_cli_prints_json_only(fake, monkeypatch, capsys):
    fake(failure=[fail("203.0.113.1", "a", ms(2026, 9, 17, 1))])
    monkeypatch.setattr(sys, "argv", ["keycloak-mcp", "spray-report", "--date", "2026-09-17", "--tz", "Asia/Tokyo"])
    with pytest.raises(SystemExit) as ex:
        cli.main()
    assert ex.value.code == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["window"]["date"] == "2026-09-17"


def test_cli_config_error_writes_nothing_to_stdout(fake, monkeypatch, capsys):
    fake(sites=False)
    monkeypatch.setattr(sys, "argv", ["keycloak-mcp", "spray-report", "--date", "2026-09-17"])
    with pytest.raises(SystemExit) as ex:
        cli.main()
    assert ex.value.code == 2
    out = capsys.readouterr()
    assert out.out == "" and "SITES" in out.err


def test_no_arguments_still_starts_the_stdio_server(monkeypatch):
    called = {}
    monkeypatch.setattr(cli.mcp, "run", lambda transport: called.setdefault("transport", transport))
    monkeypatch.setattr(sys, "argv", ["keycloak-mcp"])
    cli.main()
    assert called == {"transport": "stdio"}
