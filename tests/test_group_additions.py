"""Tests for additions to role-carrying groups (group_additions.scan and the daily_brief part)."""

import json
import time
from unittest.mock import patch

import httpx

from keycloak_mcp import group_additions as ga
from keycloak_mcp import server


class FakeKC:
    def __init__(self):
        paths = ["/Staff", "/Staff/HQ", "/Staff/HQ/IT", "/Staff/Arts", "/Staff/Arts/Office", "/Staff/Plain"]
        self.groups = {p: {"id": "g" + p.replace("/", "_"), "path": p, "name": p.rsplit("/", 1)[1]} for p in paths}
        rm = {"id": "c-rm", "clientId": "realm-management"}
        self.clients = {"c-rm": rm}
        self.roles = {
            self.groups["/Staff/HQ/IT"]["id"]: {
                "clientMappings": {"realm-management": {"mappings": [{"id": "r-ra", "name": "realm-admin"}]}}
            },
            self.groups["/Staff/Arts"]["id"]: {
                "realmMappings": [{"id": "r-dept", "name": "arts-admin", "composite": True}]
            },
        }
        self.composites = {
            "r-dept": [{"id": "r-q", "name": "query-users", "clientRole": True, "containerId": "c-rm"}],
        }
        self.deleted = set()

    def get_group_by_path(self, path, deadline=None):
        return self.groups.get(path)

    def get_group(self, gid, deadline=None):
        if gid in self.deleted:
            raise httpx.HTTPStatusError("x", request=httpx.Request("GET", "x"), response=httpx.Response(404))
        return next(g for g in self.groups.values() if g["id"] == gid)

    def get_group_role_mappings(self, gid, deadline=None):
        return self.roles.get(gid, {})

    def get_role_composites(self, role_id, deadline=None):
        return self.composites.get(role_id, [])

    def get_client(self, cid, deadline=None):
        return self.clients.get(cid, {})


def _add(kc, user, path, *, rep=True, t=None, op="CREATE", rtype="GROUP_MEMBERSHIP"):
    g = kc.groups[path]
    e = {
        "time": t if t is not None else int(time.time() * 1000),
        "operationType": op,
        "resourceType": rtype,
        "resourcePath": f"users/{user}/groups/{g['id']}",
        "authDetails": {"userId": "admin-1", "ipAddress": "10.0.0.1"},
    }
    if rep:
        e["representation"] = json.dumps({"id": g["id"], "path": path})
    return e


def test_admin_and_department_roles_are_told_apart():
    kc = FakeKC()
    out = ga.scan(kc, [_add(kc, "u1", "/Staff/Arts/Office"), _add(kc, "u2", "/Staff/HQ/IT")])
    assert out["complete"] and out["checked"] == 2
    first, second = out["rows"]
    # Administrative additions come first.
    assert first["group"] == "/Staff/HQ/IT" and first["admin_roles"] == ["realm-management:realm-admin"]
    # A department admin role expands to read-only realm-management roles: listed, not administrative.
    assert second["group"] == "/Staff/Arts/Office"
    assert second["roles"] == ["arts-admin", "realm-management:query-users"]
    assert second["admin_roles"] == []


def test_groups_without_roles_and_other_events_are_left_out():
    kc = FakeKC()
    events = [
        _add(kc, "u1", "/Staff/Plain"),
        _add(kc, "u2", "/Staff/HQ/IT", op="DELETE"),
        _add(kc, "u3", "/Staff/HQ/IT", rtype="USER"),
    ]
    out = ga.scan(kc, events)
    assert out["rows"] == [] and out["checked"] == 1


def test_group_is_identified_by_id_not_by_the_path_in_the_event():
    kc = FakeKC()
    e = _add(kc, "u1", "/Staff/HQ/IT")
    # Renamed since the event: the event still names the old path, now taken by a roleless group.
    it = kc.groups.pop("/Staff/HQ/IT")
    kc.groups["/Staff/HQ/Systems"] = {**it, "path": "/Staff/HQ/Systems", "name": "Systems"}
    kc.groups["/Staff/HQ/IT"] = {"id": "g-new", "path": "/Staff/HQ/IT", "name": "IT"}
    out = ga.scan(kc, [e])
    assert out["rows"][0]["group"] == "/Staff/HQ/Systems"
    assert out["rows"][0]["admin_roles"] == ["realm-management:realm-admin"]


def test_rows_are_ordered_when_the_scan_stops_early(monkeypatch):
    kc = FakeKC()
    events = [_add(kc, "u1", "/Staff/Arts/Office"), _add(kc, "u2", "/Staff/HQ/IT"), _add(kc, "u3", "/Staff/Plain")]
    calls = {"n": 0}

    def stop_after_two(deadline):
        calls["n"] += 1
        return calls["n"] > 2

    monkeypatch.setattr(ga, "past_deadline", stop_after_two)
    out = ga.scan(kc, events, deadline=0.0)
    assert out["complete"] is False
    assert [r["group"] for r in out["rows"]] == ["/Staff/HQ/IT", "/Staff/Arts/Office"]


def test_a_deleted_group_is_counted_as_unresolved():
    kc = FakeKC()
    kc.deleted.add(kc.groups["/Staff/HQ/IT"]["id"])
    out = ga.scan(kc, [_add(kc, "u1", "/Staff/HQ/IT", rep=False)])
    assert out["rows"] == [] and out["unresolved"] == 1


def test_out_of_time_is_incomplete():
    kc = FakeKC()
    out = ga.scan(kc, [_add(kc, "u1", "/Staff/HQ/IT")], deadline=time.monotonic() - 1)
    assert out["complete"] is False and out["checked"] == 0


def test_is_admin_role():
    assert ga.is_admin_role("realm-management:realm-admin")
    assert ga.is_admin_role("realm-management:manage-users")
    assert not ga.is_admin_role("realm-management:view-users")
    assert not ga.is_admin_role("realm-management:query-groups")
    assert not ga.is_admin_role("other-client:manage-users")
    assert not ga.is_admin_role("センター管理者")


@patch.object(server, "_kc")
def test_daily_brief_flags_administrative_additions(mock, monkeypatch):
    monkeypatch.delenv("KEYCLOAK_STATE_DIR", raising=False)
    kc = FakeKC()
    m = mock.return_value
    for name in ("get_group_by_path", "get_group", "get_group_role_mappings", "get_role_composites", "get_client"):
        getattr(m, name).side_effect = getattr(kc, name)
    m.get_events_all.return_value = ([], False)
    m.get_session_stats.return_value = []
    m.get_user_by_id.side_effect = lambda uid, deadline=None: {"username": f"{uid}@example.org"}
    old = _add(kc, "u0", "/Staff/HQ/IT", t=int(time.time() * 1000) - 30 * 3600 * 1000)

    def admin_events(**kw):
        if kw.get("resource_types") == ["GROUP_MEMBERSHIP"]:
            return [old, _add(kc, "u1", "/Staff/HQ/IT"), _add(kc, "u2", "/Staff/Arts/Office")], False
        return [], False

    m.get_admin_events_all.side_effect = admin_events
    out = server.daily_brief(since_hours=18)
    assert "## WARNING" in out
    assert "[PRIVILEGE] 1 addition(s) to groups that grant administrative roles (/Staff/HQ/IT)" in out
    assert "Additions to groups that carry roles: 2 (administrative: 1) of 2 group additions" in out
    assert "u1@example.org -> /Staff/HQ/IT  roles: realm-management:realm-admin" in out
    assert "u2@example.org -> /Staff/Arts/Office  roles: arts-admin" in out
    assert "u0@example.org" not in out  # before the window


@patch.object(server, "_kc")
def test_daily_brief_survives_a_failing_check(mock, monkeypatch, capsys):
    monkeypatch.delenv("KEYCLOAK_STATE_DIR", raising=False)
    m = mock.return_value
    m.get_events_all.return_value = ([], False)
    m.get_session_stats.return_value = []

    def admin_events(**kw):
        if kw.get("resource_types") == ["GROUP_MEMBERSHIP"]:
            raise RuntimeError("boom")
        return [], False

    m.get_admin_events_all.side_effect = admin_events
    out = server.daily_brief()
    assert "## CRITICAL" not in out and "group-addition check failed (RuntimeError)" in out
    assert "boom" in capsys.readouterr().err
