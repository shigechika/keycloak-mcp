"""Tests for planned group-membership changes (plan_changes / apply_changes)."""

import time

import httpx
import pytest

from keycloak_mcp import server
from keycloak_mcp.group_changes import GroupWriteConfig, apply_changes, load_config, plan_changes

ROOT = "/Staff"
PROTECTED = "/Staff/HQ/IT/Admins"


class FakeKC:
    """In-memory stand-in for KeyCloakClient covering the calls group changes make."""

    def __init__(self):
        paths = [
            "/Staff",
            "/Staff/HQ",
            "/Staff/HQ/IT",
            "/Staff/HQ/IT/Admins",
            "/Staff/HQ/General",
            "/Staff/HQ/Safety",
            "/Staff/Arts",
            "/Staff/Arts/Office",
            "/Staff/Arts/Office/Accounting",
            "/Staff/Med",
            "/Staff/Med/Office",
            "/Staff/Med/Office/Students",
            "/Staff/Roleful",
            "/Staff/Roleful/Child",
            "/StaffOther",
            "/StaffOther/X",
        ]
        self.groups = {p: {"id": "g" + p.replace("/", "_"), "path": p, "name": p.rsplit("/", 1)[1]} for p in paths}
        self.roles = {self.groups["/Staff/Roleful"]["id"]: {"realmMappings": [{"name": "admin"}]}}
        self.users = {
            "alice": {"id": "u-alice", "username": "alice"},
            "bob": {"id": "u-bob", "username": "bob"},
        }
        self.members = {
            "u-alice": {self.groups["/Staff/HQ/Safety"]["id"]},
            "u-bob": {self.groups["/Staff/HQ/General"]["id"]},
        }
        self.writes = []
        self.fail_on = None  # (op, user_id) -> raise before committing
        self.commit_then_raise = None  # (op, user_id) -> commit, then raise (lost response)
        self.fail_reads_after_write = False
        self.before_read_hook = None
        self.truncate_reads = False
        self.username_override = None  # simulate a user store that ignores exact=true

    def _by_id(self, gid):
        return next(g for g in self.groups.values() if g["id"] == gid)

    def get_group_by_path(self, path, deadline=None):
        return self.groups.get(path)

    def get_group_role_mappings(self, gid, deadline=None):
        return self.roles.get(gid, {})

    def get_user_by_username(self, username, deadline=None):
        if self.username_override:
            return self.users.get(self.username_override)
        return self.users.get(username)

    def get_user_groups_all(self, user_id, deadline=None):
        if self.fail_reads_after_write and self.writes:
            raise httpx.ConnectError("read failed")
        if self.before_read_hook:
            self.before_read_hook(self, user_id)
        return [self._by_id(g) for g in sorted(self.members.get(user_id, set()))], self.truncate_reads

    def add_user_to_group(self, user_id, gid, deadline=None):
        if self.fail_on == ("add", user_id):
            raise httpx.HTTPStatusError("boom", request=httpx.Request("PUT", "x"), response=httpx.Response(500))
        self.writes.append(("add", user_id, gid))
        self.members.setdefault(user_id, set()).add(gid)
        if self.commit_then_raise == ("add", user_id):
            raise httpx.ReadTimeout("response lost")
        return 204

    def remove_user_from_group(self, user_id, gid, deadline=None):
        if self.fail_on == ("remove", user_id):
            raise httpx.HTTPStatusError("boom", request=httpx.Request("DELETE", "x"), response=httpx.Response(500))
        self.writes.append(("remove", user_id, gid))
        self.members.setdefault(user_id, set()).discard(gid)
        return 204


@pytest.fixture()
def cfg():
    return GroupWriteConfig(realm="test", root=ROOT, protected=(PROTECTED,), batch_max=5)


@pytest.fixture()
def kc():
    return FakeKC()


def _swap():
    return [
        {"username": "alice", "remove": "/Staff/HQ/Safety", "add": "/Staff/HQ/General"},
        {"username": "bob", "remove": "/Staff/HQ/General", "add": "/Staff/HQ/Safety"},
    ]


class TestLoadConfig:
    def test_unset_disables(self):
        assert load_config({}) is None

    @pytest.mark.parametrize("root", ["", "/", "Staff", "/Staff/", "//Staff", "/Staff//X"])
    def test_invalid_root_disables(self, root):
        assert load_config({"KEYCLOAK_GROUP_WRITE_ROOT": root}) is None

    def test_malformed_protected_entry_disables(self):
        assert load_config({"KEYCLOAK_GROUP_WRITE_ROOT": "/Staff", "KEYCLOAK_PROTECTED_GROUPS": "/ok;bad"}) is None

    def test_bad_batch_max_disables(self):
        assert load_config({"KEYCLOAK_GROUP_WRITE_ROOT": "/Staff", "KEYCLOAK_GROUP_BATCH_MAX": "x"}) is None
        assert load_config({"KEYCLOAK_GROUP_WRITE_ROOT": "/Staff", "KEYCLOAK_GROUP_BATCH_MAX": "0"}) is None

    def test_valid(self):
        c = load_config(
            {
                "KEYCLOAK_GROUP_WRITE_ROOT": " /Staff ",
                "KEYCLOAK_PROTECTED_GROUPS": " /Staff/A ; /Staff/B ;",
                "KEYCLOAK_REALM": "r",
            }
        )
        assert c == GroupWriteConfig(realm="r", root="/Staff", protected=("/Staff/A", "/Staff/B"), batch_max=30)


class TestPlan:
    def test_swap_is_ok_with_digest(self, kc, cfg):
        p = plan_changes(kc, cfg, _swap())
        assert p["ok"] is True and p["digest"]
        assert [r["ops"] for r in p["rows"]] == [["add", "remove"], ["add", "remove"]]
        assert kc.writes == []

    def test_already_moved_is_no_op(self, kc, cfg):
        kc.members["u-alice"] = {kc.groups["/Staff/HQ/General"]["id"]}
        p = plan_changes(kc, cfg, [_swap()[0]])
        assert p["ok"] is True and p["rows"][0]["status"] == "no-op"

    def test_remove_only_non_member_is_an_error(self, kc, cfg):
        p = plan_changes(kc, cfg, [{"username": "alice", "remove": "/Staff/HQ/General", "add": None}])
        assert p["ok"] is False and "not a member" in p["rows"][0]["status"]

    def test_already_in_add_without_remove_is_no_op(self, kc, cfg):
        p = plan_changes(kc, cfg, [{"username": "alice", "remove": "/Staff/HQ/General", "add": "/Staff/HQ/Safety"}])
        assert p["ok"] is True and p["rows"][0]["status"] == "no-op"

    def test_username_mismatch_is_refused(self, kc, cfg):
        kc.username_override = "bob"
        p = plan_changes(kc, cfg, [_swap()[0]])
        assert p["ok"] is False and "returned 'bob'" in p["rows"][0]["status"]

    def test_membership_cap_is_not_reported_as_time(self, kc, cfg):
        kc.truncate_reads = True
        p = plan_changes(kc, cfg, _swap())
        assert p["ok"] is False and p["digest"] is None
        assert "more direct groups" in p["errors"][0] and "time budget" not in p["errors"][0]

    def test_missing_protected_group_blocks_every_plan(self, kc):
        cfg = GroupWriteConfig(realm="test", root=ROOT, protected=("/Staff/HQ/it/Admins",), batch_max=5)
        p = plan_changes(kc, cfg, _swap())
        assert p["ok"] is False and "protected group(s) not found" in p["errors"][0]

    @pytest.mark.parametrize("blank", ["", "   "])
    def test_blank_side_is_null(self, kc, cfg, blank):
        p = plan_changes(kc, cfg, [{"username": "alice", "remove": blank, "add": "/Staff/HQ/General"}])
        assert p["ok"] is True and p["rows"][0]["remove"] is None

    @pytest.mark.parametrize("path", ["/Staff/../StaffOther/X", "/Staff/./HQ", "/Staff/HQ/.."])
    def test_dot_segments_are_invalid(self, kc, cfg, path):
        p = plan_changes(kc, cfg, [{"username": "alice", "remove": None, "add": path}])
        assert p["ok"] is False and "invalid" in p["rows"][0]["status"]

    def test_not_member_of_remove(self, kc, cfg):
        p = plan_changes(kc, cfg, [{"username": "alice", "remove": "/Staff/HQ/General", "add": "/Staff/Med/Office"}])
        assert p["ok"] is False and "not a member" in p["rows"][0]["status"]
        assert p["digest"] is None

    def test_unknown_user_and_group(self, kc, cfg):
        p = plan_changes(kc, cfg, [{"username": "carol", "remove": None, "add": "/Staff/HQ/Safetyy"}])
        status = p["rows"][0]["status"]
        assert "not found" in status and "carol" in status

    @pytest.mark.parametrize(
        "path, needle",
        [
            ("/StaffOther/X", "outside"),  # segment-wise root check, not a string prefix
            ("/Staff", "outside"),  # the root itself is not a member group
            (PROTECTED, "protected"),
            ("/Staff/Roleful/Child", "grants roles"),  # role inherited from an ancestor
            ("Staff/HQ", "invalid"),
        ],
    )
    def test_refused_targets(self, kc, cfg, path, needle):
        p = plan_changes(kc, cfg, [{"username": "alice", "remove": None, "add": path}])
        assert p["ok"] is False and needle in p["rows"][0]["status"]

    def test_duplicate_user(self, kc, cfg):
        p = plan_changes(kc, cfg, [_swap()[0], dict(_swap()[0])])
        assert p["ok"] is False and "duplicate" in p["rows"][1]["status"]

    def test_batch_limit(self, kc, cfg):
        p = plan_changes(kc, cfg, [{"username": f"u{i}", "add": "/Staff/HQ/Safety"} for i in range(6)])
        assert p["ok"] is False and "exceed" in p["errors"][0]

    @pytest.mark.parametrize("changes", [[], "x", None, [{"username": "alice"}], [{"username": "alice", "add": 1}]])
    def test_malformed_input(self, kc, cfg, changes):
        assert plan_changes(kc, cfg, changes)["ok"] is False

    def test_digest_changes_with_membership(self, kc, cfg):
        d1 = plan_changes(kc, cfg, _swap())["digest"]
        kc.members["u-alice"].add(kc.groups["/Staff/Med/Office/Students"]["id"])
        assert plan_changes(kc, cfg, _swap())["digest"] != d1

    def test_digest_changes_with_policy(self, kc, cfg):
        d1 = plan_changes(kc, cfg, _swap())["digest"]
        other = GroupWriteConfig(realm="test", root=ROOT, protected=(PROTECTED, "/Staff/Med"), batch_max=5)
        assert plan_changes(kc, other, _swap())["digest"] != d1

    def test_digest_ignores_row_order(self, kc, cfg):
        assert plan_changes(kc, cfg, _swap())["digest"] == plan_changes(kc, cfg, _swap()[::-1])["digest"]


class TestApply:
    def test_applies_add_before_remove_and_returns_reverse(self, kc, cfg):
        d = plan_changes(kc, cfg, _swap())["digest"]
        r = apply_changes(kc, cfg, _swap(), d)
        assert r["applied"] == "yes"
        assert [w[0] for w in kc.writes] == ["add", "remove", "add", "remove"]
        assert kc.members["u-alice"] == {kc.groups["/Staff/HQ/General"]["id"]}
        rev = {x["username"]: x for x in r["reverse"]}
        assert rev["alice"] == {"username": "alice", "remove": "/Staff/HQ/General", "add": "/Staff/HQ/Safety"}

    def test_digest_mismatch_writes_nothing(self, kc, cfg):
        d = plan_changes(kc, cfg, _swap())["digest"]
        kc.members["u-bob"].add(kc.groups["/Staff/Arts/Office/Accounting"]["id"])  # someone moved bob by hand
        r = apply_changes(kc, cfg, _swap(), d)
        assert r["applied"] == "no" and "digest" in r["reason"] and kc.writes == []

    def test_missing_digest_writes_nothing(self, kc, cfg):
        assert apply_changes(kc, cfg, _swap(), "")["applied"] == "no" and kc.writes == []

    def test_unexecutable_plan_writes_nothing(self, kc, cfg):
        bad = [{"username": "alice", "remove": None, "add": PROTECTED}]
        assert apply_changes(kc, cfg, bad, "anything")["applied"] == "no" and kc.writes == []

    def test_premise_change_mid_run_stops_and_reports_reverse(self, kc, cfg):
        d = plan_changes(kc, cfg, _swap())["digest"]
        reads = {"u-bob": 0}

        def hook(fake, user_id):
            # bob's group list is read by the re-plan inside apply (1st) and again right
            # before his first write (2nd). Someone adds him to Safety by hand in between.
            if user_id == "u-bob":
                reads["u-bob"] += 1
                if reads["u-bob"] == 2:
                    fake.members["u-bob"].add(fake.groups["/Staff/HQ/Safety"]["id"])

        kc.before_read_hook = hook
        r = apply_changes(kc, cfg, _swap(), d)
        assert r["applied"] == "partial"
        assert "memberships changed" in r["reason"]
        assert [x["username"] for x in r["reverse"]] == ["alice"]

    def test_error_after_first_user_is_partial(self, kc, cfg):
        d = plan_changes(kc, cfg, _swap())["digest"]
        kc.fail_on = ("add", "u-bob")
        r = apply_changes(kc, cfg, _swap(), d)
        assert r["applied"] == "partial" and "HTTPStatusError" in r["reason"]
        assert [x["username"] for x in r["reverse"]] == ["alice"]

    def test_error_on_first_write_is_no(self, kc, cfg):
        d = plan_changes(kc, cfg, _swap())["digest"]
        kc.fail_on = ("add", "u-alice")
        r = apply_changes(kc, cfg, _swap(), d)
        assert r["applied"] == "no" and r["reverse"] == []

    def test_destination_removed_between_add_and_remove_stops(self, kc, cfg):
        d = plan_changes(kc, cfg, [_swap()[0]])["digest"]
        general = kc.groups["/Staff/HQ/General"]["id"]
        reads = {"n": 0}

        def hook(fake, user_id):
            # alice: re-plan (1), before add (2), after add (3), before remove (4).
            if user_id == "u-alice":
                reads["n"] += 1
                if reads["n"] == 4:
                    fake.members["u-alice"].discard(general)  # another admin undoes the add

        kc.before_read_hook = hook
        r = apply_changes(kc, cfg, [_swap()[0]], d)
        assert r["applied"] == "partial" and "memberships changed" in r["reason"]
        assert [w[0] for w in kc.writes] == ["add"]  # the source group was NOT removed
        assert r["reverse"] == [{"username": "alice", "remove": "/Staff/HQ/General", "add": None}]

    def test_lost_response_after_commit_counts_as_done(self, kc, cfg):
        d = plan_changes(kc, cfg, [_swap()[0]])["digest"]
        kc.commit_then_raise = ("add", "u-alice")
        r = apply_changes(kc, cfg, [_swap()[0]], d)
        assert r["applied"] == "yes" and "took effect" in r["operations"][0]["result"]
        assert [w[0] for w in kc.writes] == ["add", "remove"]

    def test_user_is_not_started_without_time_for_all_ops(self, kc, cfg, monkeypatch):
        from keycloak_mcp import group_changes

        d = plan_changes(kc, cfg, [_swap()[0]])["digest"]
        monkeypatch.setattr(group_changes.time, "monotonic", lambda: 1000.0)
        # 15 s left: enough for one write (10 s reserve) but not for alice's two.
        r = apply_changes(kc, cfg, [_swap()[0]], d, deadline=1015.0)
        assert r["applied"] == "no" and "before this user" in r["reason"] and kc.writes == []

    def test_unconfirmable_write_is_unknown(self, kc, cfg):
        d = plan_changes(kc, cfg, [_swap()[0]])["digest"]
        kc.commit_then_raise = ("add", "u-alice")
        kc.fail_reads_after_write = True
        r = apply_changes(kc, cfg, [_swap()[0]], d)
        assert r["applied"] == "unknown" and "read-back failed" in r["reason"]
        assert r["reverse"][0]["remove"] == "/Staff/HQ/General"

    def test_no_write_starts_without_budget_left(self, kc, cfg):
        d = plan_changes(kc, cfg, _swap())["digest"]
        r = apply_changes(kc, cfg, _swap(), d, deadline=time.monotonic() + 1)
        assert r["applied"] == "no" and "time budget" in r["reason"] and kc.writes == []

    def test_destination_vetted_once_within_ttl(self, kc, cfg):
        calls = {"n": 0}
        orig = kc.get_group_role_mappings

        def counting(gid, deadline=None):
            calls["n"] += 1
            return orig(gid)

        kc.users["carol"] = {"id": "u-carol", "username": "carol"}
        kc.members["u-carol"] = set()
        changes = [{"username": u, "remove": None, "add": "/Staff/Med/Office"} for u in ("alice", "carol")]
        d = plan_changes(kc, cfg, changes)["digest"]
        kc.get_group_role_mappings = counting
        r = apply_changes(kc, cfg, changes, d)
        assert r["applied"] == "yes"
        # re-plan vets once (cached), then one fresh re-vet for the first add only: 2 x 3 ancestors
        assert calls["n"] == 6

    def test_reserve_is_checked_again_after_pre_write_reads(self, kc, cfg, monkeypatch):
        from keycloak_mcp import group_changes

        d = plan_changes(kc, cfg, [_swap()[0]])["digest"]
        clock = {"t": 1000.0}
        monkeypatch.setattr(group_changes.time, "monotonic", lambda: clock["t"])
        reads = {"n": 0}

        def hook(fake, user_id):
            # re-plan (1), before the add (2): the second read is slow and eats the reserve.
            reads["n"] += 1
            if reads["n"] == 2:
                clock["t"] += 25

        kc.before_read_hook = hook
        r = apply_changes(kc, cfg, [_swap()[0]], d, deadline=1030.0)
        assert r["applied"] == "no" and "time budget" in r["reason"] and kc.writes == []

    def test_role_attached_to_destination_mid_run_stops(self, kc, cfg):
        d = plan_changes(kc, cfg, _swap())["digest"]
        safety = kc.groups["/Staff/HQ/Safety"]["id"]
        reads = {"n": 0}

        def hook(fake, user_id):
            # alice: re-plan (1); bob: re-plan (2); alice before add (3), after add (4).
            # Someone attaches a role to bob's destination after alice's add.
            reads["n"] += 1
            if reads["n"] == 4:
                fake.roles[safety] = {"realmMappings": [{"name": "admin"}]}

        kc.before_read_hook = hook
        r = apply_changes(kc, cfg, _swap(), d)
        assert r["applied"] == "partial" and "no longer writable" in r["reason"]
        assert ("add", "u-bob", safety) not in kc.writes

    def test_no_op_rows_are_skipped(self, kc, cfg):
        kc.members["u-alice"] = {kc.groups["/Staff/HQ/General"]["id"]}
        changes = [_swap()[0]]
        d = plan_changes(kc, cfg, changes)["digest"]
        r = apply_changes(kc, cfg, changes, d)
        assert r["applied"] == "yes" and kc.writes == [] and r["reverse"] == []


class TestRegistration:
    def test_not_registered_without_root(self, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_GROUP_WRITE_ROOT", raising=False)
        s = server._Server("t")
        assert server.register_group_tools(s) is False

    def test_registered_with_root(self, monkeypatch):
        import asyncio

        monkeypatch.setenv("KEYCLOAK_GROUP_WRITE_ROOT", "/Staff")
        s = server._Server("t")
        assert server.register_group_tools(s) is True
        names = {t.name for t in asyncio.run(s.list_tools())}
        assert {"plan_group_changes", "apply_group_changes"} <= names

    def test_direct_call_refused_when_disabled(self, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_GROUP_WRITE_ROOT", raising=False)
        with pytest.raises(server.ToolError, match="not enabled"):
            server.apply_group_changes([], "x")
