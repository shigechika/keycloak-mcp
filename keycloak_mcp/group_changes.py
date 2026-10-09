"""Planned, verified group-membership changes (e.g. staff transfers between departments).

Two operations share one validation path:

* :func:`plan_changes` resolves every user and group, reads each user's current direct
  memberships, decides per row what would change, and returns a ``digest`` that covers the
  resolved IDs, the current memberships and the policy in force.
* :func:`apply_changes` recomputes the plan, refuses unless the digest matches the one the
  caller approved, then performs add-before-remove per user, re-reading memberships before
  every write and reading back after it.

The write path is opt-in: the tools are registered only when
``KEYCLOAK_GROUP_WRITE_ROOT`` is set (see :func:`load_config`), so a deployment that shares
this binary without that variable (for example a gateway with no approval step) never
exposes them. Writes are confined to groups under that root that carry no realm or client
role mappings (on the group or any ancestor) and are not listed in
``KEYCLOAK_PROTECTED_GROUPS``.

Restoring a membership does not undo what happened while it was wrong (sessions, tokens,
mail). The reverse changes returned by :func:`apply_changes` are a proposal for a human to
approve, never executed automatically.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any

DIGEST_VERSION = 1
BATCH_MAX_DEFAULT = 30

OK = "ok"
NO_OP = "no-op"


@dataclass(frozen=True)
class GroupWriteConfig:
    """Policy for group-membership writes, read from the environment."""

    realm: str
    root: str
    protected: tuple[str, ...] = field(default_factory=tuple)
    batch_max: int = BATCH_MAX_DEFAULT

    def policy(self) -> dict[str, Any]:
        """The policy fields that a digest must cover."""
        return {
            "realm": self.realm,
            "root": self.root,
            "protected": sorted(self.protected),
            "batch_max": self.batch_max,
        }


def _valid_path(path: str) -> bool:
    """An absolute group path with non-empty segments: ``/a``, ``/a/b``. Not ``/``, ``//x``, ``/x/``."""
    if not path.startswith("/") or path == "/" or path.endswith("/"):
        return False
    return all(seg.strip() == seg and seg for seg in path[1:].split("/"))


def load_config(environ: dict[str, str] | None = None) -> GroupWriteConfig | None:
    """Group-write policy from the environment, or ``None`` when writes are not enabled.

    ``KEYCLOAK_GROUP_WRITE_ROOT`` must be a valid absolute group path other than ``/``; when it
    is unset, empty or malformed the group tools are not registered and any direct call is
    refused. ``KEYCLOAK_PROTECTED_GROUPS`` is a ``;``-separated list of full paths (malformed
    entries make the whole config invalid, so a typo cannot silently drop a protection).
    ``KEYCLOAK_GROUP_BATCH_MAX`` caps rows per call (default 30).
    """
    env = os.environ if environ is None else environ
    root = env.get("KEYCLOAK_GROUP_WRITE_ROOT", "").strip()
    if not root or not _valid_path(root):
        return None
    protected: list[str] = []
    for entry in env.get("KEYCLOAK_PROTECTED_GROUPS", "").split(";"):
        entry = entry.strip()
        if not entry:
            continue
        if not _valid_path(entry):
            return None
        protected.append(entry)
    try:
        batch_max = int(env.get("KEYCLOAK_GROUP_BATCH_MAX", str(BATCH_MAX_DEFAULT)))
    except ValueError:
        return None
    if batch_max <= 0:
        return None
    return GroupWriteConfig(
        realm=env.get("KEYCLOAK_REALM", "master"),
        root=root,
        protected=tuple(protected),
        batch_max=batch_max,
    )


def _within(path: str, ancestor: str) -> bool:
    """True when ``path`` is ``ancestor`` or below it (segment-wise, so ``/a`` does not contain ``/ab``)."""
    return path == ancestor or path.startswith(ancestor + "/")


def _ancestors(path: str) -> list[str]:
    """``/a/b/c`` -> ``["/a", "/a/b", "/a/b/c"]``."""
    segs = path[1:].split("/")
    return ["/" + "/".join(segs[: i + 1]) for i in range(len(segs))]


class _Resolver:
    """Resolve and vet group paths once per call."""

    def __init__(self, kc, cfg: GroupWriteConfig):
        self.kc = kc
        self.cfg = cfg
        self._groups: dict[str, dict | None] = {}
        self._has_roles: dict[str, bool] = {}

    def group(self, path: str) -> dict | None:
        """The group at exactly ``path`` (the returned ``path`` must match), else ``None``."""
        if path not in self._groups:
            g = self.kc.get_group_by_path(path)
            self._groups[path] = g if g and g.get("path") == path and g.get("id") else None
        return self._groups[path]

    def _carries_roles(self, group_id: str) -> bool:
        if group_id not in self._has_roles:
            rm = self.kc.get_group_role_mappings(group_id) or {}
            self._has_roles[group_id] = bool(rm.get("realmMappings")) or bool(rm.get("clientMappings"))
        return self._has_roles[group_id]

    def vet(self, path: str) -> tuple[dict | None, str]:
        """Resolve ``path`` and check it may be written. Returns ``(group, problem)``."""
        if not _valid_path(path):
            return None, f"invalid group path '{path}'"
        if not _within(path, self.cfg.root) or path == self.cfg.root:
            return None, f"'{path}' is outside the writable root {self.cfg.root}"
        for prot in self.cfg.protected:
            if _within(path, prot):
                return None, f"'{path}' is protected"
        g = self.group(path)
        if g is None:
            return None, f"group '{path}' not found"
        # Members of a subgroup inherit the roles of every ancestor group, so check them all.
        for anc in _ancestors(path):
            ag = self.group(anc)
            if ag is None:
                return None, f"ancestor group '{anc}' not found"
            if self._carries_roles(ag["id"]):
                return None, f"'{path}' grants roles (via '{anc}'); not writable here"
        return g, ""


def _norm_change(raw: Any) -> tuple[dict[str, Any] | None, str]:
    if not isinstance(raw, dict):
        return None, "each change must be an object with username, remove, add"
    username = raw.get("username")
    if not isinstance(username, str) or not username.strip():
        return None, "username is required"
    out: dict[str, Any] = {"username": username.strip()}
    for key in ("remove", "add"):
        val = raw.get(key)
        if val in (None, ""):
            out[key] = None
        elif isinstance(val, str):
            out[key] = val.strip()
        else:
            return None, f"{key} must be a group path or null"
    if out["remove"] is None and out["add"] is None:
        return None, "nothing to change (remove and add are both empty)"
    if out["remove"] is not None and out["remove"] == out["add"]:
        return None, "remove and add are the same group"
    return out, ""


def _digest(cfg: GroupWriteConfig, rows: list[dict]) -> str:
    payload = {
        "version": DIGEST_VERSION,
        "policy": cfg.policy(),
        "rows": [
            {
                "username": r["username"],
                "user_id": r.get("user_id"),
                "remove": [r.get("remove"), r.get("remove_id")],
                "add": [r.get("add"), r.get("add_id")],
                "current": sorted(r.get("current_ids", [])),
                "ops": r.get("ops", []),
                "status": r["status"],
            }
            for r in sorted(rows, key=lambda r: r["username"].lower())
        ],
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def plan_changes(kc, cfg: GroupWriteConfig, changes: Any) -> dict[str, Any]:
    """Validate ``changes`` against KeyCloak without writing anything.

    Returns ``{"ok", "digest", "rows", "errors"}``. ``ok`` is True only when every row is
    ``ok`` or ``no-op``. Each row carries the resolved IDs, the user's current direct groups,
    the operations that would run (``["add", "remove"]`` subset, in execution order) and a
    ``status`` that is ``ok``, ``no-op`` or a reason the row cannot run.
    """
    if not isinstance(changes, list) or not changes:
        return {"ok": False, "digest": None, "rows": [], "errors": ["changes must be a non-empty list"]}
    if len(changes) > cfg.batch_max:
        return {
            "ok": False,
            "digest": None,
            "rows": [],
            "errors": [f"{len(changes)} changes exceed the per-call limit of {cfg.batch_max}"],
        }

    resolver = _Resolver(kc, cfg)
    rows: list[dict] = []
    seen: set[str] = set()
    for raw in changes:
        norm, problem = _norm_change(raw)
        if norm is None:
            rows.append({"username": str(raw.get("username", "")) if isinstance(raw, dict) else "", "status": problem})
            continue
        row: dict[str, Any] = dict(norm)
        key = norm["username"].lower()
        if key in seen:
            row["status"] = "duplicate user in this batch"
            rows.append(row)
            continue
        seen.add(key)

        problems = []
        for side in ("remove", "add"):
            if row[side] is not None:
                g, why = resolver.vet(row[side])
                if g is None:
                    problems.append(why)
                else:
                    row[f"{side}_id"] = g["id"]
        user = kc.get_user_by_username(norm["username"])
        if not user:
            problems.append(f"user '{norm['username']}' not found")
        else:
            row["user_id"] = user["id"]
            current = kc.get_user_groups_all(user["id"])
            row["current_ids"] = sorted(g["id"] for g in current)
            row["current"] = sorted(g.get("path", g.get("name", "")) for g in current)
        if problems:
            row["status"] = "; ".join(problems)
            rows.append(row)
            continue

        cur = set(row["current_ids"])
        need_add = row["add"] is not None and row["add_id"] not in cur
        has_remove = row["remove"] is not None and row["remove_id"] in cur
        if row["remove"] is not None and not has_remove and need_add:
            row["status"] = f"not a member of '{row['remove']}'"
        else:
            row["ops"] = (["add"] if need_add else []) + (["remove"] if has_remove else [])
            row["status"] = OK if row["ops"] else NO_OP
            after = (cur - ({row["remove_id"]} if has_remove else set())) | ({row["add_id"]} if need_add else set())
            row["after_ids"] = sorted(after)
        rows.append(row)

    ok = all(r["status"] in (OK, NO_OP) for r in rows)
    return {"ok": ok, "digest": _digest(cfg, rows) if ok else None, "rows": rows, "errors": []}


def _ids(kc, user_id: str) -> set[str]:
    return {g["id"] for g in kc.get_user_groups_all(user_id)}


def apply_changes(kc, cfg: GroupWriteConfig, changes: Any, expected_digest: str) -> dict[str, Any]:
    """Re-plan, require ``expected_digest``, then apply add-before-remove per user.

    Returns ``{"applied": "yes"|"no"|"partial"|"unknown", "reason", "plan", "operations",
    "reverse"}``. Nothing is written unless the fresh plan is ``ok`` and its digest equals
    ``expected_digest``. For each user the full expected membership set is carried from the
    plan through every operation: the set read before a write and the set read back after it
    must equal what is expected, otherwise the run stops (someone else changed the user in
    between). When a write raises, memberships are read again to learn whether it took
    effect; if that read also fails the outcome is ``unknown``. ``reverse`` lists, as changes
    for a new plan, the operations that took effect or may have.
    """
    plan = plan_changes(kc, cfg, changes)
    if not plan["ok"]:
        return {"applied": "no", "reason": "plan is not executable", "plan": plan, "operations": [], "reverse": []}
    if not expected_digest or plan["digest"] != expected_digest:
        return {
            "applied": "no",
            "reason": "state changed since approval (digest mismatch)",
            "plan": plan,
            "operations": [],
            "reverse": [],
        }

    operations: list[dict] = []
    done: list[tuple[dict, str]] = []  # (row, op) that took effect or may have, in order
    uncertain = False

    def _reverse() -> list[dict]:
        rev: dict[str, dict] = {}
        for row, op in reversed(done):
            item = rev.setdefault(row["username"], {"username": row["username"], "remove": None, "add": None})
            if op == "add":
                item["remove"] = row["add"]
            else:
                item["add"] = row["remove"]
        return list(rev.values())

    def _stop(record: dict, result: str) -> dict:
        record["result"] = result
        operations.append(record)
        if uncertain:
            applied = "unknown"
        else:
            applied = "partial" if done else "no"
        return {"applied": applied, "reason": result, "plan": plan, "operations": operations, "reverse": _reverse()}

    for row in plan["rows"]:
        expected = set(row.get("current_ids", []))
        for op in row.get("ops", []):
            gid = row["add_id"] if op == "add" else row["remove_id"]
            path = row["add"] if op == "add" else row["remove"]
            target = (expected | {gid}) if op == "add" else (expected - {gid})
            record: dict[str, Any] = {"username": row["username"], "op": op, "group": path}
            try:
                before = _ids(kc, row["user_id"])
            except Exception as exc:  # noqa: BLE001 - reported to the caller
                return _stop(record, f"error reading memberships before the write: {type(exc).__name__}: {exc}")
            record["before"] = sorted(before)
            if before != expected:
                return _stop(record, "stopped: memberships changed before this operation")
            try:
                if op == "add":
                    record["status"] = kc.add_user_to_group(row["user_id"], gid)
                else:
                    record["status"] = kc.remove_user_from_group(row["user_id"], gid)
                write_error = None
            except Exception as exc:  # noqa: BLE001 - the write may still have committed
                write_error = f"{type(exc).__name__}: {exc}"
            try:
                after = _ids(kc, row["user_id"])
            except Exception as exc:  # noqa: BLE001 - outcome cannot be confirmed
                done.append((row, op))
                uncertain = True
                why = f"write error {write_error}; " if write_error else ""
                return _stop(record, f"unknown: {why}read-back failed: {type(exc).__name__}: {exc}")
            record["after"] = sorted(after)
            if after == target:
                done.append((row, op))
                expected = target
                if write_error:
                    return _stop(record, f"error reported but the change took effect: {write_error}")
                record["result"] = "done"
                operations.append(record)
                continue
            if after == before:
                why = f"error: {write_error}" if write_error else "stopped: read-back does not show the change"
                return _stop(record, why)
            # Neither the old nor the new set: someone else changed this user meanwhile.
            if (gid in after) == (op == "add"):
                done.append((row, op))
            return _stop(record, "stopped: memberships changed during this operation")

    return {"applied": "yes", "reason": "", "plan": plan, "operations": operations, "reverse": _reverse()}
