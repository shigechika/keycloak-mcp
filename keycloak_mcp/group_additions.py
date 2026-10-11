"""Who was added to a group that carries roles, from GROUP_MEMBERSHIP admin events.

Group memberships are added every day by the people who run each department's groups, so
they are not configuration changes and do not appear in the configuration snapshot. A
membership can still hand out administrative rights: a group (or one of its ancestors)
may map ``realm-management:realm-admin``. This module reads the membership additions,
resolves the roles each group carries (its own and its ancestors', through composite
roles, the same way the group-change tools report them) and keeps the additions to groups
that carry any role.

An addition is *administrative* when the group carries a ``realm-management`` client role
other than the read-only ``query-*`` and ``view-*`` ones (``realm-admin``,
``manage-users``, ``impersonation``, ...).
"""

from __future__ import annotations

import re
from typing import Any

from .client import DeadlineExceeded, past_deadline
from .group_changes import RoleResolver, RolesUnknown

ADMIN_CLIENT = "realm-management"
_READ_ONLY_PREFIXES = ("query-", "view-")
_MEMBERSHIP_PATH = re.compile(r"^users/([^/]+)/groups/([^/]+)$")


def is_admin_role(label: str) -> bool:
    """``realm-management:<role>`` that is not read-only."""
    client, _, role = label.partition(":")
    return client == ADMIN_CLIENT and bool(role) and not role.startswith(_READ_ONLY_PREFIXES)


def _status(exc: Exception) -> int | None:
    return getattr(getattr(exc, "response", None), "status_code", None)


def scan(kc, events: list[dict], deadline: float | None = None) -> dict[str, Any]:
    """Additions to role-carrying groups among ``events`` (admin events, any type).

    Returns ``{"rows", "checked", "unresolved", "complete"}``. Each row is ``{"time",
    "user_id", "group", "roles", "admin_roles", "admin", "ip"}``. ``unresolved`` counts
    additions whose group or roles could not be read (the group was deleted since, or a
    path does not resolve); they are not rows. ``complete`` is False when the time budget
    ran out before every addition was checked.

    The group is identified by the ID in the event's resource path and read as it is now
    (the path in the event's representation is the one it had then, and the group or an
    ancestor may have been renamed or moved since). Rows are ordered administrative
    first, then by time, also when the scan stops early.
    """
    resolver = RoleResolver(kc, deadline)
    paths: dict[str, str | None] = {}
    rows: list[dict[str, Any]] = []
    checked = unresolved = 0
    additions = [
        e for e in events if e.get("operationType") == "CREATE" and e.get("resourceType") == "GROUP_MEMBERSHIP"
    ]

    def result(complete: bool) -> dict[str, Any]:
        rows.sort(key=lambda r: (not r["admin_roles"], r["time"]))
        return {"rows": rows, "checked": checked, "unresolved": unresolved, "complete": complete}

    for e in additions:
        if past_deadline(deadline):
            return result(False)
        m = _MEMBERSHIP_PATH.match(e.get("resourcePath") or "")
        if not m:
            continue
        user_id, group_id = m.groups()
        try:
            if group_id not in paths:
                try:
                    paths[group_id] = (kc.get_group(group_id, deadline=deadline) or {}).get("path")
                except Exception as exc:
                    if _status(exc) != 404:
                        raise
                    paths[group_id] = None  # deleted since
            path = paths[group_id]
            checked += 1
            if not path:
                unresolved += 1
                continue
            roles = resolver.roles(path)
        except RolesUnknown:
            unresolved += 1
            continue
        except DeadlineExceeded:
            return result(False)
        if not roles:
            continue
        auth = e.get("authDetails") or {}
        rows.append(
            {
                "time": e.get("time", 0),
                "user_id": user_id,
                "group": path,
                "roles": roles,
                "admin_roles": [r for r in roles if is_admin_role(r)],
                "admin": auth.get("userId", ""),
                "ip": auth.get("ipAddress", ""),
            }
        )
    return result(True)
