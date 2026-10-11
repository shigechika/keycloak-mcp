"""Who was added to a group that carries roles, from GROUP_MEMBERSHIP admin events.

Group memberships are added every day by the people who run each department's groups, so
they are not configuration changes and do not appear in the configuration snapshot. A
membership can still hand out administrative rights: a group (or one of its ancestors)
may map ``realm-management:realm-admin``. This module reads the membership additions,
resolves the roles each group carries (its own and its ancestors', through composite
roles, the same way the group-change tools report them) and keeps the additions to groups
that carry any role.

An addition is *administrative* when the group carries a role that administers a realm:
a ``realm-management`` client role, or in the master realm a ``<realm>-realm`` client
role, other than the read-only ``query-*`` and ``view-*`` ones (``realm-admin``,
``manage-users``, ``impersonation``, ...), or the master realm's ``admin`` realm role.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .client import DeadlineExceeded, past_deadline
from .group_changes import RoleResolver

logger = logging.getLogger(__name__)

ADMIN_CLIENT = "realm-management"
_READ_ONLY_PREFIXES = ("query-", "view-")
_MEMBERSHIP_PATH = re.compile(r"^users/([^/]+)/groups/([^/]+)$")


def is_admin_role(label: str) -> bool:
    """A role that administers a realm and is not read-only (see the module docstring)."""
    if label == "admin":  # the master realm's superuser role
        return True
    client, sep, role = label.partition(":")
    if not sep or not role or role.startswith(_READ_ONLY_PREFIXES):
        return False
    return client == ADMIN_CLIENT or client.endswith("-realm")


def _status(exc: Exception) -> int | None:
    return getattr(getattr(exc, "response", None), "status_code", None)


def scan(kc, events: list[dict], deadline: float | None = None) -> dict[str, Any]:
    """Additions to role-carrying groups among ``events`` (admin events, any type), newest
    first within each tier.

    Returns ``{"rows", "checked", "unresolved", "complete"}``. Each row is ``{"time",
    "user_id", "group", "roles", "admin_roles", "admin", "ip"}``. ``unresolved`` counts
    additions whose group or roles could not be read (the group was deleted since, or a
    read failed); they are not rows, and the scan goes on with the next one. ``complete`` is False when the time budget
    ran out before every addition was checked.

    The group is identified by the ID in the event's resource path and read as it is now
    (the path in the event's representation is the one it had then, and the group or an
    ancestor may have been renamed or moved since); its roles are followed through the
    ``parentId`` chain. Rows are ordered administrative first, then newest first, also
    when the scan stops early.
    """
    resolver = RoleResolver(kc, deadline)
    groups: dict[str, dict | None] = {}
    rows: list[dict[str, Any]] = []
    checked = unresolved = 0
    additions = [
        e for e in events if e.get("operationType") == "CREATE" and e.get("resourceType") == "GROUP_MEMBERSHIP"
    ]

    def result(complete: bool) -> dict[str, Any]:
        rows.sort(key=lambda r: (not r["admin_roles"], -int(r["time"] or 0)))
        return {"rows": rows, "checked": checked, "unresolved": unresolved, "complete": complete}

    for e in additions:
        if past_deadline(deadline):
            return result(False)
        m = _MEMBERSHIP_PATH.match(e.get("resourcePath") or "")
        if not m:
            continue
        user_id, group_id = m.groups()
        checked += 1
        try:
            if group_id not in groups:
                try:
                    groups[group_id] = kc.get_group(group_id, deadline=deadline) or None
                except DeadlineExceeded:
                    raise
                except Exception as exc:
                    if _status(exc) != 404:
                        raise
                    groups[group_id] = None  # deleted since
            group = groups[group_id]
            if not group:
                unresolved += 1
                continue
            path = group.get("path", "")
            roles = resolver.roles_of(group)
        except DeadlineExceeded:
            return result(False)
        except Exception as exc:  # noqa: BLE001 - one unreadable group must not hide the others
            logger.warning("group addition %s could not be checked: %s: %s", group_id, type(exc).__name__, exc)
            unresolved += 1
            continue
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
