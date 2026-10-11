"""Daily snapshots of the realm configuration, and what changed between two of them.

A snapshot is the security-relevant configuration of the realm, read through the Admin
REST API and reduced to stable, comparable JSON: realm settings, event settings, realm
roles and what each composite role contains, authentication flows and their executions
(with each step's authenticator settings),
required actions, clients, client scopes, default client scopes, components (user
profile, key providers, client registration policies) and, when the service account may
read them, identity providers.

Secrets never reach a snapshot: values under keys that name a secret (``secret``,
``password``, ``privateKey``, ``bindCredential``, ``registrationAccessToken``, ...) are
replaced with ``<redacted>``, and long values (certificates, public keys) are replaced with
a short hash, so a rotated certificate still shows as a change. Values that change on their
own (``notBefore``, ``*.creation.time``) and internal IDs are left out, so two snapshots of
an unchanged realm are equal.

Snapshots are stored as one file per local date under ``<state dir>/config-snapshots``.
Only a complete snapshot is written: if a read fails or the time budget runs out, nothing
is stored and the previous baseline stays in place, so a partial read never shows up as
"removed" settings the next day. The first snapshot of a day is kept, also when two runs
race; later ones that day are compared but not written, so a change made during the day
is reported again the next morning.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .client import DeadlineExceeded, past_deadline

SNAPSHOT_VERSION = 1
SNAPSHOT_DIR = "config-snapshots"
#: Snapshot files kept; older ones are removed when a new one is written.
KEEP_SNAPSHOTS = 30
REDACTED = "<redacted>"
#: Strings longer than this are stored as a hash (certificates, keys, long policies).
LONG_VALUE = 200

#: Admin-event resource types that change configuration rather than users. All of them
#: are accepted by KeyCloak's ``resourceTypes`` filter; an unknown name fails the request.
CONFIG_EVENT_TYPES = (
    "REALM",
    "REALM_ROLE",
    "REALM_ROLE_MAPPING",
    "CLIENT_ROLE",
    "CLIENT_ROLE_MAPPING",
    "CLIENT_SCOPE",
    "CLIENT_SCOPE_MAPPING",
    "CLIENT_SCOPE_CLIENT_MAPPING",
    "REALM_SCOPE_MAPPING",
    "AUTH_FLOW",
    "AUTH_EXECUTION",
    "AUTH_EXECUTION_FLOW",
    "AUTHENTICATOR_CONFIG",
    "REQUIRED_ACTION",
    "IDENTITY_PROVIDER",
    "IDENTITY_PROVIDER_MAPPER",
    "COMPONENT",
    "GROUP",
    "PROTOCOL_MAPPER",
    "AUTHORIZATION_RESOURCE_SERVER",
    "AUTHORIZATION_POLICY",
    "AUTHORIZATION_SCOPE",
    "AUTHORIZATION_RESOURCE",
    "USER_PROFILE",
    "CLIENT_INITIAL_ACCESS_MODEL",
)

#: Key suffixes whose values are secrets, compared after lower-casing and removing ``.``,
#: ``_`` and ``-`` (so ``saml.signing.private.key`` and ``private_key`` both match
#: ``privatekey``). A suffix, not a substring, so that ``passwordPolicy`` or
#: ``accessTokenLifespan`` stay visible.
_SECRET_SUFFIXES = (
    "secret",
    "password",
    "passwd",
    "privatekey",
    "credential",
    "token",
    "keystore",
)
#: Keys left out everywhere: internal IDs and values that change by themselves.
_DROP_KEYS = {"id", "containerId", "parentId", "flowId", "parentFlow", "notBefore"}
#: Realm representation keys covered by their own section, or too large to compare usefully.
_REALM_SKIP = {
    "roles",
    "groups",
    "users",
    "clients",
    "clientScopes",
    "components",
    "authenticationFlows",
    "authenticatorConfig",
    "requiredActions",
    "identityProviders",
    "identityProviderMappers",
    "scopeMappings",
    "clientScopeMappings",
    "defaultDefaultClientScopes",
    "defaultOptionalClientScopes",
    "federatedUsers",
    "localizationTexts",
}
#: Client fields that decide who can sign in and what a client receives.
_CLIENT_FIELDS = (
    "enabled",
    "protocol",
    "publicClient",
    "bearerOnly",
    "clientAuthenticatorType",
    "rootUrl",
    "baseUrl",
    "adminUrl",
    "redirectUris",
    "webOrigins",
    "standardFlowEnabled",
    "implicitFlowEnabled",
    "directAccessGrantsEnabled",
    "serviceAccountsEnabled",
    "authorizationServicesEnabled",
    "frontchannelLogout",
    "consentRequired",
    "fullScopeAllowed",
    "surrogateAuthRequired",
    "authenticationFlowBindingOverrides",
    "defaultClientScopes",
    "optionalClientScopes",
    "attributes",
    "protocolMappers",
)


class SnapshotIncomplete(Exception):
    """A snapshot could not be read in full (time budget, size cap); it is not stored."""


def _normalized(key: str) -> str:
    return key.lower().replace(".", "").replace("_", "").replace("-", "")


def _is_secret_key(key: str) -> bool:
    return _normalized(key).endswith(_SECRET_SUFFIXES)


def _is_volatile_key(key: str) -> bool:
    return key in _DROP_KEYS or key.endswith(".creation.time")


def _holds_secret(key: str, value: Any) -> bool:
    """A secret-named key with a string value.

    Booleans and numbers are settings (``revokeRefreshToken: true``). A ``"true"`` /
    ``"false"`` string is a setting only under a ``...token`` key (client attributes such
    as ``client_credentials.use_refresh_token``); a password, secret or credential field
    is redacted whatever it holds.
    """
    if not _is_secret_key(key):
        return False
    flags = ("true", "false") if _normalized(key).endswith("token") else ()
    values = value if isinstance(value, list) else [value]
    return any(isinstance(v, str) and v != "" and v not in flags for v in values)


def _scrub(value: Any) -> Any:
    """Drop volatile keys, redact secrets, hash long strings, and order lists of strings.

    Lists of strings are sorted (redirect URIs, scope names: their order means nothing);
    other lists keep their order.
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if _is_volatile_key(k):
                continue
            out[k] = REDACTED if _holds_secret(k, v) else _scrub(v)
        return out
    if isinstance(value, list):
        items = [_scrub(v) for v in value]
        if all(isinstance(v, str) for v in items):
            return sorted(items)
        return items
    if isinstance(value, str):
        if "PRIVATE KEY" in value:
            return REDACTED
        if len(value) > LONG_VALUE:
            return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]
    return value


def _by_name(items: list[dict], key: str = "name") -> dict[str, Any]:
    return {str(i.get(key)): _scrub(i) for i in items if i.get(key) is not None}


def _check(deadline: float | None) -> None:
    if past_deadline(deadline):
        raise SnapshotIncomplete("time budget reached while reading the configuration")


def _get(kc, path: str, deadline: float | None, params: dict | None = None) -> Any:
    _check(deadline)
    try:
        return kc._get(path, params, deadline=deadline)
    except DeadlineExceeded as exc:
        raise SnapshotIncomplete(str(exc)) from exc


def _get_all(kc, path: str, deadline: float | None, params: dict | None = None) -> list[dict]:
    _check(deadline)
    items, truncated = kc._paginate(path, params or {}, 500, deadline=deadline)
    if truncated:
        raise SnapshotIncomplete(f"{path} could not be read in full")
    return items


def _status(exc: Exception) -> int | None:
    resp = getattr(exc, "response", None)
    return getattr(resp, "status_code", None)


def collect(kc, deadline: float | None = None) -> dict[str, Any]:
    """Read the realm configuration into a snapshot.

    Returns ``{"version", "realm", "sections", "unavailable"}``. ``unavailable`` lists the
    sections the service account may not read (HTTP 403); they are left out of the
    snapshot and of every comparison. Raises :class:`SnapshotIncomplete` when the time
    budget runs out; any other error propagates.
    """
    realm = _get(kc, "", deadline)
    sections: dict[str, Any] = {}
    unavailable: list[str] = []

    sections["realm"] = _scrub({k: v for k, v in realm.items() if k not in _REALM_SKIP})
    sections["events"] = _scrub(_get(kc, "/events/config", deadline))

    clients = _get_all(kc, "/clients", deadline)
    client_names = {c["id"]: c.get("clientId", c["id"]) for c in clients}

    flows = _get(kc, "/authentication/flows", deadline)
    flow_alias = {f["id"]: f.get("alias", f["id"]) for f in flows}
    flow_section: dict[str, Any] = {}
    auth_configs: dict[str, Any] = {}

    def auth_config(config_id: str | None) -> Any:
        # The settings of one step (for example the role a conditional step checks).
        if not config_id:
            return None
        if config_id not in auth_configs:
            c = _get(kc, f"/authentication/config/{quote(config_id, safe='')}", deadline)
            auth_configs[config_id] = _scrub({"alias": c.get("alias"), "config": c.get("config") or {}})
        return auth_configs[config_id]

    for f in flows:
        if not f.get("topLevel", True):
            continue
        execs = _get(kc, f"/authentication/flows/{quote(f['alias'], safe='')}/executions", deadline)
        flow_section[f["alias"]] = {
            "description": f.get("description"),
            "providerId": f.get("providerId"),
            "builtIn": f.get("builtIn"),
            # Keyed by position and name, so a changed step shows its own fields.
            "executions": {
                f"{i:02d} {e.get('displayName') or e.get('providerId') or ''}": _scrub(
                    {
                        "level": e.get("level"),
                        "providerId": e.get("providerId"),
                        "requirement": e.get("requirement"),
                        "authenticationFlow": e.get("authenticationFlow"),
                        "alias": e.get("alias"),
                        "authenticationConfig": auth_config(e.get("authenticationConfig")),
                    }
                )
                for i, e in enumerate(execs)
            },
        }
    sections["flows"] = flow_section

    roles = _get_all(kc, "/roles", deadline, {"briefRepresentation": "false"})
    role_section: dict[str, Any] = {}
    for r in roles:
        entry = {"description": r.get("description"), "attributes": r.get("attributes") or {}}
        if r.get("composite"):
            composites = _get(kc, f"/roles-by-id/{r['id']}/composites", deadline)
            entry["composites"] = sorted(
                f"{client_names.get(c.get('containerId'), c.get('containerId'))}:{c.get('name')}"
                if c.get("clientRole")
                else c.get("name", "")
                for c in composites
            )
        role_section[r["name"]] = _scrub(entry)
    sections["roles"] = role_section

    sections["required_actions"] = _by_name(_get(kc, "/authentication/required-actions", deadline), "alias")

    client_section: dict[str, Any] = {}
    for c in clients:
        rep = {k: c[k] for k in _CLIENT_FIELDS if k in c}
        overrides = rep.get("authenticationFlowBindingOverrides") or {}
        rep["authenticationFlowBindingOverrides"] = {k: flow_alias.get(v, v) for k, v in overrides.items()}
        rep["protocolMappers"] = _by_name(rep.get("protocolMappers") or [])
        client_section[c.get("clientId", c["id"])] = _scrub(rep)
    sections["clients"] = client_section

    scopes = _get(kc, "/client-scopes", deadline)
    sections["client_scopes"] = {
        s["name"]: _scrub({**s, "protocolMappers": _by_name(s.get("protocolMappers") or [])})
        for s in scopes
        if s.get("name")
    }
    sections["default_client_scopes"] = {
        "default": sorted(s.get("name", "") for s in _get(kc, "/default-default-client-scopes", deadline)),
        "optional": sorted(s.get("name", "") for s in _get(kc, "/default-optional-client-scopes", deadline)),
    }
    # The same name can exist once per subType (client registration policies for anonymous
    # and authenticated requests), so the key carries it.
    sections["components"] = {
        "/".join(
            x for x in (c.get("providerType", "").rsplit(".", 1)[-1], c.get("subType"), c.get("name") or "") if x
        ): _scrub(c)
        for c in _get(kc, "/components", deadline)
    }

    try:
        idps = _get(kc, "/identity-provider/instances", deadline)
        sections["identity_providers"] = _by_name(idps, "alias")
    except SnapshotIncomplete:
        raise
    except Exception as exc:
        if _status(exc) != 403:
            raise
        unavailable.append("identity_providers")

    return {
        "version": SNAPSHOT_VERSION,
        "realm": realm.get("realm", ""),
        "sections": sections,
        "unavailable": unavailable,
    }


# ---- comparison ----


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    """``{"a": {"b": 1}}`` -> ``{"a.b": 1}``. Lists are compared whole."""
    if isinstance(value, dict) and value:
        out: dict[str, Any] = {}
        for k, v in value.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
        return out
    return {prefix: value}


def diff(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, Any]]:
    """What changed from snapshot ``old`` to snapshot ``new``.

    Returns rows ``{"section", "key", "change": "added"|"removed"|"changed", "fields"}``;
    ``fields`` (for ``changed``) is a list of ``(path, old, new)``. A section missing from
    either snapshot (not readable then or now) is not compared.
    """
    rows: list[dict[str, Any]] = []
    old_s, new_s = old.get("sections", {}), new.get("sections", {})
    for section in sorted(set(old_s) & set(new_s)):
        a, b = old_s[section], new_s[section]
        if section in ("realm", "events", "default_client_scopes"):
            a, b = {"": a}, {"": b}
        for key in sorted(set(a) | set(b)):
            if key not in b:
                rows.append({"section": section, "key": key, "change": "removed", "fields": []})
            elif key not in a:
                rows.append({"section": section, "key": key, "change": "added", "fields": []})
            elif a[key] != b[key]:
                fa, fb = _flatten(a[key]), _flatten(b[key])
                fields = [(p, fa.get(p), fb.get(p)) for p in sorted(set(fa) | set(fb)) if fa.get(p) != fb.get(p)]
                rows.append({"section": section, "key": key, "change": "changed", "fields": fields})
    return rows


def _short(value: Any, limit: int = 120) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[: limit - 1] + "…"


def format_diff(rows: list[dict[str, Any]], max_lines: int | None = 40) -> list[str]:
    """Markdown bullet lines for :func:`diff` rows, at most ``max_lines`` of them (``None``: all)."""
    lines: list[str] = []
    for r in rows:
        where = f"{r['section']}/{r['key']}" if r["key"] else r["section"]
        if r["change"] != "changed":
            lines.append(f"- {where}: {r['change']}")
            continue
        for path, a, b in r["fields"]:
            field = f".{path}" if path else ""
            lines.append(f"- {where}{field}: {_short(a)} -> {_short(b)}")
    if max_lines is not None and len(lines) > max_lines:
        rest = len(lines) - max_lines
        lines = lines[:max_lines] + [f"- … {rest} more (call get_config_changes for the full list)"]
    return lines


# ---- storage ----


def snapshot_dir(state_dir: str) -> Path:
    return Path(state_dir) / SNAPSHOT_DIR


def _dated_files(directory: Path) -> list[tuple[date, Path]]:
    out = []
    if not directory.is_dir():
        return out
    for p in directory.glob("*.json"):
        try:
            out.append((date.fromisoformat(p.stem), p))
        except ValueError:
            continue
    return sorted(out)


def load_baseline(state_dir: str, today: date, on: date | None = None) -> tuple[date, dict] | None:
    """The snapshot to compare against: the one dated ``on``, else the latest before ``today``."""
    files = _dated_files(snapshot_dir(state_dir))
    if on is not None:
        files = [(d, p) for d, p in files if d == on]
    else:
        files = [(d, p) for d, p in files if d < today]
    if not files:
        return None
    d, p = files[-1]
    snap = json.loads(p.read_text(encoding="utf-8"))
    if snap.get("version") != SNAPSHOT_VERSION:
        return None
    return d, snap


def save_if_first_today(state_dir: str, today: date, snap: dict[str, Any]) -> bool:
    """Store ``snap`` as today's snapshot unless one exists. Returns True when written.

    Written to a temporary file and renamed, so a reader never sees half a file; the
    directory is 0700 and the file 0600. Snapshots beyond :data:`KEEP_SNAPSHOTS` are removed.
    """
    directory = snapshot_dir(state_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = directory / f"{today.isoformat()}.json"
    if target.exists():
        return False
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, sort_keys=True, indent=1)
        os.chmod(tmp, 0o600)
        # A hard link fails when the target exists, so of two runs racing past the check
        # above the first one wins and the other leaves today's snapshot alone.
        try:
            os.link(tmp, target)
        except FileExistsError:
            return False
    finally:
        Path(tmp).unlink(missing_ok=True)
    for _, old in _dated_files(directory)[:-KEEP_SNAPSHOTS]:
        old.unlink(missing_ok=True)
    return True
