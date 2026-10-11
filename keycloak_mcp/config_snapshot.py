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
from .redaction import looks_like_credential_key, normalized

SNAPSHOT_VERSION = 2
SNAPSHOT_DIR = "config-snapshots"
#: Snapshot files kept; older ones are removed when a new one is written.
KEEP_SNAPSHOTS = 30
REDACTED = "<redacted>"
#: Shown for a field that exists on one side of a comparison only.
ABSENT = "(absent)"
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

#: KeyCloak settings whose names contain a credential marker but which hold no secret.
_NOT_SECRET = {"passwordPolicy", "requiredCredentials", "resetCredentialsFlow", "cibaBackchannelTokenDeliveryMode"}
_NOT_SECRET_PREFIXES = ("webAuthnPolicyPasswordless",)
#: Endings (normalized) of settings about tokens rather than tokens: algorithms, modes,
#: formats, claims and claim names, endpoints, lifespans.
_TOKEN_SETTING_SUFFIXES = (
    "name",
    "url",
    "uri",
    "endpoint",
    "alg",
    "enc",
    "mode",
    "type",
    "format",
    "claim",
    "claims",
    "lifespan",
    "lowercase",
    "scope",
    "enabled",
)
#: Fields that are secrets whatever they hold, even ``"false"`` (normalized suffixes).
_ALWAYS_SECRET_SUFFIXES = ("password", "passwd", "secret", "credential", "privatekey", "apikey", "keystore")
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


def _is_volatile_key(key: str) -> bool:
    return key in _DROP_KEYS or key.endswith(".creation.time")


def _holds_secret(key: str, value: Any) -> bool:
    """A credential-named key (see :mod:`.redaction`) holding a non-empty string.

    Booleans and numbers are settings (``revokeRefreshToken: true``), and so are
    ``"true"``/``"false"`` and numeric strings (``access.token.claim``,
    ``client.secret.expiration``) except under a field that is a secret whatever it holds
    (``...password``, ``...secret``, ``...credential``, ``...privateKey``, ...).
    """
    if key in _NOT_SECRET or key.startswith(_NOT_SECRET_PREFIXES) or not looks_like_credential_key(key):
        return False
    flat = normalized(key)
    if not looks_like_credential_key(flat.replace("token", "")) and flat.endswith(_TOKEN_SETTING_SUFFIXES):
        # A key that names a token only to say how it is issued (access.token.signed.response.alg,
        # cibaBackchannelTokenDeliveryMode). Any other token-named string is treated as a token.
        return False
    strings = [v for v in (value if isinstance(value, list) else [value]) if isinstance(v, str) and v != ""]
    if not strings:
        return False
    if flat.endswith(_ALWAYS_SECRET_SUFFIXES):
        return True
    return any(v not in ("true", "false") and not v.lstrip("-").isdigit() for v in strings)


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


def _unique(base: str, used: set[str]) -> str:
    """``base``, or ``base #2``, ``base #3``... whichever is not in ``used`` yet (then added)."""
    key, n = base, 1
    while key in used:
        n += 1
        key = f"{base} #{n}"
    used.add(key)
    return key


def _step_keys(execs: list[dict]) -> list[str]:
    """One key per step: its name, with ``#2``... when it is already taken in the flow
    (also by a step whose real name ends in ``#2``)."""
    used: set[str] = set()
    return [_unique(e.get("displayName") or e.get("providerId") or "?", used) for e in execs]


def _step(e: dict, auth_config) -> dict[str, Any]:
    """One execution: what it runs, how it is required, and its settings (empty fields left out)."""
    fields = {
        "level": e.get("level"),
        "providerId": e.get("providerId"),
        "requirement": e.get("requirement"),
        "authenticationFlow": e.get("authenticationFlow"),
        "alias": e.get("alias"),
        "authenticationConfig": auth_config(e.get("authenticationConfig")),
    }
    return _scrub({k: v for k, v in fields.items() if v is not None})


def _flows(kc, deadline: float | None, flow_alias: dict[str, str]) -> dict[str, Any]:
    flows = _get(kc, "/authentication/flows", deadline)
    flow_alias.update({f["id"]: f.get("alias", f["id"]) for f in flows})
    configs: dict[str, Any] = {}

    def auth_config(config_id: str | None) -> Any:
        # The settings of one step (for example the role a conditional step checks).
        if not config_id:
            return None
        if config_id not in configs:
            try:
                c = _get(kc, f"/authentication/config/{quote(config_id, safe='')}", deadline)
                configs[config_id] = _scrub({"alias": c.get("alias"), "config": c.get("config") or {}})
            except SnapshotIncomplete:
                raise
            except Exception as exc:
                if _status(exc) != 404:
                    raise
                configs[config_id] = "<missing>"  # a step pointing at a deleted config
        return configs[config_id]

    out: dict[str, Any] = {}
    for f in flows:
        if not f.get("topLevel", True):
            continue
        execs = _get(kc, f"/authentication/flows/{quote(f['alias'], safe='')}/executions", deadline)
        keys = _step_keys(execs)
        out[f["alias"]] = {
            "description": f.get("description"),
            "providerId": f.get("providerId"),
            "builtIn": f.get("builtIn"),
            # Steps are keyed by name so that inserting one does not shift the others; the
            # order is a list of its own (not sorted: the order is the flow).
            "order": keys,
            "steps": {k: _step(e, auth_config) for k, e in zip(keys, execs, strict=True)},
        }
    return out


def _roles(kc, deadline: float | None, client_names: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for r in _get_all(kc, "/roles", deadline, {"briefRepresentation": "false"}):
        entry = {"description": r.get("description"), "attributes": r.get("attributes") or {}}
        if r.get("composite"):
            composites = _get(kc, f"/roles-by-id/{r['id']}/composites", deadline)
            entry["composites"] = sorted(
                f"{client_names.get(c.get('containerId'), c.get('containerId'))}:{c.get('name')}"
                if c.get("clientRole")
                else c.get("name", "")
                for c in composites
            )
        out[r["name"]] = _scrub(entry)
    return out


def _clients(clients: list[dict], flow_alias: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for c in clients:
        rep = {k: c[k] for k in _CLIENT_FIELDS if k in c}
        overrides = rep.get("authenticationFlowBindingOverrides") or {}
        rep["authenticationFlowBindingOverrides"] = {k: flow_alias.get(v, v) for k, v in overrides.items()}
        rep["protocolMappers"] = _by_name(rep.get("protocolMappers") or [])
        out[c.get("clientId", c["id"])] = _scrub(rep)
    return out


def _components(components: list[dict]) -> dict[str, Any]:
    """Components keyed by type, subType, parent component and name.

    The same name exists once per subType (client registration policies for anonymous
    and authenticated requests) and once per parent (the mappers of two user-federation
    providers). Whatever still repeats gets ``#2``..., in ID order so the keys are stable.
    """
    names = {c.get("id"): c.get("name") for c in components}
    out: dict[str, Any] = {}
    used: set[str] = set()
    for c in sorted(components, key=lambda c: str(c.get("id", ""))):
        parts = (
            c.get("providerType", "").rsplit(".", 1)[-1],
            c.get("subType"),
            names.get(c.get("parentId")),
            c.get("name") or "",
        )
        out[_unique("/".join(x for x in parts if x), used)] = _scrub(c)
    return out


def collect(kc, deadline: float | None = None) -> dict[str, Any]:
    """Read the realm configuration into a snapshot.

    Returns ``{"version", "realm", "sections", "unavailable"}``. ``unavailable`` lists the
    sections that could not be read (HTTP 403 or 404); they are left out of the snapshot
    and of every comparison. Raises :class:`SnapshotIncomplete` when the time budget runs
    out; any other error propagates.
    """
    realm = _get(kc, "", deadline)
    sections: dict[str, Any] = {}
    unavailable: list[str] = []

    def section(name: str, read):
        # A section the service account may not read (403) or that went away (404) is
        # left out and named, instead of failing every snapshot from then on.
        try:
            sections[name] = read()
        except SnapshotIncomplete:
            raise
        except Exception as exc:
            if _status(exc) not in (403, 404):
                raise
            unavailable.append(name)

    sections["realm"] = _scrub({k: v for k, v in realm.items() if k not in _REALM_SKIP})
    section("events", lambda: _scrub(_get(kc, "/events/config", deadline)))

    flow_alias: dict[str, str] = {}
    section("flows", lambda: _flows(kc, deadline, flow_alias))
    clients: list[dict] = []

    def read_clients() -> dict[str, Any]:
        # Flow overrides are stored by alias, so the clients come after the flows.
        clients.extend(_get_all(kc, "/clients", deadline))
        return _clients(clients, flow_alias)

    section("clients", read_clients)
    client_names = {c["id"]: c.get("clientId", c["id"]) for c in clients}

    if "clients" in sections:
        section("roles", lambda: _roles(kc, deadline, client_names))
    else:
        # Client roles inside composites are named by clientId; without the clients they
        # would be named by UUID and every composite would look changed.
        unavailable.append("roles")
    section("required_actions", lambda: _by_name(_get(kc, "/authentication/required-actions", deadline), "alias"))
    section(
        "client_scopes",
        lambda: {
            s["name"]: _scrub({**s, "protocolMappers": _by_name(s.get("protocolMappers") or [])})
            for s in _get(kc, "/client-scopes", deadline)
            if s.get("name")
        },
    )
    section(
        "default_client_scopes",
        lambda: {
            "default": sorted(s.get("name", "") for s in _get(kc, "/default-default-client-scopes", deadline)),
            "optional": sorted(s.get("name", "") for s in _get(kc, "/default-optional-client-scopes", deadline)),
        },
    )
    section("components", lambda: _components(_get(kc, "/components", deadline)))
    section("identity_providers", lambda: _by_name(_get(kc, "/identity-provider/instances", deadline), "alias"))

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
    ``fields`` (for ``changed``) is a list of ``(path, old, new)``, with :data:`ABSENT` for a
    field that is not there on one side. A section missing from
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
                fields = [
                    (p, fa.get(p, ABSENT), fb.get(p, ABSENT))
                    for p in sorted(set(fa) | set(fb))
                    if fa.get(p, ABSENT) != fb.get(p, ABSENT)
                ]
                rows.append({"section": section, "key": key, "change": "changed", "fields": fields})
    return rows


def _short(value: Any, limit: int | None = 120) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True) if not isinstance(value, str) else value
    return text if limit is None or len(text) <= limit else text[: limit - 1] + "…"


def _change(a: Any, b: Any, limit: int | None) -> str:
    """``old -> new``; for two lists, what was added and removed (a long list cut at
    ``limit`` would otherwise print the same on both sides)."""
    if isinstance(a, list) and isinstance(b, list):
        added = [x for x in b if x not in a]
        removed = [x for x in a if x not in b]
        if not added and not removed:
            return f"order changed -> {_short(b, limit)}"
        parts = []
        if added:
            parts.append(f"added {_short(added, limit)}")
        if removed:
            parts.append(f"removed {_short(removed, limit)}")
        return "; ".join(parts)
    return f"{_short(a, limit)} -> {_short(b, limit)}"


def format_diff(rows: list[dict[str, Any]], max_lines: int | None = 40, value_limit: int | None = 120) -> list[str]:
    """Markdown bullet lines for :func:`diff` rows, at most ``max_lines`` of them, each value
    cut at ``value_limit`` characters (``None``: no limit)."""
    lines: list[str] = []
    for r in rows:
        where = f"{r['section']}/{r['key']}" if r["key"] else r["section"]
        if r["change"] != "changed":
            lines.append(f"- {where}: {r['change']}")
            continue
        for path, a, b in r["fields"]:
            field = f".{path}" if path else ""
            lines.append(f"- {where}{field}: {_change(a, b, value_limit)}")
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
