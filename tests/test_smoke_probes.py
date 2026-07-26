"""Every registered tool must carry a smoke-test probe spec.

This is the CI half of the smoke test: the live run (scripts/smoke_test.py)
needs a reachable realm and a service account, but the *coverage* question —
did someone add a tool without deciding how we would know it works? — is
answerable offline, so it is enforced here on every push.
"""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

from keycloak_mcp.server import mcp

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import smoke_probes  # noqa: E402 - needs the sys.path line above
from smoke_harness import Probe  # noqa: E402

#: Literal shapes that would tie this public repository to one deployment.
#: Named by shape rather than by value: spelling out the domain in order to
#: forbid it would put that domain here, which is what the check prevents.
#:
#: The IPv6 pattern covers both the fully written form and the compressed one.
#: A compressed match requires a hex group to the left of "::" so that a clock
#: time (12:34:56) and a Python slice (a[::2]) do not read as addresses, and
#: loopback/unspecified forms (::1, ::) are not matched at all — they identify
#: no site.
ADDRESS_SHAPES = {
    "email address": r"[\w.+-]+@[\w-]+\.[\w.]+",
    "URL": r"https?://",
    # {1,} not {2,}: a bare two-label domain (example.com) is the common case
    # and was slipping through when this required a subdomain.
    "hostname": r"\b(?:[a-z0-9-]+\.){1,}(?:jp|com|org|net|edu|ac|co|io|dev)\b",
    "IPv4 address": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    "IPv6 address": (
        r"(?i)\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}\b"
        r"|\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?"
    ),
}

#: Tools that change state. The smoke test must never call these.
STATE_CHANGING = {
    "reset_password",
    "reset_passwords_batch",
    "logout_user",
    "set_user_enabled",
}


def _registered_tool_names() -> set[str]:
    """Tool names from the live registry (no realm connection needed).

    ``asyncio.run`` rather than an async test: this suite has no async plugin,
    and the registry read is the only awaitable involved.
    """

    async def _names() -> set[str]:
        return {tool.name for tool in await mcp.list_tools()}

    return asyncio.run(_names())


def test_every_registered_tool_has_a_probe():
    registered = _registered_tool_names()
    missing = sorted(registered - set(smoke_probes.PROBES))
    assert not missing, (
        f"Tool(s) registered with no smoke-test probe: {missing}. "
        "Add an entry to scripts/smoke_probes.py — arguments plus what a working "
        "answer looks like, or an explicit skip= reason."
    )


def test_no_probe_targets_a_removed_tool():
    registered = _registered_tool_names()
    stale = sorted(set(smoke_probes.PROBES) - registered)
    assert not stale, f"Probe spec(s) for tools that are no longer registered: {stale}"


def test_state_changing_tools_are_skipped():
    """A smoke test that resets a password is worse than no smoke test."""
    registered = _registered_tool_names()
    for name in sorted(STATE_CHANGING & registered):
        probe = smoke_probes.PROBES[name]
        assert probe.skip, f"{name} changes state and must be skipped, not exercised"


def test_probes_are_probe_instances():
    for name, probe in smoke_probes.PROBES.items():
        assert isinstance(probe, Probe), f"{name} is not a Probe"


def test_realm_enumerating_tools_are_probed_with_an_explicit_cap():
    """A scheduled probe must not lean on a realm-scan tool's default size.

    ``get_totp_users`` enumerates accounts and then issues one credential
    request per user. Its own default (5000) is a reasonable answer for a human
    asking a one-off question, and far too much work to repeat on a schedule —
    the first live run of this smoke test did exactly that before it was
    stopped. Any tool that enumerates the realm must therefore be probed with an
    explicit, small cap; this finds them from the source so a new one cannot be
    added without the same decision.
    """
    # encoding pinned: the default is the locale's, which is cp1252 on the
    # Windows CI runner and cannot decode this source.
    source = (Path(__file__).resolve().parent.parent / "keycloak_mcp" / "server.py").read_text(encoding="utf-8")
    # A single-string heuristic, not a general "does this enumerate the realm?"
    # analysis: it finds today's one scanning tool by the helper it calls. A
    # future tool that walks the realm some other way would not be caught here,
    # so treat this as a tripwire for the known shape rather than a proof.
    scanning: list[str] = []
    for chunk in source.split("@mcp.tool()")[1:]:
        match = re.search(r"^def ([a-z_]+)\(", chunk, re.MULTILINE)
        if not match:
            continue
        body = chunk.split("@mcp.tool()")[0]
        if "list_users_all(" in body:
            scanning.append(match.group(1))

    assert scanning, "expected at least one realm-enumerating tool; has the pattern changed?"
    for name in scanning:
        probe = smoke_probes.PROBES.get(name)
        assert probe is not None, f"{name} enumerates the realm and has no probe spec"
        if probe.skip:
            continue
        cap = probe.args.get("max_users")
        assert isinstance(cap, int) and 0 < cap <= 100, (
            f"{name} enumerates the realm, so its probe must pass a small explicit "
            f"max_users (got {cap!r}). Proving the tool works needs a sample; "
            "measuring the realm is a separate, deliberate operation."
        )


def test_every_exercised_probe_asserts_something():
    """A probe that asserts nothing reports a broken tool as OK."""
    offenders = [
        name
        for name, probe in smoke_probes.PROBES.items()
        if not probe.skip
        and not probe.must_match
        and not probe.min_chars
        and not probe.require_keys
        and not probe.min_values
    ]
    assert not offenders, (
        f"probes with nothing to assert: {offenders}. These tools answer with "
        "formatted text, so pin the header line they must produce (must_match) "
        "or at least a minimum length."
    )


def test_address_shapes_catch_what_they_claim_to():
    """The guard below is only as good as these patterns, so pin them.

    IPv6 in particular is easy to get wrong in both directions: miss the
    compressed form, or swallow anything with two colons in it.
    """
    leaks = [
        "user@example.org",
        "https://sso.example.ac.jp",
        "sso.example.ac.jp",
        "example.com",  # a bare two-label domain is the common shape
        "keycloak.io",
        "192.0.2.10",
        "2001:db8::1",
        "fe80::1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    ]
    for value in leaks:
        assert any(re.search(p, value) for p in ADDRESS_SHAPES.values()), f"missed: {value}"

    innocuous = [
        "12:34:56",  # a clock time
        "values[::2]",  # a Python slice
        "::1",  # loopback identifies no site
        r"^Clients \(\d+\):",  # a probe pattern
        "max_users=25",
    ]
    for value in innocuous:
        matched = [label for label, p in ADDRESS_SHAPES.items() if re.search(p, value)]
        assert not matched, f"false positive on {value!r}: {matched}"


def test_no_site_specific_identifiers_in_specs():
    """This repository is public: probes must not name the realm they run against.

    Arguments that identify real users, groups or hosts are discovered at run
    time by an args_factory instead of being written down here. The patterns
    below are deliberately generic: spelling out the deployment's own domain in
    order to forbid it would put that domain in a public repository, which is
    the very thing this test exists to prevent.
    """
    source = (Path(__file__).resolve().parent.parent / "scripts" / "smoke_probes.py").read_text(encoding="utf-8")
    hits = [label for label, pattern in ADDRESS_SHAPES.items() if re.search(pattern, source)]
    assert not hits, (
        f"address-like literals in smoke_probes.py: {hits}. Discover such arguments "
        "at run time (args_factory) rather than hardcoding them."
    )
