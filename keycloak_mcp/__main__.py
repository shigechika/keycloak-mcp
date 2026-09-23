"""Allow running as: python -m keycloak_mcp"""

from __future__ import annotations

import argparse
import os
import sys

from keycloak_mcp import __version__
from keycloak_mcp.server import _kc, mcp


def _check_config() -> int:
    """Verify environment variables and authenticate to KeyCloak."""
    try:
        client = _kc()
    except KeyError as e:
        print(f"Configuration error: missing environment variable {e}", file=sys.stderr)
        return 1
    try:
        client.auth.get_token()
    except Exception as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        return 2
    print(f"OK: authenticated to {client.auth.admin_base}")
    return 0


def _spray_report(args: argparse.Namespace) -> int:
    """Run ``spray-report``: JSON on stdout, diagnostics on stderr."""
    import json

    from keycloak_mcp.server import SprayReportConfigError, spray_report

    try:
        result = spray_report(
            args.date,
            tz=args.tz,
            deadline_seconds=args.deadline if args.deadline > 0 else None,
            max_events=args.max_events if args.max_events > 0 else None,
            max_resolves=args.max_resolves,
            require_sites=not args.allow_no_sites,
        )
    except SprayReportConfigError as e:
        print(f"spray-report: {e}", file=sys.stderr)
        return 2
    except KeyError as e:  # KeyCloakClient reads required env vars with os.environ[...]
        print(f"spray-report: missing environment variable {e}", file=sys.stderr)
        return 2
    except Exception as e:  # network / auth failures: no partial JSON on stdout
        print(f"spray-report: failed: {e}", file=sys.stderr)
        return 1
    # Encode the whole document first and write bytes: a redirected stdout on
    # Windows uses the ANSI code page, which cannot encode every username.
    data = (json.dumps(result, ensure_ascii=False) + "\n").encode("utf-8")
    sys.stdout.flush()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    return 0


def main() -> None:
    """Entry point for console_scripts."""
    parser = argparse.ArgumentParser(
        prog="keycloak-mcp",
        description=(
            "MCP server for KeyCloak Admin REST API. "
            "Runs a STDIO JSON-RPC server exposing user, session, and event "
            "management tools to AI assistants via a Service Account."
        ),
        epilog=(
            "Required environment variables: "
            "KEYCLOAK_URL, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET. "
            "Optional: KEYCLOAK_REALM (default: master)."
        ),
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify environment variables and authentication, then exit.",
    )
    sub = parser.add_subparsers(dest="command")
    sp = sub.add_parser(
        "spray-report",
        help="Write the spray_check analysis for one calendar day as JSON to stdout, then exit.",
        description=(
            "Batch counterpart of the spray_check tool: covers [DATE 00:00, DATE+1 00:00) "
            "in --tz and prints one JSON document to stdout. Meant for a scheduled job "
            "that archives one file per day; does not start the MCP server."
        ),
    )
    sp.add_argument("--date", required=True, help="Day to analyse (YYYY-MM-DD).")
    sp.add_argument("--tz", default="", help="IANA zone for the day boundary (default: host local zone).")
    sp.add_argument(
        "--deadline", type=float, default=900.0, help="Wall-clock budget in seconds; 0 disables (default 900)."
    )
    sp.add_argument(
        "--max-events", type=int, default=1_000_000, help="Per-type event cap; 0 disables (default 1000000)."
    )
    sp.add_argument("--max-resolves", type=int, default=2000, help="Cap on userId lookups (default 2000).")
    sp.add_argument(
        "--allow-no-sites",
        action="store_true",
        help="Run even when KEYCLOAK_SITES_INI yields no ranges (every IP is then external).",
    )
    args = parser.parse_args()

    if args.check:
        sys.exit(_check_config())

    if args.command == "spray-report":
        sys.exit(_spray_report(args))

    # On Windows, the MCP SDK creates TextIOWrapper(sys.stdout.buffer) with the
    # default newline=None, which translates \n → \r\n and corrupts the NDJSON
    # wire format (modelcontextprotocol/python-sdk#2433).
    # Intercept writes at the RawIOBase level to strip \r\n → \n, then rebuild
    # sys.stdout so that the SDK's sys.stdout.buffer access gets our wrapper.
    if sys.platform == "win32":
        import io

        class _CRStripper(io.RawIOBase):
            """Strip \\r\\n → \\n inserted by TextIOWrapper on Windows."""

            def __init__(self, fd: int) -> None:
                self._fd = fd

            def writable(self) -> bool:
                return True

            def write(self, b: bytes | bytearray | memoryview) -> int:  # type: ignore[override]
                data = bytes(b).replace(b"\r\n", b"\n")
                os.write(self._fd, data)
                return len(b)

            def fileno(self) -> int:
                return self._fd

        sys.stdout.flush()
        _buf = io.BufferedWriter(_CRStripper(sys.stdout.fileno()))
        sys.stdout = io.TextIOWrapper(_buf, encoding="utf-8", errors="replace", newline="\n")

    try:
        mcp.run(transport="stdio")
    except KeyboardInterrupt:
        # Bypass normal interpreter shutdown: FastMCP's stdio reader runs in a
        # daemon thread blocked on sys.stdin, and joining it at shutdown can
        # crash with "_enter_buffered_busy" on Python 3.14.
        os._exit(0)


if __name__ == "__main__":
    main()
