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
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify environment variables and authentication, then exit.",
    )
    args = parser.parse_args()

    if args.check:
        sys.exit(_check_config())

    try:
        mcp.run(transport="stdio")
    except KeyboardInterrupt:
        # Bypass normal interpreter shutdown: FastMCP's stdio reader runs in a
        # daemon thread blocked on sys.stdin, and joining it at shutdown can
        # crash with "_enter_buffered_busy" on Python 3.14.
        os._exit(0)


if __name__ == "__main__":
    main()
