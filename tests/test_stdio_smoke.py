"""Stdio wire-format smoke test.

Spawns keycloak-mcp as a subprocess, sends a JSON-RPC ``initialize``
request, and verifies that the response line is terminated with LF (\\n)
not CRLF (\\r\\n).  Guards against modelcontextprotocol/python-sdk#2433
where ``stdio_server()`` emitted CRLF on Windows and corrupted the
NDJSON wire format.

No Keycloak connection is required — ``initialize`` is handled entirely
by the MCP framework before any tool dispatch.
"""

import json
import subprocess
import sys

_INITIALIZE = (
    json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "0"},
            },
        }
    )
    + "\n"
)


def test_stdio_lf_not_crlf():
    """Response lines must be LF-terminated, not CRLF (guards against sdk#2433)."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "keycloak_mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, _ = proc.communicate(input=_INITIALIZE.encode(), timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise AssertionError("keycloak-mcp did not respond within 10 seconds")

    assert stdout, "keycloak-mcp produced no stdout output"

    first_nl = stdout.find(b"\n")
    assert first_nl != -1, "No newline found in response"

    line = stdout[:first_nl]
    assert not line.endswith(b"\r"), f"Response line ends with CR (CRLF): {line!r}"

    response = json.loads(line)
    assert response.get("jsonrpc") == "2.0"
    assert "id" in response
