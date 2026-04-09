"""Entry point for keycloak-mcp MCP server."""

from .server import mcp

mcp.run(transport="stdio")
