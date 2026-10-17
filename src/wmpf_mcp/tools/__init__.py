"""Public method-chain tools; private operations are never registered as aliases."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from . import binary, environment, maintenance, runtime, source, traffic

ALL_DOMAINS = (environment, maintenance, binary, runtime, source, traffic)


def register_all(server: MCPServer) -> None:
    for module in ALL_DOMAINS:
        module.register(server)
