"""Public SDK extension rejecting unknown arguments before resource mutations."""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from . import envelope
from .errors import ErrorCode, ToolError
from .state import get_state


class WMPFServer(MCPServer):
    async def list_tools(self):
        definitions = await super().list_tools()
        for tool in definitions:
            tool.input_schema = {**tool.input_schema, "additionalProperties": False}
        return definitions

    async def call_tool(self, name, arguments, context=None):
        tool = next((tool for tool in await self.list_tools() if tool.name == name), None)
        if tool is not None:
            if not isinstance(arguments, dict):
                return envelope.fail(ToolError(ErrorCode.PARAM, "Arguments must be an object."), stage=get_state().stage.value)
            unknown = set(arguments) - set(tool.input_schema.get("properties", {}))
            if unknown:
                return envelope.fail(ToolError(ErrorCode.PARAM, "Unknown arguments: " + ", ".join(sorted(unknown)),
                                     remedy="Use the current tools/list contract; legacy action parameters are not accepted."),
                                     stage=get_state().stage.value)
        return await super().call_tool(name, arguments, context)
