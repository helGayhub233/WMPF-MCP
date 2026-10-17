"""Read traffic and explicitly clear its bounded ledger."""
from __future__ import annotations

from typing import Annotated, Literal
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from ..core.schemas import ClearReply, TrafficReply
from . import _traffic
from .contracts import annotations, parameter_error


def register(server: MCPServer) -> None:
    @server.tool(name="query_traffic", annotations=annotations(read_only=True), description="""Read observed Network transactions, a selected body's sides, or a HAR 1.2 object.
After page activity use list, then body with its per-hop request_id, or har to export
recent matches chronologically. HAR merges protocol-paired ExtraInfo, retains each
redirect hop and separates entity bytes from total transfer bytes; binary bodies
remain base64. Missing/pending fields, expired bodies and truncation are explicit.
Each body side is capped at 256 KiB; HAR retains at most 2 MiB of bodies and 4 MiB
of entries with a 20-second export deadline. No file is written. content selects HAR
bodies; metadata remains readable offline, while lazy body retrieval needs a live
in-process Portal/runtime. Redirect bodies are not replaced with the final body's
content. Capture is emitted CDP Network only: wx.request depends on runtime events;
mmtls/ilink is unverified. This is not a byte-for-byte HTTP wire capture.
Use probe_runtime for transport and inspect_source for static endpoints. clear_traffic,
Portal stop or runtime replacement expires records.""")
    async def query_traffic(
        view: Annotated[Literal["list", "body", "har"], Field(description="Read per-hop metadata, selected body sides, or structured HAR.")] = "list",
        filter: Annotated[str | None, Field(description="list/har: case-insensitive literal URL fragment.")] = None,
        method: Annotated[str | None, Field(description="list/har: case-insensitive exact HTTP method.")] = None,
        limit: Annotated[int, Field(description="Maximum recent transactions.", ge=1, le=200)] = 50,
        request_id: Annotated[str | None, Field(description="body: per-hop ID from list; expires on clear/Portal stop/runtime replacement.")] = None,
        which: Annotated[Literal["request", "response", "both"], Field(description="body: select sides; each has separate error/truncation fields.")] = "both",
        content: Annotated[Literal["none", "text", "all"], Field(description="har: omit body text, include text MIME bodies, or include all (binary as base64); explicit caps/errors remain.")] = "all",
    ) -> TrafficReply:
        if view == "body" and not request_id:
            return parameter_error("request_id is required for view=body.")
        return await _traffic.execute(action=view, filter=filter, method=method, max=limit,
                                      id=request_id, which=which, content=content)

    @server.tool(name="clear_traffic", annotations=annotations(destructive=True), description="""Discard this MCP process's in-memory CDP Network ledger.
Use only when intentionally clearing captured transactions; request IDs then expire.
Does not stop hooks, Engine or Portal, or change the remote application's network.
Use query_traffic to read records and stop_runtime to stop owned resources.""")
    async def clear_traffic() -> ClearReply:
        return await _traffic.execute(action="clear")
