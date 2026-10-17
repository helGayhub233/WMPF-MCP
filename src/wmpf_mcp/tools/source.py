"""Independent static reads and explicit decompilation."""
from __future__ import annotations

from typing import Annotated, Literal
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from ..core.schemas import DecompileReply, SourceReply
from . import _source
from .contracts import annotations, parameter_error


def register(server: MCPServer) -> None:
    @server.tool(name="inspect_source", annotations=annotations(read_only=True), description="""List cached applets or search/read already decompiled local sources.
This independent static track needs no Frida, runtime process or CDP connection.
Use applets to choose an appid; search needs pattern and read needs a relative file.
Search/read default to the most recently decompiled applet. They do not decompile
implicitly: use decompile_applet when readable sources are missing. Package coverage
can be incomplete; an absent match does not prove absence in the app, and a source
match does not prove execution. Reads return bounded matches or at most 1000 lines.
Use inspect_runtime/probe_runtime and query_traffic to validate runtime hypotheses.""")
    async def inspect_source(
        view: Annotated[Literal["applets", "search", "read"], Field(description="Cached package discovery, source search or bounded source read.")] = "applets",
        appid: Annotated[str | None, Field(description="search/read applet; omitted selects most recently decompiled output.")] = None,
        pattern: Annotated[str | None, Field(description="search requires literal text, or a Python regex when regex=true.", max_length=2048)] = None,
        regex: Annotated[bool, Field(description="search only: enable regex instead of literal matching.")] = False,
        file: Annotated[str | None, Field(description="read requires a source-relative path, normally from a search hit.")] = None,
        start_line: Annotated[int, Field(description="read first inclusive line, numbered from 1.", ge=1)] = 1,
        end_line: Annotated[int, Field(description="read last inclusive line; ordered span must be <=1000 lines.", ge=1)] = 200,
        limit: Annotated[int, Field(description="Maximum applets or search matches.", ge=1, le=200)] = 50,
    ) -> SourceReply:
        if view == "search" and not pattern:
            return parameter_error("pattern is required for view=search.")
        if view == "read" and not file:
            return parameter_error("file is required for view=read.")
        action = {"applets": "list_applets", "search": "search_source", "read": "read_source"}[view]
        return await _source.execute(action=action, appid=appid, pattern=pattern, regex=regex,
                                     file=file, start_line=start_line, end_line=end_line,
                                     limit=limit, max_hits=limit)

    @server.tool(name="decompile_applet", annotations=annotations(destructive=True), description="""Decrypt/unpack cached miniapp packages and write readable sources into the workspace.
Choose an appid with inspect_source(view=applets). No running process, hook or CDP
connection is required. Unchanged packages reuse derived output; force rebuilds it.
Coverage reports missing cached/declared subpackages, so incomplete output is not
proof that a feature is absent. Writes only derived workspace files and performs no
network fetch. Use inspect_source to search/read the result; dynamic claims still
need runtime/context/traffic verification.""")
    async def decompile_applet(
        appid: Annotated[str, Field(description="Cached applet identifier from inspect_source(view=applets).", min_length=1, max_length=128)],
        force: Annotated[bool, Field(description="Rebuild derived output even when the package set is unchanged.")] = False,
    ) -> DecompileReply:
        return await _source.execute(action="decompile", appid=appid, force=force)
