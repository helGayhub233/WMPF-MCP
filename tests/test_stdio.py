"""End-to-end stdio protocol check against a real server subprocess.

Run with pytest:  uv run pytest tests/test_stdio.py -v
"""

from __future__ import annotations

import json
import os
import sys

import pytest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.mark.anyio
async def test_stdio_roundtrip():
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "wmpf_mcp.server"],
        env={name: os.environ[name] for name in ("WMPF_MCP_HOME", "WMPF_MCP_WORKSPACE")},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert init.server_info.name == "wmpf-mcp"
            assert init.server_info.version
            assert "wmpf://manual/execution-flow" in init.instructions
            resources = await session.list_resources()
            assert "wmpf://manual/execution-flow" in {str(r.uri) for r in resources.resources}
            manual = await session.read_resource("wmpf://manual/execution-flow")
            assert "manage_wechat" in manual.contents[0].text and "ready_selector" in manual.contents[0].text
            prompts = await session.list_prompts()
            assert "wechat_workflow" in {prompt.name for prompt in prompts.prompts}

            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            assert len(names) == 13
            assert "check_environment" in names

            inject_tool = next(t for t in tools.tools if t.name == "start_runtime")
            assert inject_tool.annotations is not None
            assert inject_tool.annotations.idempotent_hint is False

            result = await session.call_tool('check_environment', {'scope': 'wechat'})
            payload = json.loads(result.content[0].text)
            assert "stage" in payload and "ok" in payload

            failure = await session.call_tool('prepare_offsets', {'source': 'import'})
            assert failure.is_error
            assert failure.structured_content["error"]["code"] == "E_PARAM"
            invalid = await session.call_tool('inspect_binary', {'limit': 0})
            assert invalid.is_error
            assert "limit" in invalid.content[0].text
            page_timeout = await session.call_tool("probe_runtime", {
                "layer": "page", "ready_selector": "#business", "timeout_s": 60})
            assert page_timeout.is_error and "timeout_s" in page_timeout.content[0].text
            stale = await session.call_tool("clear_traffic", {"action": "list"})
            assert stale.is_error
            assert stale.structured_content["error"]["code"] == "E_PARAM"
