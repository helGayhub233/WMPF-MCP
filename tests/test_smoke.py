"""Smoke checks: tool surface, envelope contract, read-only chain.

Run with pytest:  uv run pytest tests/test_smoke.py -v
"""

from __future__ import annotations

import json
import os
import sys

import pytest

from wmpf_mcp.server import build_server

EXPECTED_TOOLS = {
    "check_environment", "inspect_binary", "check_offsets", "prepare_offsets",
    "start_runtime", "stop_runtime", "inspect_runtime", "probe_runtime",
    "inspect_source", "decompile_applet", "query_traffic", "clear_traffic", "manage_wechat",
}


def _payload(result) -> dict:
    """Extract the structured envelope from a CallToolResult."""
    structured = getattr(result, "structuredContent", None)
    if structured:
        return structured
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if text:
            return json.loads(text)
    raise AssertionError(f"no structured content in {result!r}")


@pytest.mark.anyio
async def test_tool_surface():
    server = build_server()
    tools = await server.list_tools()
    assert {t.name for t in tools} == EXPECTED_TOOLS


@pytest.mark.anyio
async def test_doctor_envelope():
    server = build_server()
    result = _payload(await server.call_tool('check_environment', {}))
    assert result["ok"] is True
    assert result["next_actions"] or result["data"]["blockers"]
    data = result["data"]
    assert "permission" in data and "dependencies" in data and "wechat" in data
    assert set(data["ports"]) == {"9421", "10000", "20000"}


@pytest.mark.anyio
async def test_locate_and_offset_status_flow():
    server = build_server()
    locate = _payload(await server.call_tool('check_environment', {'scope': 'wechat'}))
    if not locate["data"].get("wechat", {}).get("binary_path"):
        pytest.skip("no WeChat install on this machine")
    assert locate["ok"] is True
    assert locate["stage"] == "LOCATED"
    assert "wmpf_version" in locate["data"]["wechat"]

    status = _payload(await server.call_tool('check_offsets', {}))
    assert status["ok"] is True
    assert status["data"]["source"] in ("cache", "none")


@pytest.mark.anyio
async def test_portal_requires_live_connection():
    """Historical progress cannot create a live upstream for Portal."""
    server = build_server()
    result = _payload(await server.call_tool('start_runtime', {'component': 'portal'}))
    assert result["ok"] is False
    assert result["error"]["code"] == "E_PORTAL_NO_TARGET"


@pytest.mark.anyio
@pytest.mark.skipif(sys.platform != "darwin", reason="Live automatic extractor roundtrip requires Mach-O arm64")
async def test_offsets_extract_and_verify_roundtrip():
    server = build_server()
    locate = _payload(await server.call_tool('check_environment', {'scope': 'wechat'}))
    if not locate["data"].get("wechat", {}).get("binary_path"):
        pytest.skip("no WeChat install on this machine")

    extracted = _payload(
        await server.call_tool('prepare_offsets', {'force': True, 'source': 'extract'})
    )
    assert extracted["ok"] is True, extracted
    arm = extracted["data"]["config"]["Arch"]["arm64"]
    for key in (
        "LoadStartHookOffset",
        "SceneSwitchHookOffset",
        "CDPFilterHookOffset",
        "ResourceCachePolicyHookOffset",
    ):
        assert str(arm.get(key, "")).startswith("0x"), key
    assert isinstance(arm.get("SceneChain"), list) and len(arm["SceneChain"]) >= 3
    assert arm.get("SceneToolValue") == 1101

    verified = _payload(await server.call_tool('check_offsets', {}))
    assert verified["ok"] is True
    assert verified["data"]["ready"] is True

    status = _payload(await server.call_tool('check_offsets', {}))
    assert status["data"]["source"] in ("cache", "extract")
    assert status["stage"] == "OFFSETS_READY"


@pytest.mark.anyio
@pytest.mark.skipif(os.environ.get("WMPF_RUN_LIVE_ATTACH") != "1", reason="Live WeChat attach is opt-in; deterministic lifecycle regressions run by default.")
async def test_inject_guards_and_permission_reporting():
    server = build_server()
    locate = _payload(await server.call_tool('check_environment', {'scope': 'wechat'}))
    if not locate["data"].get("wechat", {}).get("binary_path"):
        pytest.skip("no WeChat install on this machine")
    status = _payload(await server.call_tool('check_offsets', {}))
    if not status["data"]["ready"]:
        prepared = _payload(await server.call_tool("prepare_offsets", {}))
        if not prepared["ok"]:
            pytest.skip("no implemented parameter backend on this host")

    result = _payload(await server.call_tool('start_runtime', {'component': 'hooks'}))
    if not result["ok"]:
        # Unsigned environment: honest structured refusal with a remedy.
        assert result["error"]["code"] in ("E_PERMISSION", "E_WECHAT_NOT_RUNNING")
        assert result["error"].get("remedy")
    else:
        assert result["data"]["components"]["hooks"]["data"]["injected"]
        await server.call_tool('stop_runtime', {'component': 'hooks'})


@pytest.mark.anyio
async def test_offset_status_is_observable_before_location():
    server = build_server()
    # Observation stays available before location; mutation still needs real resources.
    result = _payload(await server.call_tool('check_offsets', {}))
    assert result["ok"] is True
    assert result["data"]["ready"] is False
    assert result["next_actions"][0]["tool"] == "inspect_binary"


@pytest.mark.anyio
async def test_static_track_list_applets():
    server = build_server()
    result = _payload(
        await server.call_tool('inspect_source', {'limit': 3})
    )
    assert result["ok"] is True
    assert result["data"]["count"] <= 3
    for applet in result["data"]["applets"]:
        assert applet["appid"].startswith("wx")


@pytest.mark.anyio
async def test_decompile_pipeline_roundtrip():
    server = build_server()
    listing = _payload(
        await server.call_tool('inspect_source', {'limit': 50})
    )
    candidates = [
        a
        for a in listing["data"]["applets"]
        if any(p["name"] == "__APP__.wxapkg" for p in a["packages"])
    ]
    if not candidates:
        pytest.skip("no cached applet with a main package")
    target = min(candidates, key=lambda a: sum(p["size"] for p in a["packages"]))

    result = _payload(
        await server.call_tool('decompile_applet', {'appid': target['appid']})
    )
    assert result["ok"] is True, result
    data = result["data"]
    assert data["coverage"]["main_pack"] is True
    assert data["stats"]["files"] > 0

    # idempotent second run returns the cached result
    again = _payload(
        await server.call_tool('decompile_applet', {'appid': target['appid']})
    )
    assert again["data"]["from_cache"] is True

    # search then read back through the tool surface
    search = _payload(
        await server.call_tool('inspect_source', {'appid': target['appid'], 'pattern': 'app', 'limit': 5, 'view': 'search'})
    )
    assert search["ok"] is True
    assert search["data"]["hits"]
    first = search["data"]["hits"][0]
    read = _payload(
        await server.call_tool('inspect_source', {'appid': target['appid'], 'file': first['file'], 'start_line': 1, 'end_line': 5, 'view': 'read'})
    )
    assert read["ok"] is True
    assert read["data"]["total_lines"] >= 1


@pytest.mark.anyio
async def test_unknown_applet_is_structured_error():
    server = build_server()
    result = _payload(
        await server.call_tool('decompile_applet', {'appid': 'wx0000000000000000'})
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "E_APPLET_NOT_FOUND"
    assert result["error"]["remedy"]


@pytest.mark.anyio
async def test_path_config_env_override(monkeypatch, tmp_path):
    from wmpf_mcp.core.config import resolve_wechat_paths

    fake_app = tmp_path / "WeChat.app"
    monkeypatch.setenv("WMPF_MCP_WECHAT_APP", str(fake_app))
    monkeypatch.setenv("WMPF_MCP_RADIUM_DIR", str(tmp_path / "radium"))

    paths = resolve_wechat_paths()
    assert paths.sources["WECHAT_APP"] == "env"
    assert paths.wechat_app == fake_app
    assert any("WMPF_MCP_WECHAT_APP" in w for w in paths.warnings)

    server = build_server()
    doctor = _payload(await server.call_tool('check_environment', {}))
    assert doctor["ok"] is True
    assert doctor["data"]["config"]["sources"]["WECHAT_APP"] == "env"
    assert doctor["data"]["path_warnings"]

    locate = _payload(await server.call_tool('check_environment', {'scope': 'wechat'}))
    assert locate["ok"] is True
    assert locate["data"]["wechat"]["runtime_path"] is None
    assert any(c["check"] == "runtime_module" and c["status"] == "unknown" for c in locate["data"]["checks"])


@pytest.mark.anyio
async def test_port_config_env_override(monkeypatch):
    from wmpf_mcp.core.config import (
        DEFAULT_CDP_PORT,
        DEFAULT_PORTAL_PORT,
        resolve_cdp_port,
        resolve_portal_port,
    )

    monkeypatch.setenv("WMPF_MCP_CDP_PORT", "12021")
    monkeypatch.setenv("WMPF_MCP_PORTAL_PORT", "22022")
    assert resolve_cdp_port() == 12021
    assert resolve_portal_port() == 22022

    server = build_server()
    doctor = _payload(await server.call_tool('check_environment', {}))
    assert set(doctor["data"]["ports"]) == {"9421", "12021", "22022"}
    status = _payload(await server.call_tool('inspect_runtime', {'component': 'engine'}))
    assert "12021" in status["data"]["live"]["engine"]["listening"]
    targets = _payload(await server.call_tool('inspect_runtime', {'component': 'portal'}))
    assert targets["data"]["live"]["portal"]["port"] in (None, 22022)

    # invalid values fall back to defaults
    monkeypatch.setenv("WMPF_MCP_CDP_PORT", "not-a-port")
    monkeypatch.setenv("WMPF_MCP_PORTAL_PORT", "99999")
    assert resolve_cdp_port() == DEFAULT_CDP_PORT
    assert resolve_portal_port() == DEFAULT_PORTAL_PORT


@pytest.mark.anyio
async def test_session_snapshot_fields():
    server = build_server()
    result = _payload(await server.call_tool('inspect_runtime', {}))
    assert result["ok"] is True
    data = result["data"]
    assert set(data["live"]) == {"inject", "engine", "portal", "notification"}
    assert result["next_actions"]
