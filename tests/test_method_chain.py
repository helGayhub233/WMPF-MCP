"""Method-chain regressions: real queries, negative predicates and wire contracts."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import aiohttp
import pytest
from jsonschema import Draft202012Validator

from wmpf_mcp.core.state import Stage, get_state
from wmpf_mcp.offsets.inspection import inspect_binary
from wmpf_mcp.server import build_server


def elf_file(path: Path) -> Path:
    data = bytearray(0x1200)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, 62)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 2)
    struct.pack_into("<II6Q", data, 64, 1, 4, 0, 0x400000, 0, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<II6Q", data, 120, 1, 5, 0x1000, 0x401000, 0, 0x200, 0x200, 0x1000)
    data[0x1000:0x1007] = b"\x48\x8d\x05" + struct.pack("<i", 0x80 - 7)
    data[0x1007:0x100c] = b"\xe8" + struct.pack("<i", 0x20 - 12)
    data[0x100c] = 0xC3
    data[0x1080:0x1093] = b"SendToClientFilter\0"
    path.write_bytes(data)
    return path


def pe_file(path: Path) -> Path:
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<Q", data, 0xB0, 0x140000000)
    struct.pack_into("<8s6I2HI", data, 0x188, b".text", 0x200, 0x1000, 0x200, 0x200,
                     0, 0, 0, 0, 0x60000020)
    data[0x200:0x203] = b"\x90\x90\xc3"
    data[0x280:0x293] = b"SendToClientFilter\0"
    path.write_bytes(data)
    return path


def macho_file(path: Path) -> Path:
    data = bytearray(0x300)
    base = 0x100000000
    struct.pack_into("<8I", data, 0, 0xFEEDFACF, 0x0100000C, 0, 6, 1, 152, 0, 0)
    struct.pack_into("<II16sQQQQiiII", data, 32, 0x19, 152, b"__TEXT",
                     base, 0x300, 0, 0x300, 5, 5, 1, 0)
    struct.pack_into("<16s16sQQ8I", data, 104, b"__text", b"__TEXT",
                     base + 0x100, 0x80, 0x100, 2, 0, 0, 0x80000400, 0, 0, 0)
    struct.pack_into("<5I", data, 0x100, 0x94000020, 0xB9400808, 0x7100191F, 0x54000041, 0xD65F03C0)
    data[0x200:0x213] = b"SendToClientFilter\0"
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("factory,fmt,isa,off,va,rva", [
    (elf_file, "ELF", "x86_64", "0x1080", "0x401080", "0x1080"),
    (pe_file, "PE", "x86_64", "0x280", "0x140001080", "0x1080"),
    (macho_file, "Mach-O", "arm64", "0x200", "0x100000200", "0x200"),
])
def test_binary_questions_preserve_address_kinds(tmp_path, factory, fmt, isa, off, va, rva):
    path = factory(tmp_path / "module")
    result = inspect_binary(path, view="strings", pattern="SendToClientFilter")
    assert (result["format"], result["arch"]) == (fmt, isa)
    row = result["results"][0]
    assert (row["file_offset"], row["va"], row["rva"]) == (off, va, rva)
    assert not result["truncated"]


def test_x86_xrefs_calls_and_resume_are_bounded(tmp_path):
    path = elf_file(tmp_path / "module")
    refs = inspect_binary(path, view="xrefs", address="0x401080", scan_bytes=12)
    assert refs["results"][0]["va"] == "0x401000"
    assert refs["next_address"] == "0x40100c"
    assert refs["truncated"]
    calls = inspect_binary(path, view="calls", address="0x401000", scan_bytes=13)
    assert calls["results"][0]["target_va"] == "0x401020"
    assert calls["scanned_bytes"] <= 13


def test_macho_reader_maps_nonzero_image_base(tmp_path):
    from wmpf_mcp.offsets.formats.macho import MachOSlice
    image = MachOSlice(macho_file(tmp_path / "module"))
    assert image.find_string(b"SendToClientFilter") == [0x100000200]
    assert image.read_cstr(0x100000200) == "SendToClientFilter"
    assert image.va_to_off(0x100000100) == 0x100


@pytest.mark.parametrize("clobber,expected", [(None, {0x1200}), (0x528000C8, set()), (0xAA0103E0, set())])
def test_filter_role_follows_return_dataflow_not_first_call(clobber, expected):
    from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
    from wmpf_mcp.offsets.extractor import _filter_calls
    words = [0x94000040, 0xD503201F, 0x9400007E]
    if clobber == 0xAA0103E0:
        words.append(clobber)  # x0 replaced before the load
    words.append(0xB9400808)
    if clobber == 0x528000C8:
        words.append(clobber)  # loaded tag replaced before compare
    words += [0x7100191F, 0xD65F03C0]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    instructions = list(md.disasm(struct.pack("<" + "I" * len(words), *words), 0x1000))
    image = SimpleNamespace(disasm=lambda *_: instructions)
    assert _filter_calls(image, 0x1000) == expected


def test_empty_wrong_arch_and_missing_required_hooks_fail(tmp_path):
    from wmpf_mcp.offsets.extractor import verify_config
    path = macho_file(tmp_path / "module")
    for config in ({}, {"Arch": {"x86_64": {"LoadStartHookOffset": "0x100"}}},
                   {"Arch": {"arm64": {"LoadStartHookOffset": "0x100"}}}):
        checks = verify_config(path, config)
        assert checks and not all(c.ok for c in checks)
    checks = verify_config(path, {"Arch": {"arm64": {
        "LoadStartHookOffset": 256, "CDPFilterHookOffset": "0x100",
    }}})
    entry = next(check for check in checks if check.key == "LoadStartHookOffset")
    assert not entry.ok and "hex" in entry.note


@pytest.mark.anyio
async def test_tool_contracts_and_structured_execution_errors():
    server = build_server()
    tools = await server.list_tools()
    assert len(tools) == 13
    for tool in tools:
        definition = tool.model_dump(by_alias=True, exclude_none=True)
        assert len(definition["description"]) <= 1200
        assert all(p.get("description") for p in definition["inputSchema"]["properties"].values())
        assert definition.get("outputSchema")
    result = await server.call_tool('prepare_offsets', {'source': 'import'})
    assert result.is_error
    payload = result.structured_content
    assert payload["error"]["code"] == "E_PARAM"
    definition = next(t for t in tools if t.name == "prepare_offsets").model_dump(by_alias=True)
    Draft202012Validator(definition["outputSchema"]).validate(payload)
    from mcp.server.mcpserver.exceptions import ToolError as SDKToolError
    with pytest.raises(SDKToolError, match="limit"):
        await server.call_tool('inspect_binary', {'limit': 0})


@pytest.mark.anyio
async def test_elf_analysis_failure_has_an_executable_next_question(tmp_path):
    path = elf_file(tmp_path / "module")
    server = build_server()
    result = await server.call_tool('prepare_offsets', {'binary_path': str(path), 'source': 'extract'})
    assert result.is_error
    payload = result.structured_content
    assert payload["error"]["code"] == "E_UNSUPPORTED_ANALYSIS"
    assert payload["stage"] == "INIT"
    step = payload["next_actions"][0]
    follow = await server.call_tool(step["tool"], step["arguments"])
    assert not follow.is_error
    assert follow.structured_content["data"]["results"][0]["va"] == "0x401080"
    assert not list(tmp_path.glob("addresses.*"))


@pytest.mark.anyio
async def test_truncated_header_is_an_actionable_parameter_error(tmp_path):
    path = tmp_path / "broken"
    path.write_bytes(b"\x7fELF")
    result = await build_server().call_tool('inspect_binary', {'binary_path': str(path)})
    assert result.is_error
    assert result.structured_content["error"]["code"] == "E_PARAM"
    assert result.structured_content["next_actions"]


@pytest.mark.anyio
async def test_unknown_version_does_not_block_location(monkeypatch, tmp_path):
    from wmpf_mcp.platform.base import RuntimeInfo
    path = elf_file(tmp_path / "module")
    adapter = SimpleNamespace(
        platform="linux", locate=lambda: RuntimeInfo("linux", "x86_64", None, str(path), None, None, []),
        main_module_path=lambda: str(path),
    )
    monkeypatch.setattr("wmpf_mcp.tools.environment.get_adapter", lambda: adapter)
    result = await build_server().call_tool('check_environment', {'scope': 'wechat'})
    assert not result.is_error
    assert result.structured_content["data"]["wechat"]["wmpf_version"] is None
    assert result.structured_content["data"]["wechat"]["binary_path"] == str(path)
    assert result.structured_content["stage"] == "LOCATED"


@pytest.mark.anyio
async def test_cached_candidate_is_rechecked_and_failed_import_preserves_file(monkeypatch, tmp_path):
    from wmpf_mcp.tools import _offsets as offsets_ops
    candidate = tmp_path / "candidate.json"
    candidate.write_text('{"Arch":{"arm64":{}}}')
    installed = tmp_path / "addresses.local.json"
    installed.write_text('{"old":true}')
    monkeypatch.setattr(offsets_ops, "_config_path", lambda _: installed)
    monkeypatch.setattr(offsets_ops, "static_checks",
                        lambda *_: [{"key": "required_hook", "ok": False, "note": "missing"}])
    state = get_state()
    state.config_path = str(candidate)
    state.advance(Stage.PORTAL_UP)
    server = build_server()
    verified = await server.call_tool('check_offsets', {'config_path': str(candidate), 'binary_path': str(candidate)})
    assert not verified.structured_content["data"]["ready"]
    assert state.config_path is None
    imported = await server.call_tool('prepare_offsets', {'candidate_path': str(candidate), 'binary_path': str(candidate), 'force': True, 'source': 'import'})
    assert imported.is_error
    assert installed.read_text() == '{"old":true}'


@pytest.mark.anyio
async def test_diagnose_is_read_only_and_does_not_trust_historical_stage(monkeypatch):
    from wmpf_mcp.tools import runtime as session_ops
    get_state().advance(Stage.PORTAL_UP)
    live = {"inject": {"active": False}, "engine": {"running": False},
            "portal": {"running": False}}
    monkeypatch.setattr(session_ops, "_live", lambda: live)
    result = await build_server().call_tool('inspect_runtime', {})
    assert result.structured_content["data"]["branch"] == "environment"
    assert result.structured_content["next_actions"][0]["tool"] == "check_environment"
    source = await build_server().call_tool('inspect_runtime', {'goal': 'source'})
    assert source.structured_content["next_actions"][0]["tool"] == "inspect_source"
    assert get_state().stage == Stage.PORTAL_UP


@pytest.mark.anyio
async def test_stale_stage_cannot_start_resources():
    get_state().advance(Stage.PORTAL_UP)
    server = build_server()
    portal = await server.call_tool('start_runtime', {'component': 'portal'})
    assert portal.is_error
    assert portal.structured_content["error"]["code"] == "E_PORTAL_NO_TARGET"


@pytest.mark.anyio
async def test_missing_body_field_is_not_reported_as_an_empty_body(monkeypatch):
    from wmpf_mcp.portal.ledger import TrafficLedger
    from wmpf_mcp.tools import _traffic as traffic_ops
    ledger = TrafficLedger()
    ledger.activate()
    ledger.observe(json.dumps({"params": {
        "requestId": "request-1", "request": {"url": "https://example.test/", "method": "GET"},
    }}), "Network.requestWillBeSent")
    async def send(*_, **__):
        return {"result": {}}
    monkeypatch.setattr(traffic_ops, "get_engine", lambda: SimpleNamespace(
        running=True, miniapp_clients={object()}, send_cdp_command=send,
    ))
    monkeypatch.setattr(traffic_ops, "get_portal", lambda: SimpleNamespace(running=True, ledger=ledger))
    result = await build_server().call_tool('query_traffic', {'request_id': 'request-1', 'view': 'body'})
    data = result.structured_content["data"]
    assert "response_body_error" in data and "request_body_error" in data
    assert "response_body" not in data and "request_body" not in data


def test_server_bootstraps_without_optional_analysis_modules():
    code = """
import asyncio, importlib.abc, sys
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('capstone', 'numpy'):
            raise ModuleNotFoundError('optional dependency unavailable', name=fullname)
sys.meta_path.insert(0, Block())
from wmpf_mcp.server import build_server
async def main():
    server = build_server()
    assert len(await server.list_tools()) == 13
    result = await server.call_tool('check_environment', {'goal':'offsets'})
    assert not result.is_error, result
    capstone = next(p for p in result.structured_content['data']['dependencies']['packages'] if p['package']=='capstone')
    assert not capstone['importable']
asyncio.run(main())
"""
    subprocess.run([sys.executable, "-B", "-c", code], check=True,
                   capture_output=True, text=True, timeout=10)


def test_hook_refuses_arm64_fallback_on_x64():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js unavailable")
    from wmpf_mcp.injector.manager import TEMPLATE_PATH
    source = TEMPLATE_PATH.read_text().replace("@@CONFIG@@", '{"Arch":{"arm64":{"CDPFilterHookOffset":"0x100"}}}')
    harness = """
const vm=require('node:vm'), assert=require('node:assert/strict'), fs=require('node:fs');
const messages=[];
vm.runInNewContext(fs.readFileSync(0,'utf8'),{
  Process:{platform:'darwin',arch:'x64',id:1,findModuleByName:()=>({base:0})},
  send:message=>messages.push(message),setImmediate:fn=>fn(),
  Interceptor:{attach:()=>{throw new Error('wrong ISA was hooked')}}
});
assert(messages.some(m=>m.type==='error' && m.message.includes('arch x64')));
assert(!messages.some(m=>m.type==='armed'));
"""
    subprocess.run([node, "-e", harness], input=source, check=True,
                   capture_output=True, text=True, timeout=10)


@pytest.mark.anyio
async def test_portal_probe_uses_real_contexts_and_preserves_other_clients():
    from wmpf_mcp.portal.core import PortalService
    from wmpf_mcp.portal.probe import probe_portal

    class Engine:
        running, epoch = True, 7
        def __init__(self):
            self.miniapp_clients = {object()}
            self.listeners = []
            self.lifecycle_listeners = []
            self.reply = True
        def on_lifecycle(self, callback):
            self.lifecycle_listeners.append(callback)
        def off_lifecycle(self, callback):
            self.lifecycle_listeners.remove(callback)
        def on_cdp_upstream(self, callback):
            self.listeners.append(callback)
        def off_cdp_upstream(self, callback):
            self.listeners.remove(callback)
        def emit(self, packet):
            for callback in list(self.listeners):
                callback(json.dumps(packet), packet.get("method", ""))
        def send_cdp_payload(self, raw):
            command = json.loads(raw)
            if not self.reply:
                return
            method, params = command["method"], command.get("params", {})
            if method == "Runtime.enable":
                for context in (
                    {"id": 17, "name": "renderer-42", "auxData": {"frameId": "ui"}},
                    {"id": 18, "name": "business", "auxData": {"frameId": "business"}},
                ):
                    self.emit({"method": "Runtime.executionContextCreated", "params": {"context": context}})
            result = {}
            if method == "Page.getFrameTree":
                result = {"frameTree": {"frame": {"id": "native-root", "name": ""},
                                       "childFrames": [{"frame": {"id": "ui", "parentId": "native-root", "name": "renderer-42"}}]}}
            elif method == "Runtime.evaluate":
                value = 2 if params["expression"] == "1+1" else {
                    "dom": params.get("contextId") == 17, "wx": params.get("contextId") == 18,
                    "eval": params.get("contextId") == 17, "getCurrentPages": params.get("contextId") == 18,
                }
                result = {"result": {"value": value}}
            asyncio.get_running_loop().call_soon(self.emit, {"id": command["id"], "result": result})

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    engine, portal = Engine(), PortalService()
    cleaned = asyncio.Queue()
    real_cleanup = portal._cleanup_client
    def observe_cleanup(ws):
        real_cleanup(ws)
        cleaned.put_nowait(ws)
    portal._cleanup_client = observe_cleanup
    await portal.start(port, engine)
    try:
        async with aiohttp.ClientSession() as client:
            peer = await client.ws_connect(portal.version_payload()["webSocketDebuggerUrl"])
            await peer.send_json({"id": 99, "method": "Target.attachToTarget",
                                  "params": {"targetId": "webview-0", "flatten": True}})
            while True:
                packet = await peer.receive_json()
                if packet.get("id") == 99:
                    owned = packet["result"]["sessionId"]
                    break
            reply = await build_server().call_tool("probe_runtime", {"portal_port": port, "timeout_s": 3})
            assert not reply.is_error, reply
            result = reply.structured_content["data"]
            assert result["passed"], result
            assert any(c["capabilities"]["dom"] for c in result["contexts"])
            assert any(c["capabilities"]["wx"] for c in result["contexts"])
            assert any(f["name"] == "renderer-42" for f in result["frames"])
            await asyncio.wait_for(cleaned.get(), 1)
            assert owned in portal.state.sessions
            assert len(portal.state.sessions) == 1
            assert not peer.closed and engine.running
            engine.reply = False
            started = asyncio.get_running_loop().time()
            failed = await probe_portal(port, timeout_s=0.1)
            assert not failed["passed"]
            assert asyncio.get_running_loop().time() - started < 1
            await asyncio.wait_for(cleaned.get(), 1)
            assert owned in portal.state.sessions and len(portal.state.sessions) == 1
            await peer.close()
    finally:
        await portal.stop()
