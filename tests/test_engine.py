"""M3 pipeline tests: codec, engine bus, portal sessions, tool smoke."""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import zlib

import aiohttp
import pytest

from wmpf_mcp.core.state import Stage, get_state
from wmpf_mcp.core.syscheck import port_state
from wmpf_mcp.engine import (
    CAT_CHROME_DEVTOOLS,
    CAT_CHROME_DEVTOOLS_RESULT,
    CAT_SETUP_CONTEXT,
    ChromeDevtools,
    DebugEngine,
    DebugMessage,
    build_chrome_devtools,
    get_engine,
    parse_chrome_devtools_result,
)
from wmpf_mcp.portal import PortalService, get_portal
from wmpf_mcp.server import build_server


def pick_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def payload(response):
    structured = getattr(response, "structuredContent", None)
    if structured:
        return structured
    return json.loads(response.content[0].text)


@contextlib.asynccontextmanager
async def _cleanup_after():
    """Stop process-wide services even when a test fails midway."""
    try:
        yield
    finally:
        portal = get_portal()
        if portal.running:
            await portal.stop()
        engine = get_engine()
        if engine.running:
            await engine.stop()


async def _fake_miniapp(
    debug_port: int, ready: asyncio.Event, stop: asyncio.Event, emit_network: bool = False
) -> None:
    """A protocol-compliant fake runtime: setupContext + CDP echo."""
    async with aiohttp.ClientSession() as session:
        ws = await session.ws_connect(f"ws://127.0.0.1:{debug_port}/", max_msg_size=0)
        await ws.send_bytes(DebugMessage(seq=1, category=CAT_SETUP_CONTEXT).serialize())
        ready.set()
        seq = 100
        emitted = False
        try:
            async for msg in ws:
                if msg.type != aiohttp.WSMsgType.BINARY:
                    continue
                message = DebugMessage.parse(msg.data)
                if message.category != CAT_CHROME_DEVTOOLS:
                    continue
                inner = ChromeDevtools.parse(message.payload_bytes())
                request = json.loads(inner.payload)
                seq += 1
                await ws.send_bytes(
                    build_chrome_devtools(
                        json.dumps(
                            {"id": request["id"], "result": {"ok": True,
                                                             "method": request.get("method")}}
                        ),
                        seq=seq,
                    )
                )
                if emit_network and not emitted:
                    emitted = True
                    for event in (
                        {"method": "Network.requestWillBeSent",
                         "params": {"requestId": "t.1", "type": "XHR",
                                    "request": {"method": "GET",
                                                "url": "https://api.example.com/hello"}}},
                        {"method": "Network.responseReceived",
                         "params": {"requestId": "t.1", "type": "XHR",
                                    "response": {"status": 200, "mimeType": "application/json"}}},
                        {"method": "Network.loadingFinished",
                         "params": {"requestId": "t.1", "encodedDataLength": 42}},
                    ):
                        seq += 1
                        await ws.send_bytes(
                            build_chrome_devtools(json.dumps(event), seq=seq)
                        )
        except asyncio.CancelledError:
            pass


def _to_injected() -> None:
    """White-box: drive the session state machine to INJECTED (no real attach)."""
    state = get_state()
    state.platform = "darwin"
    state.wmpf_version = 25800
    for stage in (Stage.ENV_READY, Stage.LOCATED, Stage.OFFSETS_READY, Stage.INJECTED):
        state.advance(stage)


# -- codec --------------------------------------------------------------------
def test_codec_roundtrip_and_zlib():
    buf = build_chrome_devtools('{"id":1}', seq=5, jscontext_id="jc-1")
    outer = DebugMessage.parse(buf)
    assert outer.category == CAT_CHROME_DEVTOOLS
    assert outer.seq == 5
    inner = ChromeDevtools.parse(outer.payload_bytes())
    assert inner.payload == '{"id":1}'
    assert inner.jscontext_id == "jc-1"

    inner_bytes = ChromeDevtools(op_id=7, payload='{"id":2,"result":{}}').serialize()
    compressed = DebugMessage(
        seq=6,
        category=CAT_CHROME_DEVTOOLS_RESULT,
        data=zlib.compress(inner_bytes),
        compress_algo=1,
        original_size=len(inner_bytes),
    )
    parsed = DebugMessage.parse(compressed.serialize())
    assert parsed.payload_bytes() == inner_bytes
    decoded = parse_chrome_devtools_result(parsed)
    assert decoded is not None and decoded.op_id == 7
    assert decoded.payload == '{"id":2,"result":{}}'


# -- engine -------------------------------------------------------------------
@pytest.mark.anyio
async def test_engine_command_bus_roundtrip():
    debug_port, cdp_port = pick_port(), pick_port()
    engine = DebugEngine()
    await engine.start(debug_port, cdp_port)
    ready, stop = asyncio.Event(), asyncio.Event()
    task = asyncio.create_task(_fake_miniapp(debug_port, ready, stop))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        info = await engine.wait_miniapp(timeout_s=5)
        assert info["setup_context_seen"] is True

        response = await engine.send_cdp_command("Runtime.evaluate", {"expression": "1+1"})
        assert response["result"]["ok"] is True

        async with aiohttp.ClientSession() as session:
            proxy = await session.ws_connect(f"ws://127.0.0.1:{cdp_port}/", max_msg_size=0)
            await proxy.send_str(json.dumps({"id": 7, "method": "Page.enable"}))
            reply = json.loads(await asyncio.wait_for(proxy.receive_str(), 5))
            assert reply["id"] == 7 and reply["result"]["ok"] is True
            await proxy.close()
    finally:
        stop.set()
        await asyncio.wait_for(task, 5)
        await engine.stop()


@pytest.mark.anyio
async def test_engine_wait_miniapp_timeout():
    debug_port, cdp_port = pick_port(), pick_port()
    engine = DebugEngine()
    await engine.start(debug_port, cdp_port)
    try:
        with pytest.raises(Exception) as excinfo:
            await engine.wait_miniapp(timeout_s=0.2)
        assert "within" in str(excinfo.value)
    finally:
        await engine.stop()


# -- portal -------------------------------------------------------------------
@pytest.mark.anyio
async def test_portal_browser_session_and_ledger():
    debug_port, cdp_port, portal_port = pick_port(), pick_port(), pick_port()
    engine = DebugEngine()
    await engine.start(debug_port, cdp_port)
    portal = PortalService()
    ready, stop = asyncio.Event(), asyncio.Event()
    task = asyncio.create_task(_fake_miniapp(debug_port, ready, stop, emit_network=True))
    try:
        await asyncio.wait_for(ready.wait(), 5)
        await engine.wait_miniapp(timeout_s=5)

        info = await portal.start(portal_port, engine=engine)
        assert [t["target_id"] for t in info["targets"]] == ["webview-0", "appservice-0"]

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{portal_port}/json/version"
            ) as response:
                version = await response.json()
            async with session.get(f"http://127.0.0.1:{portal_port}/json/list") as response:
                targets = await response.json()
            assert [t["id"] for t in targets] == ["webview-0", "appservice-0"]

            ws = await session.ws_connect(version["webSocketDebuggerUrl"], max_msg_size=0)

            async def call(obj: dict) -> dict:
                await ws.send_str(json.dumps(obj))
                while True:
                    reply = json.loads(await asyncio.wait_for(ws.receive_str(), 10))
                    if reply.get("id") == obj["id"]:
                        return reply

            reply = await call({"id": 1, "method": "Browser.getVersion"})
            assert reply["result"]["product"].startswith("WMPF-MCP")

            reply = await call({"id": 2, "method": "Target.getTargets"})
            assert [t["targetId"] for t in reply["result"]["targetInfos"]] == [
                "webview-0", "appservice-0",
            ]

            reply = await call({"id": 3, "method": "Target.attachToTarget",
                                "params": {"targetId": "appservice-0", "flatten": True}})
            session_id = reply["result"]["sessionId"]

            reply = await call({"id": 4, "sessionId": session_id,
                                "method": "Runtime.evaluate",
                                "params": {"expression": "wx.getSystemInfoSync()"}})
            assert reply["id"] == 4 and reply["sessionId"] == session_id
            assert reply["result"]["ok"] is True

            # A missing browser implementation must not look like successful
            # creation/storage access, and must not consume the attached page.
            reply = await call({"id": 10, "method": "Target.createTarget",
                                "params": {"url": "about:blank"}})
            assert "result" not in reply and reply["error"]["code"] == -32000
            assert "no independent tab was created" in reply["error"]["message"]
            create_target_error = reply["error"]
            for index, method in enumerate(("Browser.getWindowForTarget",
                                           "Storage.getCookies", "Schema.getDomains",
                                           "Target.exposeDevToolsProtocol", "WMPF.nonexistent"), 11):
                reply = await call({"id": index, "method": method, "params": {"url": "about:blank"}})
                assert "result" not in reply and reply["error"]["code"] == -32601
            reply = await call({"id": 20, "method": "Target.getTargets", "params": []})
            assert reply["error"]["code"] == -32602
            reply = await call({"id": 21, "sessionId": session_id,
                                "method": "Runtime.evaluate", "params": {"expression": "1+1"}})
            assert reply["result"]["ok"] is True and reply["sessionId"] == session_id
            reply = await call({"id": 22, "method": "Target.getTargets"})
            assert len(reply["result"]["targetInfos"]) == 2
            reply = await call({"id": 23, "method": "Browser.setDownloadBehavior",
                                "params": {"behavior": "default"}})
            assert reply["result"]["method"] == "Browser.setDownloadBehavior"

            # Playwright's newBrowserCDPSession sends browser methods through
            # this owned session rather than directly on the root transport.
            reply = await call({"id": 24, "method": "Target.attachToBrowserTarget"})
            browser_session_id = reply["result"]["sessionId"]
            reply = await call({"id": 25, "sessionId": browser_session_id,
                                "method": "Target.createTarget", "params": {"url": "about:blank"}})
            assert "result" not in reply and reply["error"] == create_target_error
            assert reply["sessionId"] == browser_session_id
            reply = await call({"id": 26, "sessionId": browser_session_id,
                                "method": "WMPF.nonexistent"})
            assert "result" not in reply and reply["error"]["code"] == -32601
            assert reply["sessionId"] == browser_session_id
            reply = await call({"id": 27, "sessionId": session_id,
                                "method": "Runtime.evaluate", "params": {"expression": "1+1"}})
            assert reply["result"]["ok"] is True and reply["sessionId"] == session_id
            reply = await call({"id": 28, "sessionId": browser_session_id,
                                "method": "Target.getTargets"})
            assert reply["sessionId"] == browser_session_id
            assert [t["targetId"] for t in reply["result"]["targetInfos"]] == [
                "webview-0", "appservice-0",
            ]
            await ws.close()

        rows = portal.ledger.list()
        hello = next((r for r in rows if r["url"].endswith("/hello")), None)
        assert hello is not None, rows
        assert hello["status"] == 200 and hello["size"] == 42
    finally:
        await portal.stop()
        stop.set()
        await asyncio.wait_for(task, 5)
        await engine.stop()


# -- tool layer ---------------------------------------------------------------
@pytest.mark.anyio
async def test_engine_ops_smoke_and_timeout_diagnosis(monkeypatch):
    # Exercise real listeners through the tool without competing with live WeChat.
    debug_port = pick_port()
    monkeypatch.setattr("wmpf_mcp.tools._engine.DEBUG_PORT", debug_port)
    _to_injected()
    server = build_server()
    async with _cleanup_after():
        cdp_port = pick_port()
        while cdp_port == debug_port:
            cdp_port = pick_port()
        result = payload(
            await server.call_tool('start_runtime', {'cdp_port': cdp_port, 'component': 'engine'})
        )
        assert result["ok"] is True and result["stage"] == "ENGINE_UP"
        assert result["data"]["components"]["engine"]["data"]["status"]["running"] is True

        status = payload(await server.call_tool('inspect_runtime', {'component': 'engine'}))
        assert status["data"]["live"]["engine"]["miniapp_connected"] is False
        assert str(cdp_port) in status["data"]["live"]["engine"]["listening"]

        timeout = payload(
            await server.call_tool('probe_runtime', {'timeout_s': 1, 'layer': 'reconnect'})
        )
        assert timeout["ok"] is False
        assert timeout["error"]["code"] == "E_MINAPP_TIMEOUT"
        assert timeout["next_actions"]

        stopped = payload(await server.call_tool('stop_runtime', {'component': 'engine'}))
        assert stopped["ok"] is True and stopped["data"]["components"]["engine"]["data"]["stopped"] is True
