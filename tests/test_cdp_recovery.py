"""Regressions for native CBOR loss and the browser-level CDP contract."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import struct
from pathlib import Path
from types import SimpleNamespace

import aiohttp
import pytest

from wmpf_mcp.engine import DebugEngine, DebugMessage, ChromeDevtools, CAT_SETUP_CONTEXT
from wmpf_mcp.engine import build_chrome_devtools
from wmpf_mcp.engine.cbor import CborError, decode_message
from wmpf_mcp.injector.manager import InjectorManager, TEMPLATE_PATH, _session_alive
from wmpf_mcp.portal import PortalService


def port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def cbor(value) -> bytes:
    """Small independent test encoder for CRDTP envelopes."""
    def header(major, length):
        if length < 24:
            return bytes([(major << 5) | length])
        return bytes([(major << 5) | 26]) + struct.pack(">I", length)

    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return header(0 if value >= 0 else 1, value if value >= 0 else -1 - value)
    if isinstance(value, str):
        major = 3 if value.isascii() else 2
        raw = value.encode("ascii" if major == 3 else "utf-16-le")
        return header(major, len(raw)) + raw
    if isinstance(value, dict):
        raw = b"\xbf" + b"".join(cbor(k) + cbor(v) for k, v in value.items()) + b"\xff"
    elif isinstance(value, list):
        raw = b"\x9f" + b"".join(cbor(v) for v in value) + b"\xff"
    else:
        raise TypeError(type(value))
    return b"\xd8\x18\x5a" + struct.pack(">I", len(raw)) + raw


def test_cbor_real_response_unicode_binary_and_invalid_frames():
    # Full on-device sample from the filter entry, id=43, Runtime.evaluate 1+1.
    raw = bytes.fromhex(
        "d8185a00000050bf626964182b66726573756c74d8185a0000003bbf66726573756c74"
        "d8185a0000002bbf6474797065666e756d6265726576616c7565fb4000000000000000"
        "6b6465736372697074696f6e6132ffffff"
    )
    assert decode_message(raw)["result"]["result"]["value"] == 2
    event = {"method": "Runtime.executionContextCreated",
             "params": {"context": {"id": 5, "name": "微信小程序 🐧"}}}
    assert decode_message(cbor(event)) == event
    assert decode_message(b"\xd6\x43\x00\x01\xff") == "AAH/"
    for invalid in (b"", b"\x18", b"\x1a\x00", b"\xd8\x18\x41\xbf",
                    b"\xd8\x18\x42\xbf\x00", raw[:-1], raw + b"\x00"):
        with pytest.raises(CborError):
            decode_message(invalid)


def test_native_filter_json_detach_is_identified_before_cbor():
    # Exact 67-byte filter sample captured during a real runtime replacement.
    raw = b'{"method":"Inspector.detached","params":{"reason":"target_closed"}}'
    assert len(raw) == 67
    assert decode_message(raw) == {"method": "Inspector.detached", "params": {"reason": "target_closed"}}
    response = {"id": 7, "result": {"text": "微信 🐧"}}
    assert decode_message(b" \r\n\t" + json.dumps(response, ensure_ascii=False).encode()) == response
    for invalid in (b'{"method":', raw + b'{}', b'{"x":"\xff"}', b'{"x":NaN}', b'{"x":Infinity}'):
        with pytest.raises(CborError, match="invalid native JSON"):
            decode_message(invalid)
    # A damaged CBOR envelope stays a CBOR failure, without a text fallback.
    with pytest.raises(CborError, match="truncated byte string"):
        decode_message(cbor({"id": 7, "result": {}})[:-1])


def test_cbor_container_depth_excludes_tag24_envelopes_but_remains_bounded():
    def nested(depth):
        raw = b"\x00"
        for _ in range(depth):
            payload = b"\x9f" + raw + b"\xff"
            raw = b"\xd8\x18\x5a" + struct.pack(">I", len(payload)) + payload
        return raw

    # The captured full DOM response has 78 container levels. Test this and
    # the CRDTP stack boundary independently of a large/private page fixture.
    for depth in (78, 300):
        value = decode_message(nested(depth))
        for _ in range(depth):
            assert len(value) == 1
            value = value[0]
        assert value == 0
    with pytest.raises(CborError, match="container nesting exceeds 300"):
        decode_message(nested(301))
    # Arbitrary tag chains cannot evade the separate tag recursion budget.
    with pytest.raises(CborError, match="tag nesting exceeds"):
        decode_message(b"\xc0" * 1000 + b"\x00")


@pytest.mark.anyio
async def test_frida_thread_recovers_events_responses_and_large_payloads(monkeypatch):
    engine = DebugEngine()
    await engine.start(port(), port())
    monkeypatch.setattr("wmpf_mcp.engine.get_engine", lambda: engine)
    manager = InjectorManager()
    observed = []
    engine.on_cdp_upstream(lambda raw, method: observed.append(json.loads(raw)))
    try:
        async with aiohttp.ClientSession() as client:
            raw_ws = await client.ws_connect(f"ws://127.0.0.1:{engine.cdp_port}/")
            event = {"method": "Runtime.executionContextCreated",
                     "params": {"context": {"id": 5, "name": "微信"}}}
            response = {"id": 81, "result": {"data": "x" * 100_000}}
            future = asyncio.get_running_loop().create_future()
            engine._pending[81] = future
            for envelope in (event, response):
                await asyncio.to_thread(manager._on_message,
                    {"type": "send", "payload": {"type": "cbor_message", "pid": 123}},
                    cbor(envelope))
                assert json.loads(await asyncio.wait_for(raw_ws.receive_str(), 3)) == envelope
            assert await asyncio.wait_for(future, 3) == response
            assert observed == [event, response]
            # Native transport copies and empty filtered frames must not leak.
            engine._dispatch_miniapp_payload(json.dumps(response))
            engine._dispatch_miniapp_payload("{}")
            assert observed == [event, response]
            assert engine.status()["duplicate_payloads_dropped"] == 1
            assert engine.status()["empty_payloads_dropped"] == 1
            assert manager.status()["pid_hits"][123]["cbor_event"] == 1
            assert manager.status()["pid_hits"][123]["cbor_response"] == 1
            await raw_ws.send_json({"id": 82, "method": "Runtime.evaluate"})
            unavailable = await asyncio.wait_for(raw_ws.receive_json(), 3)
            assert unavailable["id"] == 82
            assert unavailable["error"]["code"] == -32000
            await raw_ws.close()
    finally:
        await engine.stop()
    assert engine.feed_local_payload("{}") is False


@pytest.mark.anyio
async def test_native_json_and_cbor_share_the_threadsafe_message_path(monkeypatch):
    engine = DebugEngine()
    await engine.start(port(), port())
    monkeypatch.setattr("wmpf_mcp.engine.get_engine", lambda: engine)
    manager = InjectorManager()
    observed = []
    engine.on_cdp_upstream(lambda raw, method: observed.append(json.loads(raw)))
    try:
        async with aiohttp.ClientSession() as client:
            ws = await client.ws_connect(f"ws://127.0.0.1:{engine.cdp_port}/")
            detached = {"method": "Inspector.detached", "params": {"reason": "target_closed"}}
            response = {"id": 88, "result": {"result": {"type": "number", "value": 2}}}
            future = asyncio.get_running_loop().create_future()
            engine._pending[88] = future
            for raw, value in ((json.dumps(detached).encode(), detached), (cbor(response), response)):
                await asyncio.to_thread(manager._on_message,
                    {"type": "send", "payload": {"type": "cbor_message", "pid": 123}}, raw)
                assert await asyncio.wait_for(ws.receive_json(), 3) == value
            assert await asyncio.wait_for(future, 3) == response
            assert observed == [detached, response]
            assert not manager.status()["recent_errors"]
            assert not manager.status()["failure_capture"]["frames"]
            await ws.close()
    finally:
        await engine.stop()


def test_hook_captures_large_frames_and_suppresses_only_captured_maps():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed to execute the Frida template harness")
    import subprocess

    source = TEMPLATE_PATH.read_text().replace(
        "@@CONFIG@@", json.dumps({"Version": 25800, "Arch": {"arm64": {
            "LoadStartHookOffset": "0x200", "CDPFilterHookOffset": "0x100"}}})
    )
    harness = r"""
const vm = require('vm');
const assert = require('assert');
const fs = require('fs');
const messages = [];
let hook;
const sandbox = {
  Process: {platform:'darwin', arch:'arm64', id:123, getCurrentThreadId:()=>7,
    findModuleByName:()=>({base:{add:p=>({toString:()=>p})}})},
  ptr: x=>x, Interceptor: {attach: (p, cb)=>{if(p.toString()==='0x100')hook=cb;return {detach(){}};},flush(){}},
  send: (meta, data)=>messages.push({meta, data}),
};
vm.runInNewContext(fs.readFileSync(0, 'utf8'), sandbox);
for (const size of [260, 1500000]) {
  const bytes = new Uint8Array(size);
  hook.onEnter.call({returnAddress:'0x200'}, [
    {isNull:()=>false, readByteArray: n=>{assert.equal(n,size);return bytes.buffer;}},
    {toUInt32:()=>size},
  ]);
}
const captured = messages.filter(m=>m.meta.type==='cbor_message');
assert.deepEqual(captured.map(m=>m.meta.size), [260,1500000]);
assert(captured.every(m=>m.meta.pid===123 && m.data instanceof ArrayBuffer));
let tag=6;
const retval={isNull:()=>false,add:()=>({readU32:()=>tag,writeU32:v=>{tag=v;}})};
hook.onLeave.call({cborCaptured:true}, retval);
assert.equal(tag,0);
// A failed capture must not suppress the only remaining output path.
tag=6;
hook.onLeave.call({cborCaptured:false}, retval);
assert.equal(tag,6);
tag=0;
hook.onLeave.call({cborCaptured:true}, retval);
assert.equal(tag,0);
"""
    subprocess.run([node, "-e", harness], input=source, text=True, check=True,
                   capture_output=True, timeout=10)


class FakeEngine:
    running = True
    epoch = 1

    def __init__(self):
        self.miniapp_clients = {object()}
        self.listeners = []
        self.lifecycle_listeners = []
        self.commands = []
        self.command_queue = asyncio.Queue()

    def on_lifecycle(self, callback):
        self.lifecycle_listeners.append(callback)

    def off_lifecycle(self, callback):
        self.lifecycle_listeners.remove(callback)

    def on_cdp_upstream(self, callback):
        self.listeners.append(callback)

    def off_cdp_upstream(self, callback):
        self.listeners.remove(callback)

    def send_cdp_payload(self, raw):
        if not self.miniapp_clients:
            raise RuntimeError("no miniapp")
        command = json.loads(raw)
        self.commands.append(command)
        self.command_queue.put_nowait(command)

    def emit(self, obj):
        for callback in list(self.listeners):
            callback(json.dumps(obj), obj.get("method", ""))


async def receive(ws):
    return json.loads(await asyncio.wait_for(ws.receive_str(), 3))


@pytest.mark.anyio
async def test_context_replay_survives_portal_restart_and_transport_reconnect_with_fresh_frame_filtering():
    class CachedEngine(FakeEngine):
        def __init__(self):
            super().__init__()
            self.cache = DebugEngine()
        def emit(self, packet):
            self.cache._dispatch_miniapp_payload(json.dumps(packet))
            super().emit(packet)
        def execution_contexts(self):
            return self.cache.execution_contexts()
    engine = CachedEngine()
    def context(identifier, frame, unique, default=True):
        return {"method": "Runtime.executionContextCreated", "params": {"context": {
            "id": identifier, "uniqueId": unique, "auxData": {"frameId": frame, "isDefault": default}}}}
    engine.emit(context(5, "actual-main", "first"))
    engine.emit(context(6, "removed-frame", "stale"))
    engine.emit(context(7, "actual-main", "foreign-world", False))
    assert set(engine.execution_contexts()) == {5, 6}
    async with aiohttp.ClientSession() as client:
        for cycle in range(3):
            frame, unique = ("new-main", "recreated") if cycle == 2 else ("actual-main", "first")
            if cycle == 1:
                engine.epoch += 1
            if cycle == 2:
                engine.emit({"method": "Runtime.executionContextDestroyed", "params": {"executionContextId": 5}})
                engine.emit(context(5, frame, unique))
            portal = PortalService()
            await portal.start(port(), engine)
            try:
                ws = await client.ws_connect(f"ws://127.0.0.1:{portal.state.port}/devtools/browser/{portal.browser_id}")
                await ws.send_json({"id": 1, "method": "Target.attachToTarget", "params": {"targetId": "webview-0", "flatten": True}})
                assert (await receive(ws))["method"] == "Target.attachedToTarget"
                sid = (await receive(ws))["result"]["sessionId"]
                for identifier, method in ((2, "Page.getFrameTree"), (3, "Runtime.enable")):
                    await ws.send_json({"id": identifier, "sessionId": sid, "method": method})
                    command = await asyncio.wait_for(engine.command_queue.get(), 1)
                    result = {"frameTree": {"frame": {"id": frame}}} if method == "Page.getFrameTree" else {}
                    engine.emit({"id": command["id"], "result": result})
                    assert (await receive(ws))["id"] == identifier
                    replay = await receive(ws)
                    assert replay["method"] == "Runtime.executionContextCreated"
                    assert replay["params"]["context"]["id"] == 5
                    assert replay["params"]["context"]["uniqueId"] == unique
                    assert replay["params"]["context"]["auxData"]["frameId"] == "webview-0"
                await ws.close()
            finally:
                await portal.stop()
    engine.emit({"method": "Runtime.executionContextsCleared", "params": {}})
    assert not engine.execution_contexts()
    engine.emit(context(5, "new-main", "last"))
    engine.cache.running = True
    await engine.cache.stop()
    assert not engine.execution_contexts()


@pytest.mark.anyio
async def test_portal_discovery_autoattach_session_routing_and_epoch():
    engine, portal = FakeEngine(), PortalService()
    await portal.start(port(), engine)
    try:
        async with aiohttp.ClientSession() as client:
            async with client.get(f"http://127.0.0.1:{portal.state.port}/json/version/") as res:
                assert res.status == 200
                version = await res.json()
            ws = await client.ws_connect(version["webSocketDebuggerUrl"])
            other = await client.ws_connect(version["webSocketDebuggerUrl"])
            await ws.send_json({"id": 1, "method": "Target.setAutoAttach",
                                "params": {"autoAttach": True, "flatten": True}})
            attached = [await receive(ws), await receive(ws)]
            assert all(e["method"] == "Target.attachedToTarget" for e in attached)
            assert (await receive(ws))["id"] == 1
            sessions = {e["params"]["targetInfo"]["targetId"]: e["params"]["sessionId"]
                        for e in attached}
            sid = sessions["webview-0"]
            await other.send_json({"id": 2, "sessionId": sid, "method": "Runtime.enable"})
            assert (await receive(other))["error"]["code"] == -32001
            assert not engine.commands
            # Per-page child-target setup is local and retains sessionId.
            await ws.send_json({"id": 3, "sessionId": sid, "method": "Target.setAutoAttach",
                                "params": {"autoAttach": True, "flatten": True}})
            assert await receive(ws) == {"id": 3, "sessionId": sid, "result": {}}
            engine.emit({"method": "Runtime.executionContextCreated",
                         "params": {"context": {"id": 5}}})
            events = [await receive(ws), await receive(ws)]
            assert {e["sessionId"] for e in events} == set(sessions.values())
            engine.emit({"method": "Page.loadEventFired", "params": {"timestamp": 1}})
            assert (await receive(ws))["sessionId"] == sid
            # Direct-page and session clients may use the same original ID.
            direct = await client.ws_connect(
                f"ws://127.0.0.1:{portal.state.port}/devtools/page/webview-0")
            await ws.send_json({"id": 4, "sessionId": sid, "method": "Runtime.evaluate"})
            await direct.send_json({"id": 4, "method": "Runtime.evaluate"})
            for _ in range(2):
                await asyncio.wait_for(engine.command_queue.get(), 3)
            assert engine.commands[0]["id"] != engine.commands[1]["id"]
            for command in reversed(engine.commands):
                engine.emit({"id": command["id"], "result": {"ok": True}})
            assert await receive(ws) == {"id": 4, "sessionId": sid, "result": {"ok": True}}
            assert await receive(direct) == {"id": 4, "result": {"ok": True}}
            await direct.close()
            # Disconnect removes sessions; a new epoch auto-attaches again.
            engine.miniapp_clients.clear()
            portal._sync_targets()
            assert { (await receive(ws))["params"]["sessionId"] for _ in range(2)} == set(sessions.values())
            assert not portal.state.sessions
            engine.miniapp_clients.add(object())
            engine.epoch += 1
            portal._sync_targets()
            recreated = [await receive(ws), await receive(ws)]
            assert all(e["method"] == "Target.attachedToTarget" for e in recreated)
            assert not set(sessions.values()) & set(portal.state.sessions)
            assert not set(sessions) & {e["params"]["targetInfo"]["targetId"] for e in recreated}
            await other.close()
            await ws.close()
    finally:
        await portal.stop()


@pytest.mark.anyio
async def test_replacement_targets_have_unique_ids_even_in_one_event_batch():
    engine, portal = FakeEngine(), PortalService()
    await portal.start(port(), engine)
    try:
        async with aiohttp.ClientSession() as client:
            ws = await client.ws_connect(f"ws://127.0.0.1:{portal.state.port}/devtools/browser/{portal.browser_id}")
            await ws.send_json({"id": 1, "method": "Target.setDiscoverTargets", "params": {"discover": True}})
            assert (await receive(ws))["id"] == 1
            initial = {(await receive(ws))["params"]["targetInfo"]["targetId"] for _ in range(2)}
            engine.emit({"method": "Network.requestWillBeSent", "params": {"requestId": "old", "request": {"url": "http://fixture"}}})
            assert portal.ledger.get("old") is not None
            # No client commands in between: destruction and creation are
            # delivered together, the case that previously lost CLI pages.
            engine.epoch += 1
            portal._sync_targets()
            events = [await receive(ws) for _ in range(4)]
            destroyed = {e["params"]["targetId"] for e in events if e["method"] == "Target.targetDestroyed"}
            created = {e["params"]["targetInfo"]["targetId"] for e in events if e["method"] == "Target.targetCreated"}
            assert destroyed == initial and len(created) == 2 and not initial & created
            assert portal.ledger.get("old") is None
            assert {t.target_id for t in portal.targets()} == created
            await ws.close()
    finally:
        await portal.stop()


def test_frida_liveness_uses_supported_api():
    assert _session_alive(SimpleNamespace(is_detached=False))
    assert not _session_alive(SimpleNamespace(is_detached=True))


def test_decode_error_details_survive_noisy_hook_messages():
    manager = InjectorManager()
    manager._on_message({"type": "send", "payload": {"type": "cbor_message", "pid": 123}}, b"\x18")
    for index in range(300):
        manager._on_message({"type": "send", "payload": {"type": "stage", "index": index}}, None)
    status = manager.status()
    assert status["pid_hits"][123]["cbor_decode_error"] == 1
    assert all(e["type"] == "stage" for e in status["recent_messages"])
    error = status["recent_errors"][0]
    assert error["type"] == "cbor_decode_error" and error["pid"] == 123
    assert error["detail"] and not error["truncated"]
    assert "data" not in error and "hex" not in error


def test_error_summaries_are_bounded_and_returned_as_copies():
    manager = InjectorManager()
    for index in range(14):
        manager._record({"type": "error", "pid": index, "detail": "中文" * 2000, "raw_frame": b"discard"})
    errors = manager.status()["recent_errors"]
    assert len(errors) == 10 and errors[0]["pid"] == 4
    assert all(e["truncated"] and len(e["detail"].encode("utf-8")) <= 2048 for e in errors)
    assert all("raw_frame" not in e for e in errors)
    errors[-1]["detail"] = "caller mutation"
    assert manager.status()["recent_errors"][-1]["detail"] != "caller mutation"


def test_failed_frames_are_bounded_private_and_replayable(monkeypatch):
    import wmpf_mcp.injector.manager as module

    monkeypatch.setattr(module, "FAILED_FRAME_BYTES", 16)
    manager = InjectorManager()
    for size in (2, 3, 4, 5):
        manager._on_message({"type": "send", "payload": {
            "type": "cbor_message", "pid": 123, "size": size}}, b"\x00" * size)
    capture = manager.status()["failure_capture"]
    assert len(capture["frames"]) == 3
    assert capture["retained_bytes"] == 12
    assert manager.failed_frame("cbor-1") is None
    info, raw = manager.failed_frame("cbor-2")
    assert info["declared_bytes"] == len(raw) == 3 and not info["truncated"]
    with pytest.raises(CborError, match="trailing bytes"):
        decode_message(raw)
    info["pid"] = 0
    assert manager.failed_frame("cbor-2")[0]["pid"] == 123
    assert "raw" not in json.dumps(manager.status())
    manager._on_message({"type": "send", "payload": {"type": "cbor_message"}}, b"\x00" * 8)
    capture = manager.status()["failure_capture"]
    assert capture["retained_bytes"] == 13 and len(capture["frames"]) == 2
    assert manager.failed_frame("cbor-2") is None
    # An oversize frame evicts the entire older byte budget and is clearly a
    # prefix. Successful traffic never enters this buffer.
    manager._on_message({"type": "send", "payload": {"type": "cbor_message"}}, b"\x00" * 20)
    capture = manager.status()["failure_capture"]
    assert capture["retained_bytes"] == 16 and len(capture["frames"]) == 1
    info, raw = manager.failed_frame(capture["frames"][0]["frame_id"])
    assert info["truncated"] and info["frame_bytes"] == 20 and len(raw) == 16
    manager._on_message({"type": "send", "payload": {"type": "cbor_message"}}, cbor(None))
    assert manager.status()["failure_capture"] == capture


@pytest.mark.parametrize("stage", ["input", "serialize", "forward"])
def test_cbor_failures_are_attributed_to_the_actual_stage(monkeypatch, stage):
    manager = InjectorManager()
    metadata = {"type": "cbor_message", "pid": 123}
    raw = cbor({"id": 7, "result": {}})
    if stage == "input":
        metadata["hex"] = "invalid"
        raw = None
    elif stage == "serialize":
        monkeypatch.setattr("wmpf_mcp.engine.cbor.decode_message", lambda _: {"id": 7, "result": object()})
    else:
        def feed(*_, **__):
            raise RuntimeError("forwarding failed")
        monkeypatch.setattr("wmpf_mcp.engine.get_engine", lambda: SimpleNamespace(feed_local_payload=feed))
    manager._on_message({"type": "send", "payload": metadata}, raw)
    status = manager.status()
    assert "cbor_decode_error" not in status["pid_hits"][123]
    assert status["pid_hits"][123][f"cbor_{stage}_error"] == 1
    error = status["recent_errors"][0]
    assert error["stage"] == stage and error["type"] == f"cbor_{stage}_error"
    if stage == "input":
        assert error["frame_id"] is None and not status["failure_capture"]["frames"]
    else:
        info, saved = manager.failed_frame(error["frame_id"])
        assert info["stage"] == stage and saved == raw


@pytest.mark.anyio
async def test_inject_start_covers_new_pids_without_duplicate_hooks(monkeypatch, tmp_path, fake_cancellable):
    from wmpf_mcp.core.state import Stage, get_state
    from wmpf_mcp.server import build_server

    attached = []

    class FakeScript:
        def on(self, event, callback):
            self.callback = callback

        def load(self):
            self.callback({"type": "send", "payload": {
                "type": "hook_hit", "hook": "cdp_probe", "count": 1}}, None)
            self.callback({"type": "send", "payload": {"type": "armed"}}, None)

    class FakeSession:
        is_detached = False

        def create_script(self, source):
            return FakeScript()

        def detach(self):
            self.is_detached = True

    def attach(pid):
        attached.append(pid)
        return FakeSession()

    manager = InjectorManager()
    monkeypatch.setattr(manager, "_load_frida", lambda: SimpleNamespace(
        get_local_device=lambda: SimpleNamespace(attach=attach), Cancellable=fake_cancellable))
    monkeypatch.setattr("wmpf_mcp.tools._injection.get_injector", lambda: manager)
    current_pids = [11]
    monkeypatch.setattr("wmpf_mcp.tools._injection.get_adapter", lambda: SimpleNamespace(
        platform="darwin", main_module_path=lambda: str(tmp_path / "framework"),
        running_pids=lambda: list(current_pids)))
    # This regression isolates PID coverage; candidate validity has separate tests.
    monkeypatch.setattr("wmpf_mcp.tools._injection.static_checks",
                        lambda *_: [{"key": "fixture", "ok": True}])
    config = tmp_path / "offsets.json"
    config.write_text('{"Version":25800,"Arch":{"arm64":{}}}')
    state = get_state()
    state.advance(Stage.OFFSETS_READY)
    state.config_path = str(config)
    # Isolate incremental PID coverage from environmental/static prerequisites.
    from wmpf_mcp.core import envelope as responses
    monkeypatch.setattr("wmpf_mcp.tools.runtime.collect_environment", lambda *_: {"environment_ready": True, "blockers": []})
    async def checked(**_):
        return responses.ok({"ready": True}, stage=state.stage.value)
    monkeypatch.setattr("wmpf_mcp.tools._offsets.execute", checked)
    server = build_server()
    for pids in ([11], [11, 12], [11, 12]):
        current_pids[:] = pids
        result = await server.call_tool('start_runtime', {'component': 'hooks'})
        envelope = getattr(result, "structuredContent", None) or json.loads(result.content[0].text)
        assert envelope["ok"], envelope
        assert envelope["data"]["first_unmet"] is None
    assert attached == [11, 12]
    assert all(s["alive"] for s in manager.status()["sessions"])
    assert manager.status()["pid_hits"] == {11: {"cdp_probe": 1, "armed": 1}, 12: {"cdp_probe": 1, "armed": 1}}


@pytest.mark.anyio
async def test_real_playwright_connect_over_cdp(monkeypatch):
    """Optional real-client check: no Chromium download or GUI required.

    Set WMPF_PLAYWRIGHT_MODULE to an installed playwright/index.mjs.
    The transport deliberately returns {} while Frida supplies complete CBOR.
    """
    module = os.environ.get("WMPF_PLAYWRIGHT_MODULE")
    if not module or not shutil.which("node"):
        pytest.skip("Set WMPF_PLAYWRIGHT_MODULE to run the real Playwright client")
    engine, portal, manager = DebugEngine(), PortalService(), InjectorManager()
    monkeypatch.setattr("wmpf_mcp.engine.get_engine", lambda: engine)
    await engine.start(port(), port())
    try:
        async with aiohttp.ClientSession() as client:
            miniapp = await client.ws_connect(f"ws://127.0.0.1:{engine.debug_port}/")
            await miniapp.send_bytes(DebugMessage(category=CAT_SETUP_CONTEXT).serialize())
            await engine.wait_miniapp(3)
            await portal.start(port(), engine)

            async def recover(envelope):
                await asyncio.to_thread(manager._on_message,
                    {"type": "send", "payload": {"type": "cbor_message", "pid": 123}},
                    cbor(envelope))

            async def runtime():
                async for msg in miniapp:
                    if msg.type != aiohttp.WSMsgType.BINARY:
                        continue
                    request = json.loads(ChromeDevtools.parse(
                        DebugMessage.parse(msg.data).payload_bytes()).payload)
                    method, params = request["method"], request.get("params", {})
                    await miniapp.send_bytes(build_chrome_devtools("{}", seq=request["id"]))
                    result = {}
                    if method == "Page.getFrameTree":
                        result = {"frameTree": {"frame": {"id": "main", "loaderId": "loader",
                            "url": "https://servicewechat.com/test", "securityOrigin": "https://servicewechat.com",
                            "mimeType": "text/html"}, "childFrames": [{"frame": {
                                "id": "child", "parentId": "main", "name": "page-frame_100",
                                "loaderId": "child-loader", "url": "https://servicewechat.com/view",
                                "securityOrigin": "https://servicewechat.com", "mimeType": "text/html"}}]}}
                    elif method == "Page.addScriptToEvaluateOnNewDocument":
                        result = {"identifier": "script"}
                    elif method == "Page.createIsolatedWorld":
                        result = {"executionContextId": 6}
                    elif method in ("Runtime.evaluate", "Runtime.callFunctionOn"):
                        result = {"result": {"type": "number", "value": 2}}
                    await recover({"id": request["id"], "result": result})
                    if method == "Runtime.enable":
                        for context_id, frame_id in ((5, "main"), (7, "child")):
                            await recover({"method": "Runtime.executionContextCreated", "params": {
                                "context": {"id": context_id, "origin": "https://servicewechat.com", "name": "",
                                    "auxData": {"isDefault": True, "type": "default", "frameId": frame_id}}}})

            task = asyncio.create_task(runtime())
            script = r"""
const {chromium} = await import(process.argv[1]);
setTimeout(()=>{console.error('Playwright smoke timed out');process.exit(2);},12000).unref();
try {
  await chromium.connectOverCDP(process.argv[2], {timeout:1500});
  throw new Error('Raw CDP must not connect as a browser');
} catch (error) {
  if (!String(error).includes('404')) throw error;
}
const browser = await chromium.connectOverCDP(process.argv[3], {timeout:8000});
const pages = browser.contexts().flatMap(c=>c.pages());
if (pages.length !== 2) throw new Error('Expected two initialized pages, got '+pages.length);
if (pages[0].frames().length !== 2) throw new Error('Child frame parentId was not mapped');
const view = pages[0].frames().find(f=>f.name()==='page-frame_100');
if (await view.evaluate('1+1') !== 2) throw new Error('Render frame evaluation failed');
const value = await pages[0].evaluate('1+1');
if (value !== 2) throw new Error('Unexpected evaluation result: '+value);
const session = await browser.contexts()[0].newCDPSession(pages[0]);
const raw = await session.send('Runtime.evaluate', {expression:'1+1',returnByValue:true});
if (raw.result.value !== 2) throw new Error('CDPSession evaluate failed');
await session.detach();
console.log(JSON.stringify({pages:pages.length, value}));
await browser.close();
"""
            proc = await asyncio.create_subprocess_exec(
                shutil.which("node"), "--input-type=module", "-e", script,
                Path(module).as_uri(), f"http://127.0.0.1:{engine.cdp_port}",
                f"http://127.0.0.1:{portal.state.port}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), 15)
                assert proc.returncode == 0, stderr.decode()
                assert json.loads(stdout) == {"pages": 2, "value": 2}
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
                await miniapp.close()
                await task
    finally:
        await portal.stop()
        await engine.stop()
