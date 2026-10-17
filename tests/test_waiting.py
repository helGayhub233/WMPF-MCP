"""Event ordering, request cancellation and native resource ownership regressions."""
from __future__ import annotations

import asyncio
import json
import threading
from types import SimpleNamespace

import anyio
import pytest

from wmpf_mcp.core import envelope
from wmpf_mcp.core.state import get_state
from wmpf_mcp.engine.core import DebugEngine, EngineError
from wmpf_mcp.injector.manager import InjectorManager, _Session
from wmpf_mcp.portal.core import PortalService
from wmpf_mcp.server import build_server
from wmpf_mcp.tools import _injection, _offsets, runtime


class ObservedEvent(asyncio.Event):
    def __init__(self, entered, count=1):
        super().__init__()
        self.entered, self.count = entered, count
    async def wait(self):
        self.count -= 1
        if self.count == 0:
            self.entered.set()
        return await super().wait()


@pytest.mark.anyio
@pytest.mark.parametrize("restart", [False, True])
async def test_engine_stop_wakes_reconnect_wait_even_if_restarted(restart):
    engine = DebugEngine()
    engine.running = True
    entered = asyncio.Event()
    engine._wakeup = ObservedEvent(entered)
    waiter = asyncio.create_task(engine.wait_miniapp(30))
    await asyncio.wait_for(entered.wait(), 1)
    await engine.stop()
    if restart:
        engine.running = True
    with pytest.raises(EngineError, match="stopped"):
        await asyncio.wait_for(waiter, 0.5)


@pytest.mark.anyio
async def test_engine_setup_wakes_all_waiters_and_command_cancel_cleans_future():
    engine = DebugEngine()
    engine.running = True
    entered = asyncio.Event()
    engine._wakeup = ObservedEvent(entered, 3)
    tasks = [asyncio.create_task(engine.wait_miniapp(30)) for _ in range(3)]
    await asyncio.wait_for(entered.wait(), 1)
    engine.miniapp_clients.add(object())
    engine.setup_context_at = 1
    engine._notify_lifecycle("setup_context")
    replies = await asyncio.wait_for(asyncio.gather(*tasks), 0.5)
    assert all(reply["setup_context_seen"] for reply in replies)
    sent = asyncio.Event()
    engine.send_cdp_payload = lambda _: sent.set()
    command = asyncio.create_task(engine.send_cdp_command("Runtime.evaluate"))
    await asyncio.wait_for(sent.wait(), 1)
    command.cancel()
    with pytest.raises(asyncio.CancelledError):
        await command
    assert not engine._pending


@pytest.mark.anyio
async def test_portal_reconnect_orders_sessions_before_new_contexts(monkeypatch):
    engine = DebugEngine()
    engine.running = True
    engine.epoch = 1
    engine.miniapp_clients.add(object())
    portal = PortalService()
    await portal.start(0, engine)
    emitted, forwarded = [], []
    monkeypatch.setattr(portal, "_send", lambda ws, raw: emitted.append(json.loads(raw)))
    monkeypatch.setattr(engine, "send_cdp_payload", lambda raw: forwarded.append(json.loads(raw)))
    ws = object()
    portal.state.auto_attach.add(ws)
    old = portal._attach(ws, "webview-0")
    emitted.clear()
    try:
        engine.epoch += 1
        engine._notify_lifecycle("connected")
        # This assertion runs before yielding: no timer tick is needed.
        assert old not in portal.state.sessions
        new = set(portal.state.sessions)
        assert len(new) == 2
        event = {"method": "Runtime.executionContextCreated", "params": {
            "context": {"id": 901, "name": "new-runtime"}}}
        engine._dispatch_miniapp_payload(json.dumps(event))
        contexts = [packet for packet in emitted if packet.get("method") == event["method"]]
        assert contexts and all(packet["sessionId"] in new for packet in contexts)
        portal._handle_browser_message(ws, json.dumps({"id": 1, "sessionId": old,
            "method": "Runtime.evaluate", "params": {"expression": "1+1"}}))
        assert not forwarded
        assert emitted[-1]["error"]["code"] == -32001
        assert 901 in portal._execution_contexts
        engine.running = False
        engine._notify_lifecycle("stopped")
        assert not portal.state.sessions and not portal._execution_contexts
    finally:
        await portal.stop()
    assert not engine._lifecycle_listeners and not engine._upstream_listeners


@pytest.mark.anyio
async def test_queued_frida_payload_from_previous_connection_is_dropped():
    engine = DebugEngine()
    engine.running = True
    engine._loop = asyncio.get_running_loop()
    observed = []
    engine.on_cdp_upstream(lambda raw, _: observed.append(json.loads(raw)))
    packet = json.dumps({"method": "Runtime.executionContextCreated", "params": {}})
    assert engine.feed_local_payload(packet, pid=11)
    engine.epoch += 1
    barrier = engine._loop.create_future()
    engine._loop.call_soon(barrier.set_result, None)
    await barrier
    assert not observed
    assert engine.feed_local_payload(packet, pid=11)
    barrier = engine._loop.create_future()
    engine._loop.call_soon(barrier.set_result, None)
    await barrier
    assert len(observed) == 1


@pytest.fixture
async def native_hooks(monkeypatch, tmp_path):
    loop = asyncio.get_running_loop()
    rig = SimpleNamespace(entered=asyncio.Event(), cancelled=asyncio.Event(), native_cancelled=asyncio.Event(),
        release=threading.Event(), cooperative=False, stage="load", sessions=[])
    current = threading.local()
    from wmpf_mcp.injector import manager as manager_module
    operation_type = manager_module._NativeOperation
    class CancelFlag(threading.Event):
        def set(self):
            super().set()
            loop.call_soon_threadsafe(rig.cancelled.set)
    class Operation(operation_type):
        def __init__(self):
            super().__init__()
            self.cancelled = CancelFlag()
    monkeypatch.setattr(manager_module, "_NativeOperation", Operation)

    class Cancellable:
        def __init__(self):
            self.cancelled = False
        def __enter__(self):
            self.previous = getattr(current, "operation", None)
            current.operation = self
            return self
        def __exit__(self, *_):
            current.operation = self.previous
            return False
        def cancel(self):
            self.cancelled = True
            loop.call_soon_threadsafe(rig.native_cancelled.set)
            if rig.cooperative:
                rig.release.set()

    def block(stage):
        if rig.stage == stage:
            loop.call_soon_threadsafe(rig.entered.set)
            if not rig.release.wait(3):
                raise TimeoutError("fixture worker deadline")
            if rig.cooperative and current.operation.cancelled:
                raise RuntimeError("fixture native cancellation")

    class Script:
        unloaded = False
        def on(self, _, callback):
            self.callback = callback
        def load(self):
            block("load")
            self.callback({"type": "send", "payload": {"type": "armed"}}, None)
        def unload(self):
            self.unloaded = True

    class Session:
        is_detached = False
        def __init__(self):
            self.script = Script()
        def create_script(self, _):
            block("create")
            return self.script
        def detach(self):
            self.is_detached = True

    def attach(pid):
        block("attach")
        session = Session()
        rig.sessions.append(session)
        return session

    manager = rig.manager = InjectorManager()
    manager._load_frida = lambda: SimpleNamespace(Cancellable=Cancellable,
        get_local_device=lambda: SimpleNamespace(attach=attach))
    manager._render_script = lambda _: "fixture"
    config = tmp_path / "offsets.json"
    config.write_text(json.dumps({"Format": "Mach-O", "ABI": "darwin-arm64",
                                  "Arch": {"arm64": {}}}), encoding="utf-8")
    get_state().config_path = str(config)
    rig.config = config
    monkeypatch.setattr(runtime, "_LIFECYCLE_LOCK", asyncio.Lock())
    monkeypatch.setattr(runtime, "collect_environment", lambda *_: {"environment_ready": True})
    async def verified(**_):
        return envelope.ok({"ready": True}, stage=get_state().stage.value)
    monkeypatch.setattr(_offsets, "execute", verified)
    monkeypatch.setattr(_injection, "get_injector", lambda: manager)
    monkeypatch.setattr(_injection, "get_adapter", lambda: SimpleNamespace(platform="darwin",
        main_module_path=lambda: str(config), running_pids=lambda: [11]))
    monkeypatch.setattr(_injection, "static_checks", lambda *_: [{"ok": True}])
    yield rig
    rig.release.set()
    manager.stop_sync()


@pytest.mark.anyio
@pytest.mark.parametrize("stage", ["attach", "create", "load"])
async def test_cancelled_start_cannot_commit_after_stop(native_hooks, stage):
    rig = native_hooks
    rig.stage = stage
    server = build_server()
    request = asyncio.create_task(server.call_tool("start_runtime", {"component": "hooks"}))
    await asyncio.wait_for(rig.entered.wait(), 2)
    request.cancel()
    await asyncio.wait_for(rig.cancelled.wait(), 1)
    assert not rig.native_cancelled.is_set()
    assert runtime._LIFECYCLE_LOCK.locked()
    assert not request.done()
    # A second cancellation must not interrupt ownership cleanup either.
    request.cancel()
    stop = asyncio.create_task(server.call_tool("stop_runtime", {"component": "hooks"}))
    rig.release.set()
    result, stopped = await asyncio.wait_for(asyncio.gather(request, stop, return_exceptions=True), 2)
    assert isinstance(result, asyncio.CancelledError)
    assert stopped.structured_content["ok"]
    assert not rig.manager.state.sessions
    assert all(session.is_detached for session in rig.sessions)
    assert all(session.script.unloaded is (stage in {"create", "load"}) for session in rig.sessions)
    assert not rig.manager.status()["active"]


@pytest.mark.anyio
async def test_native_deadline_cancels_and_rolls_back_partial_attach(native_hooks):
    rig = native_hooks
    rig.cooperative = True
    rig.manager.NATIVE_TIMEOUT_S = 0.05
    result = await asyncio.wait_for(build_server().call_tool("start_runtime", {"component": "hooks"}), 1)
    assert result.is_error
    assert result.structured_content["error"]["code"] == "E_HOOK_TIMEOUT"
    assert rig.cancelled.is_set()
    assert rig.native_cancelled.is_set()
    assert rig.sessions and all(session.is_detached for session in rig.sessions)
    assert not rig.manager.state.sessions


@pytest.mark.anyio
async def test_cancelled_incremental_attach_preserves_existing_owned_session(native_hooks):
    rig = native_hooks
    old_session = SimpleNamespace(is_detached=False, detach=lambda: None)
    old = _Session(7, old_session, None, ready=True)
    rig.manager.state.sessions.append(old)
    request = asyncio.create_task(rig.manager.start(rig.config, [7, 11]))
    await asyncio.wait_for(rig.entered.wait(), 1)
    request.cancel()
    await asyncio.wait_for(rig.cancelled.wait(), 1)
    rig.release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(request, 1)
    assert rig.manager.state.sessions == [old]
    assert not old_session.is_detached
    assert all(session.is_detached for session in rig.sessions)


@pytest.mark.anyio
@pytest.mark.parametrize("outcome", ["armed", "error", "stop", "timeout", "cancel"])
async def test_public_hooks_probe_waits_for_events_and_cleans_waiters(monkeypatch, fake_cancellable, outcome):
    manager = InjectorManager()
    session = SimpleNamespace(is_detached=False)
    session.detach = lambda: setattr(session, "is_detached", True)
    manager.state.sessions.append(_Session(11, session, None))
    # Historical armed counts belonging to other PIDs are never readiness.
    manager.state.pid_hits[99] = {"armed": 10}
    manager._load_frida = lambda: SimpleNamespace(Cancellable=fake_cancellable)
    monkeypatch.setattr(_injection, "get_injector", lambda: manager)
    entered = asyncio.Event()
    class Waiters(set):
        def add(self, item):
            super().add(item)
            entered.set()
    manager._waiters = Waiters()
    timeout = 0.1 if outcome == "timeout" else 30
    request = asyncio.create_task(build_server().call_tool("probe_runtime", {
        "layer": "hooks", "timeout_s": timeout}))
    await asyncio.wait_for(entered.wait(), 1)
    assert not request.done()
    try:
        if outcome in {"armed", "error"}:
            await asyncio.to_thread(manager._on_message, {"type": "send", "payload": {
                "type": outcome}}, None, pid=11)
        elif outcome == "stop":
            await manager.stop()
        elif outcome == "cancel":
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request
            return
        reply = await asyncio.wait_for(request, 0.5)
        if outcome == "armed":
            assert reply.structured_content["data"]["passed"]
            assert reply.structured_content["data"]["armed_pids"] == [11]
        else:
            assert reply.is_error
            expected = {"error": "E_INTERNAL", "stop": "E_ORDER_VIOLATION", "timeout": "E_HOOK_TIMEOUT"}
            assert reply.structured_content["error"]["code"] == expected[outcome]
    finally:
        request.cancel()
        await asyncio.gather(request, return_exceptions=True)
        assert not manager._waiters
        manager.stop_sync()


@pytest.mark.anyio
async def test_armed_callback_before_wait_does_not_require_another_event(fake_cancellable):
    manager = InjectorManager()
    manager.state.sessions.append(_Session(11, SimpleNamespace(is_detached=False), None))
    manager._on_message({"type": "send", "payload": {"type": "armed"}}, None, pid=11)
    status = await asyncio.wait_for(manager.wait_armed(30), 0.2)
    assert status["armed_pids"] == [11]
    assert not manager._waiters


@pytest.mark.anyio
async def test_cancelled_stop_finishes_cleanup_under_mcp_cancel_scope(monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()
    completed = []
    monkeypatch.setattr(runtime, "_LIFECYCLE_LOCK", asyncio.Lock())
    async def stop_hooks(**_):
        entered.set()
        await release.wait()
        completed.append(True)
        return envelope.ok({"unloaded": []}, stage=get_state().stage.value)
    monkeypatch.setattr(_injection, "execute", stop_hooks)
    scopes = []
    async def request():
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            await build_server().call_tool("stop_runtime", {"component": "hooks"})
    task = asyncio.create_task(request())
    await asyncio.wait_for(entered.wait(), 1)
    scopes[0].cancel()
    assert runtime._LIFECYCLE_LOCK.locked()
    release.set()
    await asyncio.wait_for(task, 1)
    assert completed and not runtime._LIFECYCLE_LOCK.locked()


@pytest.mark.anyio
async def test_mcp_cancel_scope_cancels_native_start_before_committing(native_hooks):
    rig = native_hooks
    scopes = []
    async def request():
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            await build_server().call_tool("start_runtime", {"component": "hooks"})
    task = asyncio.create_task(request())
    await asyncio.wait_for(rig.entered.wait(), 1)
    scopes[0].cancel()
    await asyncio.wait_for(rig.cancelled.wait(), 1)
    assert runtime._LIFECYCLE_LOCK.locked()
    rig.release.set()
    await asyncio.wait_for(task, 1)
    assert not rig.manager.state.sessions
    assert all(session.is_detached for session in rig.sessions)


@pytest.mark.anyio
async def test_old_script_callback_cannot_arm_reused_pid(native_hooks):
    rig = native_hooks
    rig.stage = None
    await rig.manager.start(rig.config, [11])
    old_callback = rig.sessions[0].script.callback
    await rig.manager.stop()
    await rig.manager.start(rig.config, [11])
    armed = {"type": "send", "payload": {"type": "armed"}}
    before = rig.manager.status()["pid_hits"]
    await asyncio.to_thread(old_callback, armed, None)
    assert rig.manager.status()["pid_hits"] == before
    assert (await rig.manager.wait_armed(1))["armed_pids"] == [11]


@pytest.mark.anyio
async def test_failed_rollback_remains_owned_until_explicit_stop(native_hooks):
    rig = native_hooks
    request = asyncio.create_task(rig.manager.start(rig.config, [11]))
    await asyncio.wait_for(rig.entered.wait(), 1)
    session = rig.sessions[0]
    real_detach = session.detach
    def refuse_detach():
        raise RuntimeError("fixture: detach refused")
    session.detach = refuse_detach
    request.cancel()
    await asyncio.wait_for(rig.cancelled.wait(), 1)
    rig.release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(request, 1)
    assert rig.manager.state.sessions and rig.manager.status()["active"]
    assert not rig.manager.status()["armed_pids"]
    rig.stage = None
    from wmpf_mcp.core.errors import ToolError, ErrorCode
    with pytest.raises(ToolError) as error:
        await rig.manager.start(rig.config, [11])
    assert error.value.code == ErrorCode.ORDER_VIOLATION
    session.detach = real_detach
    await rig.manager.stop()
    assert not rig.manager.state.sessions
