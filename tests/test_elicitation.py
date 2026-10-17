"""Public-tool Q&A over both protocol eras, including interruption and retries."""
from __future__ import annotations

import asyncio
import os
import sys
from types import SimpleNamespace

from jsonschema import Draft202012Validator
from mcp import Client, StdioServerParameters
from mcp.server.mcpserver import Context
from mcp.shared.exceptions import MCPError
from mcp.types import (CallToolRequestParams, ClientCapabilities, ElicitationCapability,
                       ElicitResult, FormElicitationCapability, InputRequiredResult,
                       UrlElicitationCapability)
import pytest

from test_onboarding import lifecycle
from wmpf_mcp.core import envelope
from wmpf_mcp.core.errors import ErrorCode, ToolError
from wmpf_mcp.core.notifications import get_prompt
from wmpf_mcp.core.state import get_state
from wmpf_mcp.server import build_server
from wmpf_mcp.tools import runtime

CONTINUE = "打开后继续"
CANCEL = "取消"


def context(protocol="2025-11-25", *, response=None, callback=None, capability=True, state=None, responses=None):
    calls = []
    async def elicit_form(**params):
        calls.append(params)
        if callback:
            return await callback(**params)
        return response or ElicitResult(action="accept", content={"choice": CONTINUE})
    elicitation = ElicitationCapability(form=FormElicitationCapability()) if capability is True else capability or None
    session = SimpleNamespace(client_capabilities=ClientCapabilities(elicitation=elicitation), elicit_form=elicit_form)
    ctx = Context(request_context=SimpleNamespace(protocol_version=protocol, session=session, request_id=1),
                  input_params=CallToolRequestParams(name="unused", input_responses=responses, request_state=state))
    return ctx, calls


@pytest.mark.anyio
@pytest.mark.parametrize("protocol", ["2025-11-25", "2026-07-28"])
@pytest.mark.parametrize("response,status", [
    (ElicitResult(action="accept", content={"choice": CONTINUE}), "accepted"),
    (ElicitResult(action="accept", content={"choice": CANCEL}), "cancelled"),
    (ElicitResult(action="decline"), "declined"),
    (ElicitResult(action="cancel"), "cancelled"),
])
async def test_prepared_start_asks_client_and_branches_on_answer(lifecycle, protocol, response, status):
    server = build_server()
    ctx, calls = context(protocol, response=response)
    result = await server.call_tool("start_runtime", {"force_hooks": True}, ctx)
    prepared = ["preflight", "parameters", "engine.start", "hooks.start"]
    assert lifecycle.events[:4] == prepared
    if protocol == "2026-07-28":
        assert isinstance(result, InputRequiredResult) and not calls
        request = result.input_requests["open_miniapp"]
        schema = request.params.requested_schema
        assert request.method == "elicitation/create" and request.params.mode == "form"
        resumed, _ = context(protocol, state=result.request_state, responses={"open_miniapp": response})
        result = await server.call_tool("start_runtime", {"force_hooks": True}, resumed)
        # The continuation must not repeat force_hooks or any startup operation.
    else:
        assert len(calls) == 1
        schema = calls[0]["requested_schema"]
        assert calls[0]["related_request_id"] == "1"
    assert schema["properties"]["choice"]["enum"] == [CONTINUE, CANCEL]
    assert schema["required"] == ["choice"]
    assert not result.is_error
    assert result.structured_content["data"]["notification"]["status"] == status
    cancelled = status != "accepted"
    assert lifecycle.events == prepared + (["portal.stop", "engine.stop", "hooks.stop"] if cancelled else [])
    assert result.structured_content["data"]["status"] == ("cancelled" if cancelled else "awaiting_miniapp")
    assert result.structured_content["data"]["awaiting_miniapp"] is not cancelled
    assert lifecycle.engine.running is not cancelled
    assert lifecycle.flags["active"] is not cancelled
    if cancelled:
        assert result.structured_content["data"]["cleanup_complete"]
        assert result.structured_content["stage"] == "INIT"
        live = (await server.call_tool("inspect_runtime", {})).structured_content["data"]["live"]
        assert not live["engine"]["running"] and not live["inject"]["active"]
    assert bool(result.structured_content["next_actions"]) is (status == "accepted")
    assert not lifecycle.callbacks and get_prompt().task is None
    output = next(t.output_schema for t in await server.list_tools() if t.name == "start_runtime")
    Draft202012Validator(output).validate(result.structured_content)


@pytest.mark.anyio
@pytest.mark.parametrize("capability", [False, ElicitationCapability(url=UrlElicitationCapability())])
async def test_missing_form_capability_returns_user_action_without_request(lifecycle, capability):
    ctx, calls = context(capability=capability)
    result = await build_server().call_tool("start_runtime", {}, ctx)
    assert not calls and not lifecycle.callbacks
    assert result.structured_content["data"]["notification"]["status"] == "unsupported"
    assert not result.structured_content["next_actions"]
    assert "Q&A" in result.structured_content["next_hint"]


@pytest.mark.anyio
async def test_empty_legacy_capability_and_once_per_preparation(lifecycle):
    ctx, calls = context(capability=ElicitationCapability())
    server = build_server()
    for _ in range(2):
        result = await server.call_tool("start_runtime", {}, ctx)
        assert result.structured_content["data"]["notification"]["status"] == "accepted"
    assert len(calls) == 1
    await server.call_tool("stop_runtime", {})
    await server.call_tool("start_runtime", {}, ctx)
    assert len(calls) == 2


@pytest.mark.anyio
@pytest.mark.parametrize("condition", ["disabled", "unarmed", "connected"])
async def test_q_and_a_only_when_enabled_prepared_and_disconnected(lifecycle, condition):
    ctx, calls = context()
    if condition == "unarmed":
        lifecycle.flags["armed"] = 0
    elif condition == "connected":
        lifecycle.engine.miniapp_clients.add(object())
        lifecycle.engine.setup_context_at = 1
    result = await build_server().call_tool("start_runtime", {"prompt_user": condition != "disabled"}, ctx)
    assert not calls and not lifecycle.callbacks
    if condition == "disabled":
        assert result.structured_content["data"]["notification"]["status"] == "disabled"


@pytest.mark.anyio
async def test_stop_remains_available_while_legacy_q_and_a_waits(lifecycle):
    entered = asyncio.Event()
    async def wait(**_):
        entered.set()
        await asyncio.Event().wait()
    ctx, _ = context(callback=wait)
    server = build_server()
    request = asyncio.create_task(server.call_tool("start_runtime", {}, ctx))
    await asyncio.wait_for(entered.wait(), 1)
    assert not runtime._LIFECYCLE_LOCK.locked()
    stopped = await asyncio.wait_for(server.call_tool("stop_runtime", {}), 1)
    assert not stopped.is_error
    result = await asyncio.wait_for(request, 1)
    assert result.structured_content["data"]["notification"]["status"] == "closed"
    assert not result.structured_content["next_actions"]
    assert not lifecycle.callbacks and get_prompt().task is None


@pytest.mark.anyio
@pytest.mark.parametrize("outcome", ["cancel", "connected", "timeout", "failure"])
async def test_legacy_q_and_a_cleans_on_every_exit(lifecycle, outcome):
    entered = asyncio.Event()
    async def wait(**_):
        entered.set()
        if outcome == "failure":
            raise MCPError(-32603, "fixture: client rejected Q&A")
        await asyncio.Event().wait()
    ctx, _ = context(callback=wait)
    if outcome == "timeout":
        get_prompt().ANSWER_TIMEOUT_S = 0.01
    request = asyncio.create_task(build_server().call_tool("start_runtime", {}, ctx))
    await asyncio.wait_for(entered.wait(), 1)
    if outcome == "cancel":
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        assert not lifecycle.engine.running and not lifecycle.flags["active"]
    else:
        if outcome == "connected":
            lifecycle.engine.miniapp_clients.add(object())
            lifecycle.engine.setup_context_at = 1
            for callback in tuple(lifecycle.callbacks):
                callback({"kind": "setup_context"})
        result = await asyncio.wait_for(request, 1)
        expected = {"connected": "not_needed", "timeout": "timeout", "failure": "failed"}[outcome]
        assert result.structured_content["data"]["notification"]["status"] == expected
    assert not lifecycle.callbacks and get_prompt().task is None


@pytest.mark.anyio
async def test_modern_continuation_rejects_changed_arguments_and_stale_state(lifecycle):
    server = build_server()
    ctx, _ = context("2026-07-28")
    pending = await server.call_tool("start_runtime", {}, ctx)
    prepared = list(lifecycle.events)
    answer = {"open_miniapp": ElicitResult(action="accept", content={"choice": CONTINUE})}
    wrong, _ = context("2026-07-28", state=pending.request_state, responses=answer)
    result = await server.call_tool("start_runtime", {"force_hooks": True}, wrong)
    assert result.is_error and lifecycle.events == prepared
    invalid, _ = context("2026-07-28", state=pending.request_state,
                         responses={"open_miniapp": ElicitResult(action="accept", content={"choice": "invented"})})
    result = await server.call_tool("start_runtime", {}, invalid)
    assert result.is_error and lifecycle.events == prepared
    await server.call_tool("stop_runtime", {})
    stopped = list(lifecycle.events)
    result = await server.call_tool("start_runtime", {}, wrong)
    assert result.is_error and lifecycle.events == stopped
    assert not lifecycle.callbacks and get_prompt().pending is None


@pytest.mark.anyio
async def test_opening_socket_during_q_and_a_does_not_invalidate_the_answer(lifecycle):
    server = build_server()
    ctx, _ = context("2026-07-28")
    pending = await server.call_tool("start_runtime", {}, ctx)
    prepared = list(lifecycle.events)
    lifecycle.engine.epoch += 1
    lifecycle.engine.miniapp_clients.add(object())
    assert lifecycle.engine.setup_context_at is None  # Reconnect is still initializing.
    resumed, _ = context("2026-07-28", state=pending.request_state,
        responses={"open_miniapp": ElicitResult(action="accept", content={"choice": CONTINUE})})
    result = await server.call_tool("start_runtime", {}, resumed)
    assert not result.is_error and lifecycle.events == prepared
    assert result.structured_content["data"]["notification"]["status"] == "accepted"
    assert result.structured_content["next_actions"][0]["arguments"]["layer"] == "reconnect"


@pytest.mark.anyio
@pytest.mark.parametrize("protocol", ["2025-11-25", "2026-07-28"])
async def test_hook_probe_q_and_a_has_separate_deadline_and_continues_once(lifecycle, monkeypatch, protocol):
    lifecycle.engine.running = lifecycle.flags["active"] = True
    waits = []
    async def armed(timeout):
        waits.append(timeout)
        return {"armed_pids": [11]}
    monkeypatch.setattr(runtime._injection.get_injector(), "wait_armed", armed, raising=False)
    async def answer(**_):
        await asyncio.sleep(0.12)  # Deliberately longer than the 0.1s hook deadline.
        return ElicitResult(action="accept", content={"choice": CONTINUE})
    ctx, _ = context(protocol, callback=answer)
    server = build_server()
    result = await server.call_tool("probe_runtime", {"layer": "hooks", "timeout_s": 0.1}, ctx)
    if protocol == "2026-07-28":
        resumed, _ = context(protocol, state=result.request_state,
                             responses={"open_miniapp": ElicitResult(action="accept", content={"choice": CONTINUE})})
        result = await server.call_tool("probe_runtime", {"layer": "hooks", "timeout_s": 0.1}, resumed)
    assert result.structured_content["data"]["passed"] and waits == [0.1]
    assert result.structured_content["data"]["notification"]["status"] == "accepted"


@pytest.mark.anyio
@pytest.mark.parametrize("protocol", ["2025-11-25", "2026-07-28"])
async def test_hook_probe_cancel_stops_preexisting_listeners_hooks_and_portal(lifecycle, monkeypatch, protocol):
    lifecycle.engine.running = lifecycle.flags["active"] = lifecycle.portal.running = True
    async def armed(timeout):
        return {"armed_pids": [11]}
    monkeypatch.setattr(runtime._injection.get_injector(), "wait_armed", armed, raising=False)
    response = ElicitResult(action="accept", content={"choice": CANCEL})
    ctx, _ = context(protocol, response=response)
    server = build_server()
    arguments = {"layer": "hooks"}
    result = await server.call_tool("probe_runtime", arguments, ctx)
    if protocol == "2026-07-28":
        ctx, _ = context(protocol, state=result.request_state, responses={"open_miniapp": response})
        result = await server.call_tool("probe_runtime", arguments, ctx)
    assert not result.is_error
    data = result.structured_content["data"]
    assert data["status"] == "cancelled" and data["cleanup_complete"]
    assert not data["passed"] and not data["awaiting_miniapp"]
    assert not lifecycle.engine.running and not lifecycle.flags["active"] and not lifecycle.portal.running
    assert lifecycle.events == ["portal.stop", "engine.stop", "hooks.stop"]
    assert not result.structured_content["next_actions"]
    schema = next(t.output_schema for t in await server.list_tools() if t.name == "probe_runtime")
    Draft202012Validator(schema).validate(result.structured_content)


@pytest.mark.anyio
@pytest.mark.parametrize("failed_component", ["portal", "engine", "hooks"])
async def test_cancel_attempts_every_stop_and_reports_partial_failure(lifecycle, monkeypatch, failed_component):
    module = {"portal": runtime._portal, "engine": runtime._engine, "hooks": runtime._injection}[failed_component]
    original = module.execute
    async def fail_stop(action, **kwargs):
        if action == "stop":
            lifecycle.events.append(failed_component + ".stop")
            return envelope.fail(ToolError(ErrorCode.INTERNAL, "fixture: stop failed"), stage=get_state().stage.value)
        return await original(action=action, **kwargs)
    monkeypatch.setattr(module, "execute", fail_stop)
    ctx, _ = context(response=ElicitResult(action="accept", content={"choice": CANCEL}))
    result = await build_server().call_tool("start_runtime", {}, ctx)
    assert result.is_error
    detail = result.structured_content["remedy_detail"]
    assert detail["status"] == "cleanup_failed" and not detail["cleanup_complete"]
    assert detail["notification"]["status"] == "cancelled"
    assert set(detail["components"]) == {"portal", "engine", "hooks"}
    assert lifecycle.events[-3:] == ["portal.stop", "engine.stop", "hooks.stop"]
    assert lifecycle.engine.running is (failed_component == "engine")
    assert lifecycle.flags["active"] is (failed_component == "hooks")
    assert result.structured_content["next_actions"][0]["tool"] == "stop_runtime"


@pytest.mark.anyio
async def test_cancel_waits_for_hook_cleanup_even_if_request_is_cancelled_again(lifecycle, monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()
    original = runtime._injection.execute
    async def stop_hooks(action, **kwargs):
        if action == "stop":
            entered.set()
            await release.wait()
        return await original(action=action, **kwargs)
    monkeypatch.setattr(runtime._injection, "execute", stop_hooks)
    ctx, _ = context(response=ElicitResult(action="accept", content={"choice": CANCEL}))
    request = asyncio.create_task(build_server().call_tool("start_runtime", {}, ctx))
    await asyncio.wait_for(entered.wait(), 1)
    assert not lifecycle.engine.running and lifecycle.flags["active"]
    assert runtime._LIFECYCLE_LOCK.locked() and not request.done()
    request.cancel()
    request.cancel()
    await asyncio.sleep(0)
    assert runtime._LIFECYCLE_LOCK.locked() and not request.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(request, 1)
    assert not lifecycle.flags["active"] and not runtime._LIFECYCLE_LOCK.locked()


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
@pytest.mark.parametrize("choice", [CONTINUE, CANCEL])
async def test_stdio_client_renders_form_and_completes_q_and_a(mode, choice):
    # Real MCP transport/serialization, with an isolated prepared-runtime fixture.
    program = '''
from types import SimpleNamespace
from wmpf_mcp.core import envelope
from wmpf_mcp.server import build_server
from wmpf_mcp.tools import runtime
callbacks = set()
flags = {"active": True}
engine = SimpleNamespace(running=False, cdp_port=10000, miniapp_clients=set(),
    setup_context_at=None, epoch=0, _stop_generation=0,
    on_lifecycle=callbacks.add, off_lifecycle=callbacks.discard)
engine.status = lambda: {"running": engine.running, "miniapp_connected": False, "setup_context_seen": False}
hooks = SimpleNamespace(status=lambda: {"active": flags["active"], "armed_pids": [11] if flags["active"] else []})
async def execute_hooks(action, **kwargs):
    flags["active"] = action == "start"
    return envelope.ok({"active": flags["active"]}, stage="INIT")
async def execute(action, **kwargs):
    engine.running = action == "start"
    return envelope.ok({"running": engine.running}, stage="INIT")
runtime._engine.get_engine = lambda: engine
runtime._engine.execute = execute
runtime._injection.get_injector = lambda: hooks
runtime._injection.execute = execute_hooks
build_server().run(transport="stdio")
'''
    params = StdioServerParameters(command=sys.executable, args=["-B", "-c", program],
        env={name: os.environ[name] for name in ("WMPF_MCP_HOME", "WMPF_MCP_WORKSPACE")})
    questions = []
    async def choose(ctx, params):
        questions.append(params)
        assert params.mode == "form"
        assert params.requested_schema["properties"]["choice"]["enum"] == [CONTINUE, CANCEL]
        return ElicitResult(action="accept", content={"choice": choice})
    async with asyncio.timeout(10):
        async with Client(params, mode=mode, elicitation_callback=choose, cache=None) as client:
            for _ in range(2 if choice == CONTINUE else 1):
                result = await client.call_tool("start_runtime", {"component": "engine"})
                assert not result.is_error
                assert result.structured_content["data"]["notification"]["status"] == ("accepted" if choice == CONTINUE else "cancelled")
                if choice == CONTINUE:
                    assert result.structured_content["next_actions"][0]["arguments"]["layer"] == "reconnect"
                else:
                    assert result.structured_content["data"]["cleanup_complete"]
                    assert not result.structured_content["data"]["awaiting_miniapp"]
                    live = (await client.call_tool("inspect_runtime", {})).structured_content["data"]["live"]
                    assert not live["engine"]["running"] and not live["inject"]["active"]
            assert len(questions) == 1
