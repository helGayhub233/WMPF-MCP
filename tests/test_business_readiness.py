"""Business readiness events, cancellation and packaged workflow instructions."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

from aiohttp import web, WSMsgType
import anyio
from mcp.server.mcpserver.exceptions import ToolError as MCPToolError
import pytest

from wmpf_mcp.portal.readiness import probe_page, _SCRIPT
from wmpf_mcp.portal.probe import probe_portal
from wmpf_mcp.server import build_server, INSTRUCTIONS
from wmpf_mcp.tools import runtime
from wmpf_mcp.workflow import execution_manual, MANUAL_URI


@asynccontextmanager
async def portal_fixture():
    registered = asyncio.Event()
    release = asyncio.Event()
    remove = []
    observers = []
    sockets = []
    received = []
    closed = asyncio.Event()
    state = SimpleNamespace(invalid=False, disconnect=False, matched=False, reset=False, drop_cleanup=False, isolated_first=False)
    async def discover(request):
        return web.json_response({"webSocketDebuggerUrl": f"ws://127.0.0.1:{request.url.port}/browser"})
    async def ws_handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        sockets.append(ws)
        tasks = []
        bindings = {}
        async def signal_ready(name):
            await release.wait()
            if state.reset:
                state.reset = False
                await ws.send_json({"method": "Runtime.executionContextsCleared", "params": {}, "sessionId": "owned"})
                await ws.send_json({"method": "Runtime.bindingCalled", "sessionId": "owned",
                    "params": {"name": name, "executionContextId": 2, "payload": json.dumps({"ready": True})}})
                await ws.send_json({"method": "Runtime.executionContextCreated", "sessionId": "owned",
                    "params": {"context": {"id": 2, "uniqueId": "new-context",
                        "auxData": {"frameId": "render", "isDefault": True}}}})
                return
            if state.disconnect:
                await ws.send_json({"method": "Target.detachedFromTarget", "params": {"sessionId": "owned"}})
                return
            state.matched = True
            payload = ({"ready": False, "reason": "invalid_selector", "error": "test invalid CSS"}
                       if state.invalid else {"ready": True, "visible_matches": 1, "document_state": "complete"})
            await ws.send_json({"method": "Runtime.bindingCalled", "sessionId": "owned",
                               "params": {"name": name, "executionContextId": 2, "payload": json.dumps(payload)}})
        try:
            async for message in ws:
                if message.type != WSMsgType.TEXT: break
                packet = message.json()
                method, params = packet["method"], packet.get("params", {})
                received.append(method)
                result = {}
                if method == "Target.getTargets":
                    result = {"targetInfos": [{"targetId": "page", "type": "page"}]}
                elif method == "Target.attachToTarget":
                    result = {"sessionId": "owned"}
                elif method == "Page.getFrameTree":
                    result = {"frameTree": {"frame": {"id": "page"}, "childFrames": [
                        {"frame": {"id": "render", "name": "page-frame_100"}}]}}
                elif method == "Runtime.enable":
                    if state.isolated_first:
                        for identifier in range(100, 117):
                            await ws.send_json({"method": "Runtime.executionContextCreated", "sessionId": "owned",
                                "params": {"context": {"id": identifier,
                                    "auxData": {"frameId": "render", "isDefault": False}}}})
                    await ws.send_json({"method": "Runtime.executionContextCreated", "sessionId": "owned",
                        "params": {"context": {"id": 2, "auxData": {"frameId": "render", "isDefault": True}}}})
                elif method == "Runtime.addBinding":
                    bindings[params["name"]] = params["executionContextId"]
                elif method == "Runtime.removeBinding":
                    remove.append(params["name"])
                    bindings.pop(params["name"], None)
                    if state.drop_cleanup:
                        continue
                elif method == "Runtime.evaluate":
                    expression = params["expression"]
                    if "MutationObserver" in expression:
                        observers.append(expression)
                        name = re.search(r"__wmpf_signal_[0-9a-f]+", expression).group()
                        tasks.append(asyncio.create_task(signal_ready(name)))
                        registered.set()
                        result = {"result": {"value": {"watching": True}}}
                    elif "typeof document" in expression:
                        result = {"result": {"value": {"dom": True, "eval": True, "wx": False}}}
                    elif expression.replace(" ", "") == "1+1":
                        result = {"result": {"value": 2}}
                    else:
                        result = {"result": {"value": None}}
                response = {"id": packet["id"], "result": result}
                if "sessionId" in packet: response["sessionId"] = packet["sessionId"]
                await ws.send_json(response)
        finally:
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            closed.set()
        return ws
    app = web.Application()
    app.router.add_get("/json/version/", discover)
    app.router.add_get("/browser", ws_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield SimpleNamespace(port=port, registered=registered, release=release, removed=remove,
                              observers=observers, sockets=sockets, received=received, state=state, closed=closed)
    finally:
        for ws in sockets: await ws.close()
        await runner.cleanup()


@pytest.mark.anyio
async def test_foreign_isolated_worlds_do_not_starve_the_business_context():
    async with portal_fixture() as f:
        f.state.isolated_first = True
        f.release.set()
        result = await probe_page(f.port, "#business", "page-frame_100", 2)
        assert result["passed"] and result["matched"]["context_id"] == 2
        assert len(f.observers) == 1 and f.removed


@pytest.mark.anyio
async def test_portal_capability_budget_prioritizes_default_contexts():
    async with portal_fixture() as f:
        f.state.isolated_first = True
        result = await probe_portal(f.port, 2)
        assert result["passed"] and result["contexts_truncated"]
        assert any(c["id"] == 2 and c.get("capabilities", {}).get("dom") for c in result["contexts"])


@pytest.mark.anyio
async def test_business_wait_ignores_early_navigation_then_accepts_content():
    async with portal_fixture() as f:
        task = asyncio.create_task(probe_page(f.port, "#business[data-loaded=true]", None, 2))
        await asyncio.wait_for(f.registered.wait(), 1)
        assert not task.done() and not f.state.matched
        f.release.set()
        result = await task
        assert result["passed"] and result["matched"]["frame_name"] == "page-frame_100"
        assert len(f.removed) == 1 and f.sockets[0].closed
        assert "Runtime.awaitPromise" not in f.received


@pytest.mark.anyio
async def test_timeout_releases_observer_binding_and_session():
    async with portal_fixture() as f:
        result = await probe_page(f.port, "#business", None, 0.1)
        assert not result["passed"] and f.removed and f.sockets[0].closed
        assert "Target.detachFromTarget" in f.received


@pytest.mark.anyio
async def test_unresponsive_cleanup_still_has_a_two_second_budget():
    async with portal_fixture() as f:
        f.state.drop_cleanup = True
        start = asyncio.get_running_loop().time()
        result = await probe_page(f.port, "#business", None, 0.1)
        await asyncio.wait_for(f.closed.wait(), 1)
        assert not result["passed"] and asyncio.get_running_loop().time() - start < 2.8


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["task", "anyio"])
async def test_cancel_releases_readiness_resources(mode):
    async with portal_fixture() as f:
        if mode == "task":
            task = asyncio.create_task(probe_page(f.port, "#business", None, 5))
            await asyncio.wait_for(f.registered.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError): await task
        else:
            with anyio.CancelScope() as scope:
                async def cancel():
                    await f.registered.wait()
                    scope.cancel()
                task = asyncio.create_task(cancel())
                await probe_page(f.port, "#business", None, 5)
            await task
        assert f.removed and f.sockets[0].closed


@pytest.mark.anyio
async def test_invalid_selector_is_not_reported_as_a_loading_timeout():
    async with portal_fixture() as f:
        f.state.invalid = True
        task = asyncio.create_task(build_server().call_tool("probe_runtime", {
            "layer": "page", "portal_port": f.port, "ready_selector": "[invalid"}))
        await f.registered.wait()
        f.release.set()
        result = await task
        assert result.is_error and result.structured_content["error"]["code"] == "E_PARAM"
        assert f.removed


@pytest.mark.anyio
async def test_public_page_wait_always_uses_the_single_sixty_second_deadline(monkeypatch):
    observed = []
    async def probe(port, selector, frame_name, timeout_s):
        observed.append((port, selector, frame_name, timeout_s))
        return {"passed": True, "matched": {"frame_name": frame_name}}
    monkeypatch.setattr(runtime, "probe_page", probe)
    result = await build_server().call_tool("probe_runtime", {
        "layer": "page", "portal_port": 20001, "ready_selector": "#business[data-loaded=true]",
        "frame_name": "render-frame"})
    assert not result.is_error
    assert observed == [(20001, "#business[data-loaded=true]", "render-frame", 60.0)]


@pytest.mark.anyio
async def test_disconnect_during_loading_never_reports_ready():
    async with portal_fixture() as f:
        f.state.disconnect = True
        task = asyncio.create_task(probe_page(f.port, "#business", None, 2))
        await f.registered.wait()
        f.release.set()
        result = await task
        assert not result["passed"] and "disconnected" in result["error"]


@pytest.mark.anyio
async def test_old_context_binding_cannot_pass_after_context_recreation():
    async with portal_fixture() as f:
        f.state.reset = True
        task = asyncio.create_task(probe_page(f.port, "#business", None, 2))
        await f.registered.wait()
        f.release.set()
        result = await task
        assert result["passed"] and len(f.observers) == 2


@pytest.mark.anyio
@pytest.mark.parametrize("args", [
    {"layer": "page"}, {"layer": "page", "ready_selector": " "}, {"layer": "page", "ready_selector": "body"},
    {"layer": "page", "ready_selector": "#business", "timeout_s": 1},
    {"layer": "portal", "ready_selector": "#business"},
    {"layer": "hooks", "frame_name": "unexpected"},
])
async def test_wrong_readiness_arguments_fail_before_network(args):
    result = await build_server().call_tool("probe_runtime", args)
    assert result.is_error and result.structured_content["error"]["code"] == "E_PARAM"


@pytest.mark.anyio
@pytest.mark.parametrize("args", [
    {"layer": "page", "ready_selector": "#business", "timeout_s": 60},
    {"layer": "raw", "timeout_s": 60},
])
async def test_timeout_outside_the_public_schema_is_rejected_before_dispatch(args):
    with pytest.raises(MCPToolError, match="less than or equal to 30"):
        await build_server().call_tool("probe_runtime", args)


def test_real_observer_script_waits_for_business_visibility_and_cleans_up():
    program = r'''
const vm = require('node:vm');
const source = JSON.parse(process.argv[1]);
const signals = [], listeners = new Map();
let mutation, deadline, disconnected = false, visible = false, loaded = false;
const imageEvents = new Map();
const image = {complete:false,naturalWidth:16,getClientRects:()=>[{}],getBoundingClientRect:()=>({top:0,bottom:16}),
  addEventListener:(name,callback)=>imageEvents.set(name,callback),removeEventListener:name=>imageEvents.delete(name)};
const business = { getClientRects: () => visible ? [{}] : [], querySelectorAll:()=>[image] };
const world = {
  document: {readyState: 'complete', querySelectorAll: selector => loaded ? [business] : [],
    fonts: {addEventListener(){},removeEventListener(){}}},
  MutationObserver: class {constructor(callback){mutation=callback} observe(){} disconnect(){disconnected=true}},
  innerHeight:150,getComputedStyle: () => ({display:'block', visibility:'visible', opacity:'1'}),
  setTimeout: callback => {deadline=callback; return 1}, clearTimeout(){deadline=null},
  addEventListener: (name, handler) => listeners.set(name, handler),
  removeEventListener: name => listeners.delete(name),
  signal: value => signals.push(JSON.parse(value))
};
world.window=world;
const result=vm.runInNewContext(source.replace('__ARGS__', JSON.stringify(['#business','observer','signal',60000])), world);
if (!result.watching || signals.length) throw Error('navigation/empty content passed');
loaded=true; mutation();
if (signals.length) throw Error('hidden business content passed');
visible=true; mutation();
if (signals.length) throw Error('pending visible image passed');
image.complete=true;imageEvents.get('load')();
if (signals.length!==1 || !signals[0].ready || !disconnected || listeners.size || world.observer || deadline)
  throw Error('business visibility or observer cleanup failed');
if(imageEvents.size) throw Error('image listeners survived cleanup');
console.log('business visibility and observer cleanup OK');
'''
    result = subprocess.run(["node", "-e", program, json.dumps(_SCRIPT)], text=True,
                            capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr


@pytest.mark.anyio
async def test_packaged_manual_matches_docs_and_is_exposed_to_mcp():
    expected = (Path(__file__).parents[1] / "docs/08-执行流手册.md").read_text()
    assert execution_manual() == expected
    server = build_server()
    assert MANUAL_URI in {str(resource.uri) for resource in await server.list_resources()}
    assert "wechat_workflow" in {prompt.name for prompt in await server.list_prompts()}
    assert "P0-P7" in INSTRUCTIONS and "ready_selector" in INSTRUCTIONS


