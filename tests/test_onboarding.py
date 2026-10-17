"""First-install failures and method-driven lifecycle through the public tools."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from wmpf_mcp import diagnostics
from wmpf_mcp.core import envelope
from wmpf_mcp.core.errors import ErrorCode, ToolError
from wmpf_mcp.core.state import get_state
from wmpf_mcp.platform.base import RuntimeInfo
from wmpf_mcp.server import build_server


@pytest.mark.parametrize("module,args,channel", [
    ("wmpf_mcp.bootstrap", ["doctor", "--goal", "source"], "stdout"),
    ("wmpf_mcp.server", [], "stderr"),
])
def test_diagnostics_work_before_sdk_is_importable(tmp_path, module, args, channel):
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
           "WMPF_MCP_HOME": str(tmp_path / "unused-home")}
    process = subprocess.run([sys.executable, "-B", "-S", "-m", module, *args],
                             env=env, capture_output=True, text=True, timeout=15)
    assert process.returncode == 1
    report = json.loads(getattr(process, channel))
    assert not report["startup_ready"]
    assert any(b["check"] == "package:mcp" for b in report["blockers"])
    assert report["python"]["executable"] == sys.executable
    if channel == "stderr":
        assert not process.stdout
        assert report["startup_error"]
        assert report["version_issues"]
    assert not (tmp_path / "unused-home").exists()


def test_installed_native_module_import_failure_is_reported(monkeypatch, tmp_path):
    (tmp_path / "frida.py").write_text("raise OSError('fixture: wrong native ABI')\n")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setattr(diagnostics.importlib.util, "find_spec", lambda _: object())
    monkeypatch.setattr(diagnostics.importlib.metadata, "distribution", lambda _: SimpleNamespace(version="17.0.0", locate_file=lambda _: tmp_path))
    row = diagnostics.package_check(("frida", "frida", ">=17", "dynamic"))
    assert row["installed"]
    assert not row["importable"]
    assert "wrong native ABI" in row["error"]


def test_startup_diagnoses_native_crypto_failure_before_tools_exist(tmp_path):
    package = tmp_path / "Crypto"
    (package / "Cipher").mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "Cipher/__init__.py").write_text("raise OSError('fixture: AES native library unavailable')\n")
    src = str(Path(__file__).resolve().parents[1] / "src")
    env = {**os.environ, "PYTHONPATH": str(tmp_path) + os.pathsep + src,
           "WMPF_MCP_HOME": str(tmp_path / "unused-home")}
    process = subprocess.run([sys.executable, "-B", "-m", "wmpf_mcp.bootstrap"],
                             env=env, capture_output=True, text=True, timeout=15)
    assert process.returncode == 1 and not process.stdout
    report = json.loads(process.stderr.splitlines()[-1])
    assert not report["startup_ready"]
    assert "AES native library unavailable" in report["startup_error"]
    crypto = next(p for p in report["packages"] if p["package"] == "pycryptodome")
    assert crypto["installed"] and not crypto["importable"]
    assert not (tmp_path / "unused-home").exists()


def test_version_requirement_and_optional_dependencies_have_separate_effects(monkeypatch):
    def package(spec):
        name, module, requirement, feature = spec
        return {"package": name, "module": module, "feature": feature,
                "importable": feature == "base", "requirement_satisfied": True}
    monkeypatch.setattr(diagnostics, "package_check", package)
    assert diagnostics.dependency_report("source")["dependencies_ready"]
    assert diagnostics.dependency_report("offsets")["dependencies_ready"]
    dynamic = diagnostics.dependency_report("automation")
    assert dynamic["startup_ready"]
    assert [b["check"] for b in dynamic["blockers"]] == ["package:frida"]
    assert diagnostics._satisfies("2.2.9", ">=2.3.0,<3") is False
    assert diagnostics._satisfies("2.3.0rc1", ">=2.3.0,<3") is False
    assert diagnostics._satisfies("3.0.0", ">=2.3.0,<3") is False
    assert diagnostics._satisfies("3.0.0rc1", ">=2.3.0,<3") is False
    assert diagnostics._satisfies("2.3.0", ">=2.3.0,<3") is True
    assert diagnostics._satisfies("2.3.0+build1", ">=2.3.0,<3") is True


def test_unknown_macos_policy_does_not_infer_root_requirement(monkeypatch):
    from wmpf_mcp.platform import darwin
    monkeypatch.setattr(darwin.os, "geteuid", lambda: 501, raising=False)
    monkeypatch.setattr(darwin.DarwinAdapter, "_sip_status", lambda _: "unknown")
    monkeypatch.setattr(darwin, "_run", lambda _: SimpleNamespace(returncode=1, stdout="", stderr=""))
    result = darwin.DarwinAdapter().signature_state()
    assert result["inject_mode"] == "unknown"
    assert "actual attach" in result["note"]


@pytest.mark.anyio
async def test_preflight_is_goal_specific_and_unknown_version_allows_queries(monkeypatch, tmp_path):
    from test_method_chain import elf_file
    from wmpf_mcp.tools import environment
    module = elf_file(tmp_path / "module")
    adapter = SimpleNamespace(platform="linux",
        locate=lambda: RuntimeInfo("linux", "arm64", None, str(module), None, None, []),
        main_module_path=lambda: str(module), signature_state=lambda: {"inject_mode": "unknown"})
    monkeypatch.setattr(environment, "get_adapter", lambda: adapter)
    monkeypatch.setattr(environment, "port_state", lambda _: {"state": "busy", "pid": 123})
    monkeypatch.setattr(environment, "proxy_state", lambda: {"checked": False})
    def report(goal):
        return {"startup_ready": True, "packages": [
            {"package": "frida", "importable": False, "feature": "dynamic",
             "required_for_goal": goal in {"automation", "traffic", "wx_api"}}]}
    monkeypatch.setattr(environment, "dependency_report", report)
    server = build_server()
    source = await server.call_tool("check_environment", {"goal": "source"})
    assert source.structured_content["data"]["environment_ready"] is True
    dynamic = await server.call_tool("check_environment", {"goal": "automation"})
    data = dynamic.structured_content["data"]
    assert data["environment_ready"] is False
    assert data["wechat"]["wmpf_version"] is None
    assert data["binary"]["arch"] == "x86_64"
    assert not data["hook_backend_implemented"]
    assert not any(c["blocking"] for c in data["checks"] if c["check"] in {"version_labels", "listeners", "attach_policy"})
    for step in dynamic.structured_content["next_actions"]:
        follow = await server.call_tool(step["tool"], step["arguments"])
        assert not follow.is_error
    scoped = await server.call_tool("check_environment", {"scope": "wechat"})
    assert scoped.structured_content["data"]["environment_ready"] is None
    assert set(tmp_path.iterdir()) == {module}


@pytest.fixture
def lifecycle(monkeypatch):
    from wmpf_mcp.tools import runtime
    events = []
    flags = {"offsets_ready": True, "armed": 1, "active": False, "port_busy": False}
    callbacks = set()
    engine = SimpleNamespace(running=False, cdp_port=None, miniapp_clients=set(), setup_context_at=None,
                             epoch=0, _stop_generation=0, on_lifecycle=callbacks.add, off_lifecycle=callbacks.discard)
    engine.status = lambda: {"running": engine.running, "miniapp_connected": bool(engine.miniapp_clients),
                             "setup_context_seen": engine.setup_context_at is not None}
    portal = SimpleNamespace(running=False, state=SimpleNamespace(port=None), targets=lambda: [],
                             ledger=SimpleNamespace(summary=lambda: {}))
    hooks = SimpleNamespace(status=lambda: {"active": flags["active"],
                                           "pid_hits": {11: {"armed": flags["armed"]}},
                                           "armed_pids": [11] if flags["active"] and flags["armed"] else []})
    monkeypatch.setattr(runtime, "_LIFECYCLE_LOCK", asyncio.Lock())
    def preflight(*_):
        events.append("preflight")
        return {"environment_ready": True, "blockers": []}
    monkeypatch.setattr(runtime, "collect_environment", preflight)
    monkeypatch.setattr(runtime._engine, "get_engine", lambda: engine)
    monkeypatch.setattr(runtime._portal, "get_portal", lambda: portal)
    monkeypatch.setattr(runtime._injection, "get_injector", lambda: hooks)
    async def parameters(**_):
        events.append("parameters")
        return envelope.ok({"ready": flags["offsets_ready"]}, stage=get_state().stage.value)
    async def run_engine(action, **kwargs):
        events.append("engine." + action)
        if flags["port_busy"] and action == "start":
            return envelope.fail(ToolError(ErrorCode.PORT_BUSY, "fixture: external listener"), stage=get_state().stage.value)
        engine.running = action == "start"
        engine.cdp_port = kwargs.get("cdp_port") or 10000
        return envelope.ok({"running": engine.running}, stage=get_state().stage.value)
    async def run_hooks(action, **_):
        events.append("hooks." + action)
        flags["active"] = action == "start"
        return envelope.ok({"active": flags["active"]}, stage=get_state().stage.value)
    async def run_portal(action, **kwargs):
        events.append("portal." + action)
        portal.running = action == "start"
        portal.state.port = kwargs.get("port") or 20000
        return envelope.ok({"running": portal.running}, stage=get_state().stage.value)
    monkeypatch.setattr(runtime._offsets, "execute", parameters)
    monkeypatch.setattr(runtime._engine, "execute", run_engine)
    monkeypatch.setattr(runtime._injection, "execute", run_hooks)
    monkeypatch.setattr(runtime._portal, "execute", run_portal)
    return SimpleNamespace(events=events, flags=flags, engine=engine, portal=portal, callbacks=callbacks)


@pytest.mark.anyio
@pytest.mark.parametrize("existing_engine", [False, True])
async def test_cancelled_start_closes_new_listeners_and_preserves_existing_engine(lifecycle, monkeypatch, existing_engine):
    from wmpf_mcp.core import envelope
    from wmpf_mcp.core.state import get_state
    from wmpf_mcp.tools import runtime
    entered, release = asyncio.Event(), asyncio.Event()
    lifecycle.engine.running = existing_engine
    if existing_engine:
        lifecycle.engine.cdp_port = 10000
    async def blocked_hooks(action, **_):
        if action == "start":
            entered.set()
            await release.wait()
        return envelope.ok({}, stage=get_state().stage.value)
    monkeypatch.setattr(runtime._injection, "execute", blocked_hooks)
    task = asyncio.create_task(build_server().call_tool("start_runtime", {"component": "all"}))
    await asyncio.wait_for(entered.wait(), 1)
    assert lifecycle.engine.running
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)
    assert lifecycle.engine.running is existing_engine
    assert not runtime._LIFECYCLE_LOCK.locked()
    assert not lifecycle.portal.running


@pytest.mark.anyio
async def test_start_prepares_listeners_and_hooks_before_requesting_reopen(lifecycle):
    server = build_server()
    result = await server.call_tool("start_runtime", {})
    assert not result.is_error
    assert lifecycle.events == ["preflight", "parameters", "engine.start", "hooks.start"]
    assert result.structured_content["data"]["status"] == "awaiting_miniapp"
    assert result.structured_content["data"]["awaiting_miniapp"]
    assert result.structured_content["data"]["notification"]["status"] == "unsupported"
    assert result.structured_content["next_actions"] == []
    schema = next(t.output_schema for t in await server.list_tools() if t.name == "start_runtime")
    Draft202012Validator(schema).validate(result.structured_content)


@pytest.mark.anyio
async def test_connected_start_exposes_portal_and_stop_engine_stops_dependent_portal(lifecycle):
    lifecycle.engine.miniapp_clients.add(object())
    lifecycle.engine.setup_context_at = 1
    server = build_server()
    started = await server.call_tool("start_runtime", {})
    assert started.structured_content["data"]["status"] == "ready"
    assert lifecycle.events[-1] == "portal.start"
    lifecycle.events.clear()
    stopped = await server.call_tool("stop_runtime", {"component": "engine"})
    assert not stopped.is_error
    assert lifecycle.events == ["portal.stop", "engine.stop"]
    assert lifecycle.flags["active"]  # Only the requested/dependent resources stopped.


@pytest.mark.anyio
async def test_failed_parameters_and_busy_port_do_not_attach(lifecycle):
    server = build_server()
    lifecycle.flags["offsets_ready"] = False
    rejected = await server.call_tool("start_runtime", {})
    assert rejected.is_error
    assert lifecycle.events == ["preflight", "parameters"]
    lifecycle.events.clear()
    lifecycle.flags.update(offsets_ready=True, port_busy=True)
    busy = await server.call_tool("start_runtime", {})
    assert busy.is_error
    assert busy.structured_content["error"]["code"] == "E_PORT_BUSY"
    assert lifecycle.events == ["preflight", "parameters", "engine.start"]
    assert "engine" in busy.structured_content["remedy_detail"]["components"]


@pytest.mark.anyio
async def test_unarmed_hooks_do_not_claim_readiness_or_request_reopen(lifecycle):
    lifecycle.flags["armed"] = 0
    result = await build_server().call_tool("start_runtime", {})
    data = result.structured_content["data"]
    assert data["status"] == "blocked" and data["first_unmet"] == "armed"
    assert not data["awaiting_miniapp"] and "portal.start" not in lifecycle.events
    assert result.structured_content["next_actions"][0]["arguments"]["layer"] == "hooks"


@pytest.mark.anyio
async def test_incompatible_parameters_are_rejected_before_start(lifecycle):
    result = await build_server().call_tool("start_runtime", {"component": "engine", "force_hooks": True})
    assert result.is_error and result.structured_content["error"]["code"] == "E_PARAM"
    assert not lifecycle.events


@pytest.mark.anyio
@pytest.mark.parametrize("arguments", [{"cdp_port": 9421}, {"portal_port": 9421}, {"cdp_port": 20000, "portal_port": 20000}])
async def test_port_roles_cannot_collide_before_start(lifecycle, arguments):
    result = await build_server().call_tool("start_runtime", arguments)
    assert result.is_error and result.structured_content["error"]["code"] == "E_PARAM"
    assert not lifecycle.events


@pytest.mark.anyio
@pytest.mark.parametrize("layer,code", [("raw", "E_CDP_UNHEALTHY"), ("reconnect", "E_MINAPP_TIMEOUT")])
async def test_probe_has_one_total_deadline(monkeypatch, layer, code):
    from wmpf_mcp.tools import runtime
    async def wait(**_):
        await asyncio.Event().wait()
    monkeypatch.setattr(runtime._engine, "execute", wait)
    result = await asyncio.wait_for(build_server().call_tool("probe_runtime", {"layer": layer, "timeout_s": 0.1}), 0.5)
    assert result.is_error
    assert result.structured_content["error"]["code"] == code
    assert result.structured_content["remedy_detail"]["passed"] is False


@pytest.mark.anyio
async def test_unknown_legacy_arguments_cannot_clear_the_ledger(monkeypatch):
    from wmpf_mcp.portal.ledger import TrafficLedger
    from wmpf_mcp.tools import _traffic
    ledger = TrafficLedger()
    ledger.activate()
    ledger.observe(json.dumps({"params": {"requestId": "keep", "request": {"url": "https://fixture.test", "method": "GET"}}}), "Network.requestWillBeSent")
    monkeypatch.setattr(_traffic, "get_portal", lambda: SimpleNamespace(ledger=ledger))
    server = build_server()
    invalid = await server.call_tool("clear_traffic", {"action": "list"})
    assert invalid.is_error and ledger.get("keep") is not None
    cleared = await server.call_tool("clear_traffic", {})
    assert cleared.structured_content["data"]["cleared"] and ledger.get("keep") is None


@pytest.mark.anyio
@pytest.mark.parametrize("tool,arguments,required", [
    ("inspect_binary", {"view": "strings"}, "pattern"),
    ("inspect_binary", {"view": "xrefs"}, "address"),
    ("inspect_source", {"view": "search"}, "pattern"),
    ("inspect_source", {"view": "read"}, "file"),
    ("query_traffic", {"view": "body"}, "request_id"),
])
async def test_missing_view_arguments_fail_before_environment_lookup(tool, arguments, required):
    result = await build_server().call_tool(tool, arguments)
    assert result.is_error
    assert result.structured_content["error"]["code"] == "E_PARAM"
    assert required in result.structured_content["error"]["message"]


@pytest.mark.anyio
async def test_portal_probe_does_not_follow_discovery_redirects():
    from aiohttp import web
    app = web.Application()
    followed = []
    async def redirect(_):
        raise web.HTTPFound("/redirected")
    async def other(_):
        followed.append(True)
        return web.json_response({})
    app.router.add_get("/json/version/", redirect)
    app.router.add_get("/redirected", other)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        result = await build_server().call_tool("probe_runtime", {"portal_port": port})
        assert result.is_error and not followed
        assert "redirect" in result.structured_content["remedy_detail"]["checks"][0]["error"]
    finally:
        await runner.cleanup()
