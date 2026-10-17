"""Maintenance rollback, operation scope and cancellation (no real WeChat changes)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import plistlib
import shutil
import signal
import sys
import threading
from types import SimpleNamespace

import pytest

from wmpf_mcp.core import paths
from wmpf_mcp.core.config import WeChatPaths
from wmpf_mcp.core.errors import ErrorCode, ToolError
from wmpf_mcp.core import envelope
from wmpf_mcp.core.state import get_state
from wmpf_mcp.platform.darwin import DarwinAdapter
from wmpf_mcp.platform import maintenance
from wmpf_mcp.server import build_server


@pytest.fixture
def installation(monkeypatch, tmp_path):
    if sys.platform == "win32":
        pytest.skip("macOS maintenance fixture requires POSIX bundle symlinks")
    app = tmp_path / "WeChat with spaces.app"
    resolved = WeChatPaths(app, tmp_path / "radium")
    main = resolved.appex_bin
    main.parent.mkdir(parents=True)
    main.write_bytes(b"original main")
    main.chmod(0o755)
    module = resolved.framework / "Versions/C/WeChatAppEx Framework"
    module.parent.mkdir(parents=True)
    module.write_bytes(b"original framework")
    helpers = module.parent / "Helpers"
    helper = helpers / "Real Helper.app"
    executable = helper / "Contents/MacOS/Real Helper"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"original helper")
    executable.chmod(0o755)
    with (helper / "Contents/Info.plist").open("wb") as stream:
        plistlib.dump({"CFBundleExecutable": "Real Helper"}, stream)
    (resolved.main_module.parent.parent / "Current").symlink_to("C")
    adapter = DarwinAdapter(resolved)
    adapter.signature_for = lambda binary: {"binary": str(binary), "adhoc": binary.read_bytes().startswith(b"signed:"),
        "hardened_runtime": not binary.read_bytes().startswith(b"signed:"), "signed": True}
    adapter.running_pids = lambda: []
    events = []
    monkeypatch.setattr(maintenance, "application_processes", lambda _: [{"pid": 11, "binary": str(main)}])
    def kill(_):
        backups = list(paths.backup_dir().glob("*/restore.json")) if paths.backup_dir().exists() else []
        events.append(("kill", bool(backups)))
        return [11]
    monkeypatch.setattr(maintenance, "kill_application", kill)
    class Worker(maintenance.Maintenance):
        fail_sign = None
        def copy_bundle(self, source, destination, *, cleanup=False):
            shutil.copytree(source, destination, symlinks=True)
        def run_command(self, args, timeout=30, *, cleanup=False):
            self.checkpoint()
            if "--sign" in args:
                target = Path(args[-1])
                events.append(("sign", target.name))
                target.write_bytes(b"signed:" + target.read_bytes())
                if self.fail_sign == target.name:
                    raise RuntimeError("test signing failed after mutation")
            else:
                events.append(("verify", Path(args[-1]).name))
        def launch(self, *, cleanup=False):
            events.append(("launch", cleanup))
            return {"requested": True, "runtime_pids": []}
    return SimpleNamespace(app=app, root=resolved.appex_app, adapter=adapter, paths=resolved,
                           Worker=Worker, events=events)


def test_prepare_backup_before_kill_and_restore_exact_bundle(installation):
    f = installation
    original = maintenance.tree_digest(f.root)
    prepared = f.Worker(f.adapter).execute("prepare", None, False)
    folder = Path(prepared["backup_path"])
    assert f.events[0] == ("kill", True)
    assert len([e for e in f.events if e[0] == "sign"]) == 2
    assert maintenance.tree_digest(folder / "WeChatAppEx.app.bak") == original
    assert maintenance.tree_digest(f.root) != original
    restored = f.Worker(f.adapter).execute("restore", str(folder), False)
    assert restored["restored"] and restored["launch"]["requested"]
    assert maintenance.tree_digest(f.root) == original
    assert (folder / "WeChatAppEx.app.bak").is_dir()
    record = json.loads((folder / "restore.json").read_text())
    assert record["state"] == "restored" and "processes" not in record


@pytest.mark.parametrize("damage", ["backup", "updated_installation"])
def test_restore_rejects_corruption_or_update_before_kill(installation, damage):
    f = installation
    result = f.Worker(f.adapter).execute("prepare", None, False)
    folder = Path(result["backup_path"])
    target = (folder / "WeChatAppEx.app.bak/Contents/MacOS/WeChatAppEx"
              if damage == "backup" else f.paths.main_module)
    target.write_bytes(b"changed independently")
    f.events.clear()
    with pytest.raises(ToolError) as caught:
        f.Worker(f.adapter).execute("restore", str(folder), False)
    assert caught.value.code == ErrorCode.BACKUP_MISMATCH
    assert not f.events


def test_partial_sign_failure_rolls_back_and_relaunches(installation):
    f = installation
    before = maintenance.tree_digest(f.root)
    worker = f.Worker(f.adapter)
    worker.fail_sign = "Real Helper"
    with pytest.raises(RuntimeError):
        worker.execute("prepare", None, False)
    assert maintenance.tree_digest(f.root) == before
    assert worker.detail["restored"] and not worker.detail["files_modified"]
    assert f.events[-1] == ("launch", True)
    assert json.loads((Path(worker.detail["backup_path"]) / "restore.json").read_text())["state"] == "rolled_back"


def test_stop_timeout_never_signs_and_still_requests_relaunch(installation, monkeypatch):
    f = installation
    before = maintenance.tree_digest(f.root)
    def timeout(_):
        raise TimeoutError("Processes kept appearing before the stop deadline")
    monkeypatch.setattr(maintenance, "kill_application", timeout)
    worker = f.Worker(f.adapter)
    with pytest.raises(TimeoutError):
        worker.execute("prepare", None, False, force_resign=True)
    assert maintenance.tree_digest(f.root) == before
    assert not [event for event in f.events if event[0] == "sign"]
    assert f.events[-1] == ("launch", True)
    assert Path(worker.detail["backup_path"], "restore.json").is_file()


def test_dry_run_and_launch_do_not_sign_or_kill(installation):
    f = installation
    result = f.Worker(f.adapter).execute("prepare", None, True)
    assert not result["executed"] and not f.events and not paths.backup_dir().exists()
    f.Worker(f.adapter).execute("launch", None, False)
    assert f.events == [("launch", False)]


def test_launch_opens_only_wechat_not_the_nested_inheriting_runtime(installation):
    f = installation
    commands = []
    worker = maintenance.Maintenance(f.adapter)
    worker.run_command = lambda args, **kwargs: commands.append(args)
    result = worker.launch()
    assert commands == [["/usr/bin/open", str(f.app)]]
    assert result["requested"] and result["runtime_start_required"] and not result["runtime_pids"]


def test_ad_hoc_units_reused_but_clean_restart_still_backed_up(installation):
    f = installation
    for binary in f.adapter.signing_targets():
        binary.write_bytes(b"signed:" + binary.read_bytes())
    result = f.Worker(f.adapter).execute("prepare", None, False)
    assert result["backup_path"] and not [e for e in f.events if e[0] == "sign"]
    assert f.events[0] == ("kill", True)
    assert result["signed_binaries"] == [] and not result["force_resign"]


def test_explicit_force_resign_executes_signing_even_for_suitable_units(installation):
    f = installation
    for binary in f.adapter.signing_targets():
        binary.write_bytes(b"signed:" + binary.read_bytes())
    preview = f.Worker(f.adapter).execute("prepare", None, True, force_resign=True)
    assert preview["force_resign"] and not preview["signed_binaries"] and not f.events
    result = f.Worker(f.adapter).execute("prepare", None, False, force_resign=True)
    assert result["force_resign"] and len(result["signed_binaries"]) == 2
    assert len([e for e in f.events if e[0] == "sign"]) == 2


@pytest.fixture
def process_stop(monkeypatch, tmp_path):
    if sys.platform == "win32":
        pytest.skip("macOS process-stop fixture requires kqueue and SIGKILL")
    root = tmp_path / "WeChat.app"
    main = str(root / "Contents/MacOS/WeChat")
    helper = str(root / "Contents/Helpers/Child.app/Contents/MacOS/Child")
    # Kernel enumeration can present the child first; ordering must not use it.
    processes = {12: helper, 11: main}
    parents = {12: 11, 11: 1}
    trace, pending = [], []
    state = SimpleNamespace(root=root, processes=processes, parents=parents,
                            trace=trace, on_exit=None, helper=helper, closed=False)
    for name, value in {"KQ_FILTER_PROC": -5, "KQ_EV_ADD": 1, "KQ_EV_ONESHOT": 16,
                        "KQ_NOTE_EXIT": 0x80000000, "KQ_EV_ERROR": 0x4000}.items():
        monkeypatch.setattr(maintenance.select, name, value, raising=False)
    def event(pid, **kwargs):
        return SimpleNamespace(ident=pid, flags=kwargs.get("flags", 0), data=0)
    class Queue:
        def control(self, changes, maximum, timeout):
            if changes:
                trace.extend(("watch", change.ident) for change in changes)
                return []
            assert timeout > 0 and pending
            batch = pending[:maximum]
            del pending[:maximum]
            if state.on_exit:
                state.on_exit()
            return batch
        def close(self): state.closed = True
    def observed(_):
        return [{"pid": pid, "binary": binary} for pid, binary in processes.items()
                if Path(binary).is_relative_to(root)]
    def kill(pid, sig):
        assert sig == signal.SIGKILL and ("watch", pid) in trace
        assert pid in processes
        trace.append(("kill", pid))
        processes.pop(pid)
        pending.append(event(pid))
    monkeypatch.setattr(maintenance.select, "kqueue", Queue, raising=False)
    monkeypatch.setattr(maintenance.select, "kevent", event, raising=False)
    monkeypatch.setattr(maintenance, "application_processes", observed)
    monkeypatch.setattr(maintenance, "_parents_of", lambda pids, timeout_s: dict(parents))
    monkeypatch.setattr(maintenance.os, "kill", kill)
    return state


def test_force_stop_subscribes_before_signalling_and_kills_parent_first(process_stop):
    f = process_stop
    assert maintenance.kill_application(f.root) == [11, 12]
    assert f.trace == [("watch", 11), ("kill", 11), ("watch", 12), ("kill", 12)]
    assert not f.processes and f.closed


def test_force_stop_drains_new_children_after_exit_events(process_stop):
    f = process_stop
    def spawn_once():
        f.processes[13] = f.helper
        f.on_exit = None
    f.on_exit = spawn_once
    assert maintenance.kill_application(f.root) == [11, 12, 13]
    assert not f.processes and f.closed


def test_continuous_respawn_shares_one_stop_deadline(process_stop, monkeypatch):
    f = process_stop
    ticks = iter(i / 10 for i in range(100))
    monkeypatch.setattr(maintenance, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    next_pid = 20
    def respawn():
        nonlocal next_pid
        f.processes[next_pid] = f.helper
        next_pid += 1
    f.on_exit = respawn
    with pytest.raises(TimeoutError, match="deadline"):
        maintenance.kill_application(f.root, timeout_s=1)
    # Deadline may fall after SIGKILL and before its queued exit is delivered.
    assert f.closed and next_pid > 21


def test_force_stop_rechecks_kernel_path_and_does_not_kill_reused_pid(process_stop, monkeypatch):
    f = process_stop
    original = maintenance.select.kevent
    def replaced(pid, **kwargs):
        f.processes[pid] = "/tmp/unrelated-app"
        return original(pid, **kwargs)
    monkeypatch.setattr(maintenance.select, "kevent", replaced)
    assert maintenance.kill_application(f.root) == []
    assert not [row for row in f.trace if row[0] == "kill"] and f.closed


def test_parent_observation_accepts_processes_exiting_during_ps(monkeypatch):
    monkeypatch.setattr(maintenance.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=1, stdout="", stderr=""))
    assert maintenance._parents_of({11}, 1) == {}


@pytest.mark.anyio
async def test_cancellation_after_file_mutation_settles_restore(installation):
    f = installation
    before = maintenance.tree_digest(f.root)
    entered = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    class Worker(f.Worker):
        def run_command(self, args, timeout=30, *, cleanup=False):
            super().run_command(args, timeout, cleanup=cleanup)
            if "--sign" in args:
                loop.call_soon_threadsafe(entered.set)
                release.wait(3)
                self.checkpoint()
        def cancel(self):
            super().cancel()
            release.set()
    worker = Worker(f.adapter)
    task = asyncio.create_task(maintenance.run_maintenance(worker, "prepare", None, False))
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert maintenance.tree_digest(f.root) == before
    assert worker.detail["restored"] and f.events[-1] == ("launch", True)


def test_helper_executable_cannot_escape_bundle(installation):
    f = installation
    helper = f.adapter.signing_targets()[1]
    outside = f.app.parent / "outside"
    outside.write_text("do not sign")
    helper.unlink()
    helper.symlink_to(outside)
    with pytest.raises(ValueError, match="out-of-bundle"):
        f.adapter.signing_targets()


def test_kernel_path_selection_excludes_name_and_prefix_matches(monkeypatch, tmp_path):
    root = tmp_path / "WeChat.app"
    binaries = {11: str(root / "Contents/MacOS/WeChat"),
                12: str(root / "Contents/MacOS/WeChatAppEx.app/Contents/MacOS/WeChatAppEx"),
                13: str(root) + "-other/WeChat", 14: "/tmp/python-WeChatAppEx.app/Contents/python"}
    class Function:
        def __init__(self, method): self.method = method
        def __call__(self, *args): return self.method(*args)
    def list_pids(buffer, size):
        if buffer is None: return len(binaries)
        for i, pid in enumerate(binaries): buffer[i] = pid
        return len(binaries)
    def pidpath(pid, buffer, size):
        buffer.value = binaries[pid].encode()
        return len(buffer.value)
    lib = SimpleNamespace(proc_listallpids=Function(list_pids), proc_pidpath=Function(pidpath))
    monkeypatch.setattr(maintenance.ctypes, "CDLL", lambda *a, **k: lib)
    assert [p["pid"] for p in maintenance.application_processes(root)] == [11, 12]
    assert DarwinAdapter(WeChatPaths(root, tmp_path / "radium")).running_pids() == [12]


def test_combined_ad_hoc_runtime_flags_are_not_mistaken_for_unhardened(monkeypatch, tmp_path):
    from wmpf_mcp.platform import darwin
    monkeypatch.setattr(darwin, "_run", lambda args: SimpleNamespace(returncode=0, stdout="",
        stderr="CodeDirectory v=20500 flags=0x10002(adhoc,runtime)\nSignature=adhoc\n"))
    result = DarwinAdapter().signature_for(tmp_path / "binary")
    assert result["adhoc"] and result["hardened_runtime"]


@pytest.mark.anyio
async def test_manage_invalid_restore_does_not_stop_owned_resources(monkeypatch, installation):
    from wmpf_mcp.tools import maintenance as tool, runtime
    f = installation
    monkeypatch.setattr(tool, "get_adapter", lambda: f.adapter)
    stopped = []
    async def stop(*_): stopped.append(True)
    monkeypatch.setattr(runtime, "stop_owned", stop)
    result = await build_server().call_tool("manage_wechat", {"action": "restore", "backup_path": str(f.app.parent / "missing")})
    assert result.is_error and result.structured_content["error"]["code"] == "E_BACKUP_MISMATCH"
    assert not stopped and not f.events


@pytest.mark.anyio
async def test_public_prepare_and_restore_envelopes_and_progress(monkeypatch, installation):
    from wmpf_mcp.tools import maintenance as tool, runtime
    from jsonschema import Draft202012Validator
    f = installation
    monkeypatch.setattr(tool, "get_adapter", lambda: f.adapter)
    monkeypatch.setattr(tool, "Maintenance", f.Worker)
    stops = []
    async def stop(*_):
        stops.append(True)
        return envelope.ok({"components": {}}, stage="INIT")
    monkeypatch.setattr(runtime, "stop_owned", stop)
    server = build_server()
    prepared = await server.call_tool("manage_wechat", {"action": "prepare"})
    assert prepared.structured_content["ok"] and get_state().wechat_prepared
    definition = next(t for t in await server.list_tools() if t.name == "manage_wechat")
    Draft202012Validator(definition.output_schema).validate(prepared.structured_content)
    restored = await server.call_tool("manage_wechat", {"action": "restore", "backup_path": prepared.structured_content["data"]["backup_path"]})
    assert restored.structured_content["ok"] and not get_state().wechat_prepared and len(stops) == 2


@pytest.mark.anyio
async def test_unwritable_app_fails_before_stopping_resources(monkeypatch, installation):
    from wmpf_mcp.tools import maintenance as tool, runtime
    f = installation
    monkeypatch.setattr(tool, "get_adapter", lambda: f.adapter)
    monkeypatch.setattr(maintenance.os, "access", lambda *_: False)
    stops = []
    async def stop(*_): stops.append(True)
    monkeypatch.setattr(runtime, "stop_owned", stop)
    result = await build_server().call_tool("manage_wechat", {"action": "prepare"})
    assert result.structured_content["error"]["code"] == "E_PERMISSION"
    assert not stops and not f.events and not paths.backup_dir().exists()


@pytest.mark.anyio
async def test_force_resign_invalid_action_fails_before_any_maintenance(installation):
    result = await build_server().call_tool("manage_wechat", {"action": "restart", "force_resign": True})
    assert result.structured_content["error"]["code"] == "E_PARAM" and not installation.events
