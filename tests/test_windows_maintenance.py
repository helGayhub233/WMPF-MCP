"""Windows maintenance over synthetic installations and fake process handles."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from wmpf_mcp.core import envelope, paths
from wmpf_mcp.core.config import WeChatPaths
from wmpf_mcp.core.errors import ErrorCode, ToolError
from wmpf_mcp.platform import windows_maintenance as maintenance
from wmpf_mcp.platform.maintenance import tree_digest
from wmpf_mcp.platform.windows_maintenance import application_processes as observe_processes
from wmpf_mcp.platform.windows_maintenance import kill_application as stop_processes
from wmpf_mcp.server import build_server


@pytest.fixture
def windows_installation(tmp_path, monkeypatch):
    app = tmp_path / "微信 app"
    app.mkdir()
    main = app / "Weixin.exe"
    main.write_bytes(b"vendor main executable")
    (app / "resources").mkdir()
    (app / "resources/vendor.dat").write_bytes(b"vendor resources")
    runtime = tmp_path / "cache/RadiumWMPF/123/extracted/runtime"
    runtime.mkdir(parents=True)
    module = runtime / "flue.dll"
    module.write_bytes(b"vendor DLL")
    adapter = SimpleNamespace(platform="win32", paths=WeChatPaths(app, tmp_path / "radium"),
                              main_module_path=lambda: str(module))
    events = []
    monkeypatch.setattr(maintenance, "application_processes", lambda _: [{"pid": 11, "parent_pid": 1,
                                                                         "binary": str(main)}])
    def kill(roots, checkpoint, *, stopped_pids=None, stop_observations=None):
        checkpoint()
        records = list(paths.backup_dir().glob("*/restore.json")) if paths.backup_dir().exists() else []
        events.append(("kill", bool(records)))
        stopped_pids.append(11)
        return [11]
    monkeypatch.setattr(maintenance, "kill_application", kill)
    class Worker(maintenance.WindowsMaintenance):
        def _permissions(self, roots, *, backup_folder=None):
            events.append(("permissions", tuple(roots)))
        def launch(self, *, cleanup=False, main=None):
            self.checkpoint()
            events.append(("launch", cleanup))
            return {"requested": True, "main_executable": str(main), "runtime_start_required": True}
    return SimpleNamespace(app=app, main=main, runtime=runtime, module=module, adapter=adapter,
                           Worker=Worker, events=events)


def test_prepare_complete_backup_precedes_stop_and_preserves_vendor_files(windows_installation):
    f = windows_installation
    originals = [tree_digest(f.app), tree_digest(f.runtime)]
    reply = f.Worker(f.adapter).execute("prepare", None, False)
    folder = Path(reply["backup_path"])
    assert ("kill", True) in f.events
    assert reply["steps"] == ["backup", "verify_backup", "force_stop", "verify_unchanged", "launch"]
    assert not reply["files_modified"] and not reply["signed_binaries"] and not reply["signatures"]
    assert [tree_digest(folder / f"tree-{i}.bak") for i in range(2)] == originals
    assert [tree_digest(f.app), tree_digest(f.runtime)] == originals
    record = json.loads((folder / "restore.json").read_text(encoding="utf-8"))
    assert record["state"] == "prepared" and "processes" not in record
    restored = f.Worker(f.adapter).execute("restore", str(folder), False)
    assert restored["restored"] and restored["already_original"] and not restored["files_modified"]
    assert [tree_digest(f.app), tree_digest(f.runtime)] == originals
    assert json.loads((folder / "restore.json").read_text(encoding="utf-8"))["state"] == "restored"


@pytest.mark.parametrize("damage", ["backup", "updated_installation", "wrong_path", "traversal"])
def test_restore_refuses_changed_or_mismatched_snapshot_before_stop(windows_installation, damage):
    f = windows_installation
    reply = f.Worker(f.adapter).execute("prepare", None, False)
    folder = Path(reply["backup_path"])
    if damage == "backup":
        (folder / "tree-1.bak/flue.dll").write_bytes(b"corrupt backup")
    elif damage == "updated_installation":
        f.main.write_bytes(b"vendor update")
    else:
        record_path = folder / "restore.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["roots"][0]["path" if damage == "wrong_path" else "backup"] = "../foreign"
        record_path.write_text(json.dumps(record), encoding="utf-8")
    f.events.clear()
    with pytest.raises(ToolError) as caught:
        f.Worker(f.adapter).execute("restore", str(folder), False)
    assert caught.value.code == ErrorCode.BACKUP_MISMATCH and not f.events


def test_failed_stop_keeps_backup_and_never_launches(windows_installation, monkeypatch):
    f = windows_installation
    def timeout(*_, stopped_pids, **__):
        stopped_pids.append(11)
        raise TimeoutError("stop deadline")
    monkeypatch.setattr(maintenance, "kill_application", timeout)
    worker = f.Worker(f.adapter)
    before = tree_digest(f.app)
    with pytest.raises(TimeoutError, match="stop deadline"):
        worker.execute("prepare", None, False)
    assert tree_digest(f.app) == before and not any(event[0] == "launch" for event in f.events)
    assert Path(worker.detail["backup_path"], "restore.json").is_file()
    assert worker.detail["killed_pids"] == [11]


def test_cancellation_after_backup_never_stops_or_launches(windows_installation):
    f = windows_installation
    class Worker(f.Worker):
        def backup(self, roots):
            result = super().backup(roots)
            self.cancel()
            return result
    worker = Worker(f.adapter)
    with pytest.raises(InterruptedError):
        worker.execute("prepare", None, False)
    assert not any(event[0] in {"kill", "launch"} for event in f.events)
    assert Path(worker.detail["backup_path"], "restore.json").is_file()


def test_dry_run_no_files_no_kill_and_force_resign_rejected(windows_installation):
    f = windows_installation
    result = f.Worker(f.adapter).execute("prepare", None, True)
    assert not result["executed"] and not paths.backup_dir().exists()
    assert all(event[0] == "permissions" for event in f.events)
    f.events.clear()
    with pytest.raises(ToolError) as caught:
        f.Worker(f.adapter).execute("prepare", None, False, force_resign=True)
    assert caught.value.code == ErrorCode.UNSUPPORTED_ANALYSIS and not f.events


def test_backup_storage_cannot_recurse_into_the_installation(windows_installation, monkeypatch):
    f = windows_installation
    monkeypatch.setenv("WMPF_MCP_HOME", str(f.app / "mcp-state"))
    with pytest.raises(ToolError, match="outside the installation"):
        f.Worker(f.adapter).execute("prepare", None, False)
    assert not (f.app / "mcp-state").exists() and not any(event[0] == "kill" for event in f.events)


def test_reparse_point_rejected_before_directory_traversal(tmp_path, monkeypatch):
    original = Path.lstat
    def stat(path):
        value = original(path)
        if path == tmp_path:
            return SimpleNamespace(st_file_attributes=0x400)
        return value
    monkeypatch.setattr(Path, "lstat", stat)
    def forbidden(_):
        pytest.fail("Reparse directory must not be traversed")
    monkeypatch.setattr(Path, "iterdir", forbidden)
    with pytest.raises(ValueError, match="reparse points"):
        maintenance._validate_tree(tmp_path)


def test_ambiguous_main_is_not_guessed_and_explicit_main_is_supported(windows_installation):
    f = windows_installation
    (f.app / "WeChat.exe").write_bytes(b"other main")
    with pytest.raises(ToolError, match="ambiguous"):
        f.Worker(f.adapter).execute("launch", None, True)
    f.adapter.paths = WeChatPaths(f.main, f.adapter.paths.radium_dir)
    result = f.Worker(f.adapter).execute("launch", None, True)
    assert result["main_executable"] == str(f.main)


def test_launch_starts_only_main_executable(windows_installation, monkeypatch):
    f = windows_installation
    commands = []
    monkeypatch.setattr(maintenance.subprocess, "Popen", lambda args, **kwargs:
                        commands.append((args, kwargs)) or SimpleNamespace(pid=1234))
    result = maintenance.WindowsMaintenance(f.adapter).launch()
    assert commands == [([str(f.main)], {"cwd": str(f.app), "close_fds": True})]
    assert result["requested"] and result["runtime_start_required"] and result["launcher_pid"] == 1234


@pytest.mark.parametrize("action", ["prepare", "restart", "restore"])
def test_relaunch_reuses_verified_main_when_stopped_runtime_becomes_ambiguous(
        windows_installation, monkeypatch, action):
    from wmpf_mcp.platform import win32

    f = windows_installation
    plugin = f.runtime.parents[2]
    runtime_exe = f.runtime / "WeChatAppEx.exe"
    runtime_exe.write_bytes(b"vendor runtime executable")
    second = plugin / "124/extracted/runtime/flue.dll"
    second.parent.mkdir(parents=True)
    second.write_bytes(b"another cached runtime DLL")
    adapter = win32.Win32Adapter(SimpleNamespace(wechat_app=f.main, radium_wmpf_dir=plugin))
    stopped = [False]
    queries, launches = [], []

    def snapshot():
        queries.append(stopped[0])
        return [] if stopped[0] else [{"pid": 11, "name": "WeChatAppEx",
                                      "path": str(runtime_exe), "modules": [str(f.module)],
                                      "module_error": None}]

    def kill(roots, checkpoint, *, stopped_pids, stop_observations=None):
        checkpoint()
        assert roots == [f.app, f.runtime]
        stopped[0] = True
        stopped_pids.append(11)
        return stopped_pids

    class Worker(maintenance.WindowsMaintenance):
        def _permissions(self, roots, *, backup_folder=None):
            pass

    monkeypatch.setattr(win32, "_process_snapshot", snapshot)
    monkeypatch.setattr(maintenance, "kill_application", kill)
    monkeypatch.setattr(maintenance.subprocess, "Popen", lambda args, **kwargs:
                        launches.append((args, kwargs)) or SimpleNamespace(pid=1234))
    backup_path = None
    if action == "restore":
        backup_path = Worker(adapter).execute("prepare", None, False)["backup_path"]
        stopped[0] = False
        queries.clear()
        launches.clear()

    result = Worker(adapter).execute(action, backup_path, False)

    assert result["executed"] and result["killed_pids"] == [11]
    assert queries == [False]
    assert launches == [([str(f.main)], {"cwd": str(f.app), "close_fds": True})]
    # Offline discovery still refuses to guess; launch needs only the verified main.
    with pytest.raises(ValueError, match="Ambiguous Windows runtime modules"):
        adapter.main_module_path()


class ProcessAPI:
    def __init__(self, root):
        self.root = root
        self.processes = {12: (root / "helper.exe", 11), 11: (root / "Weixin.exe", 1),
                          99: (root.parent / "foreign/Weixin.exe", 1)}
        self.trace = []
        self.opened = []
        self.stop_opened = set()
        self.pending = set()
        self.on_exit = None
        self.reused = None
    def entries(self):
        return [{"pid": pid, "name": path.name, "parent_pid": parent}
                for pid, (path, parent) in self.processes.items()]
    def open_process(self, pid, *, stop=False):
        if pid not in self.processes:
            return None
        if stop and self.reused == pid:
            self.processes[pid] = (self.root.parent / "foreign/Weixin.exe", 1)
        self.opened.append((pid, stop))
        if stop:
            self.stop_opened.add(pid)
        return pid
    def image(self, handle):
        return self.processes[handle][0]
    def close(self, handle):
        self.trace.append(("close", handle))
    def terminate(self, handle):
        self.trace.append(("terminate", handle))
        self.pending.add(handle)
    def wait(self, handle, timeout_ms):
        if timeout_ms == 0:
            return handle not in self.processes
        assert 0 < timeout_ms <= 100
        assert handle in self.pending
        self.processes.pop(handle, None)
        self.pending.discard(handle)
        if self.on_exit:
            self.on_exit(handle)
        return True


def assert_handles_closed(api):
    assert sorted(pid for pid, _ in api.opened) == sorted(pid for kind, pid in api.trace if kind == "close")


def native_error(code):
    error = PermissionError(13, "synthetic access denied") if code == 5 else OSError(22, "synthetic image failure")
    error.winerror = code
    return error


@pytest.mark.parametrize("denied_pid", [11, 12])
def test_stop_batch_permission_failure_precedes_every_termination(tmp_path, denied_pid):
    api = ProcessAPI(tmp_path)
    original = api.open_process
    denied = native_error(5)
    def open_process(pid, *, stop=False):
        if stop and pid == denied_pid:
            raise denied
        return original(pid, stop=stop)
    api.open_process = open_process
    with pytest.raises(PermissionError) as caught:
        maintenance.kill_application([tmp_path], lambda: None, api=api)
    assert not [event for event in api.trace if event[0] == "terminate"]
    assert caught.value is denied and caught.value.winerror == 5
    assert caught.value.pid == denied_pid and caught.value.operation == "OpenProcess(stop)"
    assert f"pid={denied_pid}" in str(caught.value) and "native_winerror=5" in str(caught.value)
    assert_handles_closed(api)


def test_cancel_during_batch_validation_closes_all_handles_before_any_kill(tmp_path):
    api = ProcessAPI(tmp_path)
    def checkpoint():
        if api.stop_opened:
            raise InterruptedError("cancelled during batch validation")
    with pytest.raises(InterruptedError, match="cancelled"):
        maintenance.kill_application([tmp_path], checkpoint, api=api)
    assert not [event for event in api.trace if event[0] == "terminate"]
    assert_handles_closed(api)


def test_parent_exit_can_signal_already_open_child_handle(tmp_path):
    api = ProcessAPI(tmp_path)
    def exited(handle):
        if handle == 11:
            assert 12 in api.stop_opened
            api.processes.pop(12)
    api.on_exit = exited
    assert maintenance.kill_application([tmp_path], lambda: None, api=api) == [11]
    assert [(kind, pid) for kind, pid in api.trace if kind == "terminate"] == [("terminate", 11)]
    assert_handles_closed(api)


@pytest.mark.parametrize("phase", ["query", "stop"])
def test_already_signaled_handle_is_skipped_before_image_query(tmp_path, phase):
    api = ProcessAPI(tmp_path)
    original_open, original_image = api.open_process, api.image
    exited = False
    def open_process(pid, *, stop=False):
        nonlocal exited
        handle = original_open(pid, stop=stop)
        if pid == 12 and stop == (phase == "stop"):
            api.processes.pop(pid)
            exited = True
        return handle
    def image(handle):
        if handle == 12 and exited:
            pytest.fail("A signaled process handle must not be queried for its image")
        return original_image(handle)
    api.open_process, api.image = open_process, image
    assert maintenance.kill_application([tmp_path], lambda: None, api=api) == [11]
    assert_handles_closed(api)


@pytest.mark.parametrize("phase", ["query", "stop"])
@pytest.mark.parametrize("code", [5, 31])
def test_image_failure_only_skips_when_same_handle_proves_exit(tmp_path, phase, code):
    api = ProcessAPI(tmp_path)
    original = api.image
    def image(handle):
        if handle == 12 and ((handle in api.stop_opened) == (phase == "stop")):
            api.processes.pop(handle)
            raise native_error(code)
        return original(handle)
    api.image = image
    assert maintenance.kill_application([tmp_path], lambda: None, api=api) == [11]
    assert not [event for event in api.trace if event == ("terminate", 12)]
    assert_handles_closed(api)


@pytest.mark.parametrize("code", [5, 31])
@pytest.mark.parametrize("wait_fails", [False, True])
def test_live_image_failure_keeps_original_error_when_exit_not_proved(tmp_path, code, wait_fails):
    api = ProcessAPI(tmp_path)
    original_image, original_wait = api.image, api.wait
    failure = native_error(code)
    image_failed = False
    def image(handle):
        nonlocal image_failed
        if handle == 12 and handle in api.stop_opened:
            image_failed = True
            raise failure
        return original_image(handle)
    def wait(handle, timeout_ms):
        if handle == 12 and image_failed and wait_fails:
            raise native_error(6)
        return original_wait(handle, timeout_ms)
    api.image, api.wait = image, wait
    with pytest.raises(OSError) as caught:
        maintenance.kill_application([tmp_path], lambda: None, api=api)
    assert caught.value is failure and caught.value.winerror == code
    assert caught.value.pid == 12 and caught.value.operation == "QueryFullProcessImageNameW"
    assert not [event for event in api.trace if event[0] == "terminate"]
    assert_handles_closed(api)


def test_query_scope_denial_keeps_original_permission_error(tmp_path):
    api = ProcessAPI(tmp_path)
    original = api.open_process
    failure = native_error(5)
    def open_process(pid, *, stop=False):
        if pid == 12:
            raise failure
        return original(pid, stop=stop)
    api.open_process = open_process
    with pytest.raises(PermissionError, match="scope.*12") as caught:
        maintenance.application_processes([tmp_path], api)
    assert caught.value is failure and caught.value.winerror == 5
    assert caught.value.pid == 12 and caught.value.operation == "OpenProcess(query)"
    assert_handles_closed(api)


def test_query_and_stop_handles_request_exact_wait_rights():
    calls = []
    api = maintenance._WindowsAPI.__new__(maintenance._WindowsAPI)
    api.lib = SimpleNamespace(OpenProcess=lambda *args: calls.append(args) or 123)
    assert api.open_process(11) == api.open_process(12, stop=True) == 123
    assert calls == [(0x101000, False, 11), (0x101001, False, 12)]


def test_terminate_false_always_raises_original_error_without_wait(monkeypatch):
    error = [5]
    waits = []
    def wait(*_):
        waits.append(True)
        error[0] = 6
        return 0
    api = maintenance._WindowsAPI.__new__(maintenance._WindowsAPI)
    api.lib = SimpleNamespace(TerminateProcess=lambda *_: False, WaitForSingleObject=wait)
    monkeypatch.setattr(maintenance.ctypes, "get_last_error", lambda: error[0])
    monkeypatch.setattr(maintenance.ctypes, "WinError", native_error)
    with pytest.raises(PermissionError) as caught:
        api.terminate(11)
    assert caught.value.winerror == 5 and not waits


class TerminateFailureAPI(ProcessAPI):
    def __init__(self, root, *, code=5, exit_after=2, wait_error=False):
        super().__init__(root)
        self.failure = native_error(code)
        self.exit_after = exit_after
        self.wait_error = wait_error
        self.denied = False
        self.elapsed = 0.0
        self.proof_waits = []
        self.after_wait = None

    def terminate(self, handle):
        if handle == 11:
            self.trace.append(("terminate", handle))
            self.denied = True
            raise self.failure
        return super().terminate(handle)

    def wait(self, handle, timeout_ms):
        if handle == 11 and self.denied:
            assert 0 <= timeout_ms <= 100
            self.proof_waits.append((self.elapsed, timeout_ms))
            self.elapsed += timeout_ms / 1000
            if self.wait_error:
                raise native_error(6)
            if self.after_wait:
                self.after_wait()
            if self.exit_after is not None and len(self.proof_waits) >= self.exit_after:
                self.processes.pop(handle, None)
                return True
            return False
        return super().wait(handle, timeout_ms)


@pytest.mark.parametrize("exit_after", [1, 2])
def test_terminate_access_denied_only_same_handle_exit_is_observed_not_killed(tmp_path, monkeypatch, exit_after):
    api = TerminateFailureAPI(tmp_path, exit_after=exit_after)
    monkeypatch.setattr(maintenance, "time", SimpleNamespace(monotonic=lambda: api.elapsed))
    observations = []
    assert maintenance.kill_application([tmp_path], lambda: None, api=api,
                                        stop_observations=observations) == [12]
    assert observations == [{"pid": 11, "operation": "TerminateProcess", "native_winerror": 5,
                             "outcome": "exited", "proof": "same_handle_signaled"}]
    assert [event for event in api.trace if event[0] == "terminate"] == [("terminate", 11), ("terminate", 12)]
    assert len(api.proof_waits) == exit_after and list(api.processes) == [99]
    assert_handles_closed(api)


def test_terminate_access_denied_live_until_original_deadline_keeps_error_and_never_launches(
        windows_installation, monkeypatch):
    f = windows_installation
    api = TerminateFailureAPI(f.app, exit_after=None)
    monkeypatch.setattr(maintenance, "time", SimpleNamespace(monotonic=lambda: api.elapsed))
    monkeypatch.setattr(maintenance, "_WindowsAPI", lambda: api)
    monkeypatch.setattr(maintenance, "application_processes", observe_processes)
    monkeypatch.setattr(maintenance, "kill_application", stop_processes)
    worker = f.Worker(f.adapter)
    with pytest.raises(PermissionError) as caught:
        worker.execute("prepare", None, False)
    assert caught.value is api.failure and caught.value.winerror == 5
    assert caught.value.pid == 11 and caught.value.operation == "TerminateProcess"
    assert all(started < 10 and 0 < duration <= 100 for started, duration in api.proof_waits)
    assert 10 <= api.elapsed < 10.001
    assert worker.detail["killed_pids"] == [] and worker.detail["stop_observations"] == []
    assert Path(worker.detail["backup_path"], "restore.json").is_file()
    assert not [event for event in f.events if event[0] == "launch"]
    assert [event for event in api.trace if event[0] == "terminate"] == [("terminate", 11)]
    assert_handles_closed(api)


def test_terminate_access_denied_wait_failure_preserves_original_terminate_error(tmp_path, monkeypatch):
    api = TerminateFailureAPI(tmp_path, wait_error=True)
    monkeypatch.setattr(maintenance, "time", SimpleNamespace(monotonic=lambda: api.elapsed))
    observations = []
    with pytest.raises(PermissionError) as caught:
        maintenance.kill_application([tmp_path], lambda: None, api=api, stop_observations=observations)
    assert caught.value is api.failure and caught.value.winerror == 5
    assert caught.value.pid == 11 and caught.value.operation == "TerminateProcess"
    assert len(api.proof_waits) == 1 and not observations
    assert_handles_closed(api)


@pytest.mark.parametrize("code", [6, 87])
def test_other_terminate_errors_do_not_gain_exit_wait(tmp_path, code):
    api = TerminateFailureAPI(tmp_path, code=code)
    with pytest.raises(OSError) as caught:
        maintenance.kill_application([tmp_path], lambda: None, api=api)
    assert caught.value is api.failure and caught.value.winerror == code
    assert caught.value.pid == 11 and caught.value.operation == "TerminateProcess"
    assert not api.proof_waits
    assert_handles_closed(api)


def test_cancel_during_terminate_denial_wait_drains_proof_then_stops_before_next_pid(tmp_path, monkeypatch):
    api = TerminateFailureAPI(tmp_path)
    monkeypatch.setattr(maintenance, "time", SimpleNamespace(monotonic=lambda: api.elapsed))
    cancelled = False
    def cancellation_arrives():
        nonlocal cancelled
        cancelled = True
    api.after_wait = cancellation_arrives
    def checkpoint():
        if cancelled:
            assert 11 not in api.processes  # Cancellation drains the same handle exit proof.
            raise InterruptedError("cancelled during exit proof")
    observations, killed = [], []
    with pytest.raises(InterruptedError, match="cancelled during exit proof"):
        maintenance.kill_application([tmp_path], checkpoint, api=api, stopped_pids=killed,
                                     stop_observations=observations)
    assert len(api.proof_waits) == 2 and not killed
    assert observations[0]["native_winerror"] == 5 and observations[0]["proof"] == "same_handle_signaled"
    assert [event for event in api.trace if event[0] == "terminate"] == [("terminate", 11)]
    assert 12 in api.processes and 99 in api.processes
    assert_handles_closed(api)


def test_verified_terminate_denial_exit_is_in_worker_result_detail(windows_installation, monkeypatch):
    f = windows_installation
    api = TerminateFailureAPI(f.app)
    monkeypatch.setattr(maintenance, "time", SimpleNamespace(monotonic=lambda: api.elapsed))
    monkeypatch.setattr(maintenance, "_WindowsAPI", lambda: api)
    monkeypatch.setattr(maintenance, "application_processes", observe_processes)
    monkeypatch.setattr(maintenance, "kill_application", stop_processes)
    worker = f.Worker(f.adapter)
    result = worker.execute("restart", None, False)
    assert result["executed"] and result["killed_pids"] == [12]
    assert result["stop_observations"] is worker.detail["stop_observations"]
    assert result["stop_observations"] == [{"pid": 11, "operation": "TerminateProcess", "native_winerror": 5,
                                           "outcome": "exited", "proof": "same_handle_signaled"}]
    assert_handles_closed(api)


def test_process_stop_exact_scope_parent_first_and_new_children(tmp_path):
    api = ProcessAPI(tmp_path)
    def born(handle):
        if handle == 11:
            api.processes[13] = (tmp_path / "new helper.exe", 11)
    api.on_exit = born
    result = maintenance.kill_application([tmp_path], lambda: None, api=api)
    assert result == [11, 12, 13]
    assert list(api.processes) == [99] and not api.pending
    assert_handles_closed(api)


def test_pid_reuse_is_rechecked_on_the_termination_handle(tmp_path):
    api = ProcessAPI(tmp_path)
    api.reused = 11
    assert maintenance.kill_application([tmp_path], lambda: None, api=api) == [12]
    assert not [event for event in api.trace if event == ("terminate", 11)]
    assert 11 in api.processes and 99 in api.processes
    assert_handles_closed(api)


@pytest.mark.parametrize("parent_exited", [False, True])
def test_uninspectable_descendant_prevents_claiming_complete_stop(tmp_path, parent_exited):
    api = ProcessAPI(tmp_path)
    original_open = api.open_process
    def open_process(pid, *, stop=False):
        if pid == 12:
            raise PermissionError("synthetic child query denied")
        return original_open(pid, stop=stop)
    api.open_process = open_process
    if parent_exited:
        api.processes.pop(11)
    with pytest.raises(PermissionError, match="scope.*12"):
        maintenance.application_processes([tmp_path], api, known_pids={11} if parent_exited else None)
    assert not [event for event in api.trace if event[0] == "terminate"]


def test_reappearing_processes_share_one_stop_deadline(tmp_path, monkeypatch):
    api = ProcessAPI(tmp_path)
    def born(handle):
        api.processes[handle + 10] = (tmp_path / "new.exe", 1)
    api.on_exit = born
    ticks = [0]
    def clock():
        ticks[0] += 0.2
        return ticks[0]
    monkeypatch.setattr(maintenance, "time", SimpleNamespace(monotonic=clock))
    stopped = []
    with pytest.raises(TimeoutError, match="deadline"):
        maintenance.kill_application([tmp_path], lambda: None, timeout_s=1, api=api, stopped_pids=stopped)
    assert 99 in api.processes
    assert stopped
    assert_handles_closed(api)


def test_cancel_drains_issued_termination_before_returning(tmp_path):
    api = ProcessAPI(tmp_path)
    cancelled = False
    def exited(_):
        nonlocal cancelled
        cancelled = True
    api.on_exit = exited
    def checkpoint():
        if cancelled:
            assert not api.pending
            raise InterruptedError("cancelled")
    with pytest.raises(InterruptedError):
        maintenance.kill_application([tmp_path], checkpoint, api=api)
    assert [(kind, pid) for kind, pid in api.trace if kind == "terminate"] == [("terminate", 11)]
    assert 12 in api.processes and 99 in api.processes
    assert_handles_closed(api)


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows ACL and process-query API")
def test_native_readonly_api_and_permissions_on_controlled_installation(windows_installation):
    f = windows_installation
    api = maintenance._WindowsAPI()
    handle = api.open_process(os.getpid())
    try:
        assert api.image(handle) in {Path(sys.executable).resolve(), Path(sys._base_executable).resolve()}
    finally:
        api.close(handle)
    assert any(row["pid"] > 0 for row in api.entries())
    maintenance.WindowsMaintenance(f.adapter)._permissions([f.app, f.runtime])
    record = f.app.parent / "restore.json"
    record.write_text("synthetic record", encoding="utf-8")
    api.check_record_write(record)
    record.chmod(0o444)
    try:
        with pytest.raises(PermissionError):
            maintenance.WindowsMaintenance(f.adapter)._permissions([f.app, f.runtime], backup_folder=f.app.parent)
    finally:
        record.chmod(0o666)
    assert record.read_text(encoding="utf-8") == "synthetic record"


@pytest.mark.anyio
async def test_public_windows_maintenance_reuses_login_q_and_a_once(windows_installation, monkeypatch):
    from mcp.types import ElicitResult, InputRequiredResult
    from jsonschema import Draft202012Validator
    from test_elicitation import context
    from wmpf_mcp.tools import maintenance as tool, runtime
    f = windows_installation
    monkeypatch.setattr(tool, "get_adapter", lambda: f.adapter)
    monkeypatch.setattr(tool, "WindowsMaintenance", f.Worker)
    async def stop(*_):
        return envelope.ok({"components": {}}, stage="INIT")
    monkeypatch.setattr(runtime, "stop_owned", stop)
    server = build_server()
    ctx, _ = context("2026-07-28")
    result = await server.call_tool("manage_wechat", {"action": "prepare"}, ctx)
    assert isinstance(result, InputRequiredResult)
    completed = list(f.events)
    resumed, _ = context("2026-07-28", state=result.request_state,
                         responses={"login_wechat": ElicitResult(action="accept", content={"choice": "已登录，继续"})})
    reply = await server.call_tool("manage_wechat", {"action": "prepare"}, resumed)
    assert f.events == completed and reply.structured_content["data"]["notification"]["status"] == "accepted"
    schema = next(t.output_schema for t in await server.list_tools() if t.name == "manage_wechat")
    Draft202012Validator(schema).validate(reply.structured_content)


@pytest.mark.anyio
async def test_public_permission_failure_precedes_owned_cleanup_and_backup(windows_installation, monkeypatch):
    from wmpf_mcp.tools import maintenance as tool, runtime
    f = windows_installation
    class Worker(f.Worker):
        def _permissions(self, roots, *, backup_folder=None):
            raise PermissionError("synthetic ACL denies reading installation")
    monkeypatch.setattr(tool, "get_adapter", lambda: f.adapter)
    monkeypatch.setattr(tool, "WindowsMaintenance", Worker)
    async def stop(*_):
        pytest.fail("Preflight permission failure must precede owned resource cleanup")
    monkeypatch.setattr(runtime, "stop_owned", stop)
    result = await build_server().call_tool("manage_wechat", {"action": "prepare"})
    assert result.structured_content["error"]["code"] == "E_PERMISSION"
    assert not paths.backup_dir().exists() and not f.events


@pytest.mark.anyio
async def test_public_stop_permission_failure_reports_api_pid_and_native_error(windows_installation, monkeypatch):
    from wmpf_mcp.tools import maintenance as tool, runtime
    f = windows_installation
    api = ProcessAPI(f.app)
    original = api.open_process
    def denied(pid, *, stop=False):
        if stop and pid == 12:
            raise native_error(5)
        return original(pid, stop=stop)
    api.open_process = denied
    monkeypatch.setattr(maintenance, "_WindowsAPI", lambda: api)
    monkeypatch.setattr(maintenance, "application_processes", observe_processes)
    monkeypatch.setattr(maintenance, "kill_application", stop_processes)
    monkeypatch.setattr(tool, "get_adapter", lambda: f.adapter)
    monkeypatch.setattr(tool, "WindowsMaintenance", f.Worker)
    async def stop(*_):
        return envelope.ok({"components": {}}, stage="INIT")
    monkeypatch.setattr(runtime, "stop_owned", stop)
    reply = await build_server().call_tool("manage_wechat", {"action": "prepare"})
    error = reply.structured_content["error"]
    detail = reply.structured_content["remedy_detail"]
    assert error["code"] == "E_PERMISSION"
    assert "pid=12" in error["message"] and "OpenProcess(stop)" in error["message"]
    assert "native_winerror=5" in error["message"]
    assert detail["phase"] == "force_stop"
    assert detail["killed_pids"] == []
    assert Path(detail["backup_path"], "restore.json").is_file()
    assert not [event for event in api.trace if event[0] == "terminate"]
    assert not [event for event in f.events if event[0] == "launch"]
    assert_handles_closed(api)
