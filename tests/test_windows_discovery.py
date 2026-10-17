"""Windows discovery uses scoped executable paths and each loaded DLL."""

from __future__ import annotations

import json
import struct
import subprocess
from pathlib import Path

import pytest

from wmpf_mcp.core import config
from wmpf_mcp.core.config import WeChatPaths
from wmpf_mcp.platform import win32


def _pe(path: Path, machine=0x8664):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0, 0, 0, 0xF0, 0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<Q", data, 0x98 + 24, 0x180000000)
    struct.pack_into("<8sIIIIIIHHI", data, 0x188, b".text", 0x200, 0x1000,
                     0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    path.write_bytes(data)
    return path


@pytest.fixture
def installation(tmp_path, monkeypatch):
    app = tmp_path / "Program Files/Tencent/Weixin"
    app.mkdir(parents=True)
    paths = WeChatPaths(app, tmp_path / "AppData/Tencent/xwechat/radium")
    monkeypatch.setattr(win32, "_process_snapshot", lambda: [])
    return win32.Win32Adapter(paths), paths


def _runtime(paths, version="v-current", machine=0x8664):
    folder = paths.radium_wmpf_dir / version / "extracted/runtime"
    module = _pe(folder / "flue.dll", machine)
    executable = folder / "WeChatAppEx.exe"
    executable.write_bytes(b"runtime executable fixture")
    return module, executable


def _row(pid, executable, modules=(), **extra):
    return {"pid": pid, "name": "WeChatAppEx", "path": str(executable),
            "modules": [str(path) for path in modules], "module_error": None, **extra}


def test_windows_install_default_is_separate_from_data_root(tmp_path, monkeypatch):
    monkeypatch.setattr(config.sys, "platform", "win32")
    install = tmp_path / "Program Files/Tencent/Weixin"
    install.mkdir(parents=True)
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "Program Files"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData"))
    assert config._wechat_app_default() == install
    assert config._radium_dir_default() == tmp_path / "AppData/Tencent/xwechat/radium"


def test_processes_must_have_a_real_executable_in_either_root(installation, tmp_path, monkeypatch):
    adapter, paths = installation
    module, plugin_exe = _runtime(paths)
    install_exe = paths.wechat_app / "runtime/WeChatAppEx.exe"
    install_exe.parent.mkdir()
    install_exe.write_bytes(b"application runtime")
    foreign = tmp_path / "foreign/WeChatAppEx.exe"
    foreign.parent.mkdir()
    foreign.write_bytes(b"foreign same name")
    main_exe = paths.wechat_app / "Weixin.exe"
    main_exe.write_bytes(b"main application")
    rows = [_row(4, plugin_exe, [module]), _row(2, install_exe, [module]),
            _row(3, foreign, [module]), _row(8, main_exe, [module]),
            _row(9, plugin_exe, [module], name="Weixin")]
    monkeypatch.setattr(win32, "_process_snapshot", lambda: rows)
    assert adapter.running_pids() == [2, 4]


def test_live_loaded_module_wins_over_newer_cache(installation, monkeypatch):
    adapter, paths = installation
    loaded, executable = _runtime(paths, "100")
    _runtime(paths, "999999")
    monkeypatch.setattr(win32, "_process_snapshot", lambda: [_row(123, executable, [loaded])])
    assert adapter.main_module_path() == str(loaded.resolve())
    located = adapter.locate()
    assert located.runtime_path == str(loaded.resolve())
    assert located.version == 100
    assert located.running_pids == [123]


@pytest.mark.parametrize("machine,arch", [(0x8664, "x86_64"), (0xAA64, "arm64"), (0x14C, "x86_32")])
def test_target_isa_is_read_from_pe_not_host(installation, machine, arch, monkeypatch):
    adapter, paths = installation
    module, _ = _runtime(paths, machine=machine)
    monkeypatch.setattr("platform.machine", lambda: "irrelevant-host-isa")
    assert adapter.locate().arch == arch
    assert adapter.main_module_path() == str(module.resolve())


def test_no_dll_is_not_a_directory_result(installation):
    adapter, paths = installation
    (paths.radium_wmpf_dir / "100/extracted/runtime").mkdir(parents=True)
    assert adapter.main_module_path() is None
    assert adapter.locate().runtime_path is None
    assert adapter.locate().arch == "unknown"


def test_multiple_offline_dlls_are_ambiguous(installation):
    adapter, paths = installation
    _runtime(paths, "100")
    _runtime(paths, "200")
    with pytest.raises(ValueError, match="Ambiguous Windows runtime modules"):
        adapter.main_module_path()


def test_multiple_actual_loaded_dlls_are_ambiguous(installation, monkeypatch):
    adapter, paths = installation
    one, exe_one = _runtime(paths, "100")
    two, exe_two = _runtime(paths, "200")
    monkeypatch.setattr(win32, "_process_snapshot", lambda: [_row(1, exe_one, [one]), _row(2, exe_two, [two])])
    with pytest.raises(ValueError, match="Ambiguous Windows runtime modules"):
        adapter.main_module_path()


@pytest.mark.parametrize("observation,message", [
    ({"modules": []}, "no observable loaded"),
    ({"module_error": "Access denied"}, "Cannot inspect loaded"),
])
def test_unobserved_live_module_never_falls_back_to_cache(installation, observation, message, monkeypatch):
    adapter, paths = installation
    module, executable = _runtime(paths)
    row = _row(1, executable, [module])
    row.update(observation)
    monkeypatch.setattr(win32, "_process_snapshot", lambda: [row])
    with pytest.raises(ValueError, match=message):
        adapter.main_module_path()


def test_every_live_pid_needs_its_own_module_observation(installation, monkeypatch):
    adapter, paths = installation
    module, executable = _runtime(paths)
    monkeypatch.setattr(win32, "_process_snapshot", lambda: [_row(1, executable, [module]), _row(2, executable)])
    with pytest.raises(ValueError, match="PID 2 has no observable"):
        adapter.main_module_path()


def test_loaded_module_cannot_escape_the_two_configured_roots(installation, tmp_path, monkeypatch):
    adapter, paths = installation
    _, executable = _runtime(paths)
    foreign = _pe(tmp_path / "foreign/flue.dll")
    monkeypatch.setattr(win32, "_process_snapshot", lambda: [_row(1, executable, [foreign])])
    with pytest.raises(ValueError, match="outside configured roots"):
        adapter.main_module_path()


def test_unknown_helper_image_is_explicitly_unknown_not_absent(installation, monkeypatch):
    adapter, _ = installation
    monkeypatch.setattr(win32, "_process_snapshot", lambda: [_row(3, None, path=None)])
    with pytest.raises(ValueError, match="Cannot determine executable scope"):
        adapter.running_pids()


def test_main_executable_override_selects_parent_install_root(installation):
    _, paths = installation
    executable = paths.wechat_app / "Weixin.exe"
    executable.write_bytes(b"main")
    adapter = win32.Win32Adapter(WeChatPaths(executable, paths.radium_dir))
    assert adapter._app_root() == executable.parent.resolve()


def test_unprivileged_discovery_does_not_assume_attach_denied(installation, monkeypatch):
    adapter, _ = installation
    monkeypatch.setattr(win32, "_is_elevated", lambda: False)
    assert adapter.signature_state()["inject_mode"] == "unknown"
    assert adapter.signature_state()["elevated"] is False


def _hook_rows(installation, monkeypatch):
    adapter, paths = installation
    module, executable = _runtime(paths)
    parent = paths.wechat_app / "Weixin.exe"
    parent.write_bytes(b"main application")
    rows = [_row(pid, executable, [module]) for pid in (10, 11, 12, 13)]
    metadata = {1: {"path": str(parent)}}
    for row, role in zip(rows, (None, "renderer", "gpu-process", "utility")):
        metadata[row["pid"]] = {"path": str(executable), "ppid": 1 if role is None else 10,
                                "argv": [str(executable)] + ([f"--type={role}"] if role else [])}
    monkeypatch.setattr(win32, "_process_snapshot", lambda: rows)
    monkeypatch.setattr(win32, "_hook_process_snapshot", lambda: metadata)
    return adapter, rows, metadata


def test_hooks_select_browser_while_discovery_keeps_every_runtime(installation, monkeypatch):
    adapter, _, _ = _hook_rows(installation, monkeypatch)
    assert adapter.running_pids() == [10, 11, 12, 13]
    assert adapter.hook_pids() == [10]
    assert adapter.hook_scope == {"role": "browser", "selected_pids": [10], "excluded": [
        {"pid": 11, "role": "renderer"}, {"pid": 12, "role": "gpu-process"},
        {"pid": 13, "role": "utility"}]}


def test_hooks_include_all_browser_roots_instead_of_a_majority_parent(installation, monkeypatch):
    adapter, _, metadata = _hook_rows(installation, monkeypatch)
    metadata[13]["argv"] = [metadata[13]["path"]]
    metadata[13]["ppid"] = 1
    assert adapter.hook_pids() == [10, 13]


def test_unknown_child_role_is_reported_instead_of_silently_excluded(installation, monkeypatch):
    adapter, _, metadata = _hook_rows(installation, monkeypatch)
    metadata[11]["argv"][1] = "--type=unrecognized"
    with pytest.raises(ValueError, match="Unsupported Windows runtime process role"):
        adapter.hook_pids()


@pytest.mark.parametrize("mutation", ["missing", "empty_argv", "path", "argv_path"])
def test_unverifiable_process_metadata_blocks_hooks(installation, monkeypatch, mutation):
    adapter, _, metadata = _hook_rows(installation, monkeypatch)
    if mutation == "missing":
        del metadata[11]
    elif mutation == "empty_argv":
        metadata[11]["argv"] = []
    elif mutation == "path":
        metadata[11]["path"] = str(Path(metadata[11]["path"]).with_name("other.exe"))
    else:
        metadata[11]["argv"][0] = "other.exe"
    with pytest.raises(ValueError, match="Cannot verify Windows hook process role"):
        adapter.hook_pids()


@pytest.mark.parametrize("mutation", ["missing", "foreign", "wrong_image"])
def test_browser_parent_must_be_real_configured_wechat(installation, monkeypatch, tmp_path, mutation):
    adapter, _, metadata = _hook_rows(installation, monkeypatch)
    if mutation == "missing":
        del metadata[1]
    else:
        image = tmp_path / "foreign/Weixin.exe" if mutation == "foreign" else adapter.paths.wechat_app / "unrelated.exe"
        image.parent.mkdir(parents=True, exist_ok=True)
        image.write_bytes(b"other application")
        metadata[1]["path"] = str(image)
    with pytest.raises(ValueError, match="configured WeChat parent"):
        adapter.hook_pids()


@pytest.mark.parametrize("switch", ["--type=renderer", "-type=renderer", "/type=renderer", "/TYPE=renderer"])
def test_windows_chromium_switch_forms_are_never_mistaken_for_browser(switch):
    assert win32._process_type(["WeChatAppEx.exe", switch]) == "renderer"


@pytest.mark.parametrize("arguments", [["--type="], ["--type"], ["--type", "renderer"],
                                      ["--type=renderer", "/TYPE=utility"]])
def test_empty_or_conflicting_roles_do_not_select_browser(arguments):
    with pytest.raises(ValueError, match="Ambiguous or empty"):
        win32._process_type(["WeChatAppEx.exe", *arguments])


def test_snapshot_uses_absolute_get_process_without_cim_or_shell(monkeypatch, tmp_path):
    called = {}
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    monkeypatch.delenv("PROCESSOR_ARCHITEW6432", raising=False)
    def run(command, **options):
        called.update(command=command, options=options)
        return subprocess.CompletedProcess(command, 0, stdout="[]", stderr="")
    monkeypatch.setattr(win32.subprocess, "run", run)
    assert win32._process_snapshot() == []
    assert Path(called["command"][0]).is_absolute()
    assert "Get-Process" in called["command"][-1]
    assert "Get-CimInstance" not in called["command"][-1]
    assert not called["options"].get("shell")
    assert called["options"]["timeout"] == 10.0


@pytest.mark.parametrize("stdout", ["not-json", "{}", json.dumps([{"pid": 1, "name": "WeChatAppEx"}])])
def test_snapshot_invalid_output_does_not_claim_no_processes(monkeypatch, stdout):
    monkeypatch.setattr(win32.subprocess, "run", lambda *args, **kwargs:
        subprocess.CompletedProcess(args[0], 0, stdout=stdout, stderr=""))
    with pytest.raises(ValueError, match="invalid"):
        win32._process_snapshot()
