"""Path configuration, installed framework selection and honest diagnostics."""
from __future__ import annotations

from pathlib import Path
import json
import os
import plistlib
import subprocess
import sys
from types import SimpleNamespace

import pytest

from wmpf_mcp.core import paths, syscheck
from wmpf_mcp.core.config import WeChatPaths, resolve_wechat_paths
from wmpf_mcp.core.path_config import PathConfigError, resolve_path
from wmpf_mcp.platform.darwin import DarwinAdapter
from wmpf_mcp.server import build_server
from wmpf_mcp.tools.environment import collect_environment


def test_all_roots_share_expansion_and_only_resolved_storage_is_created(monkeypatch, tmp_path):
    root = tmp_path / "自定义 install with spaces"
    root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    monkeypatch.setenv("WMPF_TEST_ROOT", str(alias))
    monkeypatch.setenv("WMPF_TEST_NESTED", "${WMPF_TEST_ROOT}/nested")
    for key, suffix in {"WECHAT_APP": "微信.app", "RADIUM_DIR": "cache", "HOME": "state", "WORKSPACE": "source"}.items():
        monkeypatch.setenv("WMPF_MCP_" + key, "$WMPF_TEST_NESTED/" + suffix)
    configured = resolve_wechat_paths()
    assert configured.wechat_app == root / "nested/微信.app"
    assert configured.radium_dir == root / "nested/cache"
    assert configured.sources == {"WECHAT_APP": "env", "RADIUM_DIR": "env"}
    assert len(configured.warnings) == 2
    assert paths.home_dir() == root / "nested/state"
    assert paths.workspace() == root / "nested/source"
    paths.ensure_dirs()
    assert paths.backup_dir().is_dir()
    assert not paths.workspace().exists()  # No export before a source operation.
    assert set(root.rglob("*")) == {root / "nested", paths.home_dir(),
        paths.home_dir() / "offsets", paths.backup_dir(), paths.home_dir() / "logs"}


@pytest.mark.parametrize("key", ["WECHAT_APP", "RADIUM_DIR", "HOME", "WORKSPACE"])
def test_tilde_uses_same_parser_for_each_root(monkeypatch, key):
    monkeypatch.setenv("WMPF_MCP_" + key, "~/wmpf-test-未创建")
    result = {**resolve_wechat_paths().report(), **paths.report()}
    field = {"WECHAT_APP": "wechat_app", "RADIUM_DIR": "radium_dir", "HOME": "home", "WORKSPACE": "workspace"}[key]
    assert Path(result[field]) == (Path.home() / "wmpf-test-未创建").resolve()


@pytest.mark.parametrize("raw", ["$WMPF_TEST_UNSET/path", "${WMPF_TEST_UNSET}/path", "", "${broken", "$(touch ignored)", "`ignored`", "bad\0path"])
def test_invalid_configuration_fails_before_directory_creation(monkeypatch, tmp_path, raw):
    monkeypatch.delenv("WMPF_TEST_UNSET", raising=False)
    root = tmp_path / "not-created"
    monkeypatch.setenv("WMPF_MCP_HOME", str(root))
    # Environment values cannot contain NUL, but explicit tool paths can.
    if "\0" in raw:
        with pytest.raises(PathConfigError):
            resolve_path(raw)
    else:
        monkeypatch.setenv("WMPF_MCP_WORKSPACE", raw)
        with pytest.raises(PathConfigError, match="WMPF_MCP_WORKSPACE"):
            paths.ensure_dirs()
    assert not root.exists()


def test_cycles_and_relative_paths(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert resolve_path("relative/../中文 space") == tmp_path / "中文 space"
    monkeypatch.setenv("WMPF_TEST_A", "$WMPF_TEST_B")
    monkeypatch.setenv("WMPF_TEST_B", "${WMPF_TEST_A}")
    with pytest.raises(PathConfigError, match="cyclic"):
        resolve_path("$WMPF_TEST_A")


def test_startup_reports_invalid_config_on_stderr_without_creating_storage(monkeypatch, tmp_path):
    root = tmp_path / "must-not-be-created"
    monkeypatch.setenv("WMPF_MCP_HOME", str(root))
    monkeypatch.setenv("WMPF_MCP_WORKSPACE", "$WMPF_TEST_MISSING/path")
    monkeypatch.delenv("WMPF_TEST_MISSING", raising=False)
    result = subprocess.run([sys.executable, "-B", "-m", "wmpf_mcp.bootstrap"],
                            capture_output=True, text=True, timeout=15, env=os.environ.copy())
    assert result.returncode == 1 and not result.stdout
    assert "WMPF_MCP_WORKSPACE" in json.loads(result.stderr)["startup_error"]
    assert not root.exists()


@pytest.mark.anyio
async def test_invalid_config_is_reported_and_no_startup_or_maintenance_runs(monkeypatch, tmp_path):
    from wmpf_mcp.tools import runtime
    from wmpf_mcp.platform import maintenance
    monkeypatch.delenv("WMPF_TEST_UNSET", raising=False)
    monkeypatch.setenv("WMPF_MCP_HOME", "$WMPF_TEST_UNSET/state")
    def unexpected(*args, **kwargs):
        pytest.fail("Invalid configuration reached a process/listener side effect")
    monkeypatch.setattr(runtime._engine, "execute", unexpected)
    monkeypatch.setattr(maintenance, "application_processes", unexpected)
    server = build_server()
    report = (await server.call_tool("check_environment", {})).structured_content
    assert report["ok"] and report["data"]["environment_ready"] is False
    assert report["data"]["blockers"][0]["check"] == "path_configuration"
    assert not report["next_actions"]
    started = (await server.call_tool("start_runtime", {"component": "engine"})).structured_content
    assert not started["ok"] and started["error"]["code"] == "E_PARAM"
    worker = maintenance.Maintenance(DarwinAdapter(WeChatPaths(tmp_path / "WeChat.app", tmp_path / "cache")))
    with pytest.raises(PathConfigError):
        worker.execute("restart", None, False)


@pytest.mark.anyio
async def test_preparation_rejects_invalid_root_before_binary_analysis_or_write(monkeypatch, tmp_path):
    monkeypatch.delenv("WMPF_TEST_UNSET", raising=False)
    monkeypatch.setenv("WMPF_MCP_WECHAT_APP", "$WMPF_TEST_UNSET/WeChat.app")
    destination = tmp_path / "never-written/config.json"
    reply = (await build_server().call_tool("prepare_offsets", {
        "source": "extract", "binary_path": str(tmp_path / "not-analyzed"),
        "output_path": str(destination)})).structured_content
    assert not reply["ok"] and reply["error"]["code"] == "E_PARAM"
    assert "WMPF_MCP_WECHAT_APP" in reply["error"]["message"]
    assert not destination.parent.exists()


@pytest.mark.anyio
async def test_explicit_binary_path_is_expanded_without_requiring_storage(monkeypatch, tmp_path):
    from wmpf_mcp.tools import _offsets
    binary = tmp_path / "离线 module"
    binary.write_bytes(b"fixture")
    monkeypatch.setenv("WMPF_TEST_BINARY", str(binary))
    monkeypatch.setenv("WMPF_MCP_HOME", "$WMPF_TEST_UNSET/state")
    monkeypatch.delenv("WMPF_TEST_UNSET", raising=False)
    def inspect(path, **kwargs):
        assert path == binary and path.is_file()
        return {"format": "Mach-O", "arch": "arm64"}
    monkeypatch.setattr(_offsets, "inspect_binary", inspect)
    reply = (await build_server().call_tool("inspect_binary", {"binary_path": "${WMPF_TEST_BINARY}"})).structured_content
    assert reply["ok"]


def framework(tmp_path):
    resolved = WeChatPaths(tmp_path / "自定义 微信.app", tmp_path / "cache")
    return resolved, resolved.framework


def add_module(directory: Path, name="WeChatAppEx Framework", *, metadata=False):
    directory.mkdir(parents=True, exist_ok=True)
    module = directory / name
    module.write_bytes(b"fixture module")
    if metadata:
        resources = directory / "Resources"
        resources.mkdir()
        with (resources / "Info.plist").open("wb") as stream:
            plistlib.dump({"CFBundleExecutable": name}, stream)
    return module


@pytest.mark.parametrize("version", ["A", "C", "arbitrary-layout"])
def test_single_framework_version_without_whitelist(tmp_path, version):
    resolved, bundle = framework(tmp_path)
    module = add_module(bundle / "Versions" / version)
    assert resolved.main_module == module
    assert DarwinAdapter(resolved).main_module_path() == str(module)


def test_framework_current_and_bundle_metadata_select_actual_executable(tmp_path):
    resolved, bundle = framework(tmp_path)
    add_module(bundle / "Versions/Old")
    module = add_module(bundle / "Versions/Active", "Actual Binary", metadata=True)
    (bundle / "Versions/Current").symlink_to("Active")
    (bundle / "Resources").symlink_to("Versions/Current/Resources")
    (bundle / "Actual Binary").symlink_to("Versions/Current/Actual Binary")
    assert resolved.main_module == module


def test_flat_framework_and_missing_module(tmp_path):
    resolved, bundle = framework(tmp_path)
    assert resolved.main_module is None
    bundle.mkdir(parents=True)
    assert resolved.main_module is None
    module = add_module(bundle, "Flat Binary", metadata=True)
    assert resolved.main_module == module


@pytest.mark.parametrize("broken", ["ambiguous", "broken_current", "broken_binary", "escaped", "conflict"])
def test_framework_invalid_selectors_are_not_guessed(tmp_path, broken):
    resolved, bundle = framework(tmp_path)
    add_module(bundle / "Versions/A")
    second = add_module(bundle / "Versions/B")
    if broken == "broken_current":
        (bundle / "Versions/Current").symlink_to("Missing")
    elif broken == "broken_binary":
        (bundle / "WeChatAppEx Framework").symlink_to("Missing")
    elif broken == "escaped":
        outside = tmp_path / "external"
        outside.mkdir()
        (outside / "WeChatAppEx Framework").write_bytes(b"outside")
        (bundle / "Versions/Current").symlink_to(outside)
    elif broken == "conflict":
        (bundle / "Versions/Current").symlink_to("A")
        (bundle / "WeChatAppEx Framework").symlink_to(second)
    with pytest.raises(ValueError):
        _ = resolved.main_module


def test_signing_helpers_follow_selected_framework_version(tmp_path):
    resolved, bundle = framework(tmp_path)
    module = add_module(bundle / "Versions/Custom")
    main = add_module(resolved.appex_bin.parent, resolved.appex_bin.name)
    helper = module.parent / "Helpers/真实 Helper.app/Contents"
    helper_bin = add_module(helper / "MacOS", "真实 Helper")
    with (helper / "Info.plist").open("wb") as stream:
        plistlib.dump({"CFBundleExecutable": helper_bin.name}, stream)
    assert DarwinAdapter(resolved).signing_targets() == [main, helper_bin]


@pytest.mark.parametrize("returncode,stdout,stderr,expected", [
    (1, "", "", "free"), (0, "p23\nf3\nf4\np11\nf5\np23\nf6\n", "", "busy"),
    (0, "p11\n", "", "unknown"),
    (0, "COMMAND PID", "", "unknown"), (0, "p11\nmalformed\n", "", "unknown"), (0, "", "", "unknown"),
    (2, "", "denied", "unknown"), (1, "", "permission denied", "unknown"),
])
def test_macos_listener_diagnostics_do_not_guess(monkeypatch, returncode, stdout, stderr, expected):
    monkeypatch.setattr(syscheck.sys, "platform", "darwin")
    def run(command, **kwargs):
        assert command[0] == "/usr/sbin/lsof" and "-Fp" in command
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(syscheck.subprocess, "run", run)
    result = syscheck.port_state(10000)
    assert result["state"] == expected
    if expected == "busy":
        assert result["pid"] == 11 and result["pids"] == [11, 23]


@pytest.mark.parametrize("output,returncode,checked,enabled", [
    ("<dictionary> {\n}\n", 0, True, False),
    ("<dictionary> {\n HTTPSEnable : 1\n HTTPSProxy : localhost\n HTTPSPort : 8080\n}\n", 0, True, True),
    ("<dictionary> {\n SOCKSEnable : 1\n}\n", 0, True, True),
    ("<dictionary> {\n ProxyAutoConfigEnable : 1\n}\n", 0, True, True),
    ("<dictionary> {\n HTTPEnable : broken\n}\n", 0, False, None),
    ("invalid", 0, False, None), ("<dictionary> {}", 1, False, None),
    ("<dictionary> { garbage }", 0, False, None),
    ("<dictionary> {\n garbage\n}", 0, False, None),
    ("<dictionary> {\n __SCOPED__ : <dictionary> {\n HTTPEnable : 1\n }\n}\n", 0, True, None),
])
def test_macos_proxy_diagnostics(monkeypatch, output, returncode, checked, enabled):
    monkeypatch.setattr(syscheck.sys, "platform", "darwin")
    monkeypatch.setattr(syscheck.subprocess, "run", lambda *args, **kwargs:
        SimpleNamespace(returncode=returncode, stdout=output, stderr=""))
    result = syscheck.proxy_state()
    assert result["checked"] is checked and result["enabled"] is enabled


@pytest.mark.parametrize("system,expected", [("win32", {"PATH-04", "PATH-05", "PATH-09"}), ("linux", {"PATH-06", "PATH-09"})])
def test_foreign_method_gaps_remain_visible_without_running_native_commands(monkeypatch, system, expected):
    from wmpf_mcp.tools import environment
    monkeypatch.setattr(syscheck.sys, "platform", system)
    monkeypatch.setattr(syscheck.subprocess, "run", lambda *args, **kwargs: pytest.fail("Foreign native diagnostic invoked"))
    assert syscheck.port_state(10000)["state"] == "unknown"
    assert syscheck.proxy_state()["enabled"] is None
    monkeypatch.setattr(environment, "dependency_report", lambda goal:
        {"startup_ready": True, "packages": []})
    report = collect_environment("source", "packages")
    gaps = {gap["id"]: gap for gap in report["implementation_gaps"]}
    assert expected.issubset(gaps)
    assert gaps["PATH-07"]["status"] == gaps["PATH-08"]["status"] == "native_validation_pending"
