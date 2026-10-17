"""Controlled Windows filesystem/env checks; user package caches are never changed."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from wmpf_mcp.core import paths
from wmpf_mcp.core.config import resolve_wechat_paths
from wmpf_mcp.core.path_config import PathConfigError, resolve_path
from wmpf_mcp.static_chain.locator import candidate_roots, list_applets


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Native Windows path/env validation")


def _configured_roots(monkeypatch, tmp_path):
    root = tmp_path / "中文 roots with spaces"
    root.mkdir()
    monkeypatch.setenv("WMPF_NATIVE_TEST_BASE", str(root))
    monkeypatch.setenv("WMPF_NATIVE_TEST_NESTED", "${WMPF_NATIVE_TEST_BASE}/nested")
    values = {"WECHAT_APP": "微信 install", "RADIUM_DIR": "缓存 radium",
              "HOME": "state home", "WORKSPACE": "source exports"}
    for key, child in values.items():
        monkeypatch.setenv("WMPF_MCP_" + key, "$WMPF_NATIVE_TEST_NESTED/" + child)
    return root / "nested", values


def test_windows_drive_unicode_spaces_and_cache_override(monkeypatch, tmp_path):
    root, values = _configured_roots(monkeypatch, tmp_path)
    cache = root / values["RADIUM_DIR"]
    package = cache / "Applet/packages/wx0000000000000001/12/__APP__.wxapkg"
    user_package = cache / "users/test-user/applet/packages/wx0000000000000002/3/__APP__.wxapkg"
    for target in (package, user_package):
        target.parent.mkdir(parents=True)
        target.write_bytes(b"controlled package locator input")
    settings = resolve_wechat_paths()
    assert settings.wechat_app == root / values["WECHAT_APP"]
    assert settings.radium_dir == cache
    assert settings.radium_dir.drive == tmp_path.drive
    assert settings.sources == {"WECHAT_APP": "env", "RADIUM_DIR": "env"}
    assert set(candidate_roots()) == {cache / "Applet/packages", cache / "users/test-user/applet/packages"}
    applets = list_applets()
    assert {Path(pkg.path) for app in applets for pkg in app.packages} == {package, user_package}
    paths.ensure_dirs()
    assert paths.home_dir() == root / values["HOME"]
    assert paths.backup_dir().is_dir()
    assert paths.workspace() == root / values["WORKSPACE"]
    assert not paths.workspace().exists()
    assert not settings.wechat_app.exists()


def test_windows_child_process_inherits_all_four_configured_roots(monkeypatch, tmp_path):
    root, values = _configured_roots(monkeypatch, tmp_path)
    program = (
        "import json; from wmpf_mcp.core.config import resolve_wechat_paths; "
        "from wmpf_mcp.core.paths import report; "
        "print(json.dumps({**resolve_wechat_paths().report(), **report()}))"
    )
    result = subprocess.run([sys.executable, "-B", "-c", program], capture_output=True,
                            text=True, encoding="utf-8", timeout=10, env=os.environ.copy())
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    for field, key in {"wechat_app": "WECHAT_APP", "radium_dir": "RADIUM_DIR",
                       "home": "HOME", "workspace": "WORKSPACE"}.items():
        assert Path(report[field]) == root / values[key]
    assert not root.exists()


@pytest.mark.parametrize("variable", ["WECHAT_APP", "RADIUM_DIR", "HOME", "WORKSPACE"])
def test_windows_tilde_keeps_home_anchor_without_creating_paths(monkeypatch, variable):
    monkeypatch.setenv("WMPF_MCP_" + variable, "~/中文 path not created")
    resolved = {**resolve_wechat_paths().report(), **paths.report()}
    field = {"WECHAT_APP": "wechat_app", "RADIUM_DIR": "radium_dir",
             "HOME": "home", "WORKSPACE": "workspace"}[variable]
    assert Path(resolved[field]) == Path.home() / "中文 path not created"


@pytest.mark.parametrize("value", ["$WMPF_NATIVE_TEST_MISSING/path", "${WMPF_NATIVE_TEST_EMPTY}/path",
                                    "${broken", "$(unexpected)", "`unexpected`"])
def test_windows_invalid_reference_prevents_storage_creation(monkeypatch, tmp_path, value):
    monkeypatch.delenv("WMPF_NATIVE_TEST_MISSING", raising=False)
    monkeypatch.setenv("WMPF_NATIVE_TEST_EMPTY", "")
    home = tmp_path / "must not be created"
    monkeypatch.setenv("WMPF_MCP_HOME", str(home))
    monkeypatch.setenv("WMPF_MCP_WORKSPACE", value)
    with pytest.raises(PathConfigError):
        paths.ensure_dirs()
    assert not home.exists()


def test_windows_cyclic_variables_fail_before_writes(monkeypatch, tmp_path):
    monkeypatch.setenv("WMPF_NATIVE_TEST_CYCLE_A", "$WMPF_NATIVE_TEST_CYCLE_B")
    monkeypatch.setenv("WMPF_NATIVE_TEST_CYCLE_B", "${WMPF_NATIVE_TEST_CYCLE_A}")
    monkeypatch.setenv("WMPF_MCP_HOME", str(tmp_path / "cycle must not create"))
    monkeypatch.setenv("WMPF_MCP_WORKSPACE", "$WMPF_NATIVE_TEST_CYCLE_A")
    with pytest.raises(PathConfigError, match="cyclic"):
        paths.ensure_dirs()
    assert not paths.home_dir().exists()


def test_windows_relative_path_anchors_to_actual_process_cwd(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert resolve_path(r"relative\..\中文 space") == tmp_path / "中文 space"
