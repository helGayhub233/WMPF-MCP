"""Windows discovery from actual executable and loaded-module paths.

The configured application root and the RadiumWMPF plugin root are independent.
A running process selects its loaded flue.dll; offline discovery only accepts a
single real module, rather than guessing that the newest cached version runs.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from ..core.config import WeChatPaths, resolve_wechat_paths
from ..offsets.inspection import BinaryView
from .base import RuntimeInfo


_PROCESS_QUERY = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$rows = @(foreach ($item in @(Get-Process -Name WeChatAppEx,Weixin,WeChat -ErrorAction SilentlyContinue)) {
    $image = $null
    try { $image = $item.Path } catch {}
    $modules = @()
    $moduleError = $null
    if ($item.ProcessName -ieq 'WeChatAppEx') {
        try {
            $modules = @($item.Modules | Where-Object { $_.ModuleName -ieq 'flue.dll' } |
                         ForEach-Object { $_.FileName })
        } catch { $moduleError = $_.Exception.Message }
    }
    [pscustomobject]@{pid=$item.Id; name=$item.ProcessName; path=$image;
                      modules=$modules; module_error=$moduleError}
})
ConvertTo-Json -InputObject @($rows) -Compress -Depth 4
"""


def _process_snapshot() -> list[dict]:
    """Read paths/modules without the CIM service or an elevation requirement."""
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    system_dir = "Sysnative" if os.environ.get("PROCESSOR_ARCHITEW6432") else "System32"
    powershell = system_root / system_dir / "WindowsPowerShell/v1.0/powershell.exe"
    try:
        result = subprocess.run(
            [str(powershell), "-NoProfile", "-NonInteractive", "-Command", _PROCESS_QUERY],
            capture_output=True, text=True, encoding="utf-8", timeout=10.0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"Windows process paths could not be inspected: {error}") from error
    if result.returncode or (result.stderr or "").strip():
        raise ValueError(f"Windows process inspection failed (exit {result.returncode}): {result.stderr.strip()}")
    try:
        rows = json.loads(result.stdout.lstrip("\ufeff"))
    except ValueError as error:
        raise ValueError("Windows process inspection returned invalid JSON") from error
    if not isinstance(rows, list) or any(
        not isinstance(row, dict) or type(row.get("pid")) is not int or row["pid"] <= 0
        or not isinstance(row.get("name"), str)
        or (row.get("path") is not None and not isinstance(row["path"], str))
        or not isinstance(row.get("modules"), list)
        or not all(isinstance(path, str) for path in row["modules"])
        or (row.get("module_error") is not None and not isinstance(row["module_error"], str))
        for row in rows
    ):
        raise ValueError("Windows process inspection returned an invalid process list")
    return rows


def _is_elevated() -> bool | None:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None


def _hook_process_snapshot() -> dict[int, dict]:
    """Read command-line metadata without attaching to any process."""
    import frida

    return {process.pid: process.parameters
            for process in frida.get_local_device().enumerate_processes(scope="metadata")}


def _process_type(argv: list[str]) -> str | None:
    """Chromium's browser process has no --type; its children do."""
    types = []
    for argument in argv[1:]:
        if argument == "--":
            break
        switch = argument.lower()
        prefix = next((prefix for prefix in ("--", "-", "/") if switch.startswith(prefix)), None)
        switch = switch[len(prefix):] if prefix else ""
        if switch == "type":
            types.append("")
        elif switch.startswith("type="):
            types.append(argument.partition("=")[2])
    if len(types) > 1 or (types and (not types[0] or types[0].startswith("-"))):
        raise ValueError("Ambiguous or empty Chromium --type switch")
    return types[0] if types else None


class Win32Adapter:
    platform = "win32"

    def __init__(self, paths: WeChatPaths | None = None) -> None:
        self._paths_override = paths

    @property
    def paths(self) -> WeChatPaths:
        """Resolve lazily so client-env configuration applies at call time."""
        return self._paths_override or resolve_wechat_paths()

    def _app_root(self) -> Path:
        app = self.paths.wechat_app
        return (app.parent if app.is_file() and app.suffix.lower() == ".exe" else app).resolve()

    def _in_scope(self, path: Path) -> bool:
        resolved = path.resolve()
        return any(resolved.is_relative_to(root) for root in
                   (self._app_root(), self.paths.radium_wmpf_dir.resolve()))

    def _runtime_processes(self, rows: list[dict]) -> list[dict]:
        selected = []
        for row in rows:
            if row["name"].casefold() != "wechatappex":
                continue
            if not row.get("path"):
                raise ValueError(f"Cannot determine executable scope for WeChatAppEx PID {row['pid']}")
            executable = Path(row["path"])
            if (executable.name.casefold() == "wechatappex.exe" and executable.is_file()
                    and self._in_scope(executable)):
                selected.append(row)
        return selected

    def running_pids(self) -> list[int]:
        return sorted({row["pid"] for row in self._runtime_processes(_process_snapshot())})

    def hook_pids(self) -> list[int]:
        """Select all scoped WMPF browsers, not renderer/GPU/utility children.

        OnLoadStart and SendToClientFilter belong to the browser process. Keep
        all runtime PIDs in discovery and maintenance; only hook preparation
        uses this role-specific scope. Missing metadata is an error, never a
        reason to silently omit a potentially required browser.
        """
        rows = self._runtime_processes(_process_snapshot())
        metadata = _hook_process_snapshot()
        selected = []
        excluded = []
        for row in rows:
            pid = row["pid"]
            detail = metadata.get(pid, {})
            path, argv = detail.get("path"), detail.get("argv")
            if (not isinstance(path, str) or Path(path).resolve() != Path(row["path"]).resolve()
                    or not isinstance(argv, list) or not argv
                    or not all(isinstance(argument, str) for argument in argv)
                    or Path(argv[0]).resolve() != Path(path).resolve()):
                raise ValueError(f"Cannot verify Windows hook process role for PID {pid}")
            role = _process_type(argv)
            if role is not None:
                if role not in {"renderer", "gpu-process", "utility"}:
                    raise ValueError(f"Unsupported Windows runtime process role for PID {pid}: {role}")
                excluded.append({"pid": pid, "role": role})
                continue
            parent = detail.get("ppid")
            parent_path = metadata.get(parent, {}).get("path") if type(parent) is int else None
            if (not isinstance(parent_path, str)
                    or Path(parent_path).name.casefold() not in {"weixin.exe", "wechat.exe"}
                    or not Path(parent_path).is_file()
                    or not Path(parent_path).resolve().is_relative_to(self._app_root())):
                raise ValueError(f"Cannot verify the configured WeChat parent of browser PID {pid}")
            selected.append(pid)
        self.hook_scope = {"role": "browser", "selected_pids": sorted(set(selected)),
                           "excluded": sorted(excluded, key=lambda item: item["pid"])}
        return sorted(set(selected))

    def _discover(self) -> tuple[Path | None, list[int]]:
        rows = self._runtime_processes(_process_snapshot())
        pids = sorted({row["pid"] for row in rows})
        candidates: set[Path] = set()
        if rows:
            for row in rows:
                if row.get("module_error"):
                    raise ValueError(f"Cannot inspect loaded flue.dll for PID {row['pid']}: {row['module_error']}")
                if not row["modules"]:
                    raise ValueError(f"WeChatAppEx PID {row['pid']} has no observable loaded flue.dll; do not select a cached module")
                for raw in row["modules"]:
                    module = Path(raw).resolve()
                    if (module.name.casefold() != "flue.dll" or not module.is_file()
                            or not self._in_scope(module)):
                        raise ValueError(f"Loaded runtime module is missing or outside configured roots: {module}")
                    candidates.add(module)
        else:
            plugin = self.paths.radium_wmpf_dir
            sources = list(plugin.glob("*/extracted/runtime/flue.dll")) if plugin.is_dir() else []
            app = self._app_root()
            if app.is_dir():
                sources.extend(app.rglob("flue.dll"))
            for module in sources:
                resolved = module.resolve()
                if not self._in_scope(resolved):
                    raise ValueError(f"Runtime module escapes configured roots: {module}")
                if resolved.is_file():
                    candidates.add(resolved)
        if len(candidates) > 1:
            raise ValueError("Ambiguous Windows runtime modules; start the configured WeChat or pass an explicit analysis binary: "
                             + ", ".join(str(path) for path in sorted(candidates)))
        return next(iter(candidates), None), pids

    def main_module_path(self) -> str | None:
        """The actual loaded DLL, or the unique offline module."""
        module, _ = self._discover()
        return str(module) if module is not None else None

    def locate(self) -> RuntimeInfo:
        module, pids = self._discover()
        version = None
        arch = "unknown"
        if module is not None:
            with BinaryView(module) as binary:
                if binary.format != "PE":
                    raise ValueError(f"Windows runtime module is not PE: {module}")
                arch = binary.arch
            try:
                label = module.relative_to(self.paths.radium_wmpf_dir.resolve()).parts[0]
                version = int(label) if label.isdigit() else None
            except ValueError:
                pass
        app = self._app_root()
        return RuntimeInfo(
            platform=self.platform, arch=arch,
            app_path=str(app) if app.is_dir() else None,
            runtime_path=str(module) if module is not None else None,
            version=version, version_raw=str(version) if version is not None else None,
            running_pids=pids,
        )

    def signature_state(self) -> dict:
        """Elevation is a clue; only an actual attach establishes permission."""
        return {"sip": "n/a", "euid": None, "elevated": _is_elevated(),
                "inject_mode": "unknown",
                "note": "Administrator status is not an attach requirement or proof; verify access to the selected process."}
