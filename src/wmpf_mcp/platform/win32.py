"""Windows adapter.

Runtime plugin root resolves from ``core.config``: the ``RadiumWMPF`` directory
is the sibling of the configured/default radium data root
(``<xwechat>/xplugin/Plugins/RadiumWMPF``); the runtime version is the plugin
directory name.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ..core.config import WeChatPaths, resolve_wechat_paths
from .base import RuntimeInfo, detect_arch


class Win32Adapter:
    platform = "win32"

    def __init__(self, paths: WeChatPaths | None = None) -> None:
        self._paths_override = paths

    @property
    def paths(self) -> WeChatPaths:
        """Resolve lazily so client-env configuration applies at call time."""
        return self._paths_override or resolve_wechat_paths()

    def running_pids(self) -> list[int]:
        try:
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq WeChatAppEx.exe", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=10.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        pids: list[int] = []
        for line in result.stdout.splitlines():
            match = re.search(r'"[^"]+","(\d+)"', line)
            if match:
                pids.append(int(match.group(1)))
        return pids

    def _latest_version_dir(self) -> tuple[int | None, Path | None]:
        root = self.paths.radium_wmpf_dir
        if not root.is_dir():
            return None, None
        candidates: list[tuple[int, Path]] = []
        for entry in root.iterdir():
            if entry.is_dir() and entry.name.isdigit():
                candidates.append((int(entry.name), entry))
        if not candidates:
            return None, None
        version, path = max(candidates, key=lambda item: item[0])
        return version, path

    def locate(self) -> RuntimeInfo:
        version, version_dir = self._latest_version_dir()
        runtime_path: str | None = None
        if version_dir is not None:
            flue = version_dir / "extracted" / "runtime" / "flue.dll"
            runtime_path = str(flue if flue.exists() else version_dir)
        plugin_root = self.paths.radium_wmpf_dir
        return RuntimeInfo(
            platform=self.platform,
            arch=detect_arch(),
            app_path=str(plugin_root) if plugin_root.exists() else None,
            runtime_path=runtime_path,
            version=version,
            version_raw=str(version) if version is not None else None,
            running_pids=self.running_pids(),
        )

    def signature_state(self) -> dict:
        """Windows injection requires an elevated process; report honestly."""
        try:
            import ctypes

            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            elevated = False
        return {
            "sip": "n/a",
            "euid": None,
            "elevated": elevated,
            "inject_mode": "ok" if elevated else "need_root",
        }
