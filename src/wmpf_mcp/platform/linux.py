"""Linux adapter.

Runtime: the ``WeChatAppEx`` executable; its path (read via /proc) is used to
derive install location and, when possible, version.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from .base import RuntimeInfo, detect_arch


def _run(cmd: list[str], timeout: float = 5.0) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class LinuxAdapter:
    platform = "linux"

    def running_pids(self) -> list[int]:
        try:
            result = _run(["pgrep", "-f", "WeChatAppEx"])
        except (OSError, subprocess.TimeoutExpired):
            return []
        if result.returncode != 0:
            return []
        return [int(line) for line in result.stdout.splitlines() if line.strip().isdigit()]

    def _exe_path(self, pid: int) -> str | None:
        link = Path(f"/proc/{pid}/exe")
        try:
            return str(link.resolve(strict=True))
        except OSError:
            return None

    @staticmethod
    def _version_from_path(path: str | None) -> tuple[int | None, str | None]:
        if not path:
            return None, None
        numbers = re.findall(r"\d{4,6}", path)
        if not numbers:
            return None, None
        raw = numbers[-1]
        return int(raw), raw

    def locate(self) -> RuntimeInfo:
        pids = self.running_pids()
        exe = self._exe_path(pids[0]) if pids else None
        version, raw = self._version_from_path(exe)
        return RuntimeInfo(
            platform=self.platform,
            arch=detect_arch(),
            app_path=None,
            runtime_path=exe,
            version=version,
            version_raw=raw,
            running_pids=pids,
        )

    def main_module_path(self) -> str | None:
        pids = self.running_pids()
        return self._exe_path(pids[0]) if pids else None

    def signature_state(self) -> dict:
        """Linux injection is governed by ptrace_scope."""
        scope: str | None = None
        try:
            scope = Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip()
        except OSError:
            pass
        if os.geteuid() == 0:
            mode = "ok"
        elif scope == "0":
            mode = "ok"
        elif scope is None:
            mode = "unknown"
        else:
            mode = "restricted"
        return {
            "sip": "n/a",
            "euid": os.geteuid(),
            "ptrace_scope": scope,
            "inject_mode": mode,
            "note": "ptrace_scope alone does not establish attach permission; inspect UID, dumpability, capabilities and security policy.",
        }
