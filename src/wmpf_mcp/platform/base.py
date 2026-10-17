"""Platform adapters: runtime discovery, version identification, permissions."""

from __future__ import annotations

import platform as _platform
import sys
from dataclasses import dataclass, field


@dataclass
class RuntimeInfo:
    """Result of locating the WMPF runtime on this machine."""

    platform: str  # darwin | win32 | linux
    arch: str  # arm64 | x86_64 | ...
    app_path: str | None  # WeChat app root (darwin) or install root
    runtime_path: str | None  # WeChatAppEx.app / flue.dll / executable
    version: int | None  # WMPF version number (e.g. 25800)
    version_raw: str | None  # raw source value (e.g. "7.25800")
    running_pids: list[int] = field(default_factory=list)


def detect_arch() -> str:
    return _platform.machine()


def get_adapter():
    """Return the adapter for the current platform."""
    if sys.platform == "darwin":
        from .darwin import DarwinAdapter

        return DarwinAdapter()
    if sys.platform == "win32":
        from .win32 import Win32Adapter

        return Win32Adapter()
    from .linux import LinuxAdapter

    return LinuxAdapter()
