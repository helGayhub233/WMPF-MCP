"""User-configurable settings (client env → defaults).

All keys are optional overrides in the MCP client config (``mcp.json`` →
``env``). The standard template ``mcp.json.example`` lists:

- ``WMPF_MCP_WECHAT_APP`` — WeChat application path
  (darwin default: ``/Applications/WeChat.app``).
- ``WMPF_MCP_CDP_PORT`` — engine CDP proxy port (default 10000).
- ``WMPF_MCP_PORTAL_PORT`` — browser-level CDP portal port (default 20000).

Advanced directory overrides remain supported; see the README configuration table:

- ``WMPF_MCP_RADIUM_DIR`` — independent package-cache directory.
- ``WMPF_MCP_HOME`` / ``WMPF_MCP_WORKSPACE`` — parameters/backups and source exports.

The 9421 miniapp debug port is fixed by the WeChat runtime and is not
configurable. All path settings expand ~, $VAR and ${VAR} without a shell.
Unresolved references are errors. ``check_environment()`` reports resolved roots.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from .path_config import env_path

DEFAULT_CDP_PORT: Final = 10000
DEFAULT_PORTAL_PORT: Final = 20000
DEBUG_PORT: Final = 9421  # fixed by the WeChat runtime; cannot be configured


def _wechat_app_default() -> Path:
    if sys.platform == "darwin":
        return Path("/Applications/WeChat.app")
    if sys.platform == "win32":
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        candidates = [program_files / "Tencent" / name for name in ("Weixin", "WeChat")]
        return next((path for path in candidates if path.is_dir()), candidates[0])
    return Path.home() / ".xwechat"


def _radium_dir_default() -> Path:
    home = Path.home()
    if sys.platform == "darwin":
        return (
            home
            / "Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/radium"
        )
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA", str(home / "AppData" / "Roaming")))
        return appdata / "Tencent" / "xwechat" / "radium"
    return home / ".xwechat" / "radium"


@dataclass(frozen=True)
class WeChatPaths:
    """Resolved paths plus provenance for reporting."""

    wechat_app: Path
    radium_dir: Path
    sources: dict[str, str] = field(default_factory=dict)  # key -> env|default
    warnings: list[str] = field(default_factory=list)

    # -- darwin-derived paths -------------------------------------------------
    @property
    def appex_app(self) -> Path:
        return self.wechat_app / "Contents" / "MacOS" / "WeChatAppEx.app"

    @property
    def appex_bin(self) -> Path:
        return self.appex_app / "Contents" / "MacOS" / "WeChatAppEx"

    @property
    def appex_info_plist(self) -> Path:
        return self.appex_app / "Contents" / "Info.plist"

    @property
    def framework(self) -> Path:
        return self.appex_app / "Contents/Frameworks/WeChatAppEx Framework.framework"

    @property
    def main_module(self) -> Path | None:
        from ..platform.framework import discover_module
        return discover_module(self.framework, self.appex_app)

    # -- win32-derived paths --------------------------------------------------
    @property
    def radium_wmpf_dir(self) -> Path:
        """Windows runtime plugin directory (sibling of ``radium``)."""
        return self.radium_dir.parent / "xplugin" / "Plugins" / "RadiumWMPF"

    def report(self) -> dict:
        return {
            "wechat_app": str(self.wechat_app),
            "radium_dir": str(self.radium_dir),
            "sources": dict(self.sources),
        }


def env_port(name: str, default: int) -> int:
    """Read a TCP port from the environment; invalid values fall back."""
    raw = os.environ.get(name)
    if raw:
        try:
            value = int(raw)
            if 1 <= value <= 65535:
                return value
        except ValueError:
            pass
    return default


def resolve_cdp_port() -> int:
    """Configured engine CDP proxy port (WMPF_MCP_CDP_PORT, default 10000)."""
    return env_port("WMPF_MCP_CDP_PORT", DEFAULT_CDP_PORT)


def resolve_portal_port() -> int:
    """Configured portal port (WMPF_MCP_PORTAL_PORT, default 20000)."""
    return env_port("WMPF_MCP_PORTAL_PORT", DEFAULT_PORTAL_PORT)


def resolve_wechat_paths() -> WeChatPaths:
    """Resolve configured or default WeChat paths for the current platform."""
    sources: dict[str, str] = {}
    warnings: list[str] = []

    wechat_app = env_path("WMPF_MCP_WECHAT_APP", _wechat_app_default())
    if "WMPF_MCP_WECHAT_APP" in os.environ:
        sources["WECHAT_APP"] = "env"
        if not wechat_app.exists():
            warnings.append(
                f"WMPF_MCP_WECHAT_APP points to a missing path: {wechat_app} "
                "(fix the MCP client env config or remove the key to use defaults)"
            )
    else:
        sources["WECHAT_APP"] = "default"

    radium_dir = env_path("WMPF_MCP_RADIUM_DIR", _radium_dir_default())
    if "WMPF_MCP_RADIUM_DIR" in os.environ:
        sources["RADIUM_DIR"] = "env"
        if not radium_dir.exists():
            warnings.append(
                f"WMPF_MCP_RADIUM_DIR points to a missing path: {radium_dir} "
                "(cached packages will not be discoverable)"
            )
    else:
        sources["RADIUM_DIR"] = "default"

    return WeChatPaths(
        wechat_app=wechat_app,
        radium_dir=radium_dir,
        sources=sources,
        warnings=warnings,
    )
