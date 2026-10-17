"""Filesystem conventions (docs/02-架构设计.md §5)."""

from __future__ import annotations

from pathlib import Path

from .path_config import env_path


def home_dir() -> Path:
    return env_path("WMPF_MCP_HOME", Path.home() / ".wmpf-mcp")


def backup_dir() -> Path:
    return home_dir() / "backup"


def workspace() -> Path:
    """Decompiled source trees and exports live here."""
    return env_path("WMPF_MCP_WORKSPACE", Path.home() / "wmpf-mcp-workspace")


def report() -> dict:
    """Resolve all storage configuration without creating directories."""
    root = home_dir()
    return {"home": str(root), "offsets": str(root / "offsets"),
            "backup": str(root / "backup"), "logs": str(root / "logs"),
            "workspace": str(workspace())}


def offsets_file(platform: str, version: int | None) -> Path:
    """Local parameter path; version is only an optional filename label."""
    label = version if version is not None else "local"
    return home_dir() / "offsets" / platform / f"addresses.{label}.json"


def ensure_dirs() -> None:
    # Validate every configured root before the first filesystem side effect.
    from .config import resolve_wechat_paths
    resolve_wechat_paths()
    resolved = report()
    for key in ("home", "offsets", "backup", "logs"):
        Path(resolved[key]).mkdir(parents=True, exist_ok=True)
