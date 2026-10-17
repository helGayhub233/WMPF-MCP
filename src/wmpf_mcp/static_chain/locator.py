"""Cached mini-program (wxapkg) locator for the static track.

Layout (observed on macOS, WeChat 4.1.15):
``radium/users/<hash>/applet/packages/<appid>/<version>/__APP__.wxapkg``
plus optional ``_subpackages_*_.wxapkg`` / ``_async-*_.wxapkg`` files.
Legacy installs also use ``radium/Applet/packages``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..core.config import resolve_wechat_paths


@dataclass
class PackageFile:
    name: str  # __APP__.wxapkg / _subpackages_x_.wxapkg
    version: str  # parent directory name
    path: str
    size: int


@dataclass
class CachedApplet:
    appid: str
    package_dir: str
    versions: list[str] = field(default_factory=list)
    latest_version: str | None = None
    packages: list[PackageFile] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(pkg.size for pkg in self.packages)


def candidate_roots() -> list[Path]:
    """Package cache roots derived from the configured radium data root."""
    base = resolve_wechat_paths().radium_dir
    roots: list[Path] = [base / "Applet" / "packages"]
    users = base / "users"
    if users.is_dir():
        roots.extend(
            sorted(p / "applet" / "packages" for p in users.iterdir() if p.is_dir())
        )
    return roots


def _latest_version(versions: list[str]) -> str | None:
    if not versions:
        return None
    numeric = [int(v) for v in versions if v.isdigit()]
    if numeric:
        return str(max(numeric))
    return sorted(versions)[-1]


def list_applets(limit: int = 50) -> list[CachedApplet]:
    """Aggregate cached packages into applet records, newest version first."""
    found: dict[str, CachedApplet] = {}
    for root in candidate_roots():
        if not root.is_dir():
            continue
        for app_dir in sorted(root.iterdir()):
            if not app_dir.is_dir() or not app_dir.name.startswith("wx"):
                continue
            app = found.get(app_dir.name)
            if app is None:
                app = CachedApplet(appid=app_dir.name, package_dir=str(app_dir))
                found[app_dir.name] = app
            for ver_dir in sorted(p for p in app_dir.iterdir() if p.is_dir()):
                if ver_dir.name not in app.versions:
                    app.versions.append(ver_dir.name)
                for pkg in sorted(ver_dir.glob("*.wxapkg")):
                    try:
                        size = pkg.stat().st_size
                    except OSError:
                        size = 0
                    app.packages.append(
                        PackageFile(
                            name=pkg.name,
                            version=ver_dir.name,
                            path=str(pkg),
                            size=size,
                        )
                    )
    out = sorted(found.values(), key=lambda a: a.appid)
    for app in out:
        app.latest_version = _latest_version(app.versions)
    return out[:limit]
