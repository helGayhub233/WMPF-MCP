"""Static-track pipeline: cached wxapkg -> readable source tree.

Layout produced under the workspace::

    <workspace>/decompiled/<appid>/<version>/
        __APP__/...            # main package (app-service.js, pages, ...)
        _subpackages_x_/...    # cached subpackages
        .wmpf-mcp-state.json   # signature + stats for idempotent re-runs

Idempotency: the state file records a sha256 over the source packages'
(relative path, size, mtime_ns) list. An unchanged package set returns the
previous result immediately; ``force=True`` rebuilds.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..core import paths
from .beautifier import beautify_in_place
from .crypto import WxapkgError, decrypt_wxapkg
from .locator import list_applets
from .unpacker import extract_entries, unpack_wxapkg

STATE_FILE_NAME = ".wmpf-mcp-state.json"


class AppletNotFoundError(LookupError):
    """The requested appid has no cached packages on this machine."""


class VersionNotFoundError(LookupError):
    """The requested package version is not cached."""


@dataclass
class PackageOutcome:
    name: str
    wxapkg_path: str
    output_dir: str
    file_count: int
    beautified: int
    ok: bool
    error: str | None = None


@dataclass
class DecompileResult:
    appid: str
    version: str
    output_root: str
    from_cache: bool
    elapsed_s: float
    packages: list[PackageOutcome] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)


def _package_signature(version_dir: Path) -> str:
    digest = hashlib.sha256()
    entries: list[tuple[str, int, int]] = []
    for pkg in sorted(version_dir.glob("*.wxapkg")):
        try:
            stat = pkg.stat()
        except OSError:
            continue
        entries.append((pkg.name, stat.st_size, stat.st_mtime_ns))
    for name, size, mtime_ns in entries:
        digest.update(f"{name}\0{size}\0{mtime_ns}\0".encode("utf-8"))
    return digest.hexdigest()


def _find_version_dir(appid: str, version: str | None) -> tuple[Path, str]:
    app = next((a for a in list_applets(limit=500) if a.appid == appid), None)
    if app is None:
        raise AppletNotFoundError(f"appid {appid!r} has no cached packages")
    chosen = version or app.latest_version
    if chosen is None:
        raise VersionNotFoundError(f"appid {appid!r} has no package versions")
    version_dir = Path(app.package_dir) / chosen
    if not version_dir.is_dir():
        raise VersionNotFoundError(f"version {chosen!r} of {appid!r} is not cached")
    return version_dir, chosen


def _subpackage_slugs(config_path: Path) -> tuple[list[str], bool]:
    """Read declared subpackage roots from app-config.json (best effort)."""
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], False
    slugs: list[str] = []
    for sub in config.get("subPackages") or config.get("subpackages") or []:
        root = str(sub.get("root") or "").strip("/")
        if root:
            slugs.append(f"_{root.replace('/', '_')}_")
    return slugs, True


def decompile_applet(
    appid: str,
    version: str | None = None,
    force: bool = False,
    workspace: Path | None = None,
) -> DecompileResult:
    """Decrypt, unpack and beautify every cached package of one applet."""
    started = time.monotonic()
    workspace = workspace or paths.workspace()
    version_dir, chosen_version = _find_version_dir(appid, version)
    wxapkgs = sorted(version_dir.glob("*.wxapkg"))
    if not wxapkgs:
        raise VersionNotFoundError(f"no wxapkg files under {version_dir}")

    output_root = workspace / "decompiled" / appid / chosen_version
    state_path = output_root / STATE_FILE_NAME
    signature = _package_signature(version_dir)

    if not force and state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {}
        if state.get("signature") == signature:
            return DecompileResult(
                appid=appid,
                version=chosen_version,
                output_root=str(output_root),
                from_cache=True,
                elapsed_s=round(time.monotonic() - started, 3),
                packages=[PackageOutcome(**p) for p in state.get("packages", [])],
                stats=state.get("stats", {}),
                coverage=state.get("coverage", {}),
            )

    if output_root.exists():
        shutil.rmtree(output_root)

    packages: list[PackageOutcome] = []
    total_files = 0
    total_bytes = 0
    for wxapkg in wxapkgs:
        pack_name = wxapkg.stem
        pack_out = output_root / pack_name
        outcome = PackageOutcome(
            name=pack_name,
            wxapkg_path=str(wxapkg),
            output_dir=str(pack_out),
            file_count=0,
            beautified=0,
            ok=False,
        )
        try:
            data = wxapkg.read_bytes()
            plain = decrypt_wxapkg(data, appid)
            entries = unpack_wxapkg(plain)
            written = extract_entries(plain, entries, pack_out)
            outcome.file_count = len(written)
            outcome.beautified = sum(1 for p in written if beautify_in_place(p))
            outcome.ok = True
            total_files += len(written)
            total_bytes += wxapkg.stat().st_size
        except (WxapkgError, OSError, ValueError) as error:
            outcome.error = str(error)
        packages.append(outcome)

    # coverage: declared subpackages vs cached packages (best effort)
    declared, parsed = _subpackage_slugs(output_root / "__APP__" / "app-config.json")
    cached_slugs = {pkg.name for pkg in packages if pkg.ok}
    main_pack = "__APP__" in cached_slugs
    missing = [slug for slug in declared if slug not in cached_slugs]
    coverage = {
        "main_pack": main_pack,
        "packages_extracted": sorted(cached_slugs),
        "config_parsed": parsed,
        "subpackages_declared": len(declared),
        "subpackages_missing": missing,
    }

    stats = {"files": total_files, "source_bytes": total_bytes}
    result = DecompileResult(
        appid=appid,
        version=chosen_version,
        output_root=str(output_root),
        from_cache=False,
        elapsed_s=round(time.monotonic() - started, 3),
        packages=packages,
        stats=stats,
        coverage=coverage,
    )
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "signature": signature,
                "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "packages": [asdict(pkg) for pkg in packages],
                "stats": stats,
                "coverage": coverage,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return result
