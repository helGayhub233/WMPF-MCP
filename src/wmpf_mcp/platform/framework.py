"""Resolve an installed framework's selected executable, without version guesses."""
from __future__ import annotations

from pathlib import Path
import plistlib


def discover_module(framework: Path, runtime: Path) -> Path | None:
    root, bundle = runtime.resolve(), framework.resolve()
    if not bundle.is_relative_to(root):
        raise ValueError("Framework resolves outside the configured runtime bundle")
    if not framework.exists():
        if framework.is_symlink():
            raise ValueError("Broken framework symlink")
        return None

    def contained(path: Path) -> Path:
        resolved = path.resolve()
        if not resolved.is_relative_to(bundle):
            raise ValueError(f"Framework entry escapes its bundle: {path}")
        return resolved

    def executable(directory: Path) -> Path | None:
        directory = contained(directory)
        name = framework.stem
        metadata = directory / "Resources/Info.plist"
        if metadata.exists() or metadata.is_symlink():
            with contained(metadata).open("rb") as stream:
                name = plistlib.load(stream).get("CFBundleExecutable", name)
        if not isinstance(name, str) or not name or Path(name).name != name or name in {".", ".."}:
            raise ValueError("Invalid framework CFBundleExecutable")
        candidate = directory / name
        if candidate.is_symlink() and not candidate.exists():
            raise ValueError(f"Broken framework executable link: {candidate}")
        resolved = contained(candidate)
        return resolved if resolved.is_file() else None

    # The top-level executable and Versions/Current express the install's
    # selection. Conflicting/broken selectors are not grounds for guessing.
    selected = executable(bundle)
    current = bundle / "Versions/Current"
    if current.exists() or current.is_symlink():
        if not contained(current).is_dir():
            raise ValueError("Broken framework Versions/Current selection")
        active = executable(current)
        if active is None:
            raise ValueError("Selected framework version has no executable")
        if selected is not None and selected != active:
            raise ValueError("Conflicting framework executable and Versions/Current")
        return active
    if selected is not None:
        return selected
    versions = bundle / "Versions"
    if not versions.is_dir():
        return None
    candidates = {module for version in sorted(contained(versions).iterdir())
                  if version.is_dir() and (module := executable(version)) is not None}
    if len(candidates) > 1:
        raise ValueError("Ambiguous framework versions without an executable/Current selection: "
                         + ", ".join(str(module) for module in sorted(candidates)))
    return next(iter(candidates), None)
