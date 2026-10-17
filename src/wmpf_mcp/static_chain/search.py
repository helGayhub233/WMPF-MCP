"""Source-tree search and line-range reads over decompiled artifacts."""

from __future__ import annotations

import re
from pathlib import Path

from ..core import paths

TEXT_EXTENSIONS = {
    ".js", ".json", ".wxml", ".wxss", ".wxs", ".html", ".css",
    ".txt", ".md", ".ts", ".xml",
}
SKIP_DIRS = {".git", "__pycache__"}
MAX_FILE_BYTES = 8 * 1024 * 1024


class SourceNotFoundError(LookupError):
    """No decompiled artifacts for this appid yet."""


def app_output_dir(appid: str, workspace: Path | None = None) -> Path:
    workspace = workspace or paths.workspace()
    app_dir = workspace / "decompiled" / appid
    if not app_dir.is_dir():
        raise SourceNotFoundError(
            f"no decompiled output for {appid!r}; run decompile_applet first"
        )
    return app_dir


def latest_version_dir(appid: str, workspace: Path | None = None) -> Path:
    app_dir = app_output_dir(appid, workspace)
    candidates = [p for p in app_dir.iterdir() if p.is_dir()]
    if not candidates:
        raise SourceNotFoundError(f"no decompiled versions for {appid!r}")
    numeric = [p for p in candidates if p.name.isdigit()]
    chosen = max(numeric, key=lambda p: int(p.name)) if numeric else max(
        candidates, key=lambda p: p.stat().st_mtime
    )
    return chosen


def _iter_text_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def search_source(
    appid: str,
    pattern: str,
    regex: bool = False,
    max_hits: int = 50,
    workspace: Path | None = None,
) -> dict:
    """Search every text file under the appid's latest decompiled tree."""
    root = latest_version_dir(appid, workspace)
    matcher = re.compile(pattern if regex else re.escape(pattern))
    hits: list[dict] = []
    scanned = 0
    truncated = False
    for path in sorted(_iter_text_files(root)):
        scanned += 1
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, start=1):
            if matcher.search(line):
                hits.append(
                    {
                        "file": path.relative_to(root).as_posix(),
                        "line": lineno,
                        "text": line.strip()[:300],
                    }
                )
                if len(hits) >= max_hits:
                    truncated = True
                    break
        if truncated:
            break
    return {"hits": hits, "truncated": truncated, "scanned_files": scanned, "root": str(root)}


def read_source(
    appid: str,
    file: str,
    start_line: int = 1,
    end_line: int = 200,
    workspace: Path | None = None,
) -> dict:
    """Read a line range from one decompiled file (path relative to the tree root)."""
    root = latest_version_dir(appid, workspace)
    candidate = (root / file).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise SourceNotFoundError(f"path escapes the source tree: {file!r}") from error
    if not candidate.is_file():
        raise SourceNotFoundError(f"file not found in source tree: {file!r}")
    start = max(1, start_line)
    end = max(start, end_line)
    lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    content = "\n".join(lines[start - 1 : end])
    return {
        "file": file,
        "start_line": start,
        "end_line": min(end, len(lines)),
        "total_lines": len(lines),
        "content": content,
    }
