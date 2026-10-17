"""wxapkg unpacking.

Plaintext layout:
``0xBE | u32 info1 | u32 index_len | u32 body_len | 0xED | u32 file_count``
followed by ``file_count`` entries of
``u32 name_len | name | u32 offset | u32 size`` (offsets are absolute).
"""

from __future__ import annotations

import os
import struct
from pathlib import Path, PurePosixPath
from typing import Final

from .crypto import WxapkgError

_INDEX_MARKER: Final = 0xED


def unpack_wxapkg(data: bytes) -> list[tuple[str, int, int]]:
    """Parse a plaintext wxapkg into ``(name, offset, size)`` entries."""
    if len(data) < 18:
        raise WxapkgError("data too short to be a wxapkg")
    if data[0] != 0xBE:
        raise WxapkgError(f"invalid wxapkg header: 0x{data[0]:02x}, expected 0xBE")

    pos = 1
    pos += 4  # info1
    pos += 4  # index_info_length
    pos += 4  # body_info_length
    if data[pos] != _INDEX_MARKER:
        raise WxapkgError(f"invalid wxapkg index marker: 0x{data[pos]:02x}, expected 0xED")
    pos += 1
    file_count = struct.unpack(">I", data[pos : pos + 4])[0]
    pos += 4

    entries: list[tuple[str, int, int]] = []
    for _ in range(file_count):
        if pos + 4 > len(data):
            break
        name_len = struct.unpack(">I", data[pos : pos + 4])[0]
        pos += 4
        if name_len <= 0 or pos + name_len > len(data):
            break
        name = data[pos : pos + name_len].decode("utf-8", errors="replace")
        pos += name_len
        if pos + 8 > len(data):
            break
        offset = struct.unpack(">I", data[pos : pos + 4])[0]
        pos += 4
        size = struct.unpack(">I", data[pos : pos + 4])[0]
        pos += 4
        if offset + size <= len(data):
            entries.append((name, offset, size))
    return entries


def safe_output_path(output_dir: Path, inner_name: str) -> Path | None:
    """Map an archive path into ``output_dir``, rejecting traversal attempts."""
    normalized = str(inner_name or "").lstrip("/").replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if not normalized or any(part in {"", ".", ".."} for part in parts):
        return None
    root = output_dir.resolve()
    out_path = root.joinpath(*parts)
    try:
        resolved = out_path.resolve(strict=False)
        if os.path.commonpath([str(root), str(resolved)]) != str(root):
            return None
    except (OSError, ValueError):
        return None
    return resolved


def extract_entries(
    data: bytes, entries: list[tuple[str, int, int]], output_dir: Path
) -> list[Path]:
    """Write unpacked files under ``output_dir``; returns written paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, offset, size in entries:
        out_path = safe_output_path(output_dir, name)
        if out_path is None:
            continue
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data[offset : offset + size])
        written.append(out_path)
    return written
