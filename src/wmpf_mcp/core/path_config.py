"""Literal filesystem paths, with bounded environment expansion and no shell."""
from __future__ import annotations

import os
from pathlib import Path
import re


class PathConfigError(ValueError):
    """An explicit path cannot be resolved without guessing configuration."""


_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def resolve_path(value: str | Path, *, name: str = "path") -> Path:
    """Expand ~, $VAR and ${VAR}; anchor relative paths to the process cwd.

    Missing/empty variables and cycles fail before callers create files or
    operate on processes. Symlinks resolve to one absolute path. Shell syntax
    is never evaluated, and whitespace/Unicode remain part of the path.
    """
    raw = os.fspath(value)
    seen = set()
    for _ in range(32):
        if not raw or "\0" in raw:
            raise PathConfigError(f"{name}: path is empty or contains NUL")
        if raw in seen:
            raise PathConfigError(f"{name}: cyclic environment variable reference")
        seen.add(raw)

        def replace(match):
            variable = match[1] or match[2]
            resolved = os.environ.get(variable)
            if not resolved:
                raise PathConfigError(f"{name}: environment variable {variable} is unset or empty")
            return resolved

        expanded = _VARIABLE.sub(replace, raw)
        if expanded == raw:
            if _VARIABLE.search(raw):
                raise PathConfigError(f"{name}: cyclic environment variable reference")
            if "${" in raw or "$(" in raw or "`" in raw:
                raise PathConfigError(f"{name}: unsupported variable or shell syntax")
            try:
                return Path(raw).expanduser().resolve()
            except (OSError, RuntimeError, ValueError) as error:
                raise PathConfigError(f"{name}: cannot resolve path: {error}") from error
        raw = expanded
    raise PathConfigError(f"{name}: environment references exceed 32 expansions")


def env_path(name: str, default: Path) -> Path:
    return resolve_path(os.environ.get(name, str(default)), name=name)
