"""Lazy analysis dispatch shared by offset and injection tools."""

from __future__ import annotations

from dataclasses import asdict
from importlib import import_module
from pathlib import Path

from ..core.errors import ErrorCode, ToolError
from ..platform.capabilities import analysis_module
from .inspection import BinaryView
from .methodology import METHOD_CHAIN, branch_guidance


def analysis_backend(binary: Path, arch: str | None = None):
    try:
        with BinaryView(binary, arch) as image:
            fmt, selected = image.format, image.arch
    except (OSError, ValueError) as error:
        raise ToolError(ErrorCode.PARAM, str(error),
                        remedy="Select a local runtime module, not an application directory.",
                        remedy_detail=branch_guidance("unknown", str(binary))) from error
    supported_module = analysis_module(fmt, selected)
    if supported_module is None:
        guidance = branch_guidance("format", str(binary))
        raise ToolError(
            ErrorCode.UNSUPPORTED_ANALYSIS,
            f"Automatic hook extraction/verification is not implemented for {fmt}/{selected}.",
            remedy="Continue the method chain with read-only inspection; do not reuse another ISA's hook config.",
            remedy_detail={"format": fmt, "arch": selected, "method_chain": METHOD_CHAIN, **guidance},
        )
    try:
        extractor = import_module("." + supported_module, package=__package__)
    except ImportError as error:
        raise ToolError(
            ErrorCode.DEPS_MISSING, f"Optional extraction dependency unavailable: {error.name}.",
            remedy="Install wmpf-mcp[extract]; summary/strings and the static source track remain available.",
            remedy_detail=branch_guidance("unknown", str(binary)),
        ) from error
    return extractor


def static_checks(binary: Path, config: dict, arch: str | None = None) -> list[dict]:
    backend = analysis_backend(binary, arch)
    try:
        return [asdict(check) for check in backend.verify_config(binary, config)]
    except (ValueError, TypeError, AttributeError) as error:
        raise ToolError(ErrorCode.OFFSETS_VERIFY_FAILED, f"Invalid candidate config: {error}",
                        remedy_detail=branch_guidance("verify", str(binary))) from error
