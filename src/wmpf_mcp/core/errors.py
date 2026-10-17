"""Structured error codes shared with docs/04-MCP工具设计.md §5."""

from __future__ import annotations

from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    NO_WECHAT = "E_NO_WECHAT"
    WECHAT_NOT_RUNNING = "E_WECHAT_NOT_RUNNING"
    DEPS_MISSING = "E_DEPS_MISSING"
    PERMISSION = "E_PERMISSION"
    VERSION_UNKNOWN = "E_VERSION_UNKNOWN"
    OFFSETS_MISSING = "E_OFFSETS_MISSING"
    OFFSETS_EXTRACT_FAILED = "E_OFFSETS_EXTRACT_FAILED"
    OFFSETS_VERIFY_FAILED = "E_OFFSETS_VERIFY_FAILED"
    PORT_BUSY = "E_PORT_BUSY"
    ORDER_VIOLATION = "E_ORDER_VIOLATION"
    MINAPP_TIMEOUT = "E_MINAPP_TIMEOUT"
    HOOK_TIMEOUT = "E_HOOK_TIMEOUT"
    PAGE_NOT_READY = "E_PAGE_NOT_READY"
    BACKUP_MISMATCH = "E_BACKUP_MISMATCH"
    WECHAT_PREPARE_FAILED = "E_WECHAT_PREPARE_FAILED"
    PORTAL_NO_TARGET = "E_PORTAL_NO_TARGET"
    NOT_IMPLEMENTED = "E_NOT_IMPLEMENTED"
    UNSUPPORTED_ANALYSIS = "E_UNSUPPORTED_ANALYSIS"
    CDP_UNHEALTHY = "E_CDP_UNHEALTHY"
    APPLET_NOT_FOUND = "E_APPLET_NOT_FOUND"
    SOURCE_NOT_FOUND = "E_SOURCE_NOT_FOUND"
    PARAM = "E_PARAM"
    INTERNAL = "E_INTERNAL"


class ToolError(Exception):
    """An error that maps to the envelope's structured error contract.

    Every error carries an optional ``remedy`` (a short actionable hint) and
    ``remedy_detail`` (machine-usable payload such as an exact command).
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        remedy: str | None = None,
        remedy_detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.remedy = remedy
        self.remedy_detail = remedy_detail or {}


def not_implemented(action: str, milestone: str, detail: str) -> ToolError:
    """Uniform placeholder error for actions scheduled after the MVP build."""
    return ToolError(
        ErrorCode.NOT_IMPLEMENTED,
        f"Action '{action}' is not available in this build.",
        remedy=f"Planned for milestone {milestone}: {detail}",
    )
