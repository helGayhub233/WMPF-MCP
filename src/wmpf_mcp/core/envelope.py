"""Unified response envelope (docs/04-MCP工具设计.md §3).

Every tool returns ``ok(...)`` or ``fail(...)``; the shape never varies so an
agent can parse any tool result without special-casing.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.types import CallToolResult, TextContent

from .errors import ToolError
from .schemas import NextAction, ToolEnvelope


def _result(payload: dict[str, Any]) -> CallToolResult:
    ToolEnvelope[Any].model_validate(payload)
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
        structured_content=payload,
        is_error=not payload["ok"],
    )


def next_action(tool: str, arguments: dict, reason: str, expected: str,
                on_failure: str, stop_condition: str = "Do not repeat without a changed observation.") -> dict:
    return NextAction(tool=tool, arguments=arguments, reason=reason, expected=expected,
                      on_failure=on_failure, stop_condition=stop_condition).model_dump()


def make_warning(code: str, message: str) -> dict[str, str]:
    """Build a warning entry (non-fatal, surfaced alongside data)."""
    return {"code": code, "message": message}


def ok(
    data: Any,
    *,
    stage: str,
    warnings: list[dict[str, str]] | None = None,
    next_hint: str | None = None,
    next_actions: list[dict] | None = None,
) -> CallToolResult:
    """Success envelope."""
    return _result({
        "ok": True,
        "stage": stage,
        "data": data,
        "warnings": warnings or [],
        "next_hint": next_hint,
        "next_actions": next_actions or [],
    })


def fail(error: ToolError, *, stage: str) -> CallToolResult:
    """Failure envelope carrying a structured, actionable error."""
    error_payload: dict[str, Any] = {
        "code": error.code.value,
        "message": error.message,
    }
    if error.remedy:
        error_payload["remedy"] = error.remedy
    payload: dict[str, Any] = {
        "ok": False,
        "stage": stage,
        "error": error_payload,
    }
    if error.remedy_detail:
        payload["remedy_detail"] = error.remedy_detail
        if error.remedy_detail.get("next_actions"):
            payload["next_actions"] = error.remedy_detail["next_actions"]
    return _result(payload)
