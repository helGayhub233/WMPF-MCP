"""Private bounded CDP Network ledger operations."""

from __future__ import annotations

import base64
from typing import Annotated, Literal

from mcp.types import CallToolResult
from pydantic import Field


from ..core import envelope
from ..core.errors import ErrorCode, ToolError
from ..core.state import Stage, get_state
from ..engine import EngineError, get_engine
from ..portal import get_portal
from ..portal.har import export_har

BODY_CAP_BYTES = 256 * 1024



def _decode_body(result: dict) -> tuple[str, bool]:
    body = str(result.get("body") or "")
    truncated = False
    if result.get("base64Encoded"):
        try:
            raw = base64.b64decode(body)
        except Exception:  # noqa: BLE001 - keep the wire body on decode failure
            raw = body.encode("utf-8", "replace")
        if len(raw) > BODY_CAP_BYTES:
            raw, truncated = raw[:BODY_CAP_BYTES], True
        return raw.decode("utf-8", errors="replace"), truncated
    raw = body.encode("utf-8")
    if len(raw) > BODY_CAP_BYTES:
        return raw[:BODY_CAP_BYTES].decode("utf-8", errors="ignore"), True
    return body, truncated


async def execute(
    action: Annotated[Literal["list", "body", "har", "clear"], Field(description="Read metadata, bodies or HAR; clear explicitly discards records.")] = "list",
    filter: Annotated[str | None, Field(description="list only: case-insensitive literal URL fragment; omitted means all. Use method for an HTTP method filter.")] = None,
    method: Annotated[str | None, Field(description="list only: exact HTTP method filter, compared case-insensitively, e.g. POST.")] = None,
    max: Annotated[int, Field(description="list only: maximum recent transactions returned, 1..200.", ge=1, le=200)] = 50,
    id: Annotated[str | None, Field(description="Required for body: current transaction id from list. IDs can expire when the ledger is cleared or Portal stops.")] = None,
    which: Annotated[Literal["request", "response", "both"], Field(description="body only: select request, response or both; each side reports its own error and byte truncation.")] = "both",
    content: Literal["none", "text", "all"] = "all",
) -> CallToolResult:
    state = get_state()
    portal = get_portal()
    engine = get_engine()
    try:
        if action == "list":
            ledger = portal.ledger
            return envelope.ok(
                {
                    "transactions": ledger.list(
                        filter_text=filter, method=method, max_items=max
                    ),
                    "summary": ledger.summary(),
                    "capture_scope": "Observed CDP Network events only; native wx.request depends on runtime emission, and mmtls/ilink coverage is not guaranteed.",
                    "note": (
                        None
                        if ledger.active
                        else "ledger inactive: portal not started"
                    ),
                },
                stage=state.stage.value,
                next_hint=state.next_hint,
            )

        if action == "har":
            data = await export_har(portal.ledger, engine, filter_text=filter, method=method,
                                    limit=max, content=content,
                                    live=bool(portal.running and engine.running and engine.miniapp_clients))
            return envelope.ok(data, stage=state.stage.value, next_hint=state.next_hint)

        if action == "clear":
            portal.ledger.clear()
            return envelope.ok(
                {"cleared": True, **portal.ledger.summary()},
                stage=state.stage.value,
                next_hint=state.next_hint,
            )

        if action == "body":
            if not portal.running or not engine.running or not engine.miniapp_clients:
                raise ToolError(ErrorCode.ORDER_VIOLATION, "Body retrieval needs a live Portal/runtime connection.",
                                remedy="Inspect current targets and ledger IDs; historical PORTAL_UP is insufficient.")
            if not id:
                raise ToolError(
                    ErrorCode.PARAM,
                    "request_id is required for view=body.",
                    remedy='Use the transaction id from query_traffic().',
                )
            entry = portal.ledger.get(id)
            if entry is None:
                raise ToolError(
                    ErrorCode.PARAM,
                    f"Unknown transaction id: {id}",
                    remedy="The ledger clears when the portal stops; list again.",
                )
            result: dict = {"id": id, "url": entry.url}
            generation = portal.ledger.generation
            if which in ("response", "both"):
                try:
                    if entry.redirected or not portal.ledger.can_fetch(entry):
                        raise EngineError("This hop is no longer the current runtime request; its response body is unavailable.")
                    raw = await engine.send_cdp_command(
                        "Network.getResponseBody", {"requestId": entry.runtime_request_id}, timeout=8.0
                    )
                    if generation != portal.ledger.generation or not portal.ledger.can_fetch(entry):
                        raise EngineError("Runtime request changed during response body retrieval.")
                    if raw.get("error"):
                        raise EngineError(str(raw["error"]))
                    body_result = raw.get("result") or {}
                    if "body" not in body_result:
                        raise EngineError("Network.getResponseBody returned no body field.")
                    body, truncated = _decode_body(body_result)
                    result["response_body"] = body
                    result["response_truncated"] = truncated
                except (EngineError, TimeoutError) as error:
                    result["response_body_error"] = str(error)
            if which in ("request", "both"):
                try:
                    if entry.request_post is not None:
                        post = entry.request_post
                    else:
                        if entry.redirected or not portal.ledger.can_fetch(entry):
                            raise EngineError("This hop is no longer the current runtime request; its request body is unavailable.")
                        raw = await engine.send_cdp_command(
                            "Network.getRequestPostData", {"requestId": entry.runtime_request_id}, timeout=8.0
                        )
                        if generation != portal.ledger.generation or not portal.ledger.can_fetch(entry):
                            raise EngineError("Runtime request changed during request body retrieval.")
                        if raw.get("error"):
                            raise EngineError(str(raw["error"]))
                        if "postData" not in (raw.get("result") or {}):
                            raise EngineError("Network.getRequestPostData returned no postData field.")
                        post = str((raw.get("result") or {}).get("postData") or "")
                    result["request_body"], result["request_truncated"] = _decode_body({"body": post})
                    result["request_truncated"] |= entry.request_post_truncated
                except (EngineError, TimeoutError) as error:
                    result["request_body_error"] = str(error)
            return envelope.ok(
                result, stage=state.stage.value, next_hint=state.next_hint
            )

        raise ToolError(ErrorCode.INTERNAL, f"Unknown action: {action!r}")
    except ToolError as error:
        return envelope.fail(error, stage=state.stage.value)
    except Exception as error:  # noqa: BLE001 - envelope contract requires it
        return envelope.fail(
            ToolError(ErrorCode.INTERNAL, f"traffic operation failed: {error}"),
            stage=state.stage.value,
        )

