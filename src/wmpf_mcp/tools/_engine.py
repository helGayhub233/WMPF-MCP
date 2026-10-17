"""Private 9421 and raw CDP listener/command operations."""

from __future__ import annotations

from typing import Annotated, Literal

from mcp.types import CallToolResult
from pydantic import Field


from ..core import envelope
from ..core.config import DEBUG_PORT, resolve_cdp_port
from ..core.errors import ErrorCode, ToolError
from ..core.state import Stage, get_state
from ..core.syscheck import port_busy_pid, proxy_state
from ..engine import EngineError, MiniappTimeoutError, get_engine
from ..injector import get_injector



def _diagnose_timeout() -> list[dict[str, str]]:
    """T1/T2/T3/T6-oriented checklist for a wait_miniapp timeout."""
    engine = get_engine()
    checks: list[dict[str, str]] = []

    checks.append(
        {
            "check": "engine",
            "detail": f"running={engine.running}, debug port 9421 listener pid="
            f"{port_busy_pid(DEBUG_PORT)}",
        }
    )
    if engine.last_disconnect_at is not None and not engine.miniapp_clients:
        checks.append(
            {
                "check": "connection-history",
                "detail": "a miniapp connected and then disconnected; reopen the "
                "miniapp after re-checking the hooks and proxy",
            }
        )
    elif engine.connected_at is None:
        checks.append(
            {
                "check": "never-connected (T1/T2)",
                "detail": "no miniapp has dialed 9421: hooks must be injected BEFORE "
                "the miniapp opens (inspect_runtime, hooks component), and the engine must already be "
                "running when the miniapp (re)opens; reopen via a click, not a "
                "drag-preview (T3)",
            }
        )
    if engine.miniapp_clients and engine.setup_context_at is None:
        checks.append(
            {
                "check": "setupContext",
                "detail": "connected but setupContext has not arrived yet; give the "
                "runtime a moment or reopen the miniapp",
            }
        )
    proxy = proxy_state()
    if proxy.get("enabled"):
        checks.append(
            {
                "check": "proxy (T6)",
                "detail": f"system proxy active via {proxy.get('server')}:"
                f"{proxy.get('port')}; ensure ws://127.0.0.1 bypasses it",
            }
        )
    return checks


async def execute(
    action: Annotated[Literal["start", "stop", "status", "wait_miniapp", "probe"], Field(description="status reads state; start/stop manages listeners; wait_miniapp waits for reconnect; probe issues one read-only Runtime.evaluate roundtrip.")] = "status",
    cdp_port: Annotated[int | None, Field(description="start only: raw CDP listener, default WMPF_MCP_CDP_PORT or 10000. 9421 is fixed and Portal uses its own port.", ge=1, le=65535)] = None,
    timeout_s: Annotated[int, Field(description="wait_miniapp deadline in seconds, 1..300. probe uses at most 10 seconds of this value.", ge=1, le=300)] = 120,
    require_setup_context: Annotated[bool, Field(description="wait_miniapp only: true requires the current runtime's setupContext; false checks socket connection only, not command health.")] = True,
) -> CallToolResult:
    state = get_state()
    engine = get_engine()
    try:
        if action == "status":
            return envelope.ok(
                engine.status(), stage=state.stage.value, next_hint=state.next_hint
            )

        if action == "start":
            resolved_cdp = cdp_port or (engine.cdp_port if engine.running else None) or resolve_cdp_port()
            try:
                result = await engine.start(DEBUG_PORT, resolved_cdp)
            except OSError as error:
                occupant = port_busy_pid(DEBUG_PORT) or port_busy_pid(resolved_cdp)
                raise ToolError(
                    ErrorCode.PORT_BUSY,
                    f"Could not bind the engine ports (9421 / {resolved_cdp}): {error}",
                    remedy="Inspect listener ownership; reuse or explicitly stop the owning service. "
                    "9421 is fixed; raw CDP is configurable via WMPF_MCP_CDP_PORT or cdp_port.",
                    remedy_detail={"occupant_pid": occupant},
                ) from error
            state.engine_ports = {"debug": DEBUG_PORT, "cdp": resolved_cdp}
            state.advance(Stage.ENGINE_UP)
            return envelope.ok(
                {**result, "status": engine.status()},
                stage=state.stage.value,
                next_hint='probe_runtime(layer="reconnect")',
            )

        if action == "stop":
            result = await engine.stop()
            state.engine_ports = {}
            return envelope.ok(
                result, stage=state.stage.value, next_hint=state.next_hint
            )

        if action == "wait_miniapp":
            if not engine.running:
                raise ToolError(ErrorCode.ORDER_VIOLATION, "Engine is not running.",
                                remedy='Inspect runtime state with inspect_runtime(component="engine") and start its listeners.')
            try:
                result = await engine.wait_miniapp(
                    timeout_s=float(timeout_s),
                    require_setup_context=require_setup_context,
                )
            except MiniappTimeoutError as error:
                raise ToolError(
                    ErrorCode.MINAPP_TIMEOUT,
                    str(error),
                    remedy="Work through the diagnosis checklist: inject before "
                    "opening (T1), engine before reconnect (T2), click-open not "
                    "drag (T3), loopback must bypass any proxy (T6).",
                    remedy_detail={"diagnosis": _diagnose_timeout(), "next_actions": [envelope.next_action('inspect_runtime', {'goal': 'automation'}, 'Reconnect did not satisfy the current condition.', 'The first unmet hook/reconnect/CBOR condition.', 'Use the independent source track.')]},
                ) from error
            except EngineError as error:
                raise ToolError(
                    ErrorCode.ORDER_VIOLATION,
                    str(error),
                    remedy='Run start_runtime(component="engine") first.',
                ) from error
            state.miniapp_epoch = engine.epoch
            state.advance(Stage.MINIAPP_CONNECTED)
            return envelope.ok(
                result, stage=state.stage.value, next_hint=state.next_hint
            )

        if action == "probe":
            try:
                reply = await engine.send_cdp_command(
                    "Runtime.evaluate", {"expression": "1+1", "returnByValue": True},
                    timeout=min(float(timeout_s), 10.0),
                )
                passed = not reply.get("error") and not reply.get("result", {}).get("exceptionDetails") \
                    and reply.get("result", {}).get("result", {}).get("value") == 2
                if not passed:
                    raise EngineError(f"Unexpected Runtime.evaluate reply: {reply}")
            except (EngineError, TimeoutError) as error:
                raise ToolError(
                    ErrorCode.CDP_UNHEALTHY, str(error) or "Runtime.evaluate timed out.",
                    remedy="Check per-PID CBOR replies/events, engine forwarding and request IDs before retrying.",
                    remedy_detail={"engine": engine.status(), "next_actions": [envelope.next_action('inspect_runtime', {'component': 'hooks'}, 'Separate capture failure from transport failure.', 'Armed/hit and CBOR response/event counters for the handling PID.', 'Inspect the launch/filter role and use source analysis if capture is unavailable.')]},
                ) from error
            return envelope.ok({"passed": True, "probe": reply, **engine.status()},
                               stage=state.stage.value)

        raise ToolError(ErrorCode.INTERNAL, f"Unknown action: {action!r}")
    except ToolError as error:
        return envelope.fail(error, stage=state.stage.value)
    except Exception as error:  # noqa: BLE001 - envelope contract requires it
        return envelope.fail(
            ToolError(ErrorCode.INTERNAL, f"engine operation failed: {error}"),
            stage=state.stage.value,
        )

