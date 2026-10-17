"""Private browser-level Portal lifecycle operations."""

from __future__ import annotations

from typing import Annotated, Literal

from mcp.types import CallToolResult
from pydantic import Field


from ..core import envelope
from ..core.config import resolve_portal_port
from ..core.errors import ErrorCode, ToolError
from ..core.state import Stage, get_state
from ..core.syscheck import port_busy_pid
from ..portal import get_portal
from ..engine import get_engine
from ..portal.probe import probe_portal


async def execute(
    action: Annotated[Literal["start", "stop", "targets", "probe"], Field(description="targets reads listener/target state; start/stop manages Portal; probe checks browser discovery, attachment and actual frame/context capabilities.")] = "targets",
    port: Annotated[int | None, Field(description="start only: browser-level CDP listener, default WMPF_MCP_PORTAL_PORT or 20000. Probe uses this Portal's current port.", ge=1, le=65535)] = None,
    timeout_s: Annotated[float, Field(description="probe only: total HTTP/CDP/context-probe deadline in seconds; no unbounded retries.", ge=0.1, le=30)] = 10.0,
) -> CallToolResult:
    state = get_state()
    portal = get_portal()
    try:
        if action == "targets":
            return envelope.ok(
                {
                    "portal_running": portal.running,
                    "port": portal.state.port or resolve_portal_port(),
                    "targets": [t.__dict__ for t in portal.targets()],
                    "traffic": portal.ledger.summary(),
                },
                stage=state.stage.value,
                next_hint=state.next_hint,
            )

        if action == "start":
            engine = get_engine()
            if not engine.running or not engine.miniapp_clients:
                raise ToolError(
                    ErrorCode.PORTAL_NO_TARGET, "No live runtime connection to expose.",
                remedy='Inspect runtime state with inspect_runtime and probe_runtime(layer="reconnect"); historical stage does not establish a current connection.',
                )
            resolved_port = port or (portal.state.port if portal.running else None) or resolve_portal_port()
            try:
                result = await portal.start(resolved_port)
            except OSError as error:
                raise ToolError(
                    ErrorCode.PORT_BUSY,
                    f"Could not bind portal port {resolved_port}: {error}",
                    remedy="Pick another port (WMPF_MCP_PORTAL_PORT or the port "
                    "parameter) or free the occupant.",
                    remedy_detail={"occupant_pid": port_busy_pid(resolved_port)},
                ) from error
            if not portal.targets():
                raise ToolError(
                    ErrorCode.PORTAL_NO_TARGET,
                    "Portal started but there is no attached miniapp to expose.",
                    remedy="A miniapp disconnects its targets when closed; return "
                    'to probe_runtime(layer="reconnect") and reopen the miniapp.',
                )
            state.portal_port = resolved_port
            state.advance(Stage.PORTAL_UP)
            warnings = []
            try:
                enabled = await engine.send_cdp_command("Network.enable", timeout=5)
                capture = not bool(enabled.get("error"))
                if not capture:
                    warnings.append(envelope.make_warning("NETWORK_ENABLE_FAILED", str(enabled["error"])))
            except Exception as error:
                capture = False
                warnings.append(envelope.make_warning("NETWORK_ENABLE_FAILED", str(error)))
            return envelope.ok(
                {
                    **result,
                    "network_domain_enabled": capture,
                    "connect_hint": f"agent-browser connect 127.0.0.1:{resolved_port}",
                },
                stage=state.stage.value,
                warnings=warnings,
                next_hint=f"agent-browser connect 127.0.0.1:{resolved_port}",
            )

        if action == "probe":
            if not portal.running:
                raise ToolError(ErrorCode.ORDER_VIOLATION, "This MCP process's Portal is not running.",
                                remedy='Inspect runtime state with inspect_runtime(component="portal") and the live upstream connection.')
            data = await probe_portal(portal.state.port, timeout_s)
            if not data["passed"]:
                raise ToolError(
                    ErrorCode.CDP_UNHEALTHY, "Portal protocol/frame/context probe did not pass.",
                    remedy="Follow the first failed check; runtime and Portal health are separate.",
                    remedy_detail={**data, "next_actions": [envelope.next_action('probe_runtime', {'timeout_s': 5, 'layer': 'raw'}, 'Separate upstream command health from browser/session adaptation.', 'Runtime.evaluate returns value 2.', 'Inspect per-PID capture and forwarding counters.')]},
                )
            return envelope.ok(data, stage=state.stage.value)

        if action == "stop":
            result = await portal.stop()
            state.portal_port = None
            return envelope.ok(
                result, stage=state.stage.value, next_hint=state.next_hint
            )

        raise ToolError(ErrorCode.INTERNAL, f"Unknown action: {action!r}")
    except ToolError as error:
        return envelope.fail(error, stage=state.stage.value)
    except Exception as error:  # noqa: BLE001 - envelope contract requires it
        return envelope.fail(
            ToolError(ErrorCode.INTERNAL, f"portal operation failed: {error}"),
            stage=state.stage.value,
        )

