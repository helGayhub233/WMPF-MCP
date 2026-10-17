"""Private checked Frida attach/detach operations."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Literal

from mcp.types import CallToolResult
from pydantic import Field


from ..core import envelope
from ..core.errors import ErrorCode, ToolError
from ..core.paths import offsets_file
from ..core.state import Stage, get_state
from ..injector import get_injector
from ..platform import get_adapter
from ..platform.capabilities import hook_backend_supported
from ..offsets.service import static_checks
from ..offsets.methodology import branch_guidance


async def execute(
    action: Annotated[Literal["start", "stop", "status"], Field(description="status reads current sessions/counters; start checks parameters and attaches hooks; stop unloads this process's hooks.")] = "status",
    version: Annotated[int | None, Field(description="Optional positive cache label selecting a local config instead of the session config; does not choose hook strategy.", ge=1)] = None,
    force: Annotated[bool, Field(description="start only: unload existing hooks before loading the current template; false reuses live PIDs and covers new helpers.")] = False,
) -> CallToolResult:
    state = get_state()
    injector = get_injector()
    try:
        if action == "status":
            data = injector.status()
            data["injected_pids"] = state.injected_pids
            return envelope.ok(
                data, stage=state.stage.value, next_hint=state.next_hint
            )

        if action == "start":
            adapter = get_adapter()
            config_path = str(offsets_file(state.platform or adapter.platform, version)) if version is not None else state.config_path
            if not config_path or not Path(config_path).is_file():
                raise ToolError(
                    ErrorCode.OFFSETS_MISSING if state.config_path else ErrorCode.ORDER_VIOLATION,
                    "No offset config in session to render the hook from.",
                    remedy='Run check_offsets() or action="extract".',
                )
            binary = getattr(adapter, "main_module_path", lambda: None)()
            if not binary:
                raise ToolError(ErrorCode.NO_WECHAT, "No installed runtime module to recheck.",
                                remedy="Locate the current runtime module before attaching.")
            try:
                config = json.loads(Path(config_path).read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise ToolError(ErrorCode.OFFSETS_VERIFY_FAILED, str(error)) from error
            binary_format = config.get("Format", "Mach-O")
            arches = config.get("Arch", {})
            if not isinstance(arches, dict) or not any(
                hook_backend_supported(adapter.platform, binary_format, arch, config.get("ABI"))
                for arch in arches
            ):
                raise ToolError(
                    ErrorCode.UNSUPPORTED_ANALYSIS, "No native hook backend matches this platform, format, ISA and ABI.",
                    remedy="Extract and verify the current module's own supported configuration before attaching.",
                    remedy_detail=branch_guidance("format", str(binary)),
                )
            checks = await asyncio.to_thread(static_checks, Path(binary), config)
            if not checks or not all(c["ok"] for c in checks):
                raise ToolError(
                    ErrorCode.OFFSETS_VERIFY_FAILED, "Current module does not satisfy the hook parameter checks.",
                    remedy_detail={"checks": checks, **branch_guidance("verify", binary)},
                )
            pids = await asyncio.to_thread(getattr(adapter, "hook_pids", adapter.running_pids))
            if not pids:
                raise ToolError(
                    ErrorCode.WECHAT_NOT_RUNNING,
                    "No running WeChatAppEx process found to inject into.",
                    remedy="Start WeChat and open it once, then retry. Hooks apply "
                    "to appservices started afterwards, so reopen the miniapp "
                    "after injecting.",
                )
            if force:
                await injector.stop()
            result = await injector.start(Path(config_path), pids)
            if hasattr(adapter, "hook_scope"):
                result["process_scope"] = adapter.hook_scope
            state.injected_pids = [
                item["pid"] for item in result["injected"] if item.get("ok")
            ]
            if any(not item.get("ok") for item in result["injected"]):
                raise ToolError(ErrorCode.INTERNAL, "Some target PIDs failed complete hook initialization.",
                    remedy="Inspect per-PID hook_failure role/address and the current process list before another preparation; successful sessions remain owned.",
                    remedy_detail={**result, "config_path": config_path})
            state.advance(Stage.INJECTED)
            status = injector.status()
            return envelope.ok(
                {
                    **result,
                    "config_path": config_path,
                    "hook_hits": status["hook_hits"],
                    "recent_messages": status["recent_messages"],
                },
                stage=state.stage.value,
                next_hint=state.next_hint,
            )

        if action == "stop":
            result = await injector.stop()
            state.injected_pids = []
            return envelope.ok(
                result, stage=state.stage.value, next_hint=state.next_hint
            )

        raise ToolError(ErrorCode.INTERNAL, f"Unknown action: {action!r}")
    except ToolError as error:
        return envelope.fail(error, stage=state.stage.value)
    except Exception as error:  # noqa: BLE001 - envelope contract requires it
        return envelope.fail(
            ToolError(ErrorCode.INTERNAL, f"inject operation failed: {error}"),
            stage=state.stage.value,
        )

