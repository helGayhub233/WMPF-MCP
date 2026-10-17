"""Explicit application-changing tool, separate from read-only diagnostics."""
from __future__ import annotations

import asyncio
from typing import Annotated, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult
from pydantic import Field

from ..core import envelope
from ..core.asyncio_utils import drain_task
from ..core.errors import ErrorCode, ToolError
from ..core.notifications import get_login_prompt
from ..core.path_config import PathConfigError
from ..core.schemas import MaintenanceReply
from ..core.state import get_state
from ..platform import get_adapter
from ..platform.maintenance import Maintenance, run_maintenance
from .contracts import annotations


def register(server: MCPServer):
    @server.tool(name="manage_wechat", annotations=annotations(destructive=True, idempotent=False), description="""Maintain configured macOS WeChat (manual P1): prepare, restart, restore or launch.
prepare verifies a full runtime .bak, then stops only in-app kernel executable paths.
Parents stop first; exit events drain new children under one deadline. It signs
main/helpers ad-hoc without hardened runtime and verifies; suitable units are reused
unless force_resign. restore needs matching backup_path/checksums and refuses updates.
ditto preserves bundle metadata. restart stops/relaunches; launch only opens WeChat.
Nested sandbox-inheriting runtimes are not opened alone.
After launch, MCP form Q&A asks for manual login. Continue suggests check_environment;
cancel ends flow, keeping completed maintenance. Q&A continuation never repeats writes
or restart. Unsupported clients get a login hint. Login is not runtime/Hook/page readiness.
Owned MCP resources stop first; failure/cancellation settles children, rollback/relaunch.
dry_run inspects without changes. Needs filesystem/process permissions; no sudo/install.""")
    async def manage_wechat(
        action: Annotated[Literal["prepare", "restart", "restore", "launch"], Field(description="prepare backs up/signs/restarts; restart force-restarts; restore reinstalls a matching backup; launch does not kill.")],
        backup_path: Annotated[str | None, Field(description="restore only: backup directory returned by prepare, containing .bak and restore.json.")] = None,
        dry_run: Annotated[bool, Field(description="Inspect exact paths, signatures, processes and planned operations without changing files/processes.")] = False,
        force_resign: Annotated[bool, Field(description="prepare only: re-sign all discovered units even if already suitable; default reuses suitable signatures.")] = False,
        ctx: Context = None,
    ) -> MaintenanceReply | InputRequiredResult:
        from . import runtime
        state = get_state()
        arguments = dict(action=action, backup_path=backup_path, dry_run=dry_run, force_resign=force_resign)
        resumed = get_login_prompt().resume(ctx, "manage_wechat", arguments)
        if resumed is not None:
            return resumed
        if (action == "restore") != bool(backup_path):
            return envelope.fail(ToolError(ErrorCode.PARAM, "backup_path is required only for restore"), stage=state.stage.value)
        if force_resign and action != "prepare":
            return envelope.fail(ToolError(ErrorCode.PARAM, "force_resign applies only to prepare"), stage=state.stage.value)
        adapter = get_adapter()
        if adapter.platform != "darwin":
            return envelope.fail(ToolError(ErrorCode.UNSUPPORTED_ANALYSIS,
                "Application maintenance currently implements macOS only; no other platform was changed."), stage=state.stage.value)
        worker = Maintenance(adapter)

        async def operate():
            try:
                data = await run_maintenance(worker, action, backup_path, True, force_resign=force_resign)
                if not dry_run:
                    if action in {"prepare", "restore"} and not data.get("writable"):
                        raise ToolError(ErrorCode.PERMISSION, "The current account cannot modify this runtime bundle",
                                        remedy="Resolve application filesystem access before maintenance; no sudo is executed.")
                    stopped = await runtime.stop_owned("all")
                    if not stopped.structured_content["ok"]:
                        return stopped
                    data = await run_maintenance(worker, action, backup_path, False, force_resign=force_resign)
                if not dry_run:
                    state.wechat_prepared = action in {"prepare", "restart", "launch"}
                return envelope.ok(data, stage=state.stage.value, next_actions=[envelope.next_action(
                    "check_environment", {"goal": "automation"}, "Recheck the relaunched installation and runtime processes.",
                    "Actual module and process prerequisites; launch alone is insufficient.",
                    "Resolve filesystem/process permissions or login/startup conditions before hooks.")])
            except ToolError as error:
                error.remedy_detail.update(worker.detail)
                return envelope.fail(error, stage=state.stage.value)
            except Exception as error:
                code = (ErrorCode.PARAM if isinstance(error, PathConfigError) else
                        ErrorCode.PERMISSION if isinstance(error, PermissionError) else ErrorCode.WECHAT_PREPARE_FAILED)
                return envelope.fail(ToolError(code, str(error), remedy_detail=worker.detail), stage=state.stage.value)

        async with runtime._LIFECYCLE_LOCK:
            task = asyncio.create_task(operate())
            try:
                reply = await asyncio.shield(task)
            except asyncio.CancelledError:
                worker.cancel()
                try:
                    await drain_task(task)
                except Exception:
                    pass
                raise
            if reply.structured_content["ok"] and not dry_run:
                generation = get_login_prompt().prepare()
            else:
                return reply
        return await get_login_prompt().request(ctx, reply, "manage_wechat", arguments, generation)
