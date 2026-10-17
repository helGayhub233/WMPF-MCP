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
from ..platform.windows_maintenance import WindowsMaintenance
from .contracts import annotations


def register(server: MCPServer):
    @server.tool(name="manage_wechat", annotations=annotations(destructive=True, idempotent=False), description="""Maintain configured macOS/Windows WeChat (P1): prepare, restart, restore or launch.
prepare verifies a full .bak before executable-scoped stop; parents first, new children
drained under one deadline. macOS signs ad-hoc; suitable units are reused unless force_resign.
Windows snapshots app/runtime, preserves vendor files/signatures, checks filesystem
access and rejects force_resign. Matching restore verifies already_original; updates refused.
restore requires matching backup_path/checksums; macOS ditto preserves bundle metadata.
restart stops/relaunches; launch opens only the main program, never a nested runtime alone.
After launch, Form Q&A requests manual login. Continue suggests check_environment;
cancel ends flow and keeps completed maintenance. Continuation never repeats writes/restart.
Unsupported clients get a hint. Login does not prove runtime/Hook/page readiness.
Owned resources stop first. Cancellation drains native work; backups remain. macOS mutation
failure rolls back/relaunches; Windows stop failure blocks launch. dry_run only inspects.
Needs filesystem/process permissions; no sudo/install.""")
    async def manage_wechat(
        action: Annotated[Literal["prepare", "restart", "restore", "launch"], Field(description="prepare backs up/restarts and signs on macOS only; restart force-restarts; restore validates a matching snapshot (Windows already_original); launch does not kill.")],
        backup_path: Annotated[str | None, Field(description="restore only: backup directory returned by prepare, containing .bak and restore.json.")] = None,
        dry_run: Annotated[bool, Field(description="Inspect exact paths, signatures, processes and planned operations without changing files/processes.")] = False,
        force_resign: Annotated[bool, Field(description="macOS prepare only: re-sign even suitable units; unsupported on Windows, which preserves vendor signatures.")] = False,
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
        if adapter.platform not in {"darwin", "win32"}:
            return envelope.fail(ToolError(ErrorCode.UNSUPPORTED_ANALYSIS,
                "Application maintenance currently implements macOS and Windows only."), stage=state.stage.value)
        worker = WindowsMaintenance(adapter) if adapter.platform == "win32" else Maintenance(adapter)

        async def operate():
            try:
                data = await run_maintenance(worker, action, backup_path, True, force_resign=force_resign)
                if not dry_run:
                    if action in {"prepare", "restore"} and not data.get("writable"):
                        raise ToolError(ErrorCode.PERMISSION, "The current account cannot access this installation or its backup location",
                                        remedy="Resolve the reported filesystem permissions before maintenance; no sudo is executed.")
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
