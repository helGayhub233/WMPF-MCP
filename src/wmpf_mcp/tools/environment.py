"""One read-only entry for goal-specific environment observations."""

from __future__ import annotations

import asyncio
import platform
import plistlib
import sys
from pathlib import Path
from typing import Annotated, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from ..core import envelope
from ..core import paths as storage_paths
from ..core.config import resolve_cdp_port, resolve_portal_port, resolve_wechat_paths
from ..core.path_config import PathConfigError, resolve_path
from ..core.schemas import EnvironmentReply
from ..core.state import Stage, get_state
from ..core.syscheck import port_state, proxy_state
from ..diagnostics import dependency_report
from ..offsets.inspection import inspect_binary
from ..platform import get_adapter
from ..platform.gaps import implementation_gaps
from .contracts import annotations

Goal = Literal["automation", "source", "offsets", "traffic", "wx_api"]


def collect_environment(goal: str, scope: str = "all", binary_path: str | None = None) -> dict:
    data = {"goal": goal, "scope": scope, "environment_ready": None,
            "requires_live_verification": goal in {"automation", "traffic", "wx_api"},
            "checks": [], "blockers": [], "implementation_gaps": implementation_gaps(sys.platform)}
    dynamic = data["requires_live_verification"]

    def check(name: str, status: str, detail, blocking: bool = False):
        row = {"check": name, "status": status, "detail": detail, "blocking": blocking}
        data["checks"].append(row)
        if blocking:
            data["blockers"].append(row)

    if scope in {"all", "packages"}:
        data["dependencies"] = dependency_report(goal)
        for package in data["dependencies"]["packages"]:
            usable = package["importable"] and package.get("requirement_satisfied", True)
            check("package:" + package["package"], "pass" if usable else "fail",
                  {"importable": package["importable"], "error": package.get("error")},
                  package["required_for_goal"] and not usable)
        if not data["dependencies"]["startup_ready"]:
            check("startup_dependencies", "fail", "Use the bootstrap doctor with this interpreter.", True)

    if scope != "packages":
        try:
            paths = resolve_wechat_paths()
            data["config"] = {**paths.report(), **storage_paths.report()}
            data["path_warnings"] = paths.warnings
            if binary_path:
                binary_path = str(resolve_path(binary_path, name="binary_path"))
            check("path_configuration", "pass", data["config"])
        except PathConfigError as error:
            check("path_configuration", "fail", str(error), True)
            if scope == "all":
                data["environment_ready"] = False
            return data
    if scope in {"all", "system"}:
        try:
            distribution = platform.freedesktop_os_release() if sys.platform.startswith("linux") else None
        except OSError:
            distribution = None
        data["system"] = {"os": sys.platform, "host_arch": platform.machine(), "distribution": distribution}
        data["ports"] = {str(port): port_state(port) for port in (9421, resolve_cdp_port(), resolve_portal_port())}
        data["proxy"] = proxy_state()
        check("listeners", "observed", data["ports"])
        try:
            permission = get_adapter().signature_state()
            data["permission"] = permission
            check("attach_policy", "unknown" if permission.get("inject_mode") == "unknown" else "observed",
                  {**permission, "note": "Policy/signing clues do not prove attach succeeds."})
            if dynamic and permission.get("inject_mode") == "need_signing":
                data["permission_advice"] = {"tool": "manage_wechat", "arguments": {"action": "prepare"},
                                             "executed": False, "reason": "Inspect the exact app/signing scope and current permissions; prepare creates a full rollback backup."}
        except Exception as error:
            check("attach_policy", "unknown", str(error))

    if scope in {"all", "wechat"}:
        try:
            adapter = get_adapter()
            info = adapter.locate()
            module = binary_path or getattr(adapter, "main_module_path", lambda: None)()
            app_version = None
            if sys.platform == "darwin" and info.app_path:
                try:
                    with (Path(info.app_path) / "Contents/Info.plist").open("rb") as stream:
                        metadata = plistlib.load(stream)
                    app_version = metadata.get("CFBundleShortVersionString") or metadata.get("CFBundleVersion")
                except (OSError, ValueError, plistlib.InvalidFileException):
                    pass
            data["wechat"] = {"app_path": info.app_path, "runtime_path": info.runtime_path,
                              "binary_path": module, "app_version": app_version,
                              "wmpf_version": info.version, "wmpf_version_raw": info.version_raw,
                              "running_pids": info.running_pids}
            check("version_labels", "observed" if info.version is not None else "unknown",
                  "Optional labels; analysis uses the actual module and ISA.")
            if module and Path(module).is_file():
                summary = inspect_binary(Path(module), view="summary")
                data["binary"] = summary
                implemented = adapter.platform == "darwin" and summary.get("arch") == "arm64" and summary.get("format") == "Mach-O"
                data["hook_backend_implemented"] = implemented
                check("hook_backend", "pass" if implemented else "fail",
                      "Current native backend: Darwin Mach-O arm64; parser support does not establish another hook ABI.", dynamic and not implemented)
                state = get_state()
                state.platform, state.arch = info.platform, summary.get("arch")
                state.wechat_path, state.runtime_path = info.app_path, info.runtime_path
                state.wmpf_version, state.running_pids = info.version, info.running_pids
                state.advance(Stage.LOCATED)
            else:
                check("runtime_module", "unknown", "No default module; pass binary_path for offline analysis.", dynamic)
            if dynamic and not info.running_pids:
                check("runtime_process", "fail", "No running WeChatAppEx candidate. Open WeChat before attaching.", True)
        except Exception as error:
            check("runtime_discovery", "unknown", str(error), dynamic)
    if scope == "all":
        data["environment_ready"] = not data["blockers"]
    return data


def register(server: MCPServer) -> None:
    @server.tool(name="check_environment", annotations=annotations(read_only=True), description="""Inspect dependencies, system policy and the actual WeChat/WMPF module for a goal.
Use first for a fresh dynamic workflow (manual P0), after an environment change or when startup/attach fails.
Source and basic binary inspection remain available without Frida or extract extras.
Reports the MCP interpreter, package import failures, host/target ISA, separate optional
app/WMPF version labels, listeners and permission clues. A busy port can be another
service; raw 10000 has no browser discovery, while Portal defaults to 20000.
Reports resolved path roots and unimplemented platform branches by PATH issue ID.
No install, signing, elevation, attach or probe is performed. environment_ready applies
only to a complete preflight, never command health. Scoped checks leave it unknown.
Use inspect_runtime for live state, check_offsets for parameters and probe_runtime for
command/session/frame/context validation. Static queries remain independent; no stored inventory.""")
    async def check_environment(
        goal: Annotated[Goal, Field(description="Requested outcome; missing extras block only operations that need them.")] = "automation",
        scope: Annotated[Literal["all", "packages", "system", "wechat"], Field(description="all evaluates preflight conditions; narrower scopes expand one observation without claiming overall readiness.")] = "all",
        binary_path: Annotated[str | None, Field(description="Optional local module for offline header/ISA inspection; does not select a live process or prove hook support.")] = None,
    ) -> EnvironmentReply:
        data = await asyncio.to_thread(collect_environment, goal, scope, binary_path)
        actions = []
        if scope == "all":
            module = data.get("wechat", {}).get("binary_path")
            if not data.get("hook_backend_implemented") and module and data["requires_live_verification"]:
                actions = [envelope.next_action("inspect_binary", {"binary_path": module},
                           "Establish the missing format/ISA/ABI conditions.", "Executable mappings and a bounded analysis branch.",
                           "Use inspect_source for independent static analysis.")]
            elif (data["requires_live_verification"] and sys.platform == "darwin" and not get_state().wechat_prepared
                  and all(row["check"] == "runtime_process" for row in data["blockers"])):
                from ..engine import get_engine
                from ..injector import get_injector
                if not get_engine().running and not get_injector().status()["active"]:
                    actions = [envelope.next_action("manage_wechat", {"action": "prepare"},
                        "Fresh manual P1: create a restorable backup, inspect exact processes, sign if needed and force-relaunch.",
                        "Verified backup/signatures and launch request; current account permissions are required.",
                        "Stop at permission/backup errors; no implicit sudo or guessed paths.")]
            if not actions and not data["blockers"]:
                tool = "inspect_source" if goal == "source" else "inspect_binary" if goal == "offsets" else "check_offsets"
                actions = [envelope.next_action(tool, {}, "Continue the requested method chain.",
                           "Source/module observations or statically checked parameters.", "Follow the returned failed condition.")]
        return envelope.ok(data, stage=get_state().stage.value, next_actions=actions)
