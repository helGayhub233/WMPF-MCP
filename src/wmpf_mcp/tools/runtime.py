"""Owned resource lifecycle, live observations and bounded protocol probes."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult
from pydantic import Field

from ..core import envelope
from ..core.asyncio_utils import drain_task
from ..core.config import resolve_cdp_port, resolve_portal_port, resolve_wechat_paths
from ..core import paths
from ..core.path_config import PathConfigError, resolve_path
from ..core.errors import ErrorCode, ToolError
from ..core.notifications import get_login_prompt, get_prompt
from ..core.schemas import ProbeReply, RuntimeReply, StartReply, StopReply
from ..core.state import get_state
from ..portal.probe import probe_portal
from ..portal.readiness import probe_page
from . import _engine, _injection, _offsets, _portal
from .contracts import annotations
from .environment import Goal, collect_environment

Component = Literal["all", "engine", "hooks", "portal"]
_LIFECYCLE_LOCK = asyncio.Lock()


async def stop_owned(component: str, *, continue_on_error: bool = False):
    """Shared owned cleanup for stop and explicit application maintenance."""
    await get_prompt().stop()
    await get_login_prompt().stop()
    components = {}
    failure = None
    names = ["portal", "engine", "hooks"] if component == "all" else ["portal", "engine"] if component == "engine" else [component]
    for name in names:
        operation = {"portal": _portal.execute, "engine": _engine.execute, "hooks": _injection.execute}[name]
        try:
            result = await operation(action="stop")
        except Exception as error:
            if not continue_on_error:
                raise
            result = envelope.fail(ToolError(ErrorCode.INTERNAL, f"{name} cleanup failed: {error}"), stage=get_state().stage.value)
        components[name] = result.structured_content
        if not result.structured_content["ok"]:
            if not continue_on_error:
                return _component_failure(result, components, name)
            if failure is None:
                failure = (result, name)
    if failure is not None:
        return _component_failure(failure[0], components, failure[1])
    if component == "all":
        get_state().reset()
    return envelope.ok({"components": components}, stage=get_state().stage.value)


async def prompt_if_prepared(ctx, reply, tool, arguments):
    engine = _engine.get_engine()
    if (get_state().prompt_user and engine.running and not (
            engine.miniapp_clients and engine.setup_context_at is not None)
            and _injection.get_injector().status().get("armed_pids")):
        try:
            result = await get_prompt().request(engine, ctx, reply, tool, arguments)
        except asyncio.CancelledError:
            # A cancelled tool request must settle the same owned cleanup as
            # the Q&A Cancel choice, even under repeated/AnyIO cancellation.
            await drain_task(asyncio.create_task(_cancel_prompt({"status": "cancelled"}, reply)))
            raise
        return await _finish_prompt(result)
    return get_prompt().attach_reply(reply, {"status": "disabled" if not get_state().prompt_user else "not_needed"})


async def _cancel_prompt(notification, reply):
    async with _LIFECYCLE_LOCK:
        stopped = await stop_owned("all", continue_on_error=True)
        get_prompt().status = dict(notification)
        payload = stopped.structured_content
        if not payload["ok"]:
            error = payload["error"]
            detail = {**payload.get("remedy_detail", {}), "status": "cleanup_failed",
                      "notification": dict(notification), "cleanup_complete": False, "awaiting_miniapp": False,
                      "next_actions": [envelope.next_action("stop_runtime", {"component": "all"},
                      "Retry the failed owned cleanup; all components were attempted.",
                      "Listeners and hooks are stopped.", "Inspect remaining owned resources and the reported cleanup error.")]}
            return envelope.fail(ToolError(ErrorCode(error["code"]), "Q&A cancelled, but runtime cleanup failed: " + error["message"],
                remedy="Inspect the component stop results; retry cleanup for resources still owned.", remedy_detail=detail),
                stage=get_state().stage.value)
        data = {"status": "cancelled", "components": payload["data"]["components"],
                "first_unmet": None, "awaiting_miniapp": False, "cleanup_complete": True,
                "notification": dict(notification)}
        if reply.structured_content["data"].get("layer"):
            data.update(layer=reply.structured_content["data"]["layer"], passed=False)
        return envelope.ok(data, stage=get_state().stage.value,
            next_hint="User cancelled. Owned Portal, listeners and hooks have stopped; wait for a new user instruction.")


async def _finish_prompt(reply):
    if isinstance(reply, InputRequiredResult):
        return reply
    notification = reply.structured_content.get("data", {}).get("notification", {})
    if notification.get("status") not in {"cancelled", "declined"}:
        return reply
    task = asyncio.create_task(_cancel_prompt(notification, reply))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await drain_task(task)
        raise


def _live() -> dict:
    portal = _portal.get_portal()
    return {"inject": _injection.get_injector().status(), "engine": _engine.get_engine().status(),
            "portal": {"running": portal.running, "port": portal.state.port,
                       "target_count": len(portal.targets()), "traffic": portal.ledger.summary()},
            "notification": dict(getattr(get_prompt(), "status", {"status": "not_requested"}))}


def _diagnose(goal: str, live: dict) -> tuple[str, dict]:
    state = get_state()
    inject, engine, portal = live["inject"], live["engine"], live["portal"]
    if goal == "source":
        branch, tool, args, reason = "static_source", "inspect_source", {}, "Source inspection is independent of CDP."
    elif goal == "offsets":
        branch, tool, args, reason = "binary_analysis", "inspect_binary", {}, "Choose queries from the actual format and ISA."
    elif inject.get("last_start_failures") or any(s.get("initialization") == "failed" for s in inject.get("sessions", [])):
        branch, tool, args, reason = "hook_installation", "check_environment", {"scope": "wechat", "goal": goal}, "Inspect current PIDs and the reported failed role/address before replacing hooks; another armed PID does not complete a failed preparation."
    elif not engine["running"] and not inject["active"] and not state.runtime_path:
        branch, tool, args, reason = "environment", "check_environment", {"goal": goal}, "Locate the actual module and inspect goal dependencies."
    elif not engine["running"] and not inject["active"] and (not state.config_path or not Path(state.config_path).is_file()):
        branch, tool, args, reason = "parameters", "check_offsets", {}, "Check parameters before live attachment."
    elif not engine["running"]:
        branch, tool, args, reason = "listeners", "start_runtime", {"component": "engine" if inject["active"] else "all"}, "Listeners and hooks must be ready when the miniapp opens."
    elif not engine["miniapp_connected"] or not engine["setup_context_seen"]:
        armed = bool(inject.get("armed_pids"))
        if not inject["active"]:
            branch, tool, args, reason = "hooks", "start_runtime", {"component": "hooks"}, "Prepare checked hooks before reopening once."
        elif not armed:
            branch, tool, args, reason = "armed", "probe_runtime", {"layer": "hooks", "timeout_s": 10}, "Wait once for a current armed callback; stop/error also wakes this wait."
        else:
            branch, tool, args, reason = "reconnect", "probe_runtime", {"layer": "reconnect", "timeout_s": 10}, "Separate socket/setupContext from command health; reopen once after preparation."
    elif not sum(v.get("cbor_response", 0) for v in inject.get("pid_hits", {}).values()):
        branch, tool, args, reason = "command_roundtrip", "probe_runtime", {"layer": "raw", "timeout_s": 5}, "Quiet counters may mean no command was issued; correlate a fixed reply."
    elif not portal["running"]:
        branch, tool, args, reason = "browser_adapter", "start_runtime", {"component": "portal"}, "Standard clients need browser discovery and Target sessions."
    elif goal == "traffic":
        branch, tool, args, reason = "network_observation", "query_traffic", {}, "Compare emitted Network events with source/runtime activity."
    else:
        branch, tool, args, reason = "business_context" if goal == "wx_api" else "frame_context", "probe_runtime", {"layer": "portal"}, "Select UI/business contexts by observed capabilities."
    return branch, envelope.next_action(tool, args, reason,
        "The named predicate passes; successful invocation alone is insufficient.",
        "Follow the first failed module/ABI/hook/reconnect/CBOR/frame condition, or use inspect_source.",
        "One bounded observation, then change the question or wait for a changed condition.")


def _component_failure(result, components: dict, condition: str):
    payload = result.structured_content
    detail = {**payload.get("remedy_detail", {}), "status": "blocked", "first_unmet": condition,
              "components": components, "awaiting_miniapp": False}
    detail["next_actions"] = payload.get("next_actions") or [envelope.next_action(
        "inspect_runtime", {}, "Inspect partial startup without discarding its observations.",
        "The exact failed resource/role condition.", "Use stop_runtime to release this process's resources if desired.")]
    error = payload["error"]
    return envelope.fail(ToolError(ErrorCode(error["code"]), error["message"], error.get("remedy"), detail),
                         stage=get_state().stage.value)


async def _start(component: str, cdp_port: int | None, portal_port: int | None,
                 config_path: str | None, force_hooks: bool):
    components = {}
    state = get_state()
    try:
        resolve_wechat_paths()
        paths.report()
        if config_path:
            config_path = str(resolve_path(config_path, name="config_path"))
    except PathConfigError as error:
        return envelope.fail(ToolError(ErrorCode.PARAM, str(error),
            remedy="Fix the MCP client path environment before starting resources."), stage=state.stage.value)
    engine, portal = _engine.get_engine(), _portal.get_portal()
    raw_port = cdp_port or (engine.cdp_port if engine.running else None) or resolve_cdp_port()
    browser_port = portal_port or (portal.state.port if portal.running else None) or resolve_portal_port()
    if ((component in {"all", "engine"} and raw_port == 9421)
            or (component in {"all", "portal"} and browser_port in {9421, raw_port})):
        return envelope.fail(ToolError(ErrorCode.PARAM, "Private 9421, raw CDP and Portal must use distinct ports."), stage=state.stage.value)
    if component in {"all", "engine"} and engine.running and cdp_port is not None and cdp_port != engine.cdp_port:
        return envelope.fail(ToolError(ErrorCode.PARAM, "Engine already uses another raw CDP port; inspect/stop it explicitly."), stage=state.stage.value)
    if component in {"all", "portal"} and portal.running and portal_port is not None and portal_port != portal.state.port:
        return envelope.fail(ToolError(ErrorCode.PARAM, "Portal already uses another port; inspect/stop it explicitly."), stage=state.stage.value)
    if component in {"all", "hooks"}:
        preflight = await asyncio.to_thread(collect_environment, "automation")
        components["preflight"] = preflight
        if not preflight["environment_ready"]:
            first = preflight["blockers"][0]
            code = ErrorCode.DEPS_MISSING if first["check"].startswith(("package:", "startup_")) else ErrorCode.UNSUPPORTED_ANALYSIS if first["check"] == "hook_backend" else ErrorCode.WECHAT_NOT_RUNNING if first["check"] == "runtime_process" else ErrorCode.NO_WECHAT
            return envelope.fail(ToolError(code, "Runtime preflight blocked: " + first["check"],
                remedy="Follow check_environment for this condition; no startup action ran.",
                remedy_detail={"first_unmet": first["check"], "components": components,
                               "next_actions": [envelope.next_action("check_environment", {"goal": "automation"},
                               "Inspect the exact dependency/module/backend condition.", "Local startup prerequisites.",
                               "Continue inspect_binary or inspect_source when the dynamic backend is unavailable.")]}), stage=state.stage.value)
        checked = await _offsets.execute(action="status", path=config_path or state.config_path)
        components["parameters"] = checked.structured_content
        if not checked.structured_content["ok"]:
            return _component_failure(checked, components, "parameters")
        if not checked.structured_content["data"]["ready"]:
            return envelope.fail(ToolError(ErrorCode.OFFSETS_VERIFY_FAILED, "No parameters pass current static checks.",
                remedy_detail={"components": components, "first_unmet": "parameters",
                               "next_actions": checked.structured_content.get("next_actions", [])}), stage=state.stage.value)
    for name in ("engine", "hooks"):
        if component not in {"all", name}:
            continue
        result = await (_engine.execute(action="start", cdp_port=cdp_port) if name == "engine"
                        else _injection.execute(action="start", force=force_hooks))
        components[name] = result.structured_content
        if not result.structured_content["ok"]:
            return _component_failure(result, components, name)
    if component in {"all", "hooks"}:
        hooks = _injection.get_injector().status()
        armed = bool(hooks.get("armed_pids"))
        if not hooks["active"] or not armed:
            return envelope.ok({"status": "blocked", "components": components,
                                "first_unmet": "armed", "awaiting_miniapp": False}, stage=state.stage.value,
                next_actions=[envelope.next_action("probe_runtime", {"layer": "hooks", "timeout_s": 10},
                              "Wait once for armed callbacks before reopening; inspect current hook errors on failure.",
                              "Every owned target completed initialization, with no preparation failures.", "Resolve module/ISA/parameter errors.")])
    if component in {"all", "hooks", "engine"}:
        if engine.running and _injection.get_injector().status().get("armed_pids") and (not engine.miniapp_clients or engine.setup_context_at is None):
            return envelope.ok({"status": "awaiting_miniapp", "components": components,
                                "first_unmet": "reconnect", "awaiting_miniapp": True}, stage=state.stage.value,
                next_actions=[envelope.next_action("probe_runtime", {"layer": "reconnect", "timeout_s": 10},
                              "Hooks/listeners are prepared; open/reopen the miniapp once.",
                              "A current connection and setupContext.", "Inspect launch hits and loopback/proxy conditions.",
                              "One wait per reopen or changed hook/listener observation.")])
    if component in {"all", "portal"}:
        result = await _portal.execute(action="start", port=portal_port)
        components["portal"] = result.structured_content
        if not result.structured_content["ok"]:
            return _component_failure(result, components, "portal")
    return envelope.ok({"status": "ready", "components": components, "first_unmet": None,
                        "awaiting_miniapp": False}, stage=state.stage.value,
                        next_actions=[envelope.next_action("probe_runtime", {"layer": "portal" if portal.running else "raw"},
                        "Resource preparation does not establish protocol behavior.", "A correlated command/session/frame/context result.",
                        "Inspect the first failed method condition.")])


def register(server: MCPServer) -> None:
    @server.tool(name="start_runtime", annotations=annotations(destructive=True, idempotent=False), description="""Prepare checked listeners/hooks before reopening a miniapp (manual P3-P4).
all checks dependencies/module/parameters and starts listeners before hooks.
engine prepares listeners; hooks checks/attaches; portal wraps a live connection.
Each PID must acknowledge armed after all configured hooks install and flush;
script.load alone is insufficient. Initialization waits on an event up to 5s within
the 30s native deadline. Any PID failure blocks reopening; inspect_runtime retains
failed roles/addresses and successful owned sessions. force_hooks reloads owned hooks.
When needed, MCP form Q&A offers reopen/continue or cancel. Continue returns
awaiting_miniapp; cancel/decline stops owned Portal/listeners/hooks, with cleanup
failures explicit. prompt_user=false disables Q&A; unsupported clients get a hint.
Q&A retries do not repeat startup or hold the lifecycle lock; cancellation drains cleanup.
Modifies debug data/listeners. manage_wechat handles signing/restart/restore;
prepare_offsets handles missing parameters. No install/elevation/external takeover.
setupContext is transport readiness; probe_runtime(page) needs a business selector
before client screenshots/clicks.""")
    async def start_runtime(
        component: Annotated[Component, Field(description="all prepares the chain; engine, hooks or portal targets one component.")] = "all",
        cdp_port: Annotated[int | None, Field(description="engine/all raw CDP port; default client env or 10000. Private 9421 is fixed.", ge=1, le=65535)] = None,
        portal_port: Annotated[int | None, Field(description="portal/all browser-level port; default client env or 20000.", ge=1, le=65535)] = None,
        config_path: Annotated[str | None, Field(description="hooks/all candidate; statically rechecked against the actual installed module.")] = None,
        force_hooks: Annotated[bool, Field(description="hooks/all unloads and reloads owned hooks; false reuses live PIDs and covers new helpers.")] = False,
        prompt_user: Annotated[bool | None, Field(description="Request in-band MCP Q&A after listeners/armed hooks. New sessions default true; omit keeps the setting; false returns manual user-action instructions.")] = None,
        ctx: Context = None,
    ) -> StartReply | InputRequiredResult:
        arguments = dict(component=component, cdp_port=cdp_port, portal_port=portal_port,
                         config_path=config_path, force_hooks=force_hooks, prompt_user=prompt_user)
        resumed = get_prompt().resume(ctx, _engine.get_engine(), "start_runtime", arguments)
        if resumed is not None:
            return await _finish_prompt(resumed)
        incompatible = []
        if component not in {"all", "engine"} and cdp_port is not None:
            incompatible.append("cdp_port")
        if component not in {"all", "portal"} and portal_port is not None:
            incompatible.append("portal_port")
        if component not in {"all", "hooks"} and (config_path is not None or force_hooks):
            incompatible.append("config_path/force_hooks")
        if incompatible:
            return envelope.fail(ToolError(ErrorCode.PARAM, "Arguments do not apply to component=" + component + ": " + ", ".join(incompatible)), stage=get_state().stage.value)
        async with _LIFECYCLE_LOCK:
            if prompt_user is not None:
                get_state().prompt_user = prompt_user
                if not prompt_user:
                    await get_prompt().stop()
            engine, portal, hooks = _engine.get_engine(), _portal.get_portal(), _injection.get_injector()
            had_engine, had_portal, had_hooks = engine.running, portal.running, hooks.status()["active"]
            try:
                result = await _start(component, cdp_port, portal_port, config_path, force_hooks)
            except asyncio.CancelledError:
                async def cleanup_new_resources():
                    if not had_engine and engine.running:
                        await stop_owned("engine")
                    elif not had_portal and portal.running:
                        await stop_owned("portal")
                    if not had_hooks and hooks.status()["active"]:
                        await stop_owned("hooks")
                await drain_task(asyncio.create_task(cleanup_new_resources()))
                raise
        if result.structured_content.get("data", {}).get("awaiting_miniapp"):
            return await prompt_if_prepared(ctx, result, "start_runtime", arguments)
        return result

    @server.tool(name="stop_runtime", annotations=annotations(destructive=True), description="""Stop selected resources owned by this MCP process.
all stops Portal, Engine and hooks in that order. Stopping engine also stops its
dependent Portal. Portal stop discards targets, sessions and the in-memory traffic
ledger; hooks stop detaches patches and can disrupt current runtime commands.
External listeners/processes are never killed or stopped. Safe to call when absent.
Request cancellation waits for owned cleanup before releasing the lifecycle lock.
Use inspect_runtime for observations and start_runtime to prepare resources again.""")
    async def stop_runtime(
        component: Annotated[Component, Field(description="Owned component to stop; engine also stops an active dependent Portal.")] = "all",
    ) -> StopReply:
        async with _LIFECYCLE_LOCK:
            task = asyncio.create_task(stop_owned(component))
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                try:
                    await drain_task(task)
                except Exception:
                    pass
                raise

    @server.tool(name="inspect_runtime", annotations=annotations(read_only=True), description="""Read live owned resources and select the next bounded method-chain observation.
Available at any stage; goal chooses source, binary, transport, traffic or wx-context
questions. Per-PID active/armed/hit/CBOR response/event counters are distinct, and the
TCP owner may differ from the handler. Historical stage never proves current health.
Hook failures include bounded stage/role/address and last_start_failures; raw frames are not returned.
This reads in-process observations only, without CDP commands, attach, reopen or reset.
For installation/package/module checks use check_environment; an external listener
does not appear as an owned resource. probe_runtime can test an explicit Portal port.
Suggestions are not executed. Use the first failed condition, changing the observation
before retrying; only the method chain is retained, without an identity/evidence archive.""")
    async def inspect_runtime(
        goal: Annotated[Goal, Field(description="Outcome selecting the current method branch.")] = "automation",
        component: Annotated[Component, Field(description="Select observations; branch selection still considers all live components.")] = "all",
    ) -> RuntimeReply:
        live = _live()
        branch, suggestion = _diagnose(goal, live)
        selected = live if component == "all" else {"inject" if component == "hooks" else component: live["inject" if component == "hooks" else component]}
        portal = _portal.get_portal()
        return envelope.ok({"goal": goal, "branch": branch, "live": selected,
                            "targets": [t.__dict__ for t in portal.targets()] if component in {"all", "portal"} else []},
                           stage=get_state().stage.value, next_actions=[suggestion])

    @server.tool(name="probe_runtime", annotations=annotations(destructive=True), description="""Validate one bounded manual P3-P6 condition; transport and business readiness differ.
hooks awaits armed callbacks, then offers MCP Q&A; cancel stops owned runtime resources.
reconnect awaits owned socket/setupContext; raw requires fixed 1+1=2.
portal checks discovery, flatten attachment, frames and up to 16 DOM/wx/eval contexts.
Raw 10000 has no browser discovery; standard clients use Portal 20000. An explicit
portal_port tests an existing local Portal without taking ownership. Page/Runtime
domains are shared; only this probe's sockets, sessions and observers are released.
page requires ready_selector identifying actual loaded business content, optionally
frame_name. A named isolated world waits for CSS visibility in the real frame DOM.
MutationObserver/CDP bindings drive the wait without sleeps or changes to page globals.
Visible images in the business subtree and fonts must finish loading before ready.
page has one fixed 60s deadline; observers/bindings/session are cleaned on every exit.
Choose a business-loaded selector, then perform client screenshots/clicks; a visible
selector alone does not prove all resources or business actions succeeded.""")
    async def probe_runtime(
        layer: Annotated[Literal["hooks", "reconnect", "raw", "portal", "page"], Field(description="Wait for armed hooks/setupContext, test a fixed command, validate Portal, or await visible business content.")] = "portal",
        timeout_s: Annotated[float | None, Field(description="hooks/reconnect/raw/portal only: default 10s, at most 30s; raw internally at most 10s. Omit for page: fixed 60s plus at most 2s remote cleanup.", ge=0.1, le=30)] = None,
        portal_port: Annotated[int | None, Field(description="portal/page: existing loopback endpoint; omitted uses owned Portal or configured/default 20000.", ge=1, le=65535)] = None,
        ready_selector: Annotated[str | None, Field(description="page requires a CSS selector for actual business-loaded content, e.g. a loaded-state attribute; body or navigation presence is insufficient.", min_length=1, max_length=512)] = None,
        frame_name: Annotated[str | None, Field(description="page only: exact observed rendering frame name; empty string selects the unnamed root. Omit to observe real frame DOMs in an isolated world.", max_length=256)] = None,
        ctx: Context = None,
    ) -> ProbeReply | InputRequiredResult:
        arguments = dict(layer=layer, timeout_s=timeout_s, portal_port=portal_port,
                         ready_selector=ready_selector, frame_name=frame_name)
        resumed = get_prompt().resume(ctx, _engine.get_engine(), "probe_runtime", arguments)
        if resumed is not None:
            return await _finish_prompt(resumed)
        state = get_state()
        if ((layer not in {"portal", "page"} and portal_port is not None)
                or (layer != "page" and (ready_selector is not None or frame_name is not None))
                or (layer == "page" and timeout_s is not None)
                or (layer == "page" and (ready_selector is None or not ready_selector.strip()
                    or ready_selector.strip().lower() in {"body", "html", ":root", "*", "nav", "header", "footer"}))):
            return envelope.fail(ToolError(ErrorCode.PARAM,
                "page requires a business ready_selector and uses a fixed 60s deadline: omit timeout_s. frame_name/ready_selector are page-only; portal_port applies to portal/page."), stage=state.stage.value)
        timeout_s = 60.0 if layer == "page" else (timeout_s if timeout_s is not None else 10.0)
        try:
            if layer == "hooks":
                async with asyncio.timeout(timeout_s):
                    data = await _injection.get_injector().wait_armed(timeout_s)
                result = envelope.ok({**data, "layer": layer, "passed": True}, stage=state.stage.value,
                    next_actions=[envelope.next_action("probe_runtime", {"layer": "reconnect", "timeout_s": 10},
                    "Open/reopen the miniapp after listeners/hooks are ready.", "Current socket and setupContext.", "Inspect launch hits and loopback conditions.")])
                return await prompt_if_prepared(ctx, result, "probe_runtime", arguments)
            if layer == "page":
                portal = _portal.get_portal()
                port = portal_port or (portal.state.port if portal.running else resolve_portal_port())
                data = await probe_page(port, ready_selector, frame_name, timeout_s)
                if data["passed"]:
                    warnings = []
                    if data.get("matched", {}).get("failed_images"):
                        warnings.append(envelope.make_warning("BUSINESS_IMAGE_FAILED",
                            "Business selector is visible, but a visible image failed to load; verify the rendered result."))
                    return envelope.ok(data, stage=state.stage.value, warnings=warnings,
                        next_hint="Use the matched rendering frame for actual client screenshot/click verification; then inspect traffic and stop owned resources.")
                code = ErrorCode.PARAM if data.get("failure_kind") == "invalid_selector" else ErrorCode.PAGE_NOT_READY
                return envelope.fail(ToolError(code, "Business readiness predicate did not pass.",
                    remedy="Inspect the selected frame and loading state; retry only after changing the condition or observation.",
                    remedy_detail=data), stage=state.stage.value)
            async with asyncio.timeout(timeout_s):
                if layer == "portal":
                    portal = _portal.get_portal()
                    port = portal_port or (portal.state.port if portal.running else resolve_portal_port())
                    data = await probe_portal(port, timeout_s)
                    data.update(layer=layer, port=port)
                    if not data["passed"]:
                        return envelope.fail(ToolError(ErrorCode.CDP_UNHEALTHY, "Portal predicate did not pass.",
                            remedy_detail={**data, "next_actions": [envelope.next_action("inspect_runtime", {},
                            "Separate owned upstream health from an external or adapted Portal.",
                            "Current connection/hook counters.", "Inspect the first failed discovery/session/frame/context check.")]}), stage=state.stage.value)
                    return envelope.ok(data, stage=state.stage.value,
                        next_hint="P6 business readiness remains: choose an actual loaded-business CSS condition and call probe_runtime(layer=page, ready_selector=...) before client screenshots/clicks; its event-driven deadline is fixed at 60s.")
                result = await _engine.execute(action="wait_miniapp" if layer == "reconnect" else "probe", timeout_s=timeout_s)
                payload = result.structured_content
                if payload["ok"]:
                    action = (envelope.next_action("probe_runtime", {"layer": "raw", "timeout_s": 5},
                        "Verify a correlated response before exposing browser automation.", "Fixed 1+1 returns 2.", "Inspect CBOR response/event forwarding.")
                        if layer == "reconnect" else envelope.next_action("start_runtime", {"component": "portal"},
                        "Expose browser-level CDP after the command roundtrip.", "Portal listens on 20000 or its configured port.", "Inspect current upstream and port ownership."))
                    return envelope.ok({**payload["data"], "layer": layer, "passed": True},
                                       stage=state.stage.value, next_actions=[action])
                return result
        except ToolError as error:
            error.remedy_detail.setdefault("next_actions", [envelope.next_action(
                "inspect_runtime", {"component": "hooks"}, "Inspect the stopped, failed or timed-out hook condition.",
                "Current owned sessions and per-PID errors.", "Resolve the cause before another bounded wait.")])
            return envelope.fail(error, stage=state.stage.value)
        except TimeoutError:
            code = ErrorCode.HOOK_TIMEOUT if layer == "hooks" else ErrorCode.MINAPP_TIMEOUT if layer == "reconnect" else ErrorCode.CDP_UNHEALTHY
            return envelope.fail(ToolError(code,
                f"{layer} probe exceeded {timeout_s:g}s.", remedy="Inspect the first unmet condition before another bounded probe.",
                remedy_detail={"layer": layer, "passed": False, "next_actions": [envelope.next_action("inspect_runtime", {},
                "Distinguish current hooks, reconnect and CBOR forwarding.", "A changed or failed method condition.",
                "Use the independent inspect_source track if unavailable.")]}), stage=state.stage.value)
