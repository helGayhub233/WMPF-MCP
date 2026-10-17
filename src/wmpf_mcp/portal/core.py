"""Browser-level CDP portal (docs/06).

Exposes a Chromium-compatible CDP endpoint in front of the engine's raw CDP
stream so standard clients (agent-browser, Playwright connectOverCDP) can
attach like to a chrome instance:

- ``GET /json/version`` / ``GET /json/list`` — discovery
- ``ws://127.0.0.1:<port>/devtools/browser/<id>`` — browser session handling
  ``Browser.*`` / ``Target.*`` locally and routing session-scoped traffic
- ``ws://127.0.0.1:<port>/devtools/page/<target>`` — optional direct channel

Virtual targets are ``appservice-0`` (logic layer) and ``webview-0``
(rendering layer); they exist while a miniapp is connected. Response ``id``
rewriting keeps concurrent clients from colliding on one miniapp channel, and
all upstream payloads feed the traffic ledger.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from aiohttp import WSMsgType, web

from .. import __version__
from ..engine import get_engine
from .ledger import TrafficLedger

BROWSER_PRODUCT = f"WMPF-MCP/{__version__}"


@dataclass
class TargetInfo:
    target_id: str
    type: str = "page"
    title: str = ""
    url: str = ""
    attached: bool = False


@dataclass
class _Pending:
    ws: web.WebSocketResponse
    orig_id: Any
    session_id: str | None
    timer: asyncio.TimerHandle | None = None
    method: str = ""
    target_id: str | None = None


@dataclass
class _SessionOwner:
    ws: web.WebSocketResponse
    target_id: str
    parent_session_id: str | None = None
    auto_attached: bool = False


@dataclass
class PortalState:
    port: int | None = None
    clients: set[web.WebSocketResponse] = field(default_factory=set)
    sessions: dict[str, _SessionOwner] = field(default_factory=dict)
    pending: dict[int, _Pending] = field(default_factory=dict)
    discover: set[web.WebSocketResponse] = field(default_factory=set)
    auto_attach: set[web.WebSocketResponse] = field(default_factory=set)
    direct_targets: dict[web.WebSocketResponse, str] = field(default_factory=dict)


class PortalService:
    """Owns the portal HTTP+WS endpoint and the CDP routing broker."""

    def __init__(self) -> None:
        self.running = False
        self.state = PortalState()
        self.ledger = TrafficLedger()
        self.browser_id = f"wmpf-{secrets.token_hex(8)}"
        self._pid_counter = 900_000
        self._session_counter = 0
        self._runner: web.AppRunner | None = None
        self._engine = None
        self._target_epoch: int | None = None
        self._view_epoch: int | None = None
        self._view_serial = 0
        self._known_targets: dict[str, TargetInfo] = {}
        self._frame_ids: dict[str, str] = {}
        self._tree_frame_ids: dict[str, set[str]] = {}
        self._execution_contexts: dict[int, dict] = {}

    # -- targets -------------------------------------------------------------
    def targets(self) -> list[TargetInfo]:
        engine = self._engine or get_engine()
        if not engine.running or not engine.miniapp_clients:
            return []
        epoch = engine.epoch
        # A destroyed CDP target ID cannot identify its replacement. Clients
        # may drain destroy/create events together and otherwise ignore the
        # new target as already tracked before removing the old one.
        if self._view_epoch is not None and epoch != self._view_epoch:
            self._view_serial += 1
        self._view_epoch = epoch
        return [
            TargetInfo(
                target_id=f"webview-{self._view_serial}",
                title=f"miniapp · webview (epoch {epoch})",
                url="wmpf://webview/0",
                attached=f"webview-{self._view_serial}" in {o.target_id for o in self.state.sessions.values()},
            ),
            TargetInfo(
                target_id=f"appservice-{self._view_serial}",
                title=f"miniapp · appservice (epoch {epoch})",
                url="wmpf://appservice/0",
                attached=f"appservice-{self._view_serial}" in {o.target_id for o in self.state.sessions.values()},
            ),
        ]

    def version_payload(self) -> dict:
        return {
            "Browser": BROWSER_PRODUCT,
            "Protocol-Version": "1.3",
            "User-Agent": "WMPF-MCP",
            "V8-Version": "-",
            "WebKit-Version": "-",
            "webSocketDebuggerUrl": (
                f"ws://127.0.0.1:{self.state.port}/devtools/browser/{self.browser_id}"
            ),
        }

    # -- lifecycle -----------------------------------------------------------
    async def start(self, port: int, engine: Any | None = None) -> dict:
        if self.running:
            return {"already_running": True, "port": self.state.port}
        engine = engine or get_engine()
        if not engine.running:
            raise RuntimeError("engine is not running")
        self._engine = engine
        engine.on_cdp_upstream(self._on_upstream)
        engine.on_lifecycle(self._on_engine_lifecycle)
        self.ledger.activate()

        app = web.Application()
        for path in ("/json/version", "/json/version/"):
            app.router.add_get(path, self._http_version)
        for path in ("/json/list", "/json/list/", "/json", "/json/"):
            app.router.add_get(path, self._http_list)
        app.router.add_get("/devtools/browser/{bid}", self._browser_ws)
        app.router.add_get("/devtools/page/{tid}", self._page_ws)
        try:
            self._runner = web.AppRunner(app, access_log=None)
            await self._runner.setup()
            site = web.TCPSite(self._runner, "127.0.0.1", port)
            await site.start()
        except (OSError, asyncio.CancelledError):
            engine.off_cdp_upstream(self._on_upstream)
            engine.off_lifecycle(self._on_engine_lifecycle)
            self.ledger.deactivate()
            await self._runner.cleanup()
            self._runner = None
            raise
        self.state.port = port
        self.running = True
        self._target_epoch = engine.epoch
        self._known_targets = {t.target_id: t for t in self.targets()}
        self._execution_contexts.update(getattr(engine, "execution_contexts", lambda: {})())
        return {
            "started": True,
            "port": port,
            "http_url": f"http://127.0.0.1:{port}",
            "ws_url": f"ws://127.0.0.1:{port}/devtools/browser/{self.browser_id}",
            "targets": [t.__dict__ for t in self.targets()],
        }

    async def stop(self) -> dict:
        if not self.running:
            return {"stopped": False, "reason": "not running"}
        if self._engine is not None:
            self._engine.off_cdp_upstream(self._on_upstream)
            self._engine.off_lifecycle(self._on_engine_lifecycle)
        self.running = False
        for ws in list(self.state.clients):
            try:
                await ws.close()
            except Exception:  # noqa: BLE001
                pass
        self.state.clients.clear()
        self.state.sessions.clear()
        for entry in self.state.pending.values():
            if entry.timer:
                entry.timer.cancel()
        self.state.pending.clear()
        self.state.discover.clear()
        self.state.auto_attach.clear()
        self.state.direct_targets.clear()
        self._known_targets.clear()
        self._frame_ids.clear()
        self._tree_frame_ids.clear()
        self._execution_contexts.clear()
        if self._runner is not None:
            try:
                await self._runner.cleanup()
            except Exception:  # noqa: BLE001
                pass
        self._runner = None
        self.ledger.deactivate()
        self.running = False
        return {"stopped": True}

    # -- HTTP -----------------------------------------------------------------
    async def _http_version(self, request: web.Request) -> web.Response:
        return web.json_response(self.version_payload())

    async def _http_list(self, request: web.Request) -> web.Response:
        self._sync_targets()
        base = f"ws://127.0.0.1:{self.state.port}"
        payload = [
            {
                "id": t.target_id,
                "type": t.type,
                "title": t.title,
                "url": t.url,
                "webSocketDebuggerUrl": f"{base}/devtools/page/{t.target_id}",
                "attached": t.attached,
                "browserContextId": "default",
            }
            for t in self.targets()
        ]
        return web.json_response(payload)

    # -- websocket entrypoints ------------------------------------------------
    async def _browser_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(max_msg_size=0)
        await ws.prepare(request)
        if request.match_info["bid"] != self.browser_id:
            await ws.close(code=1008, message=b"unknown browser id")
            return ws
        self.state.clients.add(ws)
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    self._handle_browser_message(ws, msg.data)
                elif msg.type == WSMsgType.BINARY:
                    self._handle_browser_message(ws, msg.data.decode("utf-8", "replace"))
        finally:
            self._cleanup_client(ws)
        return ws

    async def _page_ws(self, request: web.Request) -> web.WebSocketResponse:
        self._sync_targets()
        target_id = request.match_info["tid"]
        if target_id not in {t.target_id for t in self.targets()}:
            raise web.HTTPNotFound(text="unknown target")
        ws = web.WebSocketResponse(max_msg_size=0)
        await ws.prepare(request)
        self.state.clients.add(ws)
        self.state.direct_targets[ws] = target_id
        try:
            async for msg in ws:
                if msg.type in (WSMsgType.TEXT, WSMsgType.BINARY):
                    text = (
                        msg.data
                        if isinstance(msg.data, str)
                        else msg.data.decode("utf-8", "replace")
                    )
                    self._forward_direct(ws, text)
        finally:
            self._cleanup_client(ws)
        return ws

    def _cleanup_client(self, ws: web.WebSocketResponse) -> None:
        self.state.clients.discard(ws)
        self.state.discover.discard(ws)
        self.state.auto_attach.discard(ws)
        self.state.direct_targets.pop(ws, None)
        for sid in [s for s, owner in self.state.sessions.items() if owner.ws is ws]:
            self.state.sessions.pop(sid, None)
        for pid in [p for p, entry in self.state.pending.items() if entry.ws is ws]:
            entry = self.state.pending.pop(pid)
            if entry.timer:
                entry.timer.cancel()

    # -- browser message handling ---------------------------------------------
    def _handle_browser_message(self, ws: web.WebSocketResponse, text: str) -> None:
        self._sync_targets()
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(data, dict):
            return
        message_id = data.get("id")
        method = data.get("method")
        params = data.get("params")
        params = {} if params is None else params
        session_id = data.get("sessionId")
        if not isinstance(method, str) or not method:
            self._error(ws, message_id, -32600, "A nonempty CDP method is required")
            return
        if not isinstance(params, dict) or (session_id is not None and not isinstance(session_id, str)):
            self._error(ws, message_id, -32602, "params must be an object and sessionId a string")
            return

        if session_id:
            owner = self.state.sessions.get(session_id)
            if owner is None or owner.ws is not ws:
                self._error(ws, message_id, -32001, "Unknown session", session_id)
                return
            if owner.target_id == self.browser_id:
                if method == "Target.attachToTarget":
                    tid = params.get("targetId")
                    if tid not in {t.target_id for t in self.targets()}:
                        self._error(ws, message_id, -32602, f"No target with id {tid}", session_id)
                        return
                    sid = self._attach(ws, tid, parent_session_id=session_id)
                    self._reply(ws, message_id, {"sessionId": sid}, session_id)
                elif method == "Target.detachFromTarget":
                    child = self.state.sessions.get(params.get("sessionId"))
                    if child is None or child.ws is not ws or child.parent_session_id != session_id:
                        self._error(ws, message_id, -32001, "Unknown session", session_id)
                        return
                    self._detach(params["sessionId"])
                    self._reply(ws, message_id, {}, session_id)
                elif method == "Target.getTargets":
                    self._reply(ws, message_id, {
                        "targetInfos": [self._target_json(t) for t in self.targets()]}, session_id)
                else:
                    self._error(ws, message_id, -32601, f"Unsupported browser-session method: {method}", session_id)
                return
            # This runtime has no child-target hierarchy. A page's request to
            # auto-attach child frames is handled locally, within that session.
            if method in ("Target.setAutoAttach", "Target.setDiscoverTargets"):
                self._reply(ws, message_id, {}, session_id)
                return
            if method == "Target.getTargetInfo":
                target = next((t for t in self.targets() if t.target_id == owner.target_id), None)
                self._reply(ws, message_id, {"targetInfo": self._target_json(target)}, session_id)
                return
            self._forward_session(ws, data)
            return

        if method == "Browser.getVersion":
            self._reply(ws, message_id, {
                "protocolVersion": "1.3",
                "product": BROWSER_PRODUCT,
                "revision": "-",
                "userAgent": "WMPF-MCP",
                "jsVersion": "-",
            })
            return
        if method == "Target.attachToBrowserTarget":
            self._session_counter += 1
            sid = f"WS{self._session_counter:04d}"
            self.state.sessions[sid] = _SessionOwner(ws=ws, target_id=self.browser_id)
            self._reply(ws, message_id, {"sessionId": sid})
            return
        if method in ("Target.getTargets", "Target.getTargetInfo"):
            if method == "Target.getTargetInfo":
                tid = params.get("targetId")
                if not tid:
                    self._reply(ws, message_id, {"targetInfo": {
                        "targetId": self.browser_id, "type": "browser",
                        "title": "WMPF-MCP", "url": "", "attached": True,
                        "canAccessOpener": False,
                    }})
                    return
                match = next((t for t in self.targets() if t.target_id == tid), None)
                if match is None:
                    self._error(ws, message_id, -32602, f"No target with id {tid}")
                    return
                self._reply(ws, message_id, {"targetInfo": self._target_json(match)})
            else:
                self._reply(ws, message_id, {
                    "targetInfos": [self._target_json(t) for t in self.targets()]
                })
            return
        if method == "Target.setDiscoverTargets":
            self._reply(ws, message_id, {})
            if params.get("discover"):
                self.state.discover.add(ws)
                for target in self.targets():
                    self._emit(ws, "Target.targetCreated",
                               {"targetInfo": self._target_json(target)})
            else:
                self.state.discover.discard(ws)
            return
        if method == "Target.attachToTarget":
            target_id = params.get("targetId")
            if target_id not in {t.target_id for t in self.targets()}:
                self._error(ws, message_id, -32602, f"No target with id {target_id}")
                return
            sid = self._attach(ws, target_id)
            self._reply(ws, message_id, {"sessionId": sid})
            return
        if method == "Target.detachFromTarget":
            sid = params.get("sessionId")
            owner = self.state.sessions.get(sid)
            if owner is None or owner.ws is not ws:
                self._error(ws, message_id, -32001, "Unknown session")
                return
            self._detach(sid)
            self._reply(ws, message_id, {})
            return
        if method == "Target.getBrowserContexts":
            self._reply(ws, message_id, {"browserContextIds": []})
            return
        if method == "Target.setAutoAttach":
            if params.get("autoAttach"):
                if not params.get("flatten"):
                    self._error(ws, message_id, -32602, "Use flatten=true")
                    return
                self.state.auto_attach.add(ws)
                for target in self.targets():
                    if not any(o.ws is ws and o.target_id == target.target_id
                               for o in self.state.sessions.values()):
                        self._attach(ws, target.target_id, auto_attached=True)
            else:
                self.state.auto_attach.discard(ws)
                for sid, owner in list(self.state.sessions.items()):
                    if owner.ws is ws and owner.auto_attached:
                        self._detach(sid)
            self._reply(ws, message_id, {})
            return
        if method == "Target.createTarget":
            self._error(ws, message_id, -32000,
                "Target.createTarget is unavailable: Portal wraps one existing MiniProgram runtime. "
                "Use Target.getTargets and attach to its existing webview; no independent tab was created.")
            return
        if method == "Browser.setDownloadBehavior":
            # Embedded Chromium implements this root method. Playwright invokes
            # it during connectOverCDP; preserve the runtime's real ack/error.
            # Do not emulate it with a local no-op or change naming semantics.
            self._forward_command(ws, data)
            return
        # A successful empty result is only valid for implemented void methods.
        # Missing window/storage/context support must not look like completion.
        self._error(ws, message_id, -32601, f"Unsupported browser method: {method}")

    def _target_json(self, target: TargetInfo | None) -> dict:
        if target is None:
            return {}
        return {
            "targetId": target.target_id,
            "type": target.type,
            "title": target.title,
            "url": target.url,
            "attached": target.attached,
            "canAccessOpener": False,
            "browserContextId": "default",
        }

    def _attach(self, ws: web.WebSocketResponse, target_id: str,
                parent_session_id: str | None = None, *, auto_attached: bool = False) -> str:
        self._session_counter += 1
        sid = f"WS{self._session_counter:04d}"
        self.state.sessions[sid] = _SessionOwner(ws=ws, target_id=target_id,
            parent_session_id=parent_session_id, auto_attached=auto_attached)
        target = next(t for t in self.targets() if t.target_id == target_id)
        self._emit(ws, "Target.attachedToTarget", {
            "sessionId": sid, "targetInfo": self._target_json(target),
            "waitingForDebugger": False,
        }, parent_session_id)
        return sid

    def _detach(self, sid: str) -> None:
        for child_sid, child in list(self.state.sessions.items()):
            if child.parent_session_id == sid:
                self._detach(child_sid)
        owner = self.state.sessions.pop(sid)
        self._emit(owner.ws, "Target.detachedFromTarget", {
            "sessionId": sid, "targetId": owner.target_id,
        }, owner.parent_session_id)
        for pid, entry in list(self.state.pending.items()):
            if entry.session_id == sid:
                self._fail_pending(pid, "Target detached")

    def _on_engine_lifecycle(self, event: dict) -> None:
        if self.running:
            self._sync_targets()

    def _sync_targets(self) -> None:
        current = {t.target_id: t for t in self.targets()}
        epoch_changed = self._engine.epoch != self._target_epoch
        removed = set(self._known_targets) if epoch_changed else set(self._known_targets) - set(current)
        added = set(current) if epoch_changed else set(current) - set(self._known_targets)
        for tid in removed:
            self._frame_ids.pop(tid, None)
            self._tree_frame_ids.pop(tid, None)
            for sid, owner in list(self.state.sessions.items()):
                if owner.target_id == self.browser_id:
                    continue
                if owner.target_id == tid:
                    self._detach(sid)
            for ws in self.state.discover:
                self._emit(ws, "Target.targetDestroyed", {"targetId": tid})
        if removed:
            self.ledger.clear()
            self._execution_contexts.clear()
            for pid, entry in list(self.state.pending.items()):
                if entry.target_id in removed:
                    self._fail_pending(pid, "Target disconnected")
            for ws, tid in list(self.state.direct_targets.items()):
                if tid in removed:
                    asyncio.create_task(ws.close(code=1001, message=b"target disconnected"))
        if added:
            self._execution_contexts.update(getattr(self._engine, "execution_contexts", lambda: {})())
        for tid in (t.target_id for t in self.targets() if t.target_id in added):
            for ws in self.state.discover:
                self._emit(ws, "Target.targetCreated", {"targetInfo": self._target_json(current[tid])})
            for ws in self.state.auto_attach:
                self._attach(ws, tid, auto_attached=True)
        self._target_epoch = self._engine.epoch
        self._known_targets = current

    # -- forwarding to the engine ---------------------------------------------
    def _forward_session(self, ws: web.WebSocketResponse, data: dict) -> None:
        self._forward_command(ws, data)

    def _forward_command(self, ws: web.WebSocketResponse, data: dict) -> None:
        engine = self._engine or get_engine()
        payload = dict(data)
        session_id = payload.pop("sessionId", None)
        owner = self.state.sessions.get(session_id)
        target_id = owner.target_id if owner else self.state.direct_targets.get(ws)
        if target_id:
            payload = self._rewrite_frame_ids(payload, target_id, to_runtime=True)
        orig_id = payload.get("id")
        if orig_id is not None:
            self._pid_counter += 1
            pid = self._pid_counter
            timer = asyncio.get_running_loop().call_later(
                30, self._fail_pending, pid, "Runtime command timed out"
            )
            self.state.pending[pid] = _Pending(ws=ws, orig_id=orig_id,
                session_id=session_id, timer=timer, method=payload.get("method", ""),
                target_id=target_id)
            payload["id"] = pid
        try:
            engine.send_cdp_payload(json.dumps(payload))
        except Exception as error:  # noqa: BLE001
            if orig_id is not None:
                self._fail_pending(pid, str(error))

    def _fail_pending(self, pid: int, message: str) -> None:
        entry = self.state.pending.pop(pid, None)
        if entry is not None:
            if entry.timer:
                entry.timer.cancel()
            self._error(entry.ws, entry.orig_id, -32000, message, entry.session_id)

    def _forward_direct(self, ws: web.WebSocketResponse, text: str) -> None:
        """Direct page clients share the ID broker with browser sessions."""
        try:
            data = json.loads(text)
        except (TypeError, json.JSONDecodeError):
            return
        if isinstance(data, dict):
            data.pop("sessionId", None)
            self._forward_command(ws, data)

    # -- upstream routing ------------------------------------------------------
    def _on_upstream(self, payload: str, method: str) -> None:
        # Defensively order epoch changes before routing or caching this payload.
        self._sync_targets()
        self.ledger.observe(payload, method)
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(data, dict):
            return
        message_id = data.get("id")
        if message_id is not None and message_id in self.state.pending:
            entry = self.state.pending.pop(message_id)
            if entry.timer:
                entry.timer.cancel()
            out = dict(data)
            out["id"] = entry.orig_id
            if entry.target_id:
                if entry.method == "Page.getFrameTree":
                    tree = data.get("result", {}).get("frameTree", {})
                    frame = tree.get("frame", {})
                    if frame.get("id"):
                        self._frame_ids[entry.target_id] = frame["id"]
                        current_frames = set()
                        pending = [tree]
                        while pending:
                            node = pending.pop()
                            if node.get("frame", {}).get("id"):
                                current_frames.add(node["frame"]["id"])
                            pending.extend(node.get("childFrames", []))
                        self._tree_frame_ids[entry.target_id] = current_frames
                out = self._rewrite_frame_ids(out, entry.target_id)
            if entry.session_id:
                out["sessionId"] = entry.session_id
            self._send(entry.ws, json.dumps(out))
            if entry.method in ("Runtime.enable", "Page.getFrameTree") and entry.target_id:
                self._replay_contexts(entry.ws, entry.target_id, entry.session_id)
            return
        if message_id is None and method:
            if method == "Runtime.executionContextCreated":
                context = data.get("params", {}).get("context", {})
                if isinstance(context.get("id"), int):
                    self._execution_contexts[context["id"]] = data
                    if len(self._execution_contexts) > 512:
                        self._execution_contexts.pop(next(iter(self._execution_contexts)))
            elif method == "Runtime.executionContextDestroyed":
                self._execution_contexts.pop(data.get("params", {}).get("executionContextId"), None)
            elif method == "Runtime.executionContextsCleared":
                self._execution_contexts.clear()
            # Flattened CDP events belong to an attached session. Root-level
            # Runtime/Page events are invisible to Playwright's page objects.
            for sid, owner in list(self.state.sessions.items()):
                if self._event_for_target(method, owner.target_id):
                    out = self._rewrite_frame_ids(data, owner.target_id)
                    self._send(owner.ws, json.dumps({**out, "sessionId": sid}))
            for ws, tid in list(self.state.direct_targets.items()):
                if not self._event_for_target(method, tid):
                    continue
                self._send(ws, json.dumps(self._rewrite_frame_ids(data, tid)))

    def _replay_contexts(self, ws, target_id: str, session_id: str | None) -> None:
        if target_id not in self._frame_ids:
            return
        for event in self._execution_contexts.values():
            frame_id = event.get("params", {}).get("context", {}).get("auxData", {}).get("frameId")
            if frame_id and frame_id not in self._tree_frame_ids.get(target_id, set()):
                continue
            out = self._rewrite_frame_ids(event, target_id)
            if session_id:
                out["sessionId"] = session_id
            self._send(ws, json.dumps(out))

    def _rewrite_frame_ids(self, value, target_id: str, *, to_runtime: bool = False):
        """A Chromium page's main frame ID equals its target ID.

        The underlying runtime has one real frame tree, while Portal supplies
        virtual target IDs. Translate frame references in both directions,
        preserving execution-context, DOM-node and request IDs verbatim.
        """
        actual = self._frame_ids.get(target_id)
        if not actual:
            return dict(value)
        old, new = (target_id, actual) if to_runtime else (actual, target_id)

        def rewrite(item, parent=""):
            if isinstance(item, list):
                return [rewrite(v, parent) for v in item]
            if not isinstance(item, dict):
                return item
            return {key: new if val == old and (
                key in ("frameId", "parentFrameId") or
                (key in ("id", "parentId") and parent == "frame")
            ) else rewrite(val, key) for key, val in item.items()}

        return rewrite(value)

    @staticmethod
    def _event_for_target(method: str, target_id: str) -> bool:
        if not target_id.startswith(("webview-", "appservice-")):
            return False
        if method.startswith(("Page.", "DOM.", "CSS.", "Accessibility.", "Overlay.")):
            return target_id.startswith("webview-")
        return True

    # -- low-level senders -----------------------------------------------------
    def _send(self, ws: web.WebSocketResponse, text: str) -> None:
        async def _do() -> None:
            try:
                await ws.send_str(text)
            except Exception:  # noqa: BLE001
                pass

        asyncio.ensure_future(_do())

    def _reply(self, ws: web.WebSocketResponse, message_id: Any, result: dict,
               session_id: str | None = None) -> None:
        if message_id is None:
            return
        out = {"id": message_id, "result": result}
        if session_id:
            out["sessionId"] = session_id
        self._send(ws, json.dumps(out))

    def _error(self, ws: web.WebSocketResponse, message_id: Any, code: int, message: str,
               session_id: str | None = None) -> None:
        if message_id is None:
            return
        out = {"id": message_id, "error": {"code": code, "message": message}}
        if session_id:
            out["sessionId"] = session_id
        self._send(ws, json.dumps(out))

    def _emit(self, ws: web.WebSocketResponse, method: str, params: dict,
              session_id: str | None = None) -> None:
        out = {"method": method, "params": params}
        if session_id:
            out["sessionId"] = session_id
        self._send(ws, json.dumps(out))


_PORTAL: PortalService | None = None


def get_portal() -> PortalService:
    """Process-wide portal singleton."""
    global _PORTAL
    if _PORTAL is None:
        _PORTAL = PortalService()
    return _PORTAL


__all__ = ["PortalService", "TargetInfo", "get_portal"]
