"""Debug engine: the 9421 miniapp server + CDP proxy websockets (docs/02 §3.5).

One process-wide engine instance. In this build the miniapp side is the
protocol source of truth; the CDP proxy exposes a raw pass-through channel for
devtools:// frontends, while the portal (docs/06) consumes the engine object
directly through ``send_cdp_command`` / ``on_cdp_event``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import random
import time
from collections import OrderedDict, deque
from typing import Any, Callable

from aiohttp import WSMsgType, web

from ..core.config import DEBUG_PORT, resolve_cdp_port

from .codec import (
    CAT_CHROME_DEVTOOLS,
    CAT_CHROME_DEVTOOLS_RESULT,
    CAT_PING,
    CAT_SETUP_CONTEXT,
    CodecError,
    ChromeDevtools,
    DebugMessage,
    build_chrome_devtools,
)
from .proto import ProtoError


class EngineError(RuntimeError):
    """Engine operation failed (no miniapp, not running, ...)."""


class MiniappTimeoutError(TimeoutError):
    """No (setup-context-complete) miniapp connection within the deadline."""


def _fingerprint_data(value: Any) -> Any:
    """Match integral JSON/CBOR numbers without changing delivered payloads."""
    if isinstance(value, dict):
        return {key: _fingerprint_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_fingerprint_data(item) for item in value]
    if type(value) is float and math.isfinite(value) and value.is_integer():
        if value == 0.0 and math.copysign(1.0, value) < 0:
            return value
        return int(value)
    return value


class DebugEngine:
    """Owns the 9421 server, the CDP proxy port, and the CDP command bus."""

    def __init__(self) -> None:
        self.running = False
        self.debug_port: int | None = None
        self.cdp_port: int | None = None

        self.miniapp_clients: set[web.WebSocketResponse] = set()
        self.cdp_clients: set[web.WebSocketResponse] = set()

        self.epoch = 0
        self.connected_at: float | None = None  # monotonic, last connect
        self.setup_context_at: float | None = None
        self.last_disconnect_at: float | None = None
        self.messages_seen = 0
        self.last_category: str | None = None
        self.recent: deque[dict[str, Any]] = deque(maxlen=100)

        self._seq = 0
        self._cmd_id = 80000
        self._pending: dict[int, asyncio.Future] = {}
        self._event_listeners: dict[str, list[Callable[[dict], None]]] = {}
        self._upstream_listeners: list[Callable[[str, str], None]] = []
        self._lifecycle_listeners: list[Callable[[dict], None]] = []
        self._execution_contexts: dict[int, dict] = {}
        self._wakeup = asyncio.Event()
        self._stop_generation = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._recent_payloads: OrderedDict[bytes, tuple[str, float]] = OrderedDict()
        self.empty_payloads_dropped = 0
        self.duplicate_payloads_dropped = 0
        self.local_payloads_seen = 0

        self._debug_app = web.Application()
        self._debug_app.router.add_get("/", self._miniapp_ws)
        self._cdp_app = web.Application()
        self._cdp_app.router.add_get("/", self._cdp_ws)
        self._debug_runner: web.AppRunner | None = None
        self._cdp_runner: web.AppRunner | None = None

    # -- notes ---------------------------------------------------------------
    def _note(self, text: str) -> None:
        self.recent.append({"t": round(time.monotonic(), 3), "note": text})

    # -- lifecycle -----------------------------------------------------------
    async def start(self, debug_port: int, cdp_port: int) -> dict:
        if self.running:
            return {"already_running": True, **self.status()}
        self._loop = asyncio.get_running_loop()
        try:
            self._debug_runner = web.AppRunner(self._debug_app, access_log=None)
            await self._debug_runner.setup()
            debug_site = web.TCPSite(self._debug_runner, "127.0.0.1", debug_port)
            self._cdp_runner = web.AppRunner(self._cdp_app, access_log=None)
            await self._cdp_runner.setup()
            cdp_site = web.TCPSite(self._cdp_runner, "127.0.0.1", cdp_port)
            await debug_site.start()
            await cdp_site.start()
        except (OSError, asyncio.CancelledError):
            await self._close_runners()
            raise
        self.running = True
        self.debug_port = debug_port
        self.cdp_port = cdp_port
        self._note(f"engine started (debug={debug_port}, cdp={cdp_port})")
        self._notify_lifecycle("started")
        return {"started": True, "debug_port": debug_port, "cdp_port": cdp_port}

    async def _close_runners(self) -> None:
        for runner in (self._debug_runner, self._cdp_runner):
            if runner is not None:
                try:
                    await runner.cleanup()
                except Exception:  # noqa: BLE001 - cleanup best effort
                    pass
        self._debug_runner = None
        self._cdp_runner = None

    async def stop(self) -> dict:
        if not self.running:
            return {"stopped": False, "reason": "not running"}
        self.running = False
        self._stop_generation += 1
        self._loop = None
        self._notify_lifecycle("stopped")
        for future in self._pending.values():
            if not future.done():
                future.set_exception(EngineError("engine stopped"))
        self._pending.clear()
        for ws in list(self.miniapp_clients) + list(self.cdp_clients):
            try:
                await ws.close()
            except Exception:  # noqa: BLE001
                pass
        self.miniapp_clients.clear()
        self.cdp_clients.clear()
        self.setup_context_at = None
        await self._close_runners()
        self._recent_payloads.clear()
        self._execution_contexts.clear()
        self._note("engine stopped")
        return {"stopped": True}

    def status(self) -> dict:
        debug_port = self.debug_port if self.running else DEBUG_PORT
        cdp_port = self.cdp_port if self.running else resolve_cdp_port()
        return {
            "running": self.running,
            "listening": {
                str(debug_port): self.running,
                str(cdp_port): self.running,
            },
            "miniapp_connected": bool(self.miniapp_clients),
            "epoch": self.epoch,
            "setup_context_seen": self.setup_context_at is not None,
            "messages_seen": self.messages_seen,
            "last_category": self.last_category,
            "cdp_clients": len(self.cdp_clients),
            "local_payloads_seen": self.local_payloads_seen,
            "empty_payloads_dropped": self.empty_payloads_dropped,
            "duplicate_payloads_dropped": self.duplicate_payloads_dropped,
            "recent": list(self.recent)[-8:],
        }

    # -- miniapp side (9421) -------------------------------------------------
    async def _miniapp_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(max_msg_size=0)
        await ws.prepare(request)
        self.miniapp_clients.add(ws)
        self.epoch += 1
        self.connected_at = time.monotonic()
        self.setup_context_at = None
        self._recent_payloads.clear()
        self._note(f"miniapp connected (epoch={self.epoch})")
        self._notify_lifecycle("connected")
        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    self._on_miniapp_bytes(msg.data)
                elif msg.type == WSMsgType.TEXT:
                    self._on_miniapp_bytes(msg.data.encode("utf-8", "replace"))
        finally:
            self.miniapp_clients.discard(ws)
            self.last_disconnect_at = time.monotonic()
            if not self.miniapp_clients:
                self.setup_context_at = None
                for future in self._pending.values():
                    if not future.done():
                        future.set_exception(EngineError("miniapp disconnected"))
                self._pending.clear()
            self._note("miniapp disconnected")
            self._notify_lifecycle("disconnected")
        return ws

    def _on_miniapp_bytes(self, buf: bytes) -> None:
        self.messages_seen += 1
        try:
            message = DebugMessage.parse(buf)
        except ProtoError as error:
            self._note(f"unparseable message ({error})")
            return
        self.last_category = message.category
        if message.category == CAT_SETUP_CONTEXT:
            self.setup_context_at = time.monotonic()
            self._note("setupContext received")
            self._notify_lifecycle("setup_context")
        elif message.category in (CAT_CHROME_DEVTOOLS_RESULT, CAT_CHROME_DEVTOOLS):
            try:
                inner = ChromeDevtools.parse(message.payload_bytes())
            except (CodecError, ProtoError) as error:
                self._note(f"bad {message.category} payload ({error})")
                return
            self._dispatch_miniapp_payload(inner.payload)
        elif message.category == CAT_PING:
            self._note("ping")

    def _dispatch_miniapp_payload(self, payload: str, source: str = "runtime") -> None:
        if source != "runtime":
            self.local_payloads_seen += 1
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            self._note("non-JSON CDP payload from miniapp")
            return
        if not isinstance(data, dict):
            return
        if not data:
            self.empty_payloads_dropped += 1
            return
        # The hook and native transport can deliver the same envelope. Drop
        # only a matching copy from another source; repeated events on the
        # same source are legitimate. Keep memory bounded even for screenshots.
        fingerprint = hashlib.sha256(
            json.dumps(_fingerprint_data(data), sort_keys=True, separators=(",", ":")).encode()
        ).digest()
        now = time.monotonic()
        previous = self._recent_payloads.get(fingerprint)
        if previous and previous[0] != source and now - previous[1] < 1.0:
            self.duplicate_payloads_dropped += 1
            return
        self._recent_payloads[fingerprint] = (source, now)
        self._recent_payloads.move_to_end(fingerprint)
        if len(self._recent_payloads) > 512:
            self._recent_payloads.popitem(last=False)
        message_id = data.get("id")
        if message_id is not None and message_id in self._pending:
            future = self._pending.pop(message_id)
            if not future.done():
                future.set_result(data)
        method = data.get("method")
        if method == "Runtime.executionContextCreated":
            context = data.get("params", {}).get("context", {})
            if isinstance(context.get("id"), int) and context.get("auxData", {}).get("isDefault") is not False:
                self._execution_contexts[context["id"]] = data
                if len(self._execution_contexts) > 128:
                    self._execution_contexts.pop(next(iter(self._execution_contexts)))
        elif method == "Runtime.executionContextDestroyed":
            self._execution_contexts.pop(data.get("params", {}).get("executionContextId"), None)
        elif method == "Runtime.executionContextsCleared":
            self._execution_contexts.clear()
        if method:
            for callback in list(self._event_listeners.get(method, ())):
                try:
                    callback(data)
                except Exception:  # noqa: BLE001 - listeners must not break the bus
                    pass
        for listener in list(self._upstream_listeners):
            try:
                listener(payload, method or "")
            except Exception:  # noqa: BLE001
                pass
        self.broadcast_to_cdp_clients(payload)

    def execution_contexts(self) -> dict[int, dict]:
        """Observed default contexts, independent of Portal or transport sockets.

        Runtime.enable need not replay contexts when the shared domain is already
        enabled. Consumers must filter this snapshot against a fresh frame tree.
        Native destruction/clear events and Engine.stop invalidate the cache.
        """
        return dict(self._execution_contexts)

    # -- CDP proxy side (raw pass-through) -----------------------------------
    async def _cdp_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(max_msg_size=0)
        await ws.prepare(request)
        self.cdp_clients.add(ws)
        self._note("cdp client connected")
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    payload = msg.data
                elif msg.type == WSMsgType.BINARY:
                    payload = msg.data.decode("utf-8", "replace")
                else:
                    continue
                try:
                    self.send_cdp_payload(payload)
                except EngineError as error:
                    try:
                        command = json.loads(payload)
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if isinstance(command, dict) and command.get("id") is not None:
                        await self._safe_send(ws, json.dumps({
                            "id": command["id"], "error": {"code": -32000, "message": str(error)}
                        }))
        finally:
            self.cdp_clients.discard(ws)
            self._note("cdp client disconnected")
        return ws

    def broadcast_to_cdp_clients(self, payload: str) -> None:
        for ws in list(self.cdp_clients):
            asyncio.ensure_future(self._safe_send(ws, payload))

    @staticmethod
    async def _safe_send(ws: web.WebSocketResponse, data: str | bytes) -> None:
        try:
            if isinstance(data, bytes):
                await ws.send_bytes(data)
            else:
                await ws.send_str(data)
        except Exception:  # noqa: BLE001 - client may have vanished
            pass

    # -- command bus ---------------------------------------------------------
    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def send_cdp_payload(self, payload: str) -> None:
        """Fire-and-forget: wrap and push one CDP JSON string to the miniapp.

        ``op_id`` must be non-zero: the runtime answers op_id 0 with an empty
        JSON object (verified on 25800), which is unroutable. The verified
        WMPFDebugger implementation uses a random 1..100 op id.
        """
        if not self.miniapp_clients:
            raise EngineError("no miniapp client connected")
        buf = build_chrome_devtools(
            payload, seq=self._next_seq(), op_id=random.randint(1, 100)
        )
        for ws in list(self.miniapp_clients):
            asyncio.ensure_future(self._safe_send(ws, buf))

    async def send_cdp_command(
        self, method: str, params: dict | None = None, timeout: float = 8.0
    ) -> dict:
        """Send a CDP command and await the matching response dict."""
        if not self.miniapp_clients:
            raise EngineError("no miniapp client connected")
        self._cmd_id += 1
        command_id = self._cmd_id
        payload = json.dumps({"id": command_id, "method": method, "params": params or {}})
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[command_id] = future
        try:
            self.send_cdp_payload(payload)
            return await asyncio.wait_for(future, timeout)
        finally:
            self._pending.pop(command_id, None)

    def on_cdp_event(self, method: str, callback: Callable[[dict], None]) -> None:
        self._event_listeners.setdefault(method, []).append(callback)
    def off_cdp_event(self, method: str, callback: Callable[[dict], None]) -> None:
        listeners = self._event_listeners.get(method, [])
        if callback in listeners:
            listeners.remove(callback)

    def on_cdp_upstream(self, listener: Callable[[str, str], None]) -> None:
        """Subscribe to every upstream CDP payload (raw string + method)."""
        self._upstream_listeners.append(listener)

    def on_lifecycle(self, listener: Callable[[dict], None]) -> None:
        """Subscribe on the Engine loop; notifications precede new CDP traffic."""
        self._lifecycle_listeners.append(listener)

    def off_lifecycle(self, listener: Callable[[dict], None]) -> None:
        if listener in self._lifecycle_listeners:
            self._lifecycle_listeners.remove(listener)

    def _notify_lifecycle(self, kind: str) -> None:
        self._wakeup.set()
        event = {"kind": kind, "epoch": self.epoch}
        for listener in list(self._lifecycle_listeners):
            try:
                listener(event)
            except Exception:  # noqa: BLE001 - isolate observers from transport
                pass

    def _dispatch_local_payload(self, payload: str, source: str, epoch: int) -> None:
        if self.running and epoch == self.epoch:
            self._dispatch_miniapp_payload(payload, source)

    def feed_local_payload(self, payload: str, *, pid: int | None = None) -> bool:
        """Inject a locally produced CDP payload into the normal upstream flow.

        Used for responses and events recovered from the native message stream
        (CBOR plus JSON control messages)
        by the injector (the runtime's own output path can filter them away); the
        payload reaches the same listeners, portal fan-out and raw CDP clients
        as if the miniapp had sent it.

        Frida invokes callbacks on its own thread. All futures, WebSockets and
        portal listeners must be touched on the loop which started the engine.
        """
        loop = self._loop
        if not self.running or loop is None or loop.is_closed():
            return False
        try:
            loop.call_soon_threadsafe(
                self._dispatch_local_payload, payload, f"frida:{pid}", self.epoch
            )
        except RuntimeError:
            return False
        return True

    def off_cdp_upstream(self, listener: Callable[[str, str], None]) -> None:
        if listener in self._upstream_listeners:
            self._upstream_listeners.remove(listener)

    # -- waiting -------------------------------------------------------------
    async def wait_miniapp(
        self, timeout_s: float = 120.0, require_setup_context: bool = True
    ) -> dict:
        if not self.running:
            raise EngineError("engine is not running")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_s
        generation = self._stop_generation
        while True:
            if not self.running or generation != self._stop_generation:
                raise EngineError("engine stopped while waiting for miniapp")
            connected = bool(self.miniapp_clients)
            ready = connected and (
                not require_setup_context or self.setup_context_at is not None
            )
            if ready:
                return {
                    "connected_at": self.connected_at,
                    "epoch": self.epoch,
                    "setup_context_seen": self.setup_context_at is not None,
                    "messages_seen": self.messages_seen,
                }
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise MiniappTimeoutError(
                    f"no miniapp connection within {timeout_s:g}s"
                )
            self._wakeup.clear()
            try:
                await asyncio.wait_for(self._wakeup.wait(), remaining)
            except asyncio.TimeoutError as error:
                raise MiniappTimeoutError(
                    f"no miniapp connection within {timeout_s:g}s"
                ) from error


_ENGINE: DebugEngine | None = None


def get_engine() -> DebugEngine:
    """Process-wide engine singleton."""
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = DebugEngine()
    return _ENGINE


__all__ = [
    "DebugEngine",
    "EngineError",
    "MiniappTimeoutError",
    "get_engine",
]
