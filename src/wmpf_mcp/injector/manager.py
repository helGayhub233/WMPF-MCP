"""Frida injection manager (docs/02 §3.4).

Renders ``templates/hook.js`` with the resolved offset config and attaches a
session per target PID. Request cancellation rejects commits and drains the
bounded native phase before owned cleanup; hard deadlines interrupt Frida.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from ..core.errors import ErrorCode, ToolError
from ..core.asyncio_utils import drain_task

TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "hook.js"
ERROR_DETAIL_CAP_BYTES = 2048
FAILED_FRAME_COUNT = 3
FAILED_FRAME_BYTES = 16 * 1024 * 1024

RESIGN_HINT = (
    "Inspect the actual attach error and check_environment(scope=system). "
    "Review process ownership/signing/security policy before changing permissions; "
    "the check only returns advice and does not sign or elevate."
)


@dataclass
class _Session:
    pid: int
    session: object  # frida.Session
    script: object | None  # frida.Script, absent until creation succeeds
    accepting: bool = True
    load_started: bool = False
    initialized: threading.Event = field(default_factory=threading.Event)
    ready: bool = False
    init_error: dict | None = None
    installed_hooks: list[dict] = field(default_factory=list)


class _NativeOperation:
    def __init__(self) -> None:
        self.cancelled = threading.Event()
        self._lock = threading.Lock()
        self.native = None
        self.resources: list[_Session] = []
        self.created: list[_Session] = []

    def bind(self, frida):
        with self._lock:
            self.native = frida.Cancellable()
            if self.cancelled.is_set():
                self.native.cancel()
            return self.native

    def reject_commits(self) -> None:
        self.cancelled.set()
        for entry in self.resources:
            entry.initialized.set()

    def cancel(self) -> None:
        self.reject_commits()
        with self._lock:
            if self.native is not None:
                self.native.cancel()

    def check(self) -> None:
        if self.cancelled.is_set():
            raise RuntimeError("native hook operation cancelled")


@dataclass
class InjectionState:
    sessions: list[_Session] = field(default_factory=list)
    hits: dict[str, int] = field(default_factory=dict)
    messages: list[dict] = field(default_factory=list)
    errors: deque[dict] = field(default_factory=lambda: deque(maxlen=10))
    pid_hits: dict[int, dict[str, int]] = field(default_factory=dict)
    last_start_failures: list[dict] = field(default_factory=list)


class InjectorManager:
    """Owns Frida sessions for the current MCP process lifetime."""

    def __init__(self) -> None:
        self.state = InjectionState()
        self._lock = threading.RLock()
        self._operation_lock = asyncio.Lock()
        self._waiters: set[tuple[asyncio.AbstractEventLoop, asyncio.Future]] = set()
        self._failed_frames: deque[tuple[dict, bytes]] = deque()
        self._failed_frame_bytes = 0
        self._failure_sequence = 0

    NATIVE_TIMEOUT_S = 30.0
    CLEANUP_TIMEOUT_S = 10.0
    INITIALIZE_TIMEOUT_S = 5.0

    def _notify_waiters(self) -> None:
        with self._lock:
            waiters = list(self._waiters)
        for loop, future in waiters:
            try:
                loop.call_soon_threadsafe(self._wake_waiter, future)
            except RuntimeError:  # loop already closed
                with self._lock:
                    self._waiters.discard((loop, future))

    @staticmethod
    def _wake_waiter(future: asyncio.Future) -> None:
        if not future.done():
            future.set_result(None)

    async def _run_native(self, function, operation: _NativeOperation,
                          timeout_s: float, *, rollback: bool = False):
        def work():
            with operation.bind(self._load_frida()):
                operation.check()
                return function()

        worker = asyncio.create_task(asyncio.to_thread(work))
        # Some Frida bindings wake their Python wait before the native completion
        # callback on Cancellable.cancel(). For ordinary request cancellation,
        # reject commits immediately but let this bounded phase return its owned
        # resources before rollback. Only the hard deadline interrupts Frida.
        deadline = asyncio.get_running_loop().call_later(timeout_s, operation.cancel)
        try:
            async with asyncio.timeout(timeout_s):
                return await asyncio.shield(worker)
        except BaseException as error:
            operation.reject_commits()
            if isinstance(error, TimeoutError):
                operation.cancel()
            try:
                await drain_task(worker)
            except Exception:
                pass
            deadline.cancel()
            if rollback and operation.resources:
                cleanup = _NativeOperation()
                def clean():
                    with cleanup.bind(self._load_frida()):
                        return self._release_resources(operation.resources)
                task = asyncio.create_task(asyncio.to_thread(clean))
                timer = asyncio.get_running_loop().call_later(self.CLEANUP_TIMEOUT_S, cleanup.cancel)
                try:
                    await drain_task(task)
                except Exception as cleanup_error:
                    # Failed detach remains owned and visible for a later stop.
                    self._record({"type": "cleanup_error", "detail": str(cleanup_error)})
                finally:
                    timer.cancel()
            if isinstance(error, TimeoutError):
                raise ToolError(ErrorCode.HOOK_TIMEOUT, "Native hook operation exceeded its deadline.",
                                remedy="Inspect owned sessions and hook errors before another operation.") from error
            raise
        finally:
            deadline.cancel()

    async def start(self, config_path: Path, pids: list[int]) -> dict:
        async with self._operation_lock:
            operation = _NativeOperation()
            result = await self._run_native(
                lambda: self.start_sync(config_path, pids, _operation=operation),
                operation, self.NATIVE_TIMEOUT_S, rollback=True)
            # Only a completed, uncancelled request commits the staged sessions.
            with self._lock:
                self.state.sessions.extend(operation.created)
            self._notify_waiters()
            return result

    async def stop(self) -> dict:
        async with self._operation_lock:
            if not self.state.sessions:
                return self.stop_sync()
            return await self._run_native(self.stop_sync, _NativeOperation(), self.NATIVE_TIMEOUT_S)

    async def wait_armed(self, timeout_s: float) -> dict:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_s
        while True:
            with self._lock:
                if self.state.last_start_failures:
                    raise ToolError(ErrorCode.INTERNAL, "The latest hook preparation has failed PIDs.",
                                    remedy="Inspect last_start_failures and the failed hook role before another preparation.")
                sessions = [entry for entry in self.state.sessions
                            if entry.accepting and _session_alive(entry.session)]
                if not sessions:
                    raise ToolError(ErrorCode.ORDER_VIOLATION, "No active hooks to wait for.",
                                    remedy="Prepare hooks before waiting for armed callbacks.")
                pids = {entry.pid for entry in sessions}
                if any(self.state.pid_hits.get(pid, {}).get("hook_error", 0) for pid in pids):
                    raise ToolError(ErrorCode.INTERNAL, "Hook error received before armed.",
                                    remedy="Inspect current per-PID hook errors; unchanged waiting will not fix them.")
                if all(self.state.pid_hits.get(pid, {}).get("armed", 0) for pid in pids):
                    return self.status()
                future = loop.create_future()
                self._waiters.add((loop, future))
            try:
                await asyncio.wait_for(future, max(0.0, deadline - loop.time()))
            except TimeoutError as error:
                raise ToolError(ErrorCode.HOOK_TIMEOUT, "No current hook armed before the deadline.") from error
            finally:
                with self._lock:
                    self._waiters.discard((loop, future))

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _load_frida():
        try:
            import frida  # noqa: PLC0415 - optional heavy dependency
        except ImportError as error:
            raise ToolError(
                ErrorCode.DEPS_MISSING,
                "The 'frida' package is not installed.",
                remedy='Install the dynamic extra: uv sync --extra dynamic '
                '(or pip install "wmpf-mcp[dynamic]").',
            ) from error
        return frida

    def _render_script(self, config_path: Path) -> str:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        template_path = TEMPLATE_PATH.with_name("windows.js") if config.get("Format") == "PE" else TEMPLATE_PATH
        template = template_path.read_text(encoding="utf-8")
        # The template embeds the config inside a single-quoted JS string:
        # JSON.parse('@@CONFIG@@') — escape for that literal context.
        literal = (
            json.dumps(config, ensure_ascii=False)
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\n", "\\n")
        )
        return template.replace("@@CONFIG@@", literal)

    def _record(self, payload: dict) -> None:
        with self._lock:
            if (payload.get("type") == "error" or str(payload.get("type", "")).endswith("_error")
                    or str(payload.get("hook", "")).endswith("_error")):
                # Keep a small error summary independently of noisy hook hits.
                # Raw failed frames have a separate byte/count budget; they never
                # appear in tool output or ordinary error/message summaries.
                detail = str(payload.get("detail") or "").encode("utf-8", "replace")
                payload = {key: payload[key] for key in (
                    "type", "pid", "hook", "stage", "error_class", "frame_id",
                    "role", "offset", "address", "instruction", "rollback_complete"
                ) if key in payload}
                payload.update(detail=detail[:ERROR_DETAIL_CAP_BYTES].decode("utf-8", "ignore"),
                               truncated=len(detail) > ERROR_DETAIL_CAP_BYTES, at=time.monotonic())
                self.state.errors.append(dict(payload))
            self.state.messages.append(payload)
            if len(self.state.messages) > 200:
                del self.state.messages[:100]

    def _count(self, hook: str, pid: int | None) -> None:
        with self._lock:
            self.state.hits[hook] = self.state.hits.get(hook, 0) + 1
            if pid is not None:
                counts = self.state.pid_hits.setdefault(pid, {})
                counts[hook] = counts.get(hook, 0) + 1
        if hook in {"armed", "hook_error"}:
            self._notify_waiters()

    def _on_message(self, message: dict, data, *, pid: int | None = None) -> None:
        if message.get("type") == "error":
            self._record({"type": "error", "pid": pid,
                          "stage": "script", "detail": message.get("description")})
            self._count("hook_error", pid)
            return
        payload = message.get("payload") or {}
        if isinstance(payload, dict):
            payload = {**payload, "pid": payload.get("pid", pid)}
            if payload.get("type") == "error":
                payload["detail"] = payload.get("detail") or payload.get("message") or "Hook script failed"
            if payload.get("type") in ("cbor_message", "cbor_event"):
                self._forward_cbor_message(payload, data)
                return
            self._record(payload)
            if payload.get("type") == "hook_hit":
                self._count(str(payload.get("hook")), payload["pid"])
            elif payload.get("type") == "armed":
                self._count("armed", payload["pid"])
            elif payload.get("type") == "error":
                self._count("hook_error", payload["pid"])

    def _on_session_message(self, entry: _Session, operation: _NativeOperation | None,
                            message: dict, data) -> None:
        payload = message.get("payload")
        if isinstance(payload, dict) and payload.get("type") in {"cbor_message", "cbor_event"}:
            if entry.accepting and (not operation or not operation.cancelled.is_set()):
                self._on_message(message, data, pid=entry.pid)
            return
        # Serialize cheap armed/error callbacks with stop and PID reuse. Large
        # CBOR decoding above must not hold the lock used by loop-side status.
        with self._lock:
            if entry.accepting and (not operation or not operation.cancelled.is_set()):
                self._on_message(message, data, pid=entry.pid)
                if message.get("type") == "error" or (isinstance(payload, dict) and payload.get("type") == "error"):
                    entry.ready = False
                    entry.init_error = dict(self.state.errors[-1])
                    entry.initialized.set()
                elif isinstance(payload, dict) and payload.get("type") == "armed" and not entry.init_error:
                    entry.ready = True
                    hooks = payload.get("hooks")
                    if not isinstance(hooks, list):
                        hooks = []
                    entry.installed_hooks = [{key: str(hook[key])[:128]
                                              for key in ("role", "address", "offset") if key in hook}
                                             for hook in hooks[:8] if isinstance(hook, dict)]
                    entry.initialized.set()

    def _forward_cbor_message(self, metadata: dict, data) -> None:
        pid = metadata.get("pid")
        self._count("cbor_received", pid)
        raw = None
        stage = "input"
        try:
            from ..engine import get_engine
            from ..engine.cbor import decode_message

            # Binary Frida messages avoid the old O(n) hex-string expansion.
            # Accept hex from scripts already attached before this upgrade.
            raw = bytes(data) if data is not None else bytes.fromhex(metadata["hex"])
            stage = "decode"
            value = decode_message(raw)
            if not isinstance(value, dict):
                self._count("cbor_ignored", pid)
                return
            response = isinstance(value.get("id"), int) and (
                "result" in value or "error" in value
            )
            event = isinstance(value.get("method"), str) and "id" not in value
            if not response and not event:
                self._count("cbor_ignored", pid)
                return
            # Classification is based on top-level keys, never nested context.id
            # or a string value containing the bytes of "method".
            stage = "serialize"
            payload = json.dumps(value, separators=(",", ":"))
            stage = "forward"
            if get_engine().feed_local_payload(payload, pid=pid):
                self._count("cbor_response" if response else "cbor_event", pid)
            else:
                self._count("cbor_engine_not_running", pid)
        except Exception as error:  # noqa: BLE001 - never break the frida callback
            kind = f"cbor_{stage}_error"
            self._count(kind, pid)
            frame_id = self._retain_failed_frame(raw, metadata, stage, error)
            self._record({"type": kind, "pid": pid, "stage": stage,
                          "error_class": type(error).__name__, "frame_id": frame_id,
                          "detail": str(error)})

    def _retain_failed_frame(self, raw: bytes | None, metadata: dict,
                             stage: str, error: Exception) -> str | None:
        if raw is None:
            return None
        retained = raw[:FAILED_FRAME_BYTES]
        with self._lock:
            self._failure_sequence += 1
            info = {"frame_id": f"cbor-{self._failure_sequence}", "pid": metadata.get("pid"),
                    "stage": stage, "error_class": type(error).__name__,
                    "frame_bytes": len(raw), "retained_bytes": len(retained),
                    "truncated": len(retained) != len(raw)}
            if isinstance(metadata.get("size"), int):
                info["declared_bytes"] = metadata["size"]
            while self._failed_frames and (
                len(self._failed_frames) >= FAILED_FRAME_COUNT
                or self._failed_frame_bytes + len(retained) > FAILED_FRAME_BYTES
            ):
                _, evicted = self._failed_frames.popleft()
                self._failed_frame_bytes -= len(evicted)
            self._failed_frames.append((info, retained))
            self._failed_frame_bytes += len(retained)
            return info["frame_id"]

    def failed_frame(self, frame_id: str) -> tuple[dict, bytes] | None:
        """Explicit in-process diagnostic access; no automatic disk writes.

        Only failures are retained, at most three frames / 16 MiB total. A frame
        above that byte budget is a marked prefix, never a replayable full sample.
        Returned metadata is a copy and bytes are immutable.
        """
        with self._lock:
            for info, raw in self._failed_frames:
                if info["frame_id"] == frame_id:
                    return dict(info), raw
        return None

    # -- lifecycle (blocking; call via asyncio.to_thread) --------------------
    def start_sync(self, config_path: Path, pids: list[int], *, _operation: _NativeOperation | None = None) -> dict:
        frida = self._load_frida()
        source = self._render_script(config_path)
        device = frida.get_local_device()

        # idempotent coverage: drop dead sessions and skip already-injected pids
        # (re-running start is the documented way to cover new instances)
        alive_sessions: list[_Session] = []
        for item in self.state.sessions:
            if _session_alive(item.session):
                if not item.accepting:
                    raise ToolError(ErrorCode.ORDER_VIOLATION, "Previous hook cleanup is incomplete.",
                                    remedy="Stop the retained owned session before another attach.")
                if not item.ready or item.init_error:
                    raise ToolError(ErrorCode.ORDER_VIOLATION, "An owned hook script is not initialized.",
                                    remedy="Inspect the failed role and stop or force-replace the owned script.")
                alive_sessions.append(item)
            else:
                item.accepting = False
        with self._lock:
            self.state.sessions = alive_sessions
        already = {item.pid for item in alive_sessions}
        targets = [pid for pid in pids if pid not in already]

        injected: list[dict] = [
            {"pid": item.pid, "ok": True, "already": True} for item in alive_sessions
        ]
        for pid in targets:
            session = None
            entry = None
            try:
                if _operation:
                    _operation.check()
                with self._lock:
                    self.state.pid_hits.pop(pid, None)
                session = device.attach(pid)
                entry = _Session(pid, session, None)
                if _operation:
                    _operation.resources.append(entry)
                    _operation.check()
                script = session.create_script(source)
                entry.script = script
                script.on("message", lambda message, data, entry=entry:
                          self._on_session_message(entry, _operation, message, data))
                # Keep creation and loading in one bounded initialization segment
                # so rollback receives an initialized script. Cancellation still
                # prevents session commit and rolls that script back below.
                entry.load_started = True
                script.load()
                if _operation:
                    _operation.check()
                if not entry.initialized.wait(self.INITIALIZE_TIMEOUT_S):
                    raise ToolError(ErrorCode.HOOK_TIMEOUT, "Hook script did not acknowledge complete initialization.")
                if _operation:
                    _operation.check()
                if entry.init_error or not entry.ready:
                    raise RuntimeError((entry.init_error or {}).get("detail", "Hook initialization did not complete"))
                if _operation:
                    _operation.created.append(entry)
                else:
                    with self._lock:
                        self.state.sessions.append(entry)
                    self._notify_waiters()
                injected.append({"pid": pid, "ok": True, "hooks": [dict(hook) for hook in entry.installed_hooks]})
            except Exception as error:  # noqa: BLE001 - frida raises many types
                if _operation and _operation.cancelled.is_set():
                    raise
                if session is not None:
                    try:
                        self._release_resources([entry])
                    except Exception:  # noqa: BLE001
                        if _operation:
                            raise
                message = str(error)
                refused = "unable to access" in message.lower() or "permission" in message.lower()
                injected.append({
                    "pid": pid,
                    "ok": False,
                    "error": message,
                    "permission_refused": refused,
                    "hook_failure": dict(entry.init_error) if entry and entry.init_error else None,
                    "error_code": error.code.value if isinstance(error, ToolError) else ErrorCode.INTERNAL.value,
                })
        with self._lock:
            self.state.last_start_failures = [dict(item) for item in injected if not item["ok"]]
        if not any(item["ok"] for item in injected):
            refused_pids = [item["pid"] for item in injected if item.get("permission_refused")]
            if refused_pids:
                raise ToolError(
                    ErrorCode.PERMISSION,
                    f"Frida attach was refused for every target: {refused_pids}",
                    remedy=RESIGN_HINT,
                    remedy_detail={"pids": refused_pids},
                )
            if all(item.get("error_code") == ErrorCode.HOOK_TIMEOUT.value for item in injected):
                raise ToolError(ErrorCode.HOOK_TIMEOUT, "No target acknowledged complete hook initialization.",
                                remedy_detail={"attempts": injected})
            raise ToolError(
                ErrorCode.INTERNAL,
                "No target completed hook initialization.",
                remedy=RESIGN_HINT,
                remedy_detail={"attempts": injected},
            )
        return {"injected": injected}

    def stop_sync(self) -> dict:
        with self._lock:
            sessions = list(self.state.sessions)
        result = self._release_resources(sessions)
        with self._lock:
            self.state.last_start_failures = []
        return result

    def _release_resources(self, sessions: list[_Session]) -> dict:
        unloaded: list[dict] = []
        failures: list[dict] = []
        with self._lock:
            for entry in sessions:
                entry.accepting = False
                entry.initialized.set()
        self._notify_waiters()
        for entry in sessions:
            try:
                if entry.script is not None and entry.load_started:
                    entry.script.unload()
            except Exception:  # noqa: BLE001 - best effort detach
                pass
            try:
                entry.session.detach()
                released = True
            except Exception as error:  # noqa: BLE001
                released = not _session_alive(entry.session)
                if not released:
                    failures.append({"pid": entry.pid, "error": str(error)})
            with self._lock:
                if released:
                    self.state.sessions = [item for item in self.state.sessions if item is not entry]
                    if not any(item.pid == entry.pid for item in self.state.sessions):
                        self.state.pid_hits.pop(entry.pid, None)
                elif not any(item is entry for item in self.state.sessions):
                    self.state.sessions.append(entry)
            if not released:
                continue
            unloaded.append({"pid": entry.pid, "ok": True})
        self._notify_waiters()
        if failures:
            raise ToolError(ErrorCode.INTERNAL, "Native hook cleanup incomplete; sessions remain owned.",
                            remedy_detail={"failures": failures, "unloaded": unloaded})
        return {"unloaded": unloaded}

    # -- status --------------------------------------------------------------
    def status(self) -> dict:
        with self._lock:
            hits = dict(self.state.hits)
            pid_hits = {pid: dict(counts) for pid, counts in self.state.pid_hits.items()}
            messages = list(self.state.messages[-10:])
            errors = [dict(error) for error in self.state.errors]
            failure_capture = {"max_frames": FAILED_FRAME_COUNT, "max_bytes": FAILED_FRAME_BYTES,
                               "retained_bytes": self._failed_frame_bytes,
                               "frames": [dict(info) for info, _ in self._failed_frames]}
            last_start_failures = [dict(item, hook_failure=dict(item["hook_failure"]) if item.get("hook_failure") else None)
                                   for item in self.state.last_start_failures]
            sessions = list(self.state.sessions)
        return {
            "active": any(_session_alive(entry.session) for entry in sessions),
            "sessions": [
                {"pid": entry.pid, "alive": _session_alive(entry.session),
                 "initialization": "failed" if entry.init_error else "ready" if entry.ready else "loading",
                 "installed_hooks": [dict(hook) for hook in entry.installed_hooks]}
                for entry in sessions
            ],
            "hook_hits": [
                {"hook": hook, "count": count}
                for hook, count in sorted(hits.items())
            ],
            "pid_hits": pid_hits,
            "armed_pids": [entry.pid for entry in sessions if entry.accepting
                           and _session_alive(entry.session) and pid_hits.get(entry.pid, {}).get("armed", 0)
                           and not pid_hits.get(entry.pid, {}).get("hook_error", 0)],
            "last_start_failures": last_start_failures,
            "recent_messages": messages,
            "recent_errors": errors,
            "failure_capture": failure_capture,
        }


def _session_alive(session) -> bool:
    try:
        return not session.is_detached
    except Exception:  # noqa: BLE001
        return False


_MANAGER: InjectorManager | None = None


def get_injector() -> InjectorManager:
    global _MANAGER
    if _MANAGER is None:
        _MANAGER = InjectorManager()
    return _MANAGER
