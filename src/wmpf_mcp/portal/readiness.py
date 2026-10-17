"""Event-driven business readiness through an isolated standard CDP session."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import secrets
from urllib.parse import urlparse

from aiohttp import ClientSession, ClientTimeout, WSMsgType

from ..core.asyncio_utils import drain_task
from .probe import CAPABILITIES

_SCRIPT = Path(__file__).with_suffix(".js").read_text(encoding="utf-8")


class _Client:
    def __init__(self, ws):
        self.ws = ws
        self.sequence = 0
        self.pending = {}
        self.bindings = {}
        self.contexts = {}
        self.generation = 0
        self.changed = asyncio.Event()
        self.closed = False
        self.reader = asyncio.create_task(self.receive())

    async def receive(self):
        try:
            async for message in self.ws:
                if message.type != WSMsgType.TEXT:
                    break
                packet = message.json()
                if "id" in packet:
                    future = self.pending.get(packet["id"])
                    if future is not None and not future.done():
                        if packet.get("error"):
                            future.set_exception(ValueError(str(packet["error"])))
                        else:
                            future.set_result(packet.get("result", {}))
                    continue
                method, params = packet.get("method"), packet.get("params", {})
                if method == "Runtime.executionContextCreated":
                    context = params.get("context", {})
                    if isinstance(context.get("id"), int) and len(self.contexts) < 512:
                        self.contexts[context["id"]] = dict(context)
                    self.changed.set()
                elif method == "Runtime.executionContextDestroyed":
                    context_id = params.get("executionContextId")
                    self.contexts.pop(context_id, None)
                    for registered_id, future in self.bindings.values():
                        if registered_id == context_id and not future.done():
                            future.set_result({"ready": False, "reason": "context_destroyed"})
                    self.changed.set()
                elif method == "Runtime.executionContextsCleared":
                    self.contexts.clear()
                    self.generation += 1
                    for _, future in self.bindings.values():
                        if not future.done():
                            future.set_result({"ready": False, "reason": "contexts_cleared"})
                    self.changed.set()
                elif method == "Runtime.bindingCalled":
                    target = self.bindings.get(params.get("name"))
                    if target and target[0] == params.get("executionContextId") and not target[1].done():
                        try:
                            target[1].set_result(json.loads(params.get("payload", "")))
                        except (ValueError, TypeError):
                            target[1].set_exception(ValueError("Malformed readiness binding payload"))
                elif method == "Target.detachedFromTarget":
                    break
                elif method in {"Page.frameAttached", "Page.frameNavigated", "Page.frameDetached"}:
                    self.changed.set()
        except Exception:
            # The consumer gets a structured disconnect, not an orphan reader error.
            pass
        finally:
            self.closed = True
            self.changed.set()
            for future in [*self.pending.values(), *(item[1] for item in self.bindings.values())]:
                if not future.done():
                    future.set_exception(ValueError("Readiness session disconnected"))

    async def rpc(self, method, params=None, session=None):
        if self.closed:
            raise ValueError("Readiness session disconnected")
        self.sequence += 1
        sequence = self.sequence
        future = asyncio.get_running_loop().create_future()
        self.pending[sequence] = future
        packet = {"id": sequence, "method": method, "params": params or {}}
        if session:
            packet["sessionId"] = session
        try:
            await self.ws.send_json(packet)
            return await future
        finally:
            self.pending.pop(sequence, None)

    async def close(self):
        await self.ws.close()
        self.reader.cancel()
        await asyncio.gather(self.reader, return_exceptions=True)


def _frames(tree):
    result = {}
    pending = [tree]
    while pending and len(result) < 256:
        node = pending.pop()
        frame = node.get("frame", {})
        if frame.get("id"):
            result[frame["id"]] = frame
        pending.extend(node.get("childFrames") or [])
    return result


async def probe_page(port: int, selector: str, frame_name: str | None, timeout_s: float) -> dict:
    data = {"layer": "page", "port": port, "selector": selector, "passed": False,
            "checks": [], "observed_frames": []}
    client = None
    attached = None
    jobs = {}
    registrations = []
    deadline = asyncio.get_running_loop().time() + timeout_s

    async def watch(context, frame):
        token = secrets.token_hex(12)
        key, binding = "__wmpf_ready_" + token, "__wmpf_signal_" + token
        context_id = context["id"]
        future = asyncio.get_running_loop().create_future()
        client.bindings[binding] = (context_id, future)
        registrations.append((context_id, key, binding))
        try:
            await client.rpc("Runtime.addBinding", {"name": binding, "executionContextId": context_id}, attached)
            args = [selector, key, binding, max(1, int((deadline - asyncio.get_running_loop().time()) * 1000))]
            result = await client.rpc("Runtime.evaluate", {"contextId": context_id,
                "expression": _SCRIPT.replace("__ARGS__", json.dumps(args)), "returnByValue": True}, attached)
            if result.get("exceptionDetails"):
                raise ValueError("Readiness observer could not execute in this context")
            value = result.get("result", {}).get("value", {})
            if value.get("reason") == "no_document":
                return value
            value = await future
            return {**value, "context_id": context_id, "frame_id": frame["id"], "frame_name": frame.get("name", "")}
        finally:
            client.bindings.pop(binding, None)
            if not future.done():
                future.cancel()

    async def cleanup():
        for task in jobs.values():
            if not task.done():
                task.cancel()
        await asyncio.gather(*jobs.values(), return_exceptions=True)
        if client is None:
            return
        async def remove(context_id, key, binding):
            expression = (f"globalThis[{json.dumps(key)}]?.cancel();"
                          f"delete globalThis[{json.dumps(binding)}]")
            try:
                await client.rpc("Runtime.evaluate", {"contextId": context_id,
                    "expression": expression, "returnByValue": True}, attached)
            except (ValueError, RuntimeError):
                pass
            try:
                await client.rpc("Runtime.removeBinding", {"name": binding}, attached)
            except (ValueError, RuntimeError):
                pass
        try:
            async with asyncio.timeout(2):
                if not client.closed and attached:
                    await asyncio.gather(*(remove(*row) for row in registrations))
                    await client.rpc("Target.detachFromTarget", {"sessionId": attached})
                await client.close()
        except (ValueError, TimeoutError):
            pass
        finally:
            client.reader.cancel()
            await asyncio.gather(client.reader, return_exceptions=True)
            # Closing the HTTP session releases a peer that never acknowledged close.
            await http.close()

    async with ClientSession(trust_env=False, timeout=ClientTimeout(total=None, sock_connect=min(timeout_s, 10))) as http:
        try:
            async with asyncio.timeout(timeout_s):
                async with http.get(f"http://127.0.0.1:{port}/json/version/", allow_redirects=False) as response:
                    if 300 <= response.status < 400:
                        raise ValueError("Portal discovery redirects are not followed")
                    response.raise_for_status()
                    endpoint = (await response.json()).get("webSocketDebuggerUrl", "")
                parsed = urlparse(endpoint)
                if parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.port != port:
                    raise ValueError("Discovery did not return this local Portal")
                client = _Client(await http.ws_connect(endpoint))
                pages = [p for p in (await client.rpc("Target.getTargets")).get("targetInfos", []) if p.get("type") == "page"]
                if not pages:
                    raise ValueError("No current page target")
                attached = (await client.rpc("Target.attachToTarget", {"targetId": pages[0]["targetId"], "flatten": True})).get("sessionId")
                if not attached:
                    raise ValueError("No attached session")
                await client.rpc("Page.enable", session=attached)
                await client.rpc("Runtime.enable", session=attached)
                attempted = set()
                while True:
                    client.changed.clear()
                    if client.closed:
                        raise ValueError("Runtime disconnected during business-resource loading")
                    frames = _frames((await client.rpc("Page.getFrameTree", session=attached)).get("frameTree", {}))
                    data["observed_frames"] = [{"id": f["id"], "name": f.get("name", "")} for f in frames.values()]
                    candidates = [context for context in client.contexts.values()
                                  if context.get("auxData", {}).get("isDefault") is not False]
                    for context in candidates[:16]:
                        identifier = (client.generation, context.get("uniqueId", context["id"]))
                        if identifier in attempted:
                            continue
                        frame = frames.get(context.get("auxData", {}).get("frameId"))
                        if not frame or (frame_name is not None and frame.get("name", "") != frame_name):
                            continue
                        attempted.add(identifier)
                        try:
                            result = await asyncio.wait_for(client.rpc("Runtime.evaluate", {
                                "contextId": context["id"], "expression": CAPABILITIES, "returnByValue": True}, attached), 1)
                            capabilities = result.get("result", {}).get("value") or {}
                            if capabilities.get("dom") and capabilities.get("eval"):
                                jobs[identifier] = asyncio.create_task(watch(context, frame))
                        except (ValueError, TimeoutError):
                            continue
                    changed = asyncio.create_task(client.changed.wait())
                    try:
                        pending = [task for task in jobs.values() if not task.done()]
                        completed = [task for task in jobs.values() if task.done()]
                        if not completed:
                            done, _ = await asyncio.wait([changed, *pending], return_when=asyncio.FIRST_COMPLETED)
                            completed = [task for task in done if task is not changed]
                        for task in completed:
                            value = task.result()
                            identifier = next(key for key, job in jobs.items() if job is task)
                            current = client.contexts.get(value.get("context_id"), {})
                            still_current = identifier == (client.generation, current.get("uniqueId", current.get("id")))
                            if value.get("ready") and still_current:
                                data.update(passed=True, matched=value)
                                data["checks"].append({"check": "business_selector_visible", "passed": True})
                                return data
                            if value.get("reason") == "invalid_selector":
                                data.update(failure_kind="invalid_selector", error=value.get("error"))
                                return data
                            for identifier, job in list(jobs.items()):
                                if job is task:
                                    del jobs[identifier]
                    finally:
                        changed.cancel()
                        await asyncio.gather(changed, return_exceptions=True)
        except Exception as error:
            data["error"] = str(error) or "Business resources did not satisfy ready_selector before the deadline"
            data["checks"].append({"check": "business_selector_visible", "passed": False})
        finally:
            await drain_task(asyncio.create_task(cleanup()))
    return data
