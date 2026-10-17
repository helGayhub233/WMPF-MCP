"""A bounded standard-CDP client probe, isolated from other Portal clients."""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from aiohttp import ClientSession, ClientTimeout, WSMsgType

CAPABILITIES = """({
  dom: typeof document === 'object' && document !== null,
  eval: typeof eval === 'function',
  wx: typeof wx === 'object' && wx !== null,
  getCurrentPages: typeof getCurrentPages === 'function'
})"""


async def probe_portal(port: int, timeout_s: float = 10.0) -> dict:
    checks: list[dict] = []
    contexts: dict[int, dict] = {}
    frames: list[dict] = []
    data = {"port": port, "passed": False, "checks": checks, "frames": frames, "contexts": []}
    try:
        async with asyncio.timeout(timeout_s):
            async with ClientSession(trust_env=False, timeout=ClientTimeout(total=timeout_s)) as client:
                async with client.get(f"http://127.0.0.1:{port}/json/version/", allow_redirects=False) as response:
                    if 300 <= response.status < 400:
                        raise ValueError("Portal discovery redirects are not followed")
                    response.raise_for_status()
                    version = await response.json()
                websocket_url = version.get("webSocketDebuggerUrl", "")
                parsed = urlparse(websocket_url)
                if parsed.hostname not in ("127.0.0.1", "localhost", "::1") or parsed.port != port:
                    raise ValueError("Discovery did not return this local Portal's browser WebSocket")
                checks.append({"check": "browser_discovery", "passed": True})
                async with client.ws_connect(websocket_url) as ws:
                    sequence = 0
                    attached: str | None = None

                    async def rpc(method: str, params: dict | None = None, session: str | None = None):
                        nonlocal sequence
                        sequence += 1
                        command = {"id": sequence, "method": method, "params": params or {}}
                        if session:
                            command["sessionId"] = session
                        wanted = sequence
                        await ws.send_json(command)
                        while True:
                            message = await ws.receive()
                            if message.type != WSMsgType.TEXT:
                                raise ValueError(f"CDP socket ended while waiting for {method}")
                            packet = message.json()
                            if packet.get("method") == "Runtime.executionContextCreated":
                                context = packet.get("params", {}).get("context", {})
                                if isinstance(context.get("id"), int):
                                    contexts[context["id"]] = dict(context)
                                    if len(contexts) > 512:
                                        contexts.pop(next(iter(contexts)))
                            elif packet.get("method") == "Runtime.executionContextsCleared":
                                contexts.clear()
                            elif packet.get("method") == "Runtime.executionContextDestroyed":
                                contexts.pop(packet.get("params", {}).get("executionContextId"), None)
                            if packet.get("id") == wanted:
                                if packet.get("error"):
                                    raise ValueError(f"{method}: {packet['error']}")
                                return packet.get("result", {})

                    try:
                        targets = (await rpc("Target.getTargets")).get("targetInfos", [])
                        pages = [t for t in targets if t.get("type") == "page"]
                        if not pages:
                            raise ValueError("No page target in current runtime epoch")
                        attached = (await rpc("Target.attachToTarget", {
                            "targetId": pages[0]["targetId"], "flatten": True,
                        })).get("sessionId")
                        if not attached:
                            raise ValueError("Target.attachToTarget did not return a session")
                        checks.append({"check": "target_session", "passed": True})
                        await rpc("Page.enable", session=attached)
                        tree = (await rpc("Page.getFrameTree", session=attached)).get("frameTree", {})
                        pending = [tree]
                        while pending and len(frames) < 256:
                            node = pending.pop()
                            if isinstance(node.get("frame"), dict):
                                frames.append(node["frame"])
                            pending.extend(reversed(node.get("childFrames") or []))
                        checks.append({"check": "frame_tree", "passed": bool(frames)})
                        await rpc("Runtime.enable", session=attached)
                        evaluated = await rpc("Runtime.evaluate", {
                            "expression": "1+1", "returnByValue": True,
                        }, attached)
                        healthy = not evaluated.get("exceptionDetails") and evaluated.get("result", {}).get("value") == 2
                        checks.append({"check": "session_roundtrip", "passed": healthy})
                        # A fixed read-only expression, never caller-supplied code.
                        ordered = sorted(contexts.values(), key=lambda c: c.get("auxData", {}).get("isDefault") is False)
                        for context in ordered[:16]:
                            try:
                                result = await asyncio.wait_for(rpc("Runtime.evaluate", {
                                    "expression": CAPABILITIES, "contextId": context["id"],
                                    "returnByValue": True,
                                }, attached), timeout=min(1.0, timeout_s / 4))
                                context["capabilities"] = result.get("result", {}).get("value")
                                if result.get("exceptionDetails"):
                                    context["probe_error"] = result["exceptionDetails"]
                            except (ValueError, TimeoutError) as error:
                                context["probe_error"] = str(error) or "context probe timed out"
                        checks.append({"check": "execution_contexts", "passed": bool(contexts)})
                        checks.append({"check": "context_capabilities", "passed": any(
                            isinstance(context.get("capabilities"), dict) for context in contexts.values()
                        )})
                        data["passed"] = all(c["passed"] for c in checks)
                    finally:
                        if attached and not ws.closed:
                            # Closing the owned socket also releases its Portal sessions.
                            await ws.send_json({"id": sequence + 1, "method": "Target.detachFromTarget",
                                                "params": {"sessionId": attached}})
    except Exception as error:
        data["passed"] = False
        checks.append({"check": "probe", "passed": False, "error": str(error) or "total deadline expired"})
    data["contexts"] = sorted(contexts.values(), key=lambda c: c.get("auxData", {}).get("isDefault") is False)[:16]
    data["contexts_truncated"] = len(contexts) > 16
    data["limitations"] = [
        "Virtual targets may share a runtime; select contexts by observed DOM/wx capabilities.",
        "A successful protocol probe is not a Playwright locator/screenshot acceptance test.",
        "Native wx.request capture is not established by these checks.",
    ]
    return data
