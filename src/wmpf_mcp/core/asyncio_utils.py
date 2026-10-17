"""Complete owned cleanup before releasing resources after request cancellation."""
from __future__ import annotations

import asyncio
import anyio
from typing import TypeVar

T = TypeVar("T")


async def drain_task(task: asyncio.Task[T]) -> T:
    """Await an owned task despite repeated cancellation of its caller."""
    # MCP transports can use level-triggered AnyIO cancellation, while callers
    # may also cancel the asyncio task directly. Both must allow cleanup to run.
    with anyio.CancelScope(shield=True):
        while True:
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                if task.done():
                    return task.result()
