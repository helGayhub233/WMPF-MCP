"""Tool-level annotations; reads and resource mutations have separate entry points."""

from mcp.types import ToolAnnotations

from ..core import envelope
from ..core.errors import ErrorCode, ToolError
from ..core.state import get_state


def annotations(*, read_only: bool = False, destructive: bool = False, idempotent: bool = True):
    return ToolAnnotations(read_only_hint=read_only, destructive_hint=destructive,
                           idempotent_hint=idempotent, open_world_hint=False)


def parameter_error(message: str):
    return envelope.fail(ToolError(ErrorCode.PARAM, message), stage=get_state().stage.value)
