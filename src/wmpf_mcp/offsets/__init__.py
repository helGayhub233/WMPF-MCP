"""Offset resolution: anchors, extraction, cache-compatible config output."""

from .anchors import ANCHORS, SCENE_TOOL_VALUE
from .methodology import METHODOLOGY, branch_guidance


def __getattr__(name):
    # Keep optional disassembly dependencies out of server bootstrap and doctor.
    if name in {"AnchorReport", "ExtractionError", "ExtractionResult", "VerifyCheck",
                "extract_offsets", "verify_config"}:
        from . import extractor
        return getattr(extractor, name)
    raise AttributeError(name)

__all__ = [
    "ANCHORS",
    "METHODOLOGY",
    "SCENE_TOOL_VALUE",
    "AnchorReport",
    "ExtractionError",
    "ExtractionResult",
    "VerifyCheck",
    "branch_guidance",
    "extract_offsets",
    "verify_config",
]
