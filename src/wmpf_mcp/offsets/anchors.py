"""Anchor strings and extraction roles for WMPF hook-offset extraction.

Empirically verified against WeChat 4.1.15 / WMPF 2.5.7.25800 (macOS arm64):
the binary logs each method entry with its own signature as the message and
the source file as the location. That makes signature strings perfect anchors:
string -> adrp xref -> containing function -> method.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# OnLoadStart in AppletIndexContainer — unique in the 25800 binary.
ANCHOR_LOAD_START: Final = (
    b"virtual void applet::AppletIndexContainer::OnLoadStart(bool, const std::string &)"
)
# CDP message filter class name; its first call inside the referencing function
# is the filter implementation that must be patched.
ANCHOR_CDP_FILTER: Final = b"SendToClientFilter"
# Renderer cache-policy script name; its referencing function is hook-patched.
ANCHOR_CACHE_POLICY: Final = b"WAPCAdapterAppIndex.js"

# Scene value that marks the developer-tools (debug) launch path.
SCENE_TOOL_VALUE: Final = 0x44D  # 1101


@dataclass(frozen=True)
class AnchorSpec:
    key: str
    needle: bytes
    target: str  # what the anchor resolves to
    required: bool


ANCHORS: tuple[AnchorSpec, ...] = (
    AnchorSpec("load_start", ANCHOR_LOAD_START, "LoadStartHookOffset", True),
    AnchorSpec("cdp_filter", ANCHOR_CDP_FILTER, "CDPFilterHookOffset", True),
    AnchorSpec("cache_policy", ANCHOR_CACHE_POLICY, "ResourceCachePolicyHookOffset", False),
)
