"""Reusable analysis predicates and failure branches, never a version table."""

from __future__ import annotations

from ..core.envelope import next_action

METHOD_CHAIN = [
    "Read the actual binary's format and ISA; version labels are optional. Separate file offsets, VAs and module-relative offsets.",
    "Search related method/file/message strings. Missing strings may mean stripping or renamed logging, not an unsupported version.",
    "Resolve code and pointer-table references, then recover containing functions. Keep competing candidates until a role predicate distinguishes them.",
    "Trace the debug gate from arguments through scene/mode checks, the complete pointer chain and URL storage. Re-derive fields; never copy an older build's chain.",
    "Establish the CDP filter from caller data flow. For the current map-suppression method, the returned pointer feeds a uint32 load at +8 compared with 6; the first call is insufficient.",
    "Check exact ISA/config block, required hooks, mapped executable ranges, decoding and semantic roles before writing parameters. Static success is not runtime success.",
    "Validate per-PID armed/hit counters, setupContext, CBOR responses AND events, command roundtrip, then Portal sessions and actual frame/context capabilities.",
]
METHODOLOGY = "\n".join(f"{i}. {step}" for i, step in enumerate(METHOD_CHAIN, 1))

_BRANCHES = {
    "format": (
        "The binary format/ISA can be inspected, but the current automatic hook extractor is Mach-O arm64.",
        ["Use summary and strings to identify relevant code, then bounded xrefs/disasm/calls for the observed ISA.",
         "Establish module discovery, calling convention, string layout and filter return layout separately.",
         "An ELF/PE reader does not implement a Linux/Windows injection backend."],
        "Stop automatic extraction at the missing backend; continue read-only analysis or the independent source track.",
        "SendToClientFilter",
    ),
    "load_start": (
        "The launch entry is missing or has multiple plausible functions.",
        ["Search OnLoadStart variants and applet_index_container.cc together.",
         "Use xrefs and containing-function boundaries; distinguish generic logging wrappers.",
         "If direct references are absent, inspect pointer tables or alternate debug-entry behavior in a disassembler."],
        "Do not choose the lowest address; resolve the launch/debug role or retain an unresolved candidate.",
        "OnLoadStart",
    ),
    "scene": (
        "The launch entry was found but its complete debug-gate data flow is unresolved.",
        ["Inspect argument-guarded branches, scene comparisons and callers/callees.",
         "Trace each load back to the launch object and check mode/URL fields on the same path.",
         "Treat 1101 and libc++ string layout as current-method observations, not constants for every platform."],
        "Stop field rewrites when the pointer chain or ABI is unresolved; do not recycle previous offsets.",
        "applet_index_container.cc",
    ),
    "cdp_filter": (
        "The filter's semantic role is absent, ambiguous or inconsistent with the imported offset.",
        ["Inspect SendToClientFilter and neighbouring devtools_message_filter strings.",
         "Follow calls whose returned pointer feeds a uint32 tag-at-8 comparison with 6; reject short logging stubs.",
         "On a different return layout, re-derive capture and suppression behavior instead of applying 6->0 blindly."],
        "No unique role means no automatic filter patch; preserve the existing config.",
        "SendToClientFilter",
    ),
    "cache_policy": (
        "The optional renderer-cache hook is missing.",
        ["Search WAPCAdapter script-name variants and verify their callers.",
         "Continue without this hook and report that cache behavior remains unverified."],
        "Do not block the main analysis solely on this optional hook.",
        "WAPCAdapter",
    ),
    "verify": (
        "A candidate failed required-field, address, ISA or semantic-role checks.",
        ["Inspect the failing checks and disassemble their VAs in this binary.",
         "Resolve ambiguous role candidates and re-derive changed fields before another import.",
         "A valid JSON file and a decodable instruction do not establish a correct hook."],
        "Do not install the candidate or advance injection readiness until the failed checks are resolved.",
        "SendToClientFilter",
    ),
    "unknown": (
        "The analysis failed before a specific role could be identified.",
        ["Read the actual file header and executable mappings.",
         "Check optional analysis dependencies, then choose queries appropriate to that format and ISA.",
         "Narrow the next question using the returned error; repeating extraction unchanged supplies no new information."],
        "Stop repeated extraction and switch to a different observation or the independent source track.",
        None,
    ),
}


def branch_guidance(stage: str, binary_path: str | None = None) -> dict:
    stage = "scene" if stage == "scene_switch" else stage
    interpretation, steps, stop, pattern = _BRANCHES.get(stage, _BRANCHES["unknown"])
    arguments = {"view": "strings" if pattern else "summary"}
    if pattern:
        arguments["pattern"] = pattern
    if binary_path:
        arguments["binary_path"] = binary_path
    return {
        "interpretation": interpretation, "next_steps": steps,
        "conclusion_if_all_fail": stop,
        "next_actions": [next_action(
            "inspect_binary", arguments, interpretation,
            "Mapped addresses or format/ISA observations that distinguish the failed branch.",
            stop, "One bounded query, then change the query or follow the alternative branch.",
        )],
    }
