"""On-device offset extraction (docs/05 §4).

Pipeline per hook point:
  anchor string -> adrp xref -> containing function (prologue scan) -> role
  analysis (scene compare / first call) -> offsets relative to image base.

The scene pointer chain feeding ``cmp w?, #SCENE_TOOL_VALUE`` is traced
backwards through single ``ldr`` steps to the ``this`` register, yielding the
SceneChain list ``[this_off, struct_off, mid_off, scene_off]``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from capstone.arm64_const import ARM64_REG_X0

from .anchors import (
    ANCHOR_CDP_FILTER,
    ANCHOR_CACHE_POLICY,
    ANCHOR_LOAD_START,
    SCENE_TOOL_VALUE,
)
from .formats.macho import MachOSlice

_REGS_WRITE_MNEMONICS = {"ldr", "ldrb", "ldrh", "ldrsw", "mov", "ldp", "add", "sub", "adrp"}
_MAX_FUNC_INSN = 6000


class ExtractionError(RuntimeError):
    """Extraction failed for an anchor; carries the stage and partial report."""

    def __init__(
        self,
        message: str,
        *,
        stage: str = "unknown",
        report: list["AnchorReport"] | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.report = report or []


@dataclass
class AnchorReport:
    key: str
    found: bool
    detail: str
    address: str | None = None  # VA of what was found


@dataclass
class ExtractionResult:
    version: int | None
    arch: str
    binary_path: str
    config: dict
    anchors: list[AnchorReport] = field(default_factory=list)
    elapsed_s: float = 0.0
    verified: bool = False
    verify_notes: list[str] = field(default_factory=list)


def _filter_calls(slice_: MachOSlice, func_va: int) -> set[int]:
    """Calls whose returned pointer feeds a 32-bit tag-at-8 comparison with 6.

    This is a role predicate for the current hook, not a version signature.
    A call's position in its parent is not evidence of that role.
    """
    insns = slice_.disasm(func_va, 0x400)
    targets: set[int] = set()
    for i, call in enumerate(insns):
        if call.mnemonic != "bl" or not call.operands or call.operands[0].type != 2:
            continue
        pointers = {"x0"}
        tags: set[str] = set()
        for ins in insns[i + 1:i + 13]:
            ops = ins.operands
            def key(reg):
                name = ins.reg_name(reg)
                return "x" + name[1:] if name.startswith("w") else name
            if ins.mnemonic in ("bl", "blr", "ret", "b"):
                break
            pointer_copy = ins.mnemonic == "mov" and len(ops) == 2 \
                and all(op.type == 1 for op in ops) and key(ops[1].reg) in pointers
            tag_load = ins.mnemonic == "ldr" and len(ops) == 2 and ops[1].type == 3 \
                and key(ops[1].mem.base) in pointers and ops[1].mem.disp == 8 \
                and ins.reg_name(ops[0].reg).startswith("w")
            # Test reads before applying writes. Capstone also reports the first
            # operand of the CMP alias as written on some releases.
            if ins.mnemonic == "cmp" and len(ops) == 2 and ops[0].type == 1 \
                    and key(ops[0].reg) in tags and ops[1].type == 2 and ops[1].imm == 6:
                targets.add(int(call.operands[0].imm))
                break
            _, written = ins.regs_access()
            for reg in written:
                pointers.discard(key(reg))
                tags.discard(key(reg))
            if pointer_copy:
                pointers.add(key(ops[0].reg))
            if tag_load:
                tags.add(key(ops[0].reg))
    return targets


def _filter_candidates(slice_: MachOSlice) -> set[int]:
    functions: set[int] = set()
    for va in slice_.find_string(ANCHOR_CDP_FILTER):
        for ref in slice_.xrefs(va):
            function = slice_.find_function_start(ref)
            if function is not None:
                functions.add(function)
    return set().union(*(_filter_calls(slice_, fn) for fn in functions)) if functions else set()


def _writes_reg(ins, reg: int) -> bool:
    if ins.mnemonic not in _REGS_WRITE_MNEMONICS:
        return False
    if not ins.operands or ins.operands[0].type != 1:
        return False
    if ins.mnemonic in ("add", "sub"):
        # only register-destination forms count as writes
        return ins.operands[0].reg == reg and len(ins.operands) == 3
    return ins.operands[0].reg == reg


def _trace_chain(
    insns: list, ldr_index: int, this_regs: set[int]
) -> list[int] | None:
    """Backward ldr-chain trace from one load instruction to ``this``."""
    ins = insns[ldr_index]
    if len(ins.operands) < 2 or ins.operands[1].type != 3:
        return None
    chain = [ins.operands[1].mem.disp]
    reg = ins.operands[1].mem.base

    for _hop in range(6):
        if reg in this_regs:
            return chain
        found = None
        for k in range(ldr_index - 1, max(-1, ldr_index - 300), -1):
            prev = insns[k]
            if prev.mnemonic == "mov" and len(prev.operands) == 2 and prev.operands[1].type == 1:
                if prev.operands[0].reg == reg:
                    reg = prev.operands[1].reg
                    break
            if prev.mnemonic == "ldr" and len(prev.operands) >= 2 and prev.operands[1].type == 3:
                if prev.operands[0].reg == reg:
                    found = (k, prev.operands[1].mem.base, prev.operands[1].mem.disp)
                    break
            if _writes_reg(prev, reg):
                return None  # clobbered by something we cannot follow
        if found is None:
            return None
        k, base, disp = found
        chain.append(disp)
        reg = base
        ldr_index = k
    return None


def _find_scene_analysis(slice_: MachOSlice, func_va: int) -> dict | None:
    """Locate ``cmp w?, #1101`` and the ldr that feeds it, then trace the chain."""
    insns = slice_.disasm(func_va, _MAX_FUNC_INSN)
    if not insns:
        return None
    # ``this`` registers: x0 plus whatever the prologue saves from x0
    this_regs: set[int] = {ARM64_REG_X0}
    body = insns
    for ins in body[:24]:
        if ins.mnemonic == "mov" and len(ins.operands) == 2 and ins.operands[0].type == 1 \
                and ins.operands[1].type == 1 and ins.operands[1].reg == ARM64_REG_X0:
            this_regs.add(ins.operands[0].reg)

    for i, ins in enumerate(body):
        if ins.mnemonic.startswith("cmp") and len(ins.operands) == 2 and ins.operands[1].type == 2:
            if ins.operands[1].imm != SCENE_TOOL_VALUE:
                continue
            cmp_reg = ins.operands[0].reg
            # nearest earlier ldr writing the compared register
            for k in range(i - 1, max(-1, i - 24), -1):
                prev = body[k]
                if prev.mnemonic == "ldr" and prev.operands and prev.operands[0].reg == cmp_reg \
                        and len(prev.operands) >= 2 and prev.operands[1].type == 3:
                    chain = _trace_chain(body, k, this_regs)
                    if chain:
                        chain.reverse()  # [this_off, ..., scene_off]
                    return {
                        "cmp_va": ins.address,
                        "scene_ldr_va": prev.address,
                        "scene_offset": prev.operands[1].mem.disp,
                        "scene_chain": chain,
                        "scene_reg": prev.reg_name(prev.operands[0].reg),
                        "scene_base_reg": prev.operands[1].mem.base,
                    }
                if _writes_reg(prev, cmp_reg):
                    break
    return None


def _find_debug_chain(slice_: MachOSlice, func_va: int, scene: dict) -> dict:
    """Derive the debug-gate data-chain fields around the scene check.

    Verified code patterns (WMPF 25800, function tail):
        ldr  wN, [xM, #mode]      ; gate: remote-debug mode must equal 1
        cmp  wN, #1
        b.ne <return>
        ldr  wN, [xM, #scene]     ; scene check (already located)
        cmp  wN, #0x44d
        b.ne <return>
        ldrsb xN, [xM, #url+23]   ; guard: websocket-URL std::string non-empty
        ...
        bl   <debug-connect>      ; runs when every gate passes

    All fields are optional — a layout change simply drops the key and the
    hook template's guards skip that rewrite (self-adapting extraction).
    """
    insns = slice_.disasm(func_va, _MAX_FUNC_INSN)
    if not insns:
        return {}
    cmp_va = scene.get("cmp_va")
    base_reg = scene.get("scene_base_reg")
    cmp_idx = next((i for i, ins in enumerate(insns) if ins.address == cmp_va), None)
    if cmp_idx is None:
        return {}
    result: dict = {}

    # gate: the nearest earlier `cmp w?, #1` fed by an ldr on the same base
    for k in range(cmp_idx - 1, max(-1, cmp_idx - 6), -1):
        ins = insns[k]
        if ins.mnemonic == "cmp" and len(ins.operands) == 2 \
                and ins.operands[1].type == 2 and ins.operands[1].imm == 1:
            cmp_reg = ins.operands[0].reg
            for j in range(k - 1, max(-1, k - 4), -1):
                prev = insns[j]
                if prev.mnemonic == "ldr" and len(prev.operands) >= 2 \
                        and prev.operands[0].reg == cmp_reg and prev.operands[1].type == 3:
                    if base_reg is None or prev.operands[1].mem.base == base_reg:
                        result["RemoteDebugModeOffset"] = prev.operands[1].mem.disp
                    break
            break

    # URL string slot: first ldrsb on the same base after the scene compare
    # (libc++ std::string: marker byte sits at string_base + 23)
    for k in range(cmp_idx + 1, min(len(insns), cmp_idx + 40)):
        ins = insns[k]
        if ins.mnemonic == "ldrsb" and len(ins.operands) >= 2 and ins.operands[1].type == 3:
            if base_reg is None or ins.operands[1].mem.base == base_reg:
                disp = ins.operands[1].mem.disp
                if disp >= 23:
                    result["WebSocketURLStringOffset"] = disp - 23
            break

    # debug-start: the first bl after the scene compare and its target
    for k in range(cmp_idx + 1, min(len(insns), cmp_idx + 60)):
        ins = insns[k]
        if ins.mnemonic == "bl" and ins.operands:
            result["DebugStartBlOffset"] = hex(slice_.offset_of(ins.address))
            target = ins.operands[0].imm
            if target:
                result["DebugConnectOffset"] = hex(slice_.offset_of(target))
            break
    return result


def extract_offsets(binary_path: Path, version: int | None, arch: str = "arm64") -> ExtractionResult:
    """Extract all hook offsets for one WMPF runtime binary."""
    started = time.monotonic()
    if arch != "arm64":
        raise ExtractionError("This method's hook ABI requires arm64", stage="format")
    slice_ = MachOSlice(binary_path)
    result = ExtractionResult(
        version=version,
        arch=arch,
        binary_path=str(binary_path),
        config={},
    )
    arm: dict = {}

    # ---- anchor: OnLoadStart (unique signature string) ---------------------
    hits = [va for va in slice_.find_string(ANCHOR_LOAD_START) if slice_.segment_of(va)]
    if not hits:
        raise ExtractionError(
            "OnLoadStart anchor string not found", stage="load_start", report=result.anchors
        )
    funcs: list[int] = []
    for va in hits:
        for ref in slice_.xrefs(va):
            func = slice_.find_function_start(ref)
            if func and func not in funcs:
                funcs.append(func)
    if not funcs:
        raise ExtractionError(
            "no xref resolved for the OnLoadStart anchor",
            stage="load_start",
            report=result.anchors,
        )
    if len(funcs) != 1:
        raise ExtractionError(
            f"OnLoadStart has multiple candidates: {[hex(v) for v in sorted(funcs)]}",
            stage="load_start", report=result.anchors,
        )
    load_start_va = funcs[0]
    arm["LoadStartHookOffset"] = hex(slice_.offset_of(load_start_va))
    result.anchors.append(
        AnchorReport("load_start", True, f"{len(funcs)} candidate function(s)",
                     hex(load_start_va))
    )

    scene = _find_scene_analysis(slice_, load_start_va)
    if scene:
        arm["SceneSwitchHookOffset"] = hex(slice_.offset_of(scene["scene_ldr_va"]))
        if scene.get("scene_reg"):
            arm["SceneSwitchRegister"] = scene["scene_reg"]
        if scene.get("scene_chain"):
            arm["SceneChain"] = scene["scene_chain"]
        arm["SceneToolValue"] = SCENE_TOOL_VALUE
        # self-adapting: derive the rest of the debug-gate chain (mode field,
        # URL string slot, debug-start call site) from the same code region
        debug_chain = _find_debug_chain(slice_, load_start_va, scene)
        arm.update(debug_chain)
        result.anchors.append(
            AnchorReport("scene_switch", True,
                         f"cmp@{hex(scene['cmp_va'])} ldr@{hex(scene['scene_ldr_va'])} "
                         f"chain={scene.get('scene_chain')} "
                         f"debug_chain_keys={sorted(debug_chain)}",
                         hex(scene["scene_ldr_va"]))
        )
    else:
        result.anchors.append(
            AnchorReport("scene_switch", False, "scene compare not located", None)
        )

    # ---- role: returned CBOR-map pointer / tag-at-8 comparison with 6 -------
    targets = _filter_candidates(slice_)
    if len(targets) != 1:
        raise ExtractionError(
            f"CDP filter role is missing or ambiguous: {[hex(v) for v in sorted(targets)]}",
            stage="cdp_filter",
            report=result.anchors,
        )
    target = next(iter(targets))
    arm["CDPFilterHookOffset"] = hex(slice_.offset_of(target))
    result.anchors.append(
        AnchorReport("cdp_filter", True, "caller reads returned pointer +8 as uint32 and compares with 6",
                     hex(target))
    )

    # ---- anchor: renderer cache policy (optional) --------------------------
    cache_hits = slice_.find_string(ANCHOR_CACHE_POLICY)
    cache_funcs: list[int] = []
    for va in cache_hits:
        for ref in slice_.xrefs(va):
            func = slice_.find_function_start(ref)
            if func and func not in cache_funcs:
                cache_funcs.append(func)
    if len(cache_funcs) == 1:
        arm["ResourceCachePolicyHookOffset"] = hex(slice_.offset_of(cache_funcs[0]))
        result.anchors.append(
            AnchorReport("cache_policy", True, f"{len(cache_funcs)} function(s)",
                         hex(cache_funcs[0]))
        )
    else:
        result.anchors.append(
            AnchorReport("cache_policy", False, f"optional role absent or ambiguous ({len(cache_funcs)} candidates)", None)
        )

    result.config = {"Version": version, "Arch": {arch: arm}}

    # ---- static verification ----------------------------------------------
    text_lo, text_hi = slice_.text.addr, slice_.text.addr + slice_.text.size
    notes: list[str] = []
    ok = True
    for key, value in arm.items():
        if not isinstance(value, str) or not value.startswith("0x"):
            continue
        va = int(value, 16) + slice_.image_base
        if not (text_lo <= va < text_hi):
            ok = False
            notes.append(f"{key} 0x{value} outside __TEXT,__text")
        elif va % 4 != 0:
            ok = False
            notes.append(f"{key} 0x{value} not 4-byte aligned")
    if not notes:
        notes.append("all offsets inside __TEXT,__text and 4-byte aligned")
    checks = verify_config(binary_path, result.config, arch=arch, image=slice_)
    result.verified = ok and all(check.ok for check in checks)
    result.verify_notes = notes + [f"{check.key}: {check.note}" for check in checks if not check.ok]
    result.elapsed_s = round(time.monotonic() - started, 2)
    return result


@dataclass
class VerifyCheck:
    key: str
    value: str | None
    ok: bool
    note: str


def verify_config(
    binary_path: Path, config: dict, arch: str = "arm64", *, image: MachOSlice | None = None
) -> list[VerifyCheck]:
    """Static dry-run checks over a candidate config (docs/05 §5)."""
    slice_ = image or MachOSlice(binary_path)
    arm = (config.get("Arch") or {}).get(arch)
    if not isinstance(arm, dict) or not arm:
        return [VerifyCheck("Arch", None, False, f"non-empty exact {arch} block required; no fallback")]
    text_lo, text_hi = slice_.text.addr, slice_.text.addr + slice_.text.size
    checks: list[VerifyCheck] = []

    for key in (
        "LoadStartHookOffset",
        "SceneSwitchHookOffset",
        "CDPFilterHookOffset",
        "ResourceCachePolicyHookOffset",
        "DebugStartBlOffset",
        "DebugConnectOffset",
    ):
        value = arm.get(key)
        if not value:
            required = key in ("LoadStartHookOffset", "CDPFilterHookOffset")
            checks.append(VerifyCheck(key, None, not required,
                                      "missing required hook" if required else "absent (optional; runtime effect unverified)"))
            continue
        try:
            if not isinstance(value, str) or not value.startswith("0x"):
                raise ValueError("explicit hexadecimal string required")
            va = int(str(value), 16) + slice_.image_base
        except ValueError:
            checks.append(VerifyCheck(key, str(value), False, "not a hex offset"))
            continue
        if not (text_lo <= va < text_hi):
            checks.append(VerifyCheck(key, str(value), False, "outside __TEXT,__text"))
            continue
        if va % 4 != 0:
            checks.append(VerifyCheck(key, str(value), False, "not 4-byte aligned"))
            continue
        first = slice_.disasm(va, 1)
        if not first:
            checks.append(VerifyCheck(key, str(value), False, "not decodable as arm64"))
            continue
        checks.append(
            VerifyCheck(key, str(value), True, f"decodes: {first[0].mnemonic} {first[0].op_str}")
        )

    chain = arm.get("SceneChain")
    if chain is not None:
        ok = isinstance(chain, list) and 2 <= len(chain) <= 8 \
            and all(type(v) is int and 0 <= v < 65536 for v in chain)
        checks.append(VerifyCheck("SceneChain", str(chain), ok, "plausible small offsets" if ok else "implausible"))
    for key in ("RemoteDebugModeOffset", "WebSocketURLStringOffset"):
        if key in arm:
            value = arm[key]
            valid = type(value) is int and 0 <= value < 65536 \
                and isinstance(chain, list) and 2 <= len(chain) <= 8 \
                and all(type(v) is int and 0 <= v < 65536 for v in chain)
            checks.append(VerifyCheck(key, str(value), valid, "bounded field in extracted SceneChain" if valid else "field requires a valid pointer chain"))
    if "WebSocketURL" in arm:
        url = arm["WebSocketURL"]
        valid = url in ("ws://127.0.0.1:9421", "ws://localhost:9421", "ws://[::1]:9421")
        checks.append(VerifyCheck("WebSocketURL", str(url), valid,
                                  "fixed local engine endpoint fits the current string slot" if valid else "expected loopback endpoint on 9421"))
    if arm.get("LoadStartHookOffset") and all(c.ok for c in checks):
        candidate = int(str(arm["LoadStartHookOffset"]), 16) + slice_.image_base
        entries = {fn for va in slice_.find_string(ANCHOR_LOAD_START) for ref in slice_.xrefs(va)
                   if (fn := slice_.find_function_start(ref)) is not None}
        valid = entries == {candidate}
        checks.append(VerifyCheck("LoadStartRole", hex(candidate), valid,
                                  "unique launch-entry anchor reference" if valid else "launch entry missing or ambiguous"))
        if valid and any(key in arm for key in (
            "SceneChain", "SceneSwitchHookOffset", "RemoteDebugModeOffset",
            "WebSocketURLStringOffset", "DebugStartBlOffset", "DebugConnectOffset",
        )):
            scene = _find_scene_analysis(slice_, candidate)
            derived = _find_debug_chain(slice_, candidate, scene) if scene else {}
            if scene:
                derived["SceneChain"] = scene.get("scene_chain")
                derived["SceneSwitchHookOffset"] = hex(slice_.offset_of(scene["scene_ldr_va"]))
            for key in ("SceneChain", "SceneSwitchHookOffset", "RemoteDebugModeOffset",
                        "WebSocketURLStringOffset", "DebugStartBlOffset", "DebugConnectOffset"):
                if key in arm:
                    valid = arm[key] == derived.get(key)
                    checks.append(VerifyCheck(key + "Role", str(arm[key]), valid,
                                              "matches launch-gate data flow" if valid else "does not match derived launch-gate data flow"))
    if arm.get("ResourceCachePolicyHookOffset") and all(c.ok for c in checks):
        candidate = int(arm["ResourceCachePolicyHookOffset"], 16) + slice_.image_base
        functions = {fn for va in slice_.find_string(ANCHOR_CACHE_POLICY) for ref in slice_.xrefs(va)
                     if (fn := slice_.find_function_start(ref)) is not None}
        valid = functions == {candidate}
        checks.append(VerifyCheck("CachePolicyRole", hex(candidate), valid,
                                  "unique cache-policy anchor function" if valid else "optional cache-policy role is ambiguous or incorrect"))
    if "SceneToolValue" in arm and (type(arm["SceneToolValue"]) is not int or arm["SceneToolValue"] != SCENE_TOOL_VALUE):
        checks.append(VerifyCheck("SceneToolValue", str(arm["SceneToolValue"]), False,
                                  "current method requires the observed debug-scene value 1101"))
    if arm.get("CDPFilterHookOffset") and all(c.ok for c in checks):
        candidate = int(str(arm["CDPFilterHookOffset"]), 16) + slice_.image_base
        roles = _filter_candidates(slice_)
        valid = roles == {candidate}
        checks.append(VerifyCheck("CDPFilterRole", hex(candidate), valid,
                                  "unique caller proves returned-pointer tag +8 == 6" if valid
                                  else f"missing/ambiguous role; candidates={[hex(v) for v in sorted(roles)]}"))
    return checks
