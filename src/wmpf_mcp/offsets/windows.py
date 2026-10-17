"""PE x64 legacy hook roles recovered from the selected Windows runtime.

The analysis uses PE unwind boundaries, RIP-relative string references and
Win64 argument provenance.  It deliberately has no runtime-version table.
"""

from __future__ import annotations

import bisect
import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .inspection import BinaryView


class ExtractionError(RuntimeError):
    def __init__(self, message: str, *, stage: str = "unknown",
                 report: list["AnchorReport"] | None = None) -> None:
        super().__init__(message)
        self.stage = stage
        self.report = report or []


@dataclass
class AnchorReport:
    key: str
    found: bool
    detail: str
    address: str | None = None


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


@dataclass
class VerifyCheck:
    key: str
    value: str | None
    ok: bool
    note: str


_ARGUMENTS = {"rcx": 0, "rdx": 1, "r8": 2, "r9": 3}
_VOLATILE = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
_LEA_RIP = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")


def _canonical(name: str) -> str:
    aliases = {
        "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
        "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
        "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
        "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
        "esi": "rsi", "si": "rsi", "sil": "rsi",
        "edi": "rdi", "di": "rdi", "dil": "rdi",
        "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
        "esp": "rsp", "sp": "rsp", "spl": "rsp",
    }
    if name in aliases:
        return aliases[name]
    return re.sub(r"^(r(?:[89]|1[0-5]))[dwb]$", r"\1", name)


def _add(base, displacement: int):
    if base is None:
        return None
    if not displacement:
        return base
    if base[0] == "stack":
        return ("stack", base[1] + displacement)
    if base[0] == "add":
        return _add(base[1], base[2] + displacement)
    return ("add", base, displacement)


def _register(instructions, before: int, requested: str, depth: int = 0):
    """Recover pointer expressions without carrying volatile values past calls."""
    if depth > 48:
        return None
    register = _canonical(requested)
    for index in range(before - 1, -1, -1):
        ins = instructions[index]
        if ins.mnemonic == "call":
            if register in _VOLATILE:
                return None
            # A returned Win64 call preserves nonvolatile registers and RSP.
            continue
        _, written = ins.regs_access()
        if register not in {_canonical(ins.reg_name(reg)) for reg in written}:
            continue
        ops = ins.operands
        if register == "rsp" and ins.mnemonic in ("push", "pop"):
            return _add(_register(instructions, index, "rsp", depth + 1),
                        -8 if ins.mnemonic == "push" else 8)
        if not ops or ops[0].type != X86_OP_REG or _canonical(ins.reg_name(ops[0].reg)) != register:
            return None
        if len(ops) != 2:
            return None
        source = ops[1]
        if ins.mnemonic in ("mov", "movabs"):
            # Partial-register writes do not preserve a pointer's provenance.
            if ops[0].size != 8:
                return None
            if source.type == X86_OP_REG and source.size == 8:
                return _register(instructions, index, ins.reg_name(source.reg), depth + 1)
            if source.type == X86_OP_MEM and source.size == 8:
                base = _memory_base(instructions, index, source, depth + 1)
                return ("load", base, source.mem.disp) if base is not None else None
            if source.type == X86_OP_IMM:
                return ("constant", source.imm)
        if ins.mnemonic == "lea" and source.type == X86_OP_MEM:
            return _add(_memory_base(instructions, index, source, depth + 1), source.mem.disp)
        if ins.mnemonic in ("add", "sub") and source.type == X86_OP_IMM:
            return _add(_register(instructions, index, register, depth + 1),
                        source.imm if ins.mnemonic == "add" else -source.imm)
        return None
    if register in _ARGUMENTS:
        return ("arg", _ARGUMENTS[register])
    return ("stack", 0) if register == "rsp" else None


def _memory_base(instructions, index: int, operand, depth: int = 0):
    if operand.mem.index or not operand.mem.base:
        return None
    return _register(instructions, index,
                     instructions[index].reg_name(operand.mem.base), depth + 1)


def _chain(expression):
    if expression is None:
        return None
    if expression[0] == "arg":
        return expression[1], []
    if expression[0] != "load":
        return None
    parent = _chain(expression[1])
    return (parent[0], parent[1] + [expression[2]]) if parent is not None else None


def _comparison(ins):
    ops = ins.operands
    if ins.mnemonic != "cmp" or len(ops) != 2:
        return None
    if ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_IMM and not ops[0].mem.index:
        return ops[0], ops[1].imm
    return None


def _direct_call(ins) -> int | None:
    return ins.operands[0].imm if ins.mnemonic == "call" and len(ins.operands) == 1 \
        and ins.operands[0].type == X86_OP_IMM else None


def _unique(values, role: str):
    unique = {repr(value): value for value in values}
    if len(unique) != 1:
        raise ExtractionError(f"{role}: expected one proven candidate, found {len(unique)}", stage=role)
    return next(iter(unique.values()))


def _valid_chain(chain: list[int], *, field_width: int = 4) -> bool:
    return 1 <= len(chain) <= 16 and all(type(offset) is int and 0 <= offset <= 0x10000
        and offset % 8 == 0 for offset in chain[:-1]) \
        and type(chain[-1]) is int and 0 <= chain[-1] <= 0x10000 and chain[-1] % field_width == 0


class _PEAnalysis:
    def __init__(self, image: BinaryView):
        if image.format != "PE" or image.arch != "x86_64":
            raise ExtractionError(f"Expected PE/x86_64, got {image.format}/{image.arch}", stage="binary")
        self.image = image
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.text = [section for section in image.sections if section["executable"]]
        self.functions: dict[int, int] = {}
        pdata = [section for section in image.sections if section["name"] == ".pdata"]
        if len(pdata) != 1:
            raise ExtractionError("PE unwind .pdata section is missing or ambiguous", stage="functions")
        section = pdata[0]
        for offset in range(section["file_offset"], section["file_offset"] + section["size"] - 11, 12):
            begin, end, _ = struct.unpack_from("<III", image.data, offset)
            if 0 < begin < end and any(s["va"] - image.image_base <= begin < end
                    <= s["va"] - image.image_base + s["size"] for s in self.text):
                self.functions[begin] = max(end, self.functions.get(begin, 0))
        self.starts = sorted(self.functions)
        self.decoded: dict[int, list] = {}
        if not self.starts:
            raise ExtractionError("PE has no executable unwind function boundaries", stage="functions")

    def owner(self, rva: int) -> int | None:
        index = bisect.bisect_right(self.starts, rva) - 1
        if index >= 0 and rva < self.functions[self.starts[index]]:
            return self.starts[index]
        return None

    def instructions(self, begin: int):
        if begin not in self.functions:
            raise ExtractionError(f"No unwind boundary at {hex(begin)}", stage="functions")
        if begin not in self.decoded:
            size = self.functions[begin] - begin
            if size > 0x10000:
                raise ExtractionError(f"Function exceeds bounded role analysis at {hex(begin)}", stage="functions")
            offset = self.image.va_to_offset(self.image.image_base + begin)
            self.decoded[begin] = list(self.cs.disasm(bytes(self.image.data[offset:offset + size]), begin))
        return self.decoded[begin]

    def string_ranges(self, needle: bytes, exact: bool = False) -> list[tuple[int, int]]:
        ranges = []
        for section in self.image.sections:
            if section["executable"] or section["name"] == ".pdata":
                continue
            lo, hi = section["file_offset"], section["file_offset"] + section["size"]
            position = lo
            while (position := self.image.data.find(needle, position, hi)) >= 0:
                before = self.image.data.rfind(b"\0", max(lo, position - 4096), position)
                start = before + 1 if before >= 0 else max(lo, position - 4096)
                end = position + len(needle)
                if not exact or (start == position and end < hi and self.image.data[end] == 0):
                    rva = section["va"] - self.image.image_base - lo
                    ranges.append((rva + start, rva + end))
                position += len(needle)
        return ranges

    def anchors(self) -> dict[str, set[int]]:
        ranges = {
            "LoadStartFile": self.string_ranges(b"applet_index_container.cc"),
            "LoadStartName": self.string_ranges(b"AppletIndexContainer::OnLoadStart"),
            "FilterName": self.string_ranges(b"SendToClientFilter", exact=True),
            "FilterAppletFile": self.string_ranges(b"devtools_message_filter_applet_webview.cc"),
            "FilterWebviewFile": self.string_ranges(b"devtools_message_filter_webview.cc"),
        }
        found: dict[str, set[int]] = {key: set() for key in ranges}
        for section in self.text:
            lo, hi = section["file_offset"], section["file_offset"] + section["size"]
            for match in _LEA_RIP.finditer(self.image.data, lo, hi - 4):
                offset = match.start()
                rva = section["va"] - self.image.image_base + offset - lo
                target = rva + 7 + struct.unpack_from("<i", self.image.data, offset + 3)[0]
                keys = [key for key, spans in ranges.items() if any(a <= target < b for a, b in spans)]
                if not keys:
                    continue
                owner = self.owner(rva)
                if owner is None:
                    continue
                # Reject byte patterns occurring inside another instruction.
                ins = next((ins for ins in self.instructions(owner) if ins.address == rva), None)
                if ins is None or ins.mnemonic != "lea" or len(ins.operands) != 2 \
                        or ins.operands[1].type != X86_OP_MEM \
                        or ins.reg_name(ins.operands[1].mem.base) != "rip":
                    continue
                for key in keys:
                    found[key].add(owner)
        return found

    def scene(self, load_start: int) -> dict:
        candidates = []
        caller = self.instructions(load_start)
        for index, call in enumerate(caller):
            target = _direct_call(call)
            entry = _chain(_register(caller, index, "rcx"))
            if target not in self.functions or entry is None or entry[0] != 0 or not entry[1]:
                continue
            helper = self.instructions(target)
            for at in range(len(helper) - 4):
                compare = _comparison(helper[at])
                if compare is None or compare[1] != 1101 or compare[0].size != 4:
                    continue
                root = _chain(_memory_base(helper, at, compare[0]))
                alternative = _comparison(helper[at + 2])
                yes, no = helper[at + 1], helper[at + 3]
                if root is None or root[0] != 0 or not root[1] or alternative is None \
                        or alternative[1] != 1 or alternative[0].size not in (1, 4) \
                        or yes.mnemonic not in ("je", "jz") or no.mnemonic not in ("jne", "jnz") \
                        or not yes.operands or yes.operands[0].type != X86_OP_IMM \
                        or not no.operands or no.operands[0].type != X86_OP_IMM \
                        or yes.operands[0].imm != helper[at + 4].address \
                        or not helper[at + 4].address < no.operands[0].imm < self.functions[target]:
                    continue
                other = _chain(_memory_base(helper, at + 2, alternative[0]))
                if other is None or other[0] != 0:
                    continue
                chain = entry[1] + root[1] + [compare[0].mem.disp]
                alternative_chain = entry[1] + other[1] + [alternative[0].mem.disp]
                if not _valid_chain(chain) or not _valid_chain(alternative_chain, field_width=alternative[0].size):
                    continue
                candidates.append({
                    "SceneChain": chain,
                    "SceneGuard": {"HelperOffset": hex(target), "CallOffset": hex(call.address),
                        "CompareOffset": hex(helper[at].address), "PointerChain": root[1],
                        "Expected": 1101, "Width": 4, "Operator": "or",
                        "AlternativeChain": alternative_chain, "AlternativeWidth": alternative[0].size,
                        "AlternativeExpected": 1},
                })
        return _unique(candidates, "SceneChain")

    def filter_abi(self, target: int) -> bool:
        instructions = self.instructions(target)
        outputs = False
        span_consumed = False
        returns = []
        for index, ins in enumerate(instructions):
            ops = ins.operands
            if ins.mnemonic == "ret":
                returns.append(_register(instructions, index, "rax") == ("arg", 0))
            if ins.mnemonic == "mov" and len(ops) == 2 and ops[0].type == X86_OP_MEM \
                    and ops[0].size == 8 and ops[0].mem.disp == 0 \
                    and _memory_base(instructions, index, ops[0]) == ("arg", 0) \
                    and ops[1].type == X86_OP_REG and ins.reg_name(ops[1].reg) == "rax":
                outputs = True
            if _direct_call(ins) is None:
                continue
            span = _register(instructions, index, "rcx")
            if span is None or span[0] != "stack":
                continue
            stores = {}
            for before in range(index - 1, -1, -1):
                previous = instructions[before]
                if previous.mnemonic == "call":
                    break
                prior = previous.operands
                if previous.mnemonic != "mov" or len(prior) != 2 or prior[0].type != X86_OP_MEM \
                        or prior[0].size != 8 or prior[1].type != X86_OP_REG:
                    continue
                address = _add(_memory_base(instructions, before, prior[0]), prior[0].mem.disp)
                if address in (span, _add(span, 8)) and address not in stores:
                    stores[address] = _register(instructions, before, previous.reg_name(prior[1].reg))
            span_consumed |= stores.get(span) == ("arg", 1) and stores.get(_add(span, 8)) == ("arg", 2)
        return outputs and span_consumed and bool(returns) and all(returns)

    def filter_candidates(self, owner: int) -> list[dict]:
        instructions = self.instructions(owner)
        candidates = []
        for index, call in enumerate(instructions):
            target = _direct_call(call)
            if target not in self.functions:
                continue
            out = _register(instructions, index, "rcx")
            data = _register(instructions, index, "rdx")
            length = _register(instructions, index, "r8")
            if out is None or out[0] != "stack" or data is None or length is None \
                    or data[0] != "load" or length[0] != "load" or data[1] != length[1] \
                    or data[2] != 0 or length[2] != 8 or _chain(data[1]) is None:
                continue
            for at in range(index + 1, min(index + 17, len(instructions))):
                ins = instructions[at]
                if ins.mnemonic in ("call", "ret", "jmp"):
                    break
                compare = _comparison(ins)
                if compare is None or compare[1] != 6 or compare[0].size != 4 or compare[0].mem.disp != 8:
                    continue
                if _memory_base(instructions, at, compare[0]) != ("load", out, 0) \
                        or not self.filter_abi(target):
                    continue
                candidates.append({"CDPFilterHookOffset": hex(target),
                    "FilterOwnerOffset": hex(owner), "FilterCallOffset": hex(call.address),
                    "FilterTagCompareOffset": hex(ins.address),
                    "FilterABI": {"OutArgument": 0, "DataArgument": 1, "LengthArgument": 2,
                                  "Return": "out-pointer", "TagOffset": 8, "MapTag": 6, "SuppressedTag": 0}})
        return candidates

    def filter(self, owner: int) -> dict:
        return _unique(self.filter_candidates(owner), "CDPFilterHookOffset")


def _analyze(binary_path: Path, arch: str) -> tuple[dict, list[AnchorReport]]:
    report: list[AnchorReport] = []
    try:
        with BinaryView(binary_path, arch) as image:
            analysis = _PEAnalysis(image)
            anchors = analysis.anchors()
            load = _unique(list(anchors["LoadStartFile"] & anchors["LoadStartName"]), "LoadStartHookOffset")
            report.append(AnchorReport("LoadStartHookOffset", True,
                "Source filename and qualified OnLoadStart name share an unwind-bounded function", hex(load)))
            owner = _unique(list(anchors["FilterName"] & anchors["FilterAppletFile"]), "FilterOwner")
            report.append(AnchorReport("FilterOwner", True,
                "Exact SendToClientFilter and applet-webview source xrefs share an unwind-bounded function",
                hex(owner)))
            scene = analysis.scene(load)
            report.append(AnchorReport("SceneChain", True,
                "Win64 this provenance reaches scene==1101 OR alternate boolean==1 guard",
                scene["SceneGuard"]["CompareOffset"]))
            filter_role = analysis.filter(owner)
            report.append(AnchorReport("CDPFilterHookOffset", True,
                "Native out-pointer, input span ABI, and returned object dword tag+8==6 proven",
                filter_role["CDPFilterHookOffset"]))
            def call_site(role: str, proven: dict) -> dict:
                return {"Role": role, "OwnerOffset": proven["FilterOwnerOffset"],
                        "CallOffset": proven["FilterCallOffset"],
                        "TagCompareOffset": proven["FilterTagCompareOffset"]}

            sites = [call_site("applet_webview", filter_role)]
            if anchors["FilterWebviewFile"]:
                webview = _unique([candidate for entry in sorted(anchors["FilterWebviewFile"])
                    for candidate in analysis.filter_candidates(entry)], "FilterCallSites.webview")
                if any(webview[key] != filter_role[key] for key in ("CDPFilterHookOffset", "FilterABI")):
                    raise ExtractionError("Webview call does not share the proven native decoder and ABI",
                                          stage="FilterCallSites.webview")
                sites.append(call_site("webview", webview))
                report.append(AnchorReport("FilterCallSites.webview", True,
                    "Independent webview source, input span, out-pointer, tag and native return ABI proven",
                    webview["FilterCallOffset"]))
            filter_role["FilterCallSites"] = sites
            return {"Format": "PE", "ABI": "win64-legacy", "Module": "flue.dll",
                    "Arch": {"x86_64": {"LoadStartHookOffset": hex(load), **scene, **filter_role}}}, report
    except ExtractionError as error:
        error.report = report + [AnchorReport(error.stage, False, str(error))]
        raise
    except (OSError, ValueError, struct.error) as error:
        raise ExtractionError(str(error), stage="binary", report=report) from error


def _compare_config(config: dict, expected: dict) -> list[VerifyCheck]:
    def same(actual, required):
        if type(actual) is not type(required):
            return False
        if isinstance(required, dict):
            return actual.keys() == required.keys() and all(same(actual[key], value) for key, value in required.items())
        if isinstance(required, list):
            return len(actual) == len(required) and all(same(a, b) for a, b in zip(actual, required))
        return actual == required

    checks = []
    for key in ("Format", "ABI", "Module"):
        value = config.get(key)
        checks.append(VerifyCheck(key, str(value), value == expected[key],
                                  f"Current binary requires {expected[key]}"))
    actual = (config.get("Arch") or {}).get("x86_64")
    if not isinstance(actual, dict):
        return checks + [VerifyCheck("Arch.x86_64", None, False, "Exact x86_64 role block required")]
    for key, value in expected["Arch"]["x86_64"].items():
        candidate = actual.get(key)
        equal = same(candidate, value)
        if key.endswith("Offset"):
            try:
                equal = int(str(candidate), 0) == int(value, 0)
            except (TypeError, ValueError):
                equal = False
        checks.append(VerifyCheck(key, str(candidate), equal,
                                  "Matches current PE role/dataflow proof" if equal
                                  else f"Does not match current PE role/dataflow proof: {value}"))
    return checks


def extract_offsets(binary_path: Path, version: int | None,
                    arch: str = "x86_64") -> ExtractionResult:
    started = time.monotonic()
    config, report = _analyze(Path(binary_path), arch)
    if version is not None:
        config["Version"] = version
    checks = _compare_config(config, config)
    return ExtractionResult(version, arch, str(binary_path), config, report,
                            round(time.monotonic() - started, 2), all(check.ok for check in checks),
                            [check.note for check in checks if not check.ok])


def verify_config(binary_path: Path, config: dict,
                  arch: str = "x86_64") -> list[VerifyCheck]:
    """Repeat role recovery against the binary; a range check alone cannot pass."""
    try:
        expected, _ = _analyze(Path(binary_path), arch)
    except ExtractionError as error:
        return [VerifyCheck(error.stage, None, False, str(error))]
    return _compare_config(config, expected)
