"""Minimal Mach-O (fat) reader and arm64 xref toolkit.

No lief/macholib dependency: only what offset extraction needs — fat slice
selection, segment/section maps, VA<->file mapping, string search, adrp-based
cross references (numpy prefilter + capstone exact match) and a heuristic
function-start finder (nearest standard prologue frame).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007
_LC_SEGMENT_64 = 0x19
_MH_MAGIC_64 = 0xFEEDFACF

# arm64 prologue frame: stp x29, x30, [sp, #-imm]! / stp x29, x30, [sp, #imm]
_FRAME_MASK = 0xFFC07FFF
_FRAME_PRE = 0xA9807BFD
_FRAME_OFF = 0xA9007BFD
_PACIBSP = 0xD503237F


class MachOError(ValueError):
    """Raised when the binary cannot be parsed or a slice is missing."""


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


@dataclass
class Section:
    seg: str
    name: str
    addr: int
    size: int
    fileoff: int


@dataclass
class _AdrpIndex:
    """Precomputed adrp page targets for the __text section."""

    instr_indices: np.ndarray  # index of each adrp instruction (in words)
    pages: np.ndarray  # page base each adrp targets


class MachOSlice:
    """One architecture slice of a Mach-O (fat) binary with arm64 tools."""

    def __init__(self, path: Path, cputype: int = CPU_TYPE_ARM64) -> None:
        self.path = Path(path)
        raw = self.path.read_bytes()
        self.slice_offset, self.data = _select_slice(raw, cputype)
        self.segments, self.sections = _parse_macho(self.data)
        self.image_base = _image_base(self.segments)
        self.text = next(
            (s for s in self.sections if s.seg == "__TEXT" and s.name == "__text"), None
        )
        if self.text is None:
            raise MachOError("no __TEXT,__text section in this slice")
        self._md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self._md.detail = True
        self._adrp: _AdrpIndex | None = None

    # -- mapping -------------------------------------------------------------
    def va_to_off(self, va: int) -> int:
        for segment in self.segments:
            delta = va - segment.vmaddr
            if 0 <= delta < segment.filesize:
                return segment.fileoff + delta
        raise MachOError(f"VA {hex(va)} is not file-backed")

    def off_to_va(self, offset: int) -> int | None:
        for segment in self.segments:
            if segment.fileoff <= offset < segment.fileoff + segment.filesize:
                return segment.vmaddr + offset - segment.fileoff
        return None

    def read(self, va: int, size: int) -> bytes:
        off = self.va_to_off(va)
        return self.data[off : off + size]

    # -- strings -------------------------------------------------------------
    def find_string(self, needle: bytes) -> list[int]:
        """Mapped virtual addresses, including images whose VA != file offset."""
        out: list[int] = []
        start = 0
        while True:
            i = self.data.find(needle, start)
            if i < 0:
                return out
            va = self.off_to_va(i)
            if va is not None:
                out.append(va)
            start = i + 1

    def read_cstr(self, va: int, limit: int = 512) -> str:
        off = self.va_to_off(va)
        end = self.data.find(b"\x00", off, off + limit)
        end = min(off + limit, len(self.data)) if end < 0 else end
        return self.data[off:end].decode("utf-8", errors="replace")

    def segment_of(self, va: int) -> Segment | None:
        return next(
            (
                s
                for s in self.segments
                if s.vmaddr <= va < s.vmaddr + s.filesize
            ),
            None,
        )

    # -- adrp index ----------------------------------------------------------
    def _adrp_index(self) -> _AdrpIndex:
        if self._adrp is not None:
            return self._adrp
        off, size = self.text.fileoff, self.text.size
        arr = np.frombuffer(self.data[off : off + size], dtype="<u4")
        idx = np.nonzero((arr & np.uint32(0x9F000000)) == np.uint32(0x90000000))[0]
        instr = arr[idx].astype(np.uint64)
        immlo = (instr >> np.uint64(29)) & np.uint64(3)
        immhi = (instr >> np.uint64(5)) & np.uint64(0x7FFFF)
        imm = (immhi << np.uint64(2)) | immlo
        signed = np.where(
            imm & np.uint64(1 << 20), imm.astype(np.int64) - (1 << 21), imm.astype(np.int64)
        )
        pc = self.text.addr + idx.astype(np.int64) * 4
        pages = (pc & ~np.int64(0xFFF)) + (signed << 12)
        self._adrp = _AdrpIndex(instr_indices=idx, pages=pages)
        return self._adrp

    # -- xrefs ---------------------------------------------------------------
    def xrefs(self, target_va: int, word_span: int = 3) -> list[int]:
        """Code addresses whose adrp(+add/ldr) addresses exactly ``target_va``."""
        index = self._adrp_index()
        low12 = target_va & 0xFFF
        hits = np.nonzero(index.pages == np.int64(target_va & ~0xFFF))[0]
        refs: list[int] = []
        for h in hits:
            word_i = int(index.instr_indices[h])
            va = self.text.addr + word_i * 4
            insns = list(self.disasm(va, 4))
            if not insns or insns[0].mnemonic != "adrp":
                continue
            rd = insns[0].operands[0].reg
            for ins in insns[1 : 1 + word_span]:
                if (
                    ins.mnemonic == "add"
                    and len(ins.operands) == 3
                    and ins.operands[0].reg == rd
                    and ins.operands[1].reg == rd
                    and ins.operands[2].type == 2
                    and ins.operands[2].imm == low12
                ):
                    refs.append(va)
                    break
                if (
                    ins.mnemonic in ("ldr", "ldrb", "ldrh", "ldrsw")
                    and len(ins.operands) >= 2
                    and ins.operands[1].type == 3
                    and ins.operands[1].mem.base == rd
                    and ins.operands[1].mem.disp == low12
                ):
                    refs.append(va)
                    break
                if ins.operands and ins.operands[0].type == 1 and ins.operands[0].reg == rd:
                    break
        return refs

    # -- disassembly ---------------------------------------------------------
    def disasm(self, va: int, count: int = 8):
        off = self.va_to_off(va)
        return list(self._md.disasm(self.data[off : off + count * 4], va))

    def find_function_start(self, ref_va: int, max_back: int = 0x20000) -> int | None:
        """Nearest standard arm64 frame prologue at or before ``ref_va``."""
        off = self.va_to_off(ref_va)
        start = max(self.text.fileoff, off - max_back)
        for probe in range(off - 4, start - 4, -4):
            word = struct.unpack_from("<I", self.data, probe)[0]
            if word & _FRAME_MASK in (_FRAME_PRE, _FRAME_OFF):
                entry = probe
                prev = struct.unpack_from("<I", self.data, probe - 4)[0]
                if prev == _PACIBSP:
                    entry = probe - 4
                return self.text.addr + (entry - self.text.fileoff)
        return None

    def offset_of(self, va: int) -> int:
        """Offset relative to the image base (what Frida's base.add() wants)."""
        return va - self.image_base


def _select_slice(raw: bytes, cputype: int) -> tuple[int, bytes]:
    magic = struct.unpack(">I", raw[:4])[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        count = struct.unpack(">I", raw[4:8])[0]
        for i in range(count):
            base = 8 + i * 20
            ct, _cs, offset, size, _al = struct.unpack(">IIIII", raw[base : base + 20])
            if ct == cputype:
                return offset, raw[offset : offset + size]
        raise MachOError(f"no slice for cputype 0x{cputype:x}")
    # thin binary
    ct = struct.unpack("<I", raw[4:8])[0]
    if ct != cputype:
        raise MachOError(f"thin binary cputype 0x{ct:x} != requested 0x{cputype:x}")
    return 0, raw


def _parse_macho(sl: bytes) -> tuple[list[Segment], list[Section]]:
    magic = struct.unpack("<I", sl[:4])[0]
    if magic != _MH_MAGIC_64:
        raise MachOError(f"unsupported Mach-O magic 0x{magic:x}")
    ncmds = struct.unpack("<I", sl[16:20])[0]
    pos = 32
    segments: list[Segment] = []
    sections: list[Section] = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", sl[pos : pos + 8])
        if cmd == _LC_SEGMENT_64:
            segname = sl[pos + 8 : pos + 24].rstrip(b"\x00").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack("<QQQQ", sl[pos + 24 : pos + 56])
            nsects = struct.unpack("<I", sl[pos + 64 : pos + 68])[0]
            segments.append(Segment(segname, vmaddr, vmsize, fileoff, filesize))
            spos = pos + 72
            for _s in range(nsects):
                secname = sl[spos : spos + 16].rstrip(b"\x00").decode()
                sseg = sl[spos + 16 : spos + 32].rstrip(b"\x00").decode()
                saddr, ssize = struct.unpack("<QQ", sl[spos + 32 : spos + 48])
                soff = struct.unpack("<I", sl[spos + 48 : spos + 52])[0]
                sections.append(Section(sseg, secname, saddr, ssize, soff))
                spos += 80
        pos += cmdsize
    return segments, sections


def _image_base(segments: list[Segment]) -> int:
    text = next((s for s in segments if s.name == "__TEXT"), None)
    if text is None:
        raise MachOError("no __TEXT segment")
    return text.vmaddr
