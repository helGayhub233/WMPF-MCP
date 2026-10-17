"""Bounded, read-only binary questions for the agent's analysis method chain.

No version lookup, learned-layout database, fingerprint or persistent report.
"""

from __future__ import annotations

import mmap
import platform
import struct
from pathlib import Path

from ..core.errors import ErrorCode, ToolError


def normalize_arch(value: str) -> str:
    return {"aarch64": "arm64", "amd64": "x86_64", "x64": "x86_64",
            "x86": "x86_32", "i386": "x86_32", "i686": "x86_32"}.get(value.lower(), value.lower())


class BinaryView:
    """Address maps derived from headers, with an explicitly selected fat slice."""

    def __init__(self, path: Path, arch: str | None = None):
        self.path = path
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"Analysis binary is missing or empty: {path}")
        with path.open("rb") as stream:
            self.data = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        self.start, self.end = 0, len(self.data)
        self.sections: list[dict] = []
        self.available_arches: list[str] = []
        self.endian = "<"
        self.bits = 64
        try:
            self._headers(normalize_arch(arch) if arch else None)
        except (struct.error, IndexError) as error:
            self.close()
            raise ValueError("Truncated or invalid binary header") from error
        except Exception:
            self.close()
            raise

    def close(self):
        self.data.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def unpack(self, fmt: str, offset: int):
        size = struct.calcsize(fmt)
        if offset < self.start or offset + size > self.end:
            raise ValueError("Truncated or invalid binary header")
        return struct.unpack_from(fmt, self.data, offset)

    def _section(self, name: str, offset: int, size: int, va: int, executable: bool):
        if size < 0 or offset < self.start or offset + size > self.end:
            raise ValueError(f"Section outside selected binary: {name}")
        if size:
            self.sections.append({"name": name, "file_offset": offset, "size": size,
                                  "va": va, "executable": executable})

    def _headers(self, requested: str | None):
        magic = self.data[:4]
        if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
            count = self.unpack(">I", 4)[0]
            if not 0 < count <= 64:
                raise ValueError("Invalid Mach-O slice count")
            slices = []
            for i in range(count):
                if magic[-1] == 0xBF:
                    cpu, _, off, size, _, _ = self.unpack(">IIQQII", 8 + 32 * i)
                else:
                    cpu, _, off, size, _ = self.unpack(">IIIII", 8 + 20 * i)
                name = {0x0100000C: "arm64", 0x01000007: "x86_64"}.get(cpu, f"cpu_{cpu}")
                slices.append((name, off, size))
            self.available_arches = [s[0] for s in slices]
            selected = requested or (slices[0][0] if len(slices) == 1 else normalize_arch(platform.machine()))
            match = next((s for s in slices if s[0] == selected), None)
            if match is None:
                raise ValueError(f"Select arch from {self.available_arches}; requested {selected}")
            _, self.start, size = match
            self.end = self.start + size
            if self.start < 8 or self.end > len(self.data):
                raise ValueError("Mach-O slice outside file")
            magic = self.data[self.start:self.start + 4]
        if magic == b"\xcf\xfa\xed\xfe":
            self._macho()
        elif magic == b"\x7fELF":
            self._elf()
        elif magic[:2] == b"MZ":
            self._pe()
        else:
            raise ValueError("Expected a Mach-O, ELF or PE analysis binary")
        if requested and requested != self.arch:
            raise ValueError(f"Binary architecture is {self.arch}, requested {requested}")
        self.available_arches = self.available_arches or [self.arch]
        if not self.sections:
            raise ValueError("Binary has no file-backed address map")

    def _macho(self):
        self.format = "Mach-O"
        _, cpu, _, _, ncmds, sizeofcmds, _, _ = self.unpack("<8I", self.start)
        self.arch = {0x0100000C: "arm64", 0x01000007: "x86_64"}.get(cpu, f"cpu_{cpu}")
        pos = self.start + 32
        stop = pos + sizeofcmds
        if stop > self.end or ncmds > 65536:
            raise ValueError("Invalid Mach-O load commands")
        for _ in range(ncmds):
            cmd, size = self.unpack("<II", pos)
            if size < 8 or pos + size > stop:
                raise ValueError("Invalid Mach-O load-command size")
            if cmd == 0x19:
                values = self.unpack("<II16sQQQQiiII", pos)
                _, _, name, va, _, off, file_size, _, protection, nsects, _ = values
                self._section(name.rstrip(b"\0").decode("ascii", "replace"),
                              self.start + off, file_size, va, bool(protection & 4) and nsects == 0)
                if 72 + nsects * 80 > size:
                    raise ValueError("Mach-O sections exceed segment command")
                for i in range(nsects):
                    section = self.unpack("<16s16sQQ8I", pos + 72 + i * 80)
                    sectname, _, sectva, sectsize, sectoff, _, _, _, flags, _, _, _ = section
                    if flags & 0x80000400:
                        self._section(sectname.rstrip(b"\0").decode("ascii", "replace"),
                                      self.start + sectoff, sectsize, sectva, True)
            pos += size
        self.image_base = next((s["va"] for s in self.sections if s["name"] == "__TEXT"),
                               min(s["va"] - (s["file_offset"] - self.start) for s in self.sections))

    def _elf(self):
        self.format = "ELF"
        cls, order = self.data[4], self.data[5]
        if cls not in (1, 2) or order not in (1, 2):
            raise ValueError("Invalid ELF class or byte order")
        self.bits = 64 if cls == 2 else 32
        self.endian = "<" if order == 1 else ">"
        machine = self.unpack(self.endian + "H", 18)[0]
        self.arch = {183: "arm64", 62: "x86_64", 3: "x86_32", 40: "arm"}.get(machine, f"machine_{machine}")
        if cls == 2:
            phoff = self.unpack(self.endian + "Q", 32)[0]
            entsize, count = self.unpack(self.endian + "HH", 54)
            expected = 56
        else:
            phoff = self.unpack(self.endian + "I", 28)[0]
            entsize, count = self.unpack(self.endian + "HH", 42)
            expected = 32
        if entsize < expected or count > 65536:
            raise ValueError("Invalid ELF program headers")
        for i in range(count):
            pos = phoff + i * entsize
            if cls == 2:
                kind, flags, off, va, _, file_size, _, _ = self.unpack(self.endian + "II6Q", pos)
            else:
                kind, off, va, _, file_size, _, flags, _ = self.unpack(self.endian + "8I", pos)
            if kind == 1:
                self._section(f"PT_LOAD_{i}", off, file_size, va, bool(flags & 1))
        self.image_base = min((s["va"] - s["file_offset"] for s in self.sections), default=0)

    def _pe(self):
        self.format = "PE"
        pe = self.unpack("<I", 0x3C)[0]
        if self.data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("Invalid PE signature")
        machine, count, _, _, _, optional_size, _ = self.unpack("<HHIIIHH", pe + 4)
        self.arch = {0xAA64: "arm64", 0x8664: "x86_64", 0x14C: "x86_32"}.get(machine, f"machine_{machine}")
        optional = pe + 24
        kind = self.unpack("<H", optional)[0]
        if kind == 0x20B:
            self.image_base = self.unpack("<Q", optional + 24)[0]
        elif kind == 0x10B:
            self.bits = 32
            self.image_base = self.unpack("<I", optional + 28)[0]
        else:
            raise ValueError("Unsupported PE optional header")
        if count > 4096:
            raise ValueError("Invalid PE section count")
        for i in range(count):
            pos = optional + optional_size + i * 40
            name, _, rva, size, off, _, _, _, _, flags = self.unpack("<8s6I2HI", pos)
            self._section(name.rstrip(b"\0").decode("ascii", "replace"),
                          off, size, self.image_base + rva, bool(flags & 0x20000000))

    def va_to_offset(self, va: int) -> int:
        for section in self.sections:
            delta = va - section["va"]
            if 0 <= delta < section["size"]:
                return section["file_offset"] + delta
        raise ValueError(f"VA {hex(va)} is not file-backed")

    def addresses(self, off: int) -> dict:
        va = next((s["va"] + off - s["file_offset"] for s in self.sections
                   if s["file_offset"] <= off < s["file_offset"] + s["size"]), None)
        return {"file_offset": hex(off), "va": hex(va) if va is not None else None,
                "rva": hex(va - self.image_base) if va is not None else None}

    def summary(self) -> dict:
        return {"format": self.format, "arch": self.arch, "bits": self.bits,
                "endian": "little" if self.endian == "<" else "big",
                "available_arches": self.available_arches, "image_base": hex(self.image_base),
                "sections": [{**s, "file_offset": hex(s["file_offset"]), "va": hex(s["va"])}
                             for s in self.sections],
                "limitations": ["Header/ISA recognition does not establish hook ABI or runtime compatibility."]}


def _disassembler(image: BinaryView):
    try:
        import capstone as cs
    except ImportError as error:
        raise ToolError(ErrorCode.DEPS_MISSING, "Disassembly requires the optional capstone module.",
                        remedy="Install wmpf-mcp[extract]; summary and strings remain usable.") from error
    if image.arch == "arm64":
        mode = cs.CS_MODE_LITTLE_ENDIAN if image.endian == "<" else cs.CS_MODE_BIG_ENDIAN
        md = cs.Cs(cs.CS_ARCH_ARM64, mode)
    elif image.arch in ("x86_64", "x86_32"):
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if image.bits == 64 else cs.CS_MODE_32)
    else:
        raise ToolError(ErrorCode.UNSUPPORTED_ANALYSIS, f"No disassembler for {image.arch}.",
                        remedy="Use summary/strings, then inspect the indicated ISA in an external disassembler.")
    md.detail = True
    md.skipdata = True
    return md


def inspect_binary(path: Path, *, view: str = "summary", arch: str | None = None,
                   pattern: str | None = None, address: str | None = None,
                   scan_from: str | None = None, scan_bytes: int = 262144, limit: int = 50) -> dict:
    """Return a bounded question's answer; addresses are link-time VAs, never ASLR pointers."""
    with BinaryView(path, arch) as image:
        result = {"binary": str(path), "view": view, **image.summary()}
        rows: list[dict] = []
        if view == "summary":
            return {**result, "results": rows, "truncated": False}
        if view == "strings":
            if not pattern:
                raise ValueError("pattern is required for view=strings")
            needle = pattern.encode("utf-8")
            pos = image.start
            while len(rows) <= limit:
                off = image.data.find(needle, pos, image.end)
                if off < 0:
                    break
                end = image.data.find(b"\0", off, min(off + 240, image.end))
                end = min(off + 240, image.end) if end < 0 else end
                rows.append({**image.addresses(off), "text": image.data[off:end].decode("utf-8", "replace")})
                pos = off + len(needle)
            return {**result, "results": rows[:limit], "truncated": len(rows) > limit}
        if not address:
            raise ValueError("address (link-time VA from an inspection row) is required")
        target = int(address, 0)
        md = _disassembler(image)
        if view in ("disasm", "calls"):
            start = target
        else:
            start = int(scan_from, 0) if scan_from else min(
                (s["va"] for s in image.sections if s["executable"]), default=target)
        section = next((s for s in image.sections if s["va"] <= start < s["va"] + s["size"]
                        and s["executable"]), None)
        if section is None:
            raise ValueError("Code scan must start inside an executable, file-backed section")
        off = image.va_to_offset(start)
        size = min(scan_bytes, section["size"] - (start - section["va"]))
        if view == "disasm":
            size = min(size, limit * 16)
        pages: dict[int, tuple[int, int]] = {}
        end_va = start
        for index, ins in enumerate(md.disasm(image.data[off:off + size], start)):
            end_va = ins.address + ins.size
            row = {**image.addresses(image.va_to_offset(ins.address)),
                   "mnemonic": ins.mnemonic, "operands": ins.op_str}
            if ins.id == 0:
                if view == "disasm":
                    rows.append(row)
                    if len(rows) >= limit:
                        break
                continue
            ops = ins.operands
            if view == "disasm":
                rows.append(row)
            elif view == "calls" and ins.mnemonic in ("bl", "blr", "call"):
                destination = ops[0].imm if ops and ops[0].type == 2 else None
                rows.append({**row, "target_va": hex(destination) if destination is not None else None})
            elif view == "xrefs":
                hit = any(op.type == 2 and op.imm == target for op in ops) and ins.mnemonic != "adrp"
                if image.arch == "arm64":
                    for op in ops:
                        if op.type == 3 and op.mem.base in pages:
                            page, seen = pages[op.mem.base]
                            hit |= index - seen <= 4 and page + op.mem.disp == target
                    if ins.mnemonic == "add" and len(ops) >= 3 and ops[1].type == 1 and ops[2].type == 2:
                        page, seen = pages.get(ops[1].reg, (0, -100))
                        hit |= index - seen <= 4 and page + ops[2].imm == target
                    _, written = ins.regs_access()
                    for reg in written:
                        pages.pop(reg, None)
                    if ins.mnemonic == "adrp" and len(ops) == 2:
                        pages[ops[0].reg] = (ops[1].imm, index)
                else:
                    hit |= any(op.type == 3 and ins.reg_name(op.mem.base) in ("rip", "eip")
                               and end_va + op.mem.disp == target for op in ops)
                if hit:
                    rows.append(row)
            else:
                if view not in ("disasm", "calls", "xrefs"):
                    raise ValueError(f"Unknown inspection view: {view}")
            if len(rows) >= limit:
                break
        # Undecodable bytes at the end still consume this window; never repeat it.
        if end_va == start:
            end_va = start + size
        remaining = end_va < section["va"] + section["size"]
        next_va = end_va if remaining and end_va > start else None
        if not remaining:
            next_va = next((s["va"] for s in sorted(image.sections, key=lambda s: s["va"])
                            if s["executable"] and s["va"] >= end_va), None)
        return {**result, "results": rows, "scanned_bytes": end_va - start,
                "truncated": next_va is not None, "next_address": hex(next_va) if next_va is not None else None,
                "limitations": [*result["limitations"],
                    "An empty bounded scan is not proof that no reference exists; continue at next_address.",
                    "Linear code scans can miss indirect references and split instruction/data-flow boundaries; inspect known functions as well.",
                    "Function role must be established from callers and data flow, not the first call instruction."]}
