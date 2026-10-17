"""Read-only binary/parameter checks and explicit parameter preparation."""
from __future__ import annotations

from typing import Annotated, Literal
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from ..core.schemas import BinaryReply, OffsetsReply
from . import _offsets
from .contracts import annotations, parameter_error

ISA = Literal["arm64", "x86_64", "x86_32"]


def register(server: MCPServer) -> None:
    @server.tool(name="inspect_binary", annotations=annotations(read_only=True), description="""Ask a bounded question about a local Mach-O/ELF/PE module without attaching.
Follow summary -> related strings -> xrefs -> disassembly/calls -> role predicates.
Use explicit binary_path for offline files; otherwise locate the installed module.
summary/strings need no extract extras; code queries require Capstone. Parser/ISA
support does not establish a native hook backend. Addresses are link-time VAs,
distinct from file offsets, RVAs and live ASLR pointers. Bounded empty results do
not establish absence; resume xrefs with next_address. Choose check_offsets for
candidate validation and prepare_offsets only after required roles are resolved.
No config write, process attach, install or network fetch.""")
    async def inspect_binary(
        view: Annotated[Literal["summary", "strings", "xrefs", "disasm", "calls"], Field(description="Question: headers/maps, literal strings, references, instructions or direct calls.")] = "summary",
        binary_path: Annotated[str | None, Field(description="Local module file; omitted uses the installed module, without requiring an earlier tool call.")] = None,
        pattern: Annotated[str | None, Field(description="strings requires a literal UTF-8 fragment.", max_length=512)] = None,
        address: Annotated[str | None, Field(description="xrefs/disasm/calls require a link-time VA obtained from an inspection row.")] = None,
        arch: Annotated[ISA | None, Field(description="Exact fat-slice ISA; omitted uses the file ISA or matching host slice.")] = None,
        scan_from: Annotated[str | None, Field(description="xrefs resume VA from next_address; omitted starts at the first executable region.")] = None,
        scan_bytes: Annotated[int, Field(description="Maximum examined code bytes per call.", ge=4, le=8388608)] = 262144,
        limit: Annotated[int, Field(description="Maximum returned rows/instructions.", ge=1, le=200)] = 50,
    ) -> BinaryReply:
        if view == "strings" and not pattern:
            return parameter_error("pattern is required for view=strings.")
        if view in {"xrefs", "disasm", "calls"} and not address:
            return parameter_error("address is required for view=" + view + ".")
        return await _offsets.execute(action="inspect", binary_path=binary_path, view=view,
                                      pattern=pattern, address=address, arch=arch,
                                      scan_from=scan_from, scan_bytes=scan_bytes, limit=limit)

    @server.tool(name="check_offsets", annotations=annotations(read_only=True), description="""Read and statically validate local hook parameters against the current module.
Use before attaching, after a module change or to inspect a candidate without installing
it. Missing files return ready=false; failed predicates remain visible in checks.
Validation establishes exact ISA, mapped addresses and implemented semantic roles,
never live hook behavior. Version is an optional file label, not a strategy selector.
No files are written. A successful check may select the candidate in process memory;
start_runtime rechecks the actual installed module. Use inspect_binary to resolve
failed roles, prepare_offsets to write checked parameters, inspect_runtime for live hits.""")
    async def check_offsets(
        config_path: Annotated[str | None, Field(description="Candidate JSON file; omitted uses selected parameters or the detected/local cache label.")] = None,
        binary_path: Annotated[str | None, Field(description="Module to check; omitted locates the actual installed module.")] = None,
        arch: Annotated[ISA | None, Field(description="Exact target ISA; unsupported verifier backends remain explicit.")] = None,
    ) -> OffsetsReply:
        from ..core.state import get_state
        selected = config_path or get_state().config_path
        return await _offsets.execute(action="status", path=selected, binary_path=binary_path, arch=arch)

    @server.tool(name="prepare_offsets", annotations=annotations(destructive=True), description="""Extract or import hook parameters and write them only after static verification.
Use extract when the implemented binary/ABI role predicates apply; import accepts a
local candidate already derived through analysis. Currently automatic extraction and
verification implement Mach-O arm64 and PE x86_64 win64-legacy. Other formats/ISAs return a focused inspect_binary
branch. No fallback to another ISA or old build's offsets. force permits replacement
after checks, never bypasses validation. Existing files are preserved by default.
This writes local parameters and selects them in memory, without attaching or installing
packages. Use check_offsets for read-only checks, start_runtime for live validation.""")
    async def prepare_offsets(
        source: Annotated[Literal["extract", "import"], Field(description="extract derives from the module; import requires candidate_path.")] = "extract",
        candidate_path: Annotated[str | None, Field(description="Required for import: local parameter JSON checked before installation.")] = None,
        binary_path: Annotated[str | None, Field(description="Local module; omitted locates the installed module.")] = None,
        output_path: Annotated[str | None, Field(description="extract only: optional destination; default is detected/local parameter cache.")] = None,
        arch: Annotated[ISA | None, Field(description="Exact target ISA; does not enable an unimplemented hook ABI.")] = None,
        force: Annotated[bool, Field(description="Replace an existing destination only after all required checks pass.")] = False,
    ) -> OffsetsReply:
        from ..core import envelope
        from ..core.errors import ErrorCode, ToolError
        from ..core.state import get_state
        if source == "import" and output_path:
            return envelope.fail(ToolError(ErrorCode.PARAM, "output_path applies only to extract."), stage=get_state().stage.value)
        if source == "extract" and candidate_path:
            return envelope.fail(ToolError(ErrorCode.PARAM, "candidate_path applies only to import."), stage=get_state().stage.value)
        return await _offsets.execute(action=source, path=candidate_path if source == "import" else output_path,
                                      binary_path=binary_path, arch=arch, force=force)
