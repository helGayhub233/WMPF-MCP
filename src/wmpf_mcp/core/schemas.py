"""Compact documented reply contracts, without a persistent runtime inventory."""
from __future__ import annotations

from typing import Annotated, Any, Generic, Literal, TypeVar
from mcp.types import CallToolResult
from pydantic import BaseModel, ConfigDict, Field, model_validator

ToolName = Literal[
    "check_environment", "inspect_binary", "check_offsets", "prepare_offsets",
    "start_runtime", "stop_runtime", "inspect_runtime", "probe_runtime",
    "inspect_source", "decompile_applet", "query_traffic", "clear_traffic", "manage_wechat",
]


def _compact(schema: dict) -> None:
    """Drop generated titles/defaults; preserve constraints and field docs."""
    schema.pop("title", None)
    for field in schema.get("properties", {}).values():
        field.pop("title", None)
        field.pop("default", None)


class Contract(BaseModel):
    model_config = ConfigDict(json_schema_extra=_compact)


class NextAction(Contract):
    tool: ToolName = Field(description="Registered follow-up tool.")
    arguments: dict[str, Any] = Field(description="Concrete input arguments.")
    reason: str = Field(description="Question this observation resolves.")
    expected: str = Field(description="Condition to verify in the result.")
    on_failure: str = Field(description="Alternative investigation on failure.")
    stop_condition: str = Field(description="Retry bound or stopping condition.")


class WarningInfo(Contract):
    code: str = Field(description="Stable warning code.")
    message: str = Field(description="Non-fatal interpretation limit.")


class ErrorInfo(Contract):
    code: str = Field(description="Stable E_* execution error.")
    message: str = Field(description="Failed operation and reason.")
    remedy: str | None = Field(None, description="Suggested recovery.")


class ResultData(Contract):
    model_config = ConfigDict(extra="allow", json_schema_extra=_compact)


class EnvironmentData(ResultData):
    goal: str = Field(description="Requested outcome.")
    scope: str = Field(description="all, packages, system or wechat.")
    environment_ready: bool | None = Field(description="Complete preflight passed; null for scoped checks. Never live health.")
    requires_live_verification: bool = Field(description="Goal needs attach/command/client validation.")
    checks: list[dict[str, Any]] = Field(description="check/status/detail/blocking observations.")
    blockers: list[dict[str, Any]] = Field(description="Conditions blocking this goal's preflight.")
    dependencies: dict[str, Any] | None = Field(None, description="MCP interpreter and package import/version checks.")
    wechat: dict[str, Any] | None = Field(None, description="Paths, PID candidates and optional app/WMPF labels.")
    binary: dict[str, Any] | None = Field(None, description="Module format/ISA/maps, separate from host ISA.")
    permission: dict[str, Any] | None = Field(None, description="Policy clues; attach remains unverified.")
    ports: dict[str, Any] | None = Field(None, description="9421/private, raw CDP and Portal listeners.")
    config: dict[str, Any] | None = Field(None, description="Resolved app/cache/home/workspace roots; ~ and $VAR/${VAR} expanded without a shell.")
    implementation_gaps: list[dict[str, str]] = Field(default_factory=list, description="Missing or unverified platform method branches and PATH issue IDs; no version inventory.")


class BinaryData(ResultData):
    format: str = Field(description="Observed Mach-O, ELF or PE container.")
    arch: str = Field(description="Selected target ISA.")
    image_base: str | None = Field(None, description="Link-time base; VA minus base is RVA, not file offset.")
    sections: list[dict[str, Any]] | None = Field(None, description="Mapped file_offset/VA/size/executable regions.")
    results: list[dict[str, Any]] | None = Field(None, description="Bounded rows with VA/RVA/file-offset address kinds.")
    scanned_bytes: int | None = Field(None, description="Code bytes examined.")
    truncated: bool | None = Field(None, description="Bounds may exclude further matches.")
    next_address: str | None = Field(None, description="Resume xrefs at this link-time VA.")
    limitations: list[str] | None = Field(None, description="Coverage and missing analyses.")


class OffsetsData(ResultData):
    config_path: str | None = Field(None, description="Local parameters; version is only a file label.")
    ready: bool | None = Field(None, description="Current static checks passed; hook behavior remains unverified.")
    passed: bool | None = Field(None, description="Candidate static verification result.")
    verified: bool | None = Field(None, description="Static verification only.")
    checks: list[dict[str, Any]] | None = Field(None, description="Per-field/ISA/address/role key/value/ok/note checks.")
    config: dict[str, Any] | None = Field(None, description="Exact-ISA hook parameters.")
    written: bool | None = Field(None, description="Checked extraction wrote a file.")
    imported: bool | None = Field(None, description="Checked candidate was installed.")


class PromptNotification(Contract):
    status: Literal["not_requested", "pending", "accepted", "declined", "cancelled",
                    "timeout", "failed", "closed", "not_needed", "unsupported", "disabled"] = Field(
        description="MCP Q&A outcome; accepted records the reported user action, not readiness. Miniapp cancel stops owned resources; login cancel ends follow-up without undoing completed maintenance.")
    choice: str | None = Field(None, description="User's selected Q&A option, when a valid form was submitted.")
    message: str | None = Field(None, description="Unsupported-client, failure or timeout details.")


class StartData(ResultData):
    status: str = Field(description="ready, awaiting_miniapp, blocked or cancelled; cancelled means owned cleanup completed, ready still needs a probe.")
    components: dict[str, Any] = Field(description="Component results, including partial startup.")
    first_unmet: str | None = Field(None, description="Condition stopping startup.")
    awaiting_miniapp: bool = Field(description="Hooks/listeners prepared; open/reopen the miniapp once.")
    notification: PromptNotification | None = Field(None, description="Client-rendered Q&A outcome after resource preparation.")
    cleanup_complete: bool | None = Field(None, description="True after Q&A cancellation has stopped owned Portal, listeners and hooks.")


class StopData(ResultData):
    components: dict[str, Any] = Field(description="Per-component stops; external services untouched.")


class MaintenanceData(ResultData):
    action: str = Field(description="prepare, restart, restore or launch the configured macOS WeChat application.")
    dry_run: bool = Field(description="Only planned operations were inspected.")
    executed: bool = Field(description="Requested maintenance finished; app launch still needs readiness checks.")
    backup_path: str | None = Field(None, description="Full runtime bundle .bak and rollback checksums; pass to restore.")
    signatures: list[dict[str, Any]] = Field(description="Discovered main/helper signing units and ad-hoc/runtime flags.")
    force_resign: bool = Field(False, description="prepare was requested to re-sign even suitable units.")
    signed_binaries: list[str] = Field(default_factory=list, description="Signing units whose codesign command completed in this operation; empty for dry-run/reuse.")
    awaiting_login: bool = Field(False, description="Workflow awaits manual login confirmation; false after accepted/cancelled/closed, not a statement of verified login.")
    notification: PromptNotification | None = Field(None, description="Login Q&A outcome; accepted permits fresh environment checks, not assumed runtime readiness.")
    launch: dict[str, Any] | None = Field(None, description="Launch request and currently observed runtime PIDs.")


class RuntimeData(ResultData):
    live: dict[str, Any] = Field(description="This process's hook/engine/Portal status and counters.")
    goal: str = Field(description="Goal selecting the method branch.")
    branch: str = Field(description="First unmet current condition.")
    targets: list[dict[str, Any]] | None = Field(None, description="Compatibility views may alias one runtime.")


class ProbeData(ResultData):
    status: Literal["cancelled"] | None = Field(None, description="hooks: Q&A was cancelled and owned cleanup completed.")
    components: dict[str, Any] | None = Field(None, description="hooks cancellation: per-component owned stop results.")
    cleanup_complete: bool | None = Field(None, description="hooks: true after Q&A cancellation stops owned Portal, listeners and hooks.")
    layer: str | None = Field(None, description="hooks, reconnect, raw, portal or page business-readiness.")
    passed: bool | None = Field(None, description="Named hook/protocol predicate passed, not full client acceptance.")
    checks: list[dict[str, Any]] | None = Field(None, description="Individual bounded protocol checks.")
    frames: list[dict[str, Any]] | None = Field(None, description="Actual runtime frame tree.")
    contexts: list[dict[str, Any]] | None = Field(None, description="DOM/wx/eval/getCurrentPages observations.")
    contexts_truncated: bool | None = Field(None, description="Only first 16 contexts were capability-probed.")
    matched: dict[str, Any] | None = Field(None, description="page: matched business selector, actual frame/context and image/font readiness counts.")
    selector: str | None = Field(None, description="page: caller-chosen business-loaded CSS condition.")
    notification: PromptNotification | None = Field(None, description="hooks: MCP Q&A runs after the bounded armed wait.")


class SourceData(ResultData):
    applets: list[dict[str, Any]] | None = Field(None, description="Cached applets/packages; independent of CDP.")
    hits: list[dict[str, Any]] | None = Field(None, description="Source matches, not runtime execution proof.")
    content: str | None = Field(None, description="Bounded source line range.")
    coverage: dict[str, Any] | None = Field(None, description="Cached/declared subpackages and omissions.")
    appid: str | None = Field(None, description="Selected applet.")


class DecompileData(ResultData):
    appid: str = Field(description="Applet decompiled into the workspace.")
    output_root: str = Field(description="Derived source directory.")
    from_cache: bool = Field(description="Unchanged packages reused prior output.")
    coverage: dict[str, Any] = Field(description="Package coverage and omissions.")
    stats: dict[str, Any] = Field(description="Unpacking/beautification counts.")


class TrafficData(ResultData):
    har: dict[str, Any] | None = Field(None, description="HAR 1.2 object; _wmpf fields declare omissions, failures and byte truncation.")
    export: dict[str, Any] | None = Field(None, description="HAR selection, retained byte counts, caps and deadline.")
    transactions: list[dict[str, Any]] | None = Field(None, description="Observed CDP Network transactions.")
    summary: dict[str, Any] | None = Field(None, description="Ledger activation/counts; native coverage unverified.")
    capture_scope: str | None = Field(None, description="Actual capture coverage.")
    response_body: str | None = Field(None, description="Response capped at 256 KiB.")
    request_body: str | None = Field(None, description="Request capped at 256 KiB.")
    response_body_error: str | None = Field(None, description="Retrieval error, distinct from empty body.")
    request_body_error: str | None = Field(None, description="Retrieval error, distinct from empty body.")
    response_truncated: bool | None = Field(None, description="Response exceeded byte cap.")
    request_truncated: bool | None = Field(None, description="Request exceeded byte cap.")


class ClearData(ResultData):
    cleared: bool = Field(description="In-memory traffic ledger discarded.")


T = TypeVar("T")


class ToolEnvelope(Contract, Generic[T]):
    ok: bool = Field(description="Operation completed; inspect passed/ready for the tested condition.")
    stage: str = Field(description="Historical progress, never live health.")
    data: T | None = Field(None, description="Current operation result.")
    warnings: list[WarningInfo] = Field(default_factory=list, description="Non-fatal limits.")
    next_hint: str | None = Field(None, description="Short recovery hint.")
    next_actions: list[NextAction] = Field(default_factory=list, description="Bounded suggestions; never auto-executed.")
    error: ErrorInfo | None = Field(None, description="Failure also sets MCP isError=true.")
    remedy_detail: dict[str, Any] | None = Field(None, description="Focused failure and method branches.")

    @model_validator(mode="after")
    def consistent_result(self):
        if (not self.ok and self.error is None) or (self.ok and self.error is not None):
            raise ValueError("ok and error are inconsistent")
        return self


EnvironmentReply = Annotated[CallToolResult, ToolEnvelope[EnvironmentData]]
BinaryReply = Annotated[CallToolResult, ToolEnvelope[BinaryData]]
OffsetsReply = Annotated[CallToolResult, ToolEnvelope[OffsetsData]]
StartReply = Annotated[CallToolResult, ToolEnvelope[StartData]]
MaintenanceReply = Annotated[CallToolResult, ToolEnvelope[MaintenanceData]]
StopReply = Annotated[CallToolResult, ToolEnvelope[StopData]]
RuntimeReply = Annotated[CallToolResult, ToolEnvelope[RuntimeData]]
ProbeReply = Annotated[CallToolResult, ToolEnvelope[ProbeData]]
SourceReply = Annotated[CallToolResult, ToolEnvelope[SourceData]]
DecompileReply = Annotated[CallToolResult, ToolEnvelope[DecompileData]]
TrafficReply = Annotated[CallToolResult, ToolEnvelope[TrafficData]]
ClearReply = Annotated[CallToolResult, ToolEnvelope[ClearData]]
