"""Offset questions, derivation and checked local parameter files."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Literal

from mcp.types import CallToolResult
from pydantic import Field

from ..core import envelope
from ..core.config import resolve_wechat_paths
from ..core.errors import ErrorCode, ToolError
from ..core.paths import offsets_file
from ..core.path_config import resolve_path
from ..core.state import Stage, get_state
from ..offsets.inspection import inspect_binary
from ..offsets.methodology import METHOD_CHAIN, branch_guidance
from ..offsets.service import analysis_backend, static_checks
from ..platform import get_adapter



def _config_path(version: int | None) -> Path:
    return offsets_file(get_state().platform or get_adapter().platform, version)


def _write_cache(path: Path, config: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _binary_for_extraction(binary_path: str | None) -> Path:
    state = get_state()
    if binary_path:
        return resolve_path(binary_path, name="binary_path")
    module = getattr(get_adapter(), "main_module_path", lambda: None)()
    if module:
        return Path(module)
    if state.runtime_path and Path(state.runtime_path).is_file():
        return Path(state.runtime_path)
    raise ToolError(
        ErrorCode.NO_WECHAT, "No analysis module is available.",
        remedy="Pass binary_path or locate the installed/running runtime.",
        remedy_detail={"next_actions": [envelope.next_action('check_environment', {'scope': 'wechat'}, 'Find the runtime module.', 'A binary_path for local inspection.', 'Use an explicit local binary or the static source track.')]},
    )


def _read_config(path: Path) -> dict:
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(result, dict):
            raise ValueError("config root must be an object")
        version = result.get("Version")
        if version is not None and (type(version) is not int or version < 1):
            raise ValueError("Version must be a positive integer or omitted/null")
        return result
    except (OSError, ValueError) as error:
        raise ToolError(ErrorCode.OFFSETS_VERIFY_FAILED, f"Cannot read config {path}: {error}",
                        remedy="Inspect/correct the local JSON; no cached parameters were replaced.") from error


def _accept(path: Path, source: str) -> None:
    state = get_state()
    state.config_path, state.offsets_source = str(path), source
    state.advance(Stage.OFFSETS_READY)


def _reject(path: Path) -> None:
    state = get_state()
    if state.config_path == str(path):
        state.config_path, state.offsets_source = None, None


async def execute(
    action: Annotated[Literal["status", "inspect", "extract", "verify", "import"], Field(description="status reads/rechecks cache; inspect asks a bounded binary question; extract derives/writes; verify checks; import checks and installs.")] = "status",
    version: Annotated[int | None, Field(description="Optional local cache label, default detected version. Unknown versions use addresses.local.json; never selects an analysis strategy.", ge=1)] = None,
    binary_path: Annotated[str | None, Field(description="Local module file, not an app directory. Defaults to the located module; explicit files allow analysis without WeChat running.")] = None,
    force: Annotated[bool, Field(description="extract/import only: replace an existing parameter file after checks pass. Does not bypass verification.")] = False,
    path: Annotated[str | None, Field(description="Config file for status/verify/import; optional output file for extract. import requires this path.")] = None,
    view: Annotated[Literal["summary", "strings", "xrefs", "disasm", "calls"], Field(description="inspect only: summary reads headers/maps; strings searches literal UTF-8; xrefs scans references; disasm/calls inspect code.")] = "summary",
    pattern: Annotated[str | None, Field(description="Required for inspect view=strings; literal UTF-8 fragment such as OnLoadStart or SendToClientFilter.", max_length=512)] = None,
    address: Annotated[str | None, Field(description="Required for xrefs/disasm/calls: link-time VA, e.g. 0x1234, from an inspection row. Never pass file offsets, RVAs or ASLR pointers here.")] = None,
    arch: Annotated[Literal["arm64", "x86_64", "x86_32"] | None, Field(description="Optional exact ISA to select a fat slice. Otherwise use the binary's ISA or the matching host slice; no arm64 fallback.")] = None,
    scan_from: Annotated[str | None, Field(description="xrefs only: resume code scan at the previous next_address VA. Omitted starts at the first executable region.")] = None,
    scan_bytes: Annotated[int, Field(description="Maximum code bytes examined by one inspect call; bounded scans return next_address when more code remains.", ge=4, le=8388608)] = 262144,
    limit: Annotated[int, Field(description="Maximum inspection rows/instructions returned. Empty bounded results do not establish absence.", ge=1, le=200)] = 50,
) -> CallToolResult:
    state = get_state()
    try:
        target_version = version if version is not None else (state.wmpf_version if not binary_path else None)
        if action == "inspect":
            binary = _binary_for_extraction(binary_path)
            data = await asyncio.to_thread(
                inspect_binary, binary, view=view, pattern=pattern, address=address,
                arch=arch, scan_from=scan_from, scan_bytes=scan_bytes, limit=limit,
            )
            if view == "summary":
                data["method_chain"] = METHOD_CHAIN
            return envelope.ok(data, stage=state.stage.value)

        selected = resolve_path(path, name="config_path") if path else (
            resolve_path(state.config_path, name="config_path") if action == "verify" and state.config_path else _config_path(target_version)
        )
        if action in {"extract", "import"}:
            from ..core import paths
            paths.report()
            resolve_wechat_paths()

        if action == "status":
            data = {"ready": False, "source": "none", "config": None,
                    "verified": False, "config_path": str(selected)}
            if not selected.is_file():
                return envelope.ok(data, stage=state.stage.value,
                                   next_hint='inspect_binary(view="summary")',
                                   next_actions=branch_guidance("unknown", binary_path)["next_actions"])
            config = _read_config(selected)
            data.update(source="cache", config=config)
            try:
                binary = _binary_for_extraction(binary_path)
                checks = await asyncio.to_thread(static_checks, binary, config, arch)
                passed = bool(checks) and all(c["ok"] for c in checks)
                data.update(ready=passed, verified=passed, checks=checks)
                if passed:
                    _accept(selected, "cache")
                else:
                    _reject(selected)
            except ToolError as error:
                _reject(selected)
                data["verification_error"] = {"code": error.code.value, "message": error.message}
            return envelope.ok(data, stage=state.stage.value,
                               next_actions=[] if data["ready"] else branch_guidance("verify", binary_path)["next_actions"],
                               next_hint='start_runtime(component="hooks")' if data["ready"] else 'inspect_binary()')

        if action == "extract":
            binary = _binary_for_extraction(binary_path)
            backend = analysis_backend(binary, arch)
            try:
                result = await asyncio.to_thread(backend.extract_offsets, binary, target_version)
            except (backend.ExtractionError, ValueError) as error:
                failed = getattr(error, "stage", "unknown")
                raise ToolError(
                    ErrorCode.OFFSETS_EXTRACT_FAILED, str(error),
                    remedy="Follow the failed role's analysis branch; unchanged extraction adds no evidence.",
                    remedy_detail={"failed_stage": failed, "method_chain": METHOD_CHAIN,
                                   **branch_guidance(failed, str(binary))},
                ) from error
            if not result.verified:
                raise ToolError(ErrorCode.OFFSETS_VERIFY_FAILED, "Derived parameters failed static checks.",
                                remedy_detail={"checks": result.verify_notes, **branch_guidance("verify", str(binary))})
            if selected.is_file() and not force:
                return envelope.ok(
                    {"written": False, "reason": "File exists; verify it or pass force=true to replace.",
                     "config_path": str(selected), "config": result.config},
                    stage=state.stage.value, next_hint='check_offsets()',
                )
            _write_cache(selected, result.config)
            _accept(selected, "extract")
            return envelope.ok(
                {"written": True, "ready": True, "verified": True, "config": result.config,
                 "config_path": str(selected), "elapsed_s": result.elapsed_s,
                 "anchors": [vars(a) for a in result.anchors]},
                stage=state.stage.value, next_hint='start_runtime(component="hooks")',
            )

        if action in ("verify", "import"):
            if action == "import" and not path:
                raise ToolError(ErrorCode.PARAM, "candidate_path is required for source=import.",
                                remedy="Provide a local candidate config; it will be checked against binary_path.")
            if not selected.is_file():
                raise ToolError(ErrorCode.OFFSETS_MISSING, f"No config at {selected}.",
                                remedy="Pass a candidate path or derive parameters with extract.")
            config = _read_config(selected)
            binary = _binary_for_extraction(binary_path)
            checks = await asyncio.to_thread(static_checks, binary, config, arch)
            passed = bool(checks) and all(c["ok"] for c in checks)
            if action == "verify":
                if passed:
                    _accept(selected, "cache")
                else:
                    _reject(selected)
                return envelope.ok(
                    {"config_path": str(selected), "passed": passed, "checks": checks},
                    stage=state.stage.value,
                    next_actions=[] if passed else branch_guidance("verify", str(binary))["next_actions"],
                )
            if not passed:
                raise ToolError(ErrorCode.OFFSETS_VERIFY_FAILED, "Import rejected by static checks.",
                                remedy_detail={"checks": checks, **branch_guidance("verify", str(binary))})
            target = _config_path(config.get("Version"))
            if target.is_file() and not force:
                return envelope.ok({"imported": False, "config_path": str(target),
                                    "reason": "File exists; force=true permits replacement after checks."},
                                   stage=state.stage.value)
            _write_cache(target, config)
            _accept(target, "import")
            return envelope.ok({"imported": True, "config_path": str(target),
                                "imported_version": config.get("Version"), "verified": True},
                               stage=state.stage.value)
        raise ToolError(ErrorCode.PARAM, f"Unknown action: {action}")
    except ToolError as error:
        return envelope.fail(error, stage=state.stage.value)
    except (ValueError, OSError) as error:
        return envelope.fail(ToolError(ErrorCode.PARAM, str(error),
                                      remedy_detail=branch_guidance("unknown", binary_path)),
                             stage=state.stage.value)
    except Exception as error:
        return envelope.fail(ToolError(ErrorCode.INTERNAL, f"offsets operation failed: {error}"),
                             stage=state.stage.value)

