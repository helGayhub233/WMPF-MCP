"""Private cached-package and source operations."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from typing import Annotated, Literal

from mcp.types import CallToolResult
from pydantic import Field


from ..core import envelope
from ..core import paths
from ..core.errors import ErrorCode, ToolError
from ..core.path_config import PathConfigError
from ..core.state import get_state
from ..static_chain import (
    AppletNotFoundError,
    SourceNotFoundError,
    VersionNotFoundError,
    decompile_applet,
    list_applets,
    read_source,
    search_source,
)



def _recent_appid() -> str | None:
    """appid whose decompiled state was finished most recently (if any)."""
    root = paths.workspace() / "decompiled"
    if not root.is_dir():
        return None
    best_appid: str | None = None
    best_ts = ""
    for app_dir in root.iterdir():
        if not app_dir.is_dir():
            continue
        for version_dir in app_dir.iterdir():
            state_file = version_dir / ".wmpf-mcp-state.json"
            if not state_file.is_file():
                continue
            try:
                ts = str(json.loads(state_file.read_text(encoding="utf-8")).get("finished_at", ""))
            except (OSError, json.JSONDecodeError):
                ts = ""
            if ts > best_ts:
                best_ts = ts
                best_appid = app_dir.name
    return best_appid


async def execute(
    action: Annotated[Literal[
        "list_applets", "decompile", "search_source", "read_source"
    ], Field(description="list_applets lists local packages; decompile writes source output; search_source searches it; read_source reads a bounded line range.")] = "list_applets",
    appid: Annotated[str | None, Field(description="Required for decompile. For search/read, omitted selects the most recently decompiled applet; use an explicit appid when comparing apps.")] = None,
    limit: Annotated[int, Field(description="list_applets only: maximum applets returned, 1..200.", ge=1, le=200)] = 50,
    pattern: Annotated[str | None, Field(description="Required for search_source: literal text, or a regular expression when regex=true.", max_length=2048)] = None,
    regex: Annotated[bool, Field(description="search_source only: interpret pattern as a Python regular expression; false performs literal matching.")] = False,
    max_hits: Annotated[int, Field(description="search_source only: maximum source matches returned, 1..200.", ge=1, le=200)] = 50,
    file: Annotated[str | None, Field(description="Required for read_source: a path relative to the decompiled source root, normally obtained from a search hit.")] = None,
    start_line: Annotated[int, Field(description="read_source only: first inclusive line, numbered from 1.", ge=1)] = 1,
    end_line: Annotated[int, Field(description="read_source only: last inclusive line; must be >= start_line and span at most 1000 lines.", ge=1)] = 200,
    force: Annotated[bool, Field(description="decompile only: rebuild workspace output even when the cached package set is unchanged.")] = False,
) -> CallToolResult:
    state = get_state()
    try:
        if action == "list_applets":
            applets = await asyncio.to_thread(list_applets, limit=limit)
            return envelope.ok(
                {
                    "count": len(applets),
                    "applets": [
                        {
                            "appid": app.appid,
                            "package_dir": app.package_dir,
                            "versions": app.versions,
                            "latest_version": app.latest_version,
                            "package_count": len(app.packages),
                            "total_bytes": app.total_bytes,
                            "packages": [
                                {"name": pkg.name, "version": pkg.version,
                                 "path": pkg.path, "size": pkg.size}
                                for pkg in app.packages
                            ],
                        }
                        for app in applets
                    ],
                },
                stage=state.stage.value,
                next_hint=state.next_hint,
            )

        if action == "decompile":
            paths.report()
            if not appid:
                raise ToolError(
                    ErrorCode.PARAM,
                    "'appid' is required for action='decompile'.",
                    remedy='Call inspect_source() to pick one.',
                )
            result = await asyncio.to_thread(decompile_applet, appid, force=force)
            return envelope.ok(
                asdict(result),
                stage=state.stage.value,
                next_hint='inspect_source(view="search", pattern=...)',
            )

        if action == "search_source":
            target = appid or _recent_appid()
            if not target:
                raise ToolError(
                    ErrorCode.SOURCE_NOT_FOUND,
                    "No decompiled applet found to search.",
                    remedy='Run decompile_applet(appid="wx...") '
                    "first, or pass an appid explicitly.",
                )
            if not pattern:
                raise ToolError(
                    ErrorCode.PARAM,
                    "pattern is required for view=search.",
                    remedy="Provide a literal string or a regex when regex=true.",
                )
            data = await asyncio.to_thread(search_source, target, pattern, regex=regex, max_hits=max_hits)
            data["appid"] = target
            return envelope.ok(
                data, stage=state.stage.value, next_hint=state.next_hint
            )

        if action == "read_source":
            if end_line < start_line or end_line - start_line + 1 > 1000:
                raise ToolError(ErrorCode.PARAM, "read_source requires an ordered range of at most 1000 lines.",
                                remedy="Set end_line >= start_line and narrow the requested range.")
            target = appid or _recent_appid()
            if not target:
                raise ToolError(
                    ErrorCode.SOURCE_NOT_FOUND,
                    "No decompiled applet found to read from.",
                    remedy='Run decompile_applet(appid="wx...") '
                    "first, or pass an appid explicitly.",
                )
            if not file:
                raise ToolError(
                    ErrorCode.PARAM,
                    "file is required for view=read.",
                    remedy="Use a path from search_source hits (relative to the "
                    "source tree root, e.g. '__APP__/app-service.js').",
                )
            data = await asyncio.to_thread(read_source, target, file, start_line=start_line, end_line=end_line)
            data["appid"] = target
            return envelope.ok(
                data, stage=state.stage.value, next_hint=state.next_hint
            )

        raise ToolError(ErrorCode.INTERNAL, f"Unknown action: {action!r}")
    except AppletNotFoundError as error:
        return envelope.fail(
            ToolError(
                ErrorCode.APPLET_NOT_FOUND,
                str(error),
                remedy="Open the miniapp in WeChat once so its packages are cached, "
                'then confirm with inspect_source().',
            ),
            stage=state.stage.value,
        )
    except VersionNotFoundError as error:
        return envelope.fail(
            ToolError(
                ErrorCode.APPLET_NOT_FOUND,
                str(error),
                remedy='Check cached versions via action="list_applets".',
            ),
            stage=state.stage.value,
        )
    except SourceNotFoundError as error:
        return envelope.fail(
            ToolError(
                ErrorCode.SOURCE_NOT_FOUND,
                str(error),
                remedy='Run decompile_applet(appid=...) first.',
            ),
            stage=state.stage.value,
        )
    except PathConfigError as error:
        return envelope.fail(ToolError(ErrorCode.PARAM, str(error)), stage=state.stage.value)
    except ToolError as error:
        return envelope.fail(error, stage=state.stage.value)
    except Exception as error:  # noqa: BLE001 - envelope contract requires it
        return envelope.fail(
            ToolError(ErrorCode.INTERNAL, f"decompile operation failed: {error}"),
            stage=state.stage.value,
        )

