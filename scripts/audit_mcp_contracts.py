"""Audit actual tools/list structural requirements without invoking runtime tools."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import get_args

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wmpf_mcp.server import build_server
from wmpf_mcp.core.schemas import ToolName


def undocumented_output_fields(schema: dict, prefix: str = "") -> list[str]:
    missing = []
    for name, definition in schema.get("properties", {}).items():
        key = f"{prefix}.{name}" if prefix else name
        if not definition.get("description"):
            missing.append(key)
        missing.extend(undocumented_output_fields(definition, key))
    for name, definition in schema.get("$defs", {}).items():
        missing.extend(undocumented_output_fields(definition, f"$defs.{name}"))
    return missing


async def audit() -> dict:
    rows, issues, definitions = [], [], []
    for tool in await build_server().list_tools():
        definition = tool.model_dump(by_alias=True, exclude_none=True)
        definitions.append(definition)
        properties = definition["inputSchema"].get("properties", {})
        undocumented = [name for name, field in properties.items() if not field.get("description")]
        output = definition.get("outputSchema")
        missing_output = undocumented_output_fields(output) if output else ["outputSchema"]
        row = {
            "tool": tool.name,
            "description_chars": len(definition.get("description", "")),
            "parameters": len(properties),
            "parameter_descriptions": len(properties) - len(undocumented),
            "selectors": {name: field["enum"] for name, field in properties.items() if name in {"scope", "goal", "view", "source", "component", "layer"} and "enum" in field},
            "definition_bytes": len(json.dumps(definition, ensure_ascii=False, separators=(",", ":")).encode()),
            "output_schema": bool(output),
        }
        rows.append(row)
        if not 0 < row["description_chars"] <= 1200:
            issues.append(f"{tool.name}: description outside 1..1200 characters")
        issues.extend(f"{tool.name}: missing input description: {name}" for name in undocumented)
        issues.extend(f"{tool.name}: missing output description: {name}" for name in missing_output)
        if not definition.get("annotations"):
            issues.append(f"{tool.name}: missing behavior annotations")
        if definition["inputSchema"].get("additionalProperties") is not False:
            issues.append(f"{tool.name}: unknown input arguments are not forbidden")
    if {row["tool"] for row in rows} != set(get_args(ToolName)):
        issues.append("Registered tools differ from the declared method contract")
    return {
        "scope": "Structural checks only; no LLM TDQS score and no runtime action was executed.",
        "tool_count": len(rows),
        "definition_bytes": len(json.dumps({"tools": definitions}, ensure_ascii=False, separators=(",", ":")).encode()),
        "parameter_count": sum(row["parameters"] for row in rows),
        "parameter_description_count": sum(row["parameter_descriptions"] for row in rows),
        "tools": rows,
        "issues": issues,
        "passed": not issues,
    }


if __name__ == "__main__":
    report = asyncio.run(audit())
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(0 if report["passed"] else 1)
