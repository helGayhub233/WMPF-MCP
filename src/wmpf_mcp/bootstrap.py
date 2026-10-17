"""Standard-library-only CLI entry, including diagnostics before SDK import."""

from __future__ import annotations

import argparse
import json
import sys

from .diagnostics import GOALS, dependency_report, startup_version_issues
from .core.path_config import PathConfigError


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="wmpf-mcp")
    parser.add_argument("command", nargs="?", choices=("doctor",), help="Check startup dependencies without starting MCP.")
    parser.add_argument("--goal", choices=GOALS, default="automation")
    args = parser.parse_args(argv)
    if args.command == "doctor":
        report = dependency_report(args.goal)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        raise SystemExit(0 if report["dependencies_ready"] else 1)
    if issues := startup_version_issues():
        report = dependency_report(args.goal)
        report["startup_error"] = "Core dependency requirements are not satisfied."
        report["version_issues"] = issues
        print(json.dumps(report, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)
    try:
        from .server import run_server
        run_server()
    except (ImportError, OSError, PathConfigError) as error:
        report = dependency_report(args.goal)
        report["startup_error"] = f"{type(error).__name__}: {error}"
        print(json.dumps(report, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
