"""Run the real MCP server over loopback for an interactive native Windows test.

Use from an ordinary terminal when a coding sandbox prevents Frida ACL setup.
It does not attach, change files, terminate WeChat or elevate at startup. A real
MCP client must request those actions through the existing tool contracts.
"""
from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=20101)
    parser.add_argument("--home", type=Path, required=True, help="Writable test parameters/backup root.")
    parser.add_argument("--workspace", type=Path, required=True, help="Writable test source/output root.")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("This native acceptance launcher requires Windows.")
    if not 1 <= args.port <= 65535:
        parser.error("port must be in 1..65535")
    os.environ["WMPF_MCP_HOME"] = str(args.home.resolve())
    os.environ["WMPF_MCP_WORKSPACE"] = str(args.workspace.resolve())
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from wmpf_mcp.core import paths
    from wmpf_mcp.server import build_server
    paths.ensure_dirs()

    async def serve():
        from wmpf_mcp.injector import get_injector
        from wmpf_mcp.engine import get_engine
        from wmpf_mcp.portal import get_portal
        try:
            print(f"MCP endpoint: http://127.0.0.1:{args.port}/mcp", flush=True)
            print("Close with Ctrl+C after stop_runtime(component='all').", flush=True)
            await build_server().run_streamable_http_async(host="127.0.0.1", port=args.port)
        finally:
            # Application shutdown must release every resource this server owns.
            # Attempt all components even if one reports a cleanup failure.
            for name, component in (("portal", get_portal()), ("engine", get_engine()), ("hooks", get_injector())):
                try:
                    await component.stop()
                except Exception as error:
                    print(f"{name} cleanup failed: {error}", file=sys.stderr, flush=True)
    asyncio.run(serve())


if __name__ == "__main__":
    main()
