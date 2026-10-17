"""Packaged execution manual for every MCP client, independent of repository access."""
from importlib.resources import files

MANUAL_URI = "wmpf://manual/execution-flow"


def execution_manual() -> str:
    return files("wmpf_mcp").joinpath("resources/execution-flow.md").read_text(encoding="utf-8")


def register(server):
    @server.resource(MANUAL_URI, name="execution-flow", title="WMPF-MCP 执行流手册",
                     mime_type="text/markdown", description="P0-P7 tools, predicates, backup/restore and business-readiness waits.")
    def manual() -> str:
        return execution_manual()

    @server.prompt(name="wechat_workflow", description="Run the P0-P7 method chain with explicit app maintenance and business readiness.")
    def wechat_workflow() -> str:
        return execution_manual()
