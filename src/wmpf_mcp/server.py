"""WMPF-MCP server entry point.

Run directly:            python -m wmpf_mcp.server
Installed console script: wmpf-mcp
Transport: stdio (Streamable HTTP remains an option for later milestones).
"""

from __future__ import annotations

from . import __version__

INSTRUCTIONS = """\
WMPF-MCP drives AI-assisted automation and security assessment of WeChat MiniPrograms
running under the PC WMPF runtime (WeChatAppEx).

For a fresh dynamic workflow, read wmpf://manual/execution-flow or the wechat_workflow
prompt and follow P0-P7. P0 check_environment; P1 manage_wechat(prepare) backs up,
force-stops exact app processes, signs if needed and relaunches the host to its login
screen. P1 login Q&A offers manual login then continue, or cancel; only confirmation
suggests rechecking the environment. Do not click login or launch nested runtimes
alone. Completed maintenance stays on login cancellation; Q&A retries never repeat
file changes or restart. Unsupported clients get a manual-login hint.
P2 check_offsets/prepare_offsets; P3 start_runtime (listeners then armed hooks);
P4 in-band MCP form Q&A then probe_runtime(reconnect) only after user confirmation; P5 probe_runtime(raw);
P4 miniapp Q&A offers only continue after reopening or cancel. Cancel/decline stops owned Portal,
listeners and hooks before returning cancelled; report cleanup failures explicitly.
P6 start_runtime(portal), probe_runtime(portal), then probe_runtime(page) with an
actual business-loaded ready_selector before client screenshots/clicks; P7 traffic
and stop_runtime(all). Existing healthy resources may resume at the first unmet
condition. Static source/binary questions remain independent.
Remember the method: inspect actual binary/ISA -> strings/xrefs/data flow -> unique
hook roles and static checks -> per-PID armed/hits -> reconnect/setupContext ->
CBOR responses AND events -> command roundtrip -> Portal session/frame/context ->
client operation. Version labels are optional; never guess offsets or reuse another
ISA's ABI. inspect_runtime selects a bounded next branch without executing it.
Use probe_runtime(layer=hooks/reconnect) to await one event-driven condition;
never sleep and repeatedly call inspect_runtime. Stop/error/cancellation end waits.
Hook readiness means each prepared PID acknowledged after all configured attachments
and flush completed; script.load or another PID's armed does not prove this.
Initialization awaits an event up to 5s within the native 30s deadline. Inspect
last_start_failures and installed role/address summaries; partial failure blocks Q&A.
On Windows, hook_pids selects every browser by actual scoped executable, full argv
without --type, and a verified Weixin.exe/WeChat.exe parent in the configured app.
Renderer/gpu-process/utility roles are explicitly excluded; missing or ambiguous
metadata and unknown roles block preparation. Never select targets by attach/load
success. All selected browsers must arm; utility armed is insufficient. running_pids,
DLL discovery and maintenance still cover all scoped runtimes. OnLoadStart and
SendToClientFilter have static flue/browser role evidence. Native Windows checks
cover verified browser armed, reconnect, raw CDP, Portal and business-frame client
operations. Full acceptance remains partial: native wx.request, complete HAR fields,
six runtime replacements and remaining public MCP cancellation cases are unverified.
DebugStartBlOffset is a caller reference, not an interception point: observe the
callee entry and verify its return address. A relocation failure is not proof that
signing is wrong; do not force-register/branch rewrites to hide an attach failure.

check_environment supplies P0 for a fresh dynamic workflow; static/scoped queries
do not force a complete workflow.
Resolve app/cache/home/workspace roots from client env; paths expand ~/$VAR/${VAR}
without a shell. Stop at path_configuration errors before file/process changes.
Read implementation_gaps on each platform. Windows PATH-04/05/09 and the PE x86_64
win64-legacy analysis/hook backend are implemented; full Windows native dynamic
acceptance remains pending. Windows paths have partial native coverage; Linux
PATH-06/09 and other native ISAs remain unimplemented. Parser/shared-path tests
never close native acceptance gaps. Windows does not use macOS signing actions.
Startup failures before tools are available use wmpf-mcp doctor. Only manage_wechat
changes app signatures/processes, with a verified full bundle backup and restoration.
No package install or implicit sudo/elevation is performed. inspect_source is independent.
For a launch/reconnect test, hooks and engine
listeners need to be ready when the miniapp opens. Raw 10000 is single-runtime CDP;
standard browser clients connect to Portal 20000.
Portal exposes existing runtime views; Target.createTarget cannot create an independent
tab and returns an explicit error. Unsupported root methods fail instead of empty
success. Keep the existing page/session after that error. For faithful network export,
use query_traffic(view=har): ExtraInfo, redirect hops, entity/transfer byte scopes and
body omissions are explicit. Client-native HAR may lose those fields; verify consumers
independently, including iframe command contexts. Do not infer full Chromium support.
After runtime replacement, keep the browser connection but rediscover targets and
select the current webview tab/frame. Discard old Page/locator/CDPSession objects and
traffic IDs. For actions that may replace a Page, wait for responses on BrowserContext
and then reacquire the current Page; an old Page's timeout is not proof of capture failure.
When native decode/hook error counters change, inspect bounded recent_errors before
retrying: distinguish input/decode/serialize/forward stages and inspect failure_capture
metadata. Only failed frames stay in process memory (last 3, 16 MiB total); tool
responses contain no raw bytes and nothing is automatically written to disk. A
truncated sample cannot prove the full input. The native filter carries CBOR and JSON
control messages; do not assume every captured frame is CBOR. These are temporary
diagnostics, not a version or environment archive.
setupContext, DOM counts and navbar presence do not mean business resources finished loading. page waits use DOM/binding
events with one fixed 60-second deadline; omit timeout_s for page. Timeout/stop/
cancellation explicitly clean up owned resources.
Choose DOM/wx contexts by observed
capabilities; virtual target names and connection success do not establish them.
Only macOS arm64 has end-to-end validation here; inspect other platforms and report
the precise missing backend or failed condition. No version table or identity/evidence
archive is maintained. Operate on miniapps you are authorized to test.
"""


def build_server():
    from .core.mcp_server import WMPFServer
    from .tools import register_all
    from .workflow import register as register_workflow
    server = WMPFServer(
        name="wmpf-mcp",
        title="WMPF-MCP",
        version=__version__,
        instructions=INSTRUCTIONS,
    )
    register_all(server)
    register_workflow(server)
    return server


def run_server() -> None:
    from .core import paths
    server = build_server()
    paths.ensure_dirs()
    server.run(transport="stdio")


def main() -> None:
    from .bootstrap import main as bootstrap_main
    bootstrap_main()


if __name__ == "__main__":
    main()
