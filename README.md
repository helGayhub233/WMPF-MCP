# WMPF-MCP

MCP tools for inspecting and interacting with the desktop WeChat MiniProgram runtime.
Python 3.11 or later is required.

```powershell
python -m pip install -e ".[extract,dynamic]"
python -m wmpf_mcp.server doctor --goal automation
python -m wmpf_mcp.server
```

The server uses stdio by default. Configure the real WeChat installation with
`WMPF_MCP_WECHAT_APP`; cache data has a separate `WMPF_MCP_RADIUM_DIR` root.
Optional `WMPF_MCP_HOME` and `WMPF_MCP_WORKSPACE` choose writable local storage.
The default private reconnect, raw CDP and browser Portal ports are 9421, 10000
and 20000. Existing listeners are never taken over automatically.

Read the [execution manual](docs/08-执行流手册.md), or request MCP resource
`wmpf://manual/execution-flow`. The same manual is included in installed wheels.
The [Windows acceptance checklist](docs/10-Windows链路补齐与验收.md) distinguishes
implemented code, individual native checks and full dynamic acceptance.

Windows discovery, listener/proxy diagnostics and the PE x86_64 `win64-legacy`
analysis/hook backend are implemented. Native checks reached Hook, reconnect,
raw CDP, Portal and both standard clients, including business-frame evaluation
and reversible input. A 51-minute recording covered one runtime replacement;
the original six-replacement acceptance remains incomplete. Each config is
derived from and rechecked against the current DLL; there is no version table.
Windows ARM64/x86 and Linux native hooks are not implemented.

Windows maintenance has a separate snapshot, process-stop and launch backend.
It preserves vendor files/signatures; matching restore verifies an unchanged
installation and refuses updates or corruption. Native prepare, relaunch/login
and matching already-original restore passed, as did ordinary task cancellation
during Frida attach/create_script/load. Public MCP cancellation cases remain open.

Receiver, MCP HAR and agent HAR matched 44 scoped requests one-to-one with no
comparable-field conflicts. Unknown fields and truncated bodies keep complete
HAR acceptance open. Public native `wx.request` still fails with `invalid url`
before reaching the receiver. See the checklist for the exact tested scope.

For a Windows native test from an ordinary terminal when a coding sandbox denies
Frida ACL setup, use `scripts/windows_native_session.py --help`. This temporary
loopback MCP server performs no attach or application maintenance on startup.
Close it after stopping owned resources. No administrator login is assumed.
