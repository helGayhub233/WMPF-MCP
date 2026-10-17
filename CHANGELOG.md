# Changelog

## Unreleased

### Added

- Add a Windows PE x86_64 native backend with actual loaded-module and ISA discovery, static hook-role/ABI checks, and preparation of every verified browser process.
- Support Windows application maintenance with complete installation/runtime backups, executable-scoped process stopping, host relaunch and checksum-matched restoration. Windows maintenance does not run macOS signing operations.
- Provide an opt-in Windows MCP HTTP launcher and document the native workflow, demonstrated coverage and remaining acceptance cases.

### Fixed

- Install native hooks atomically, wait for per-PID armed acknowledgements, and drain in-flight native operations before cancellation cleanup.
- Pin and validate each batch of Windows process handles before stopping processes; preserve native error details and distinguish successful termination from same-handle proof of an independently completed exit.
- Wait for business readiness in an isolated world and preserve standard-client recovery after unsupported browser operations.
- Deduplicate equivalent JSON/CBOR integral numbers without modifying delivered payloads, and report unavailable redirect-hop body sizes as unknown.
- Diagnose Windows listeners and proxy sources separately, preserving unknown results when native queries fail.

### Windows verification and remaining limits

- Existing Windows regression: 419 passed, 42 skipped, exactly 5 SDK subprocess cases deselected after independently reproducing the runner's overlapped-pipe access error; 23 subtests passed. Wheel/sdist and an isolated installation matched all 74 package source/resource files at that tested snapshot.
- Native PE checks, verified browser hooks, reconnect, raw CDP, Portal, Playwright/agent-browser business operations, ordinary Frida attach/create_script/load cancellation, prepare/login and matching already-original restore passed.
- A 51-minute-43-second capture covered one actual runtime replacement. Its 44 scoped requests correspond one-to-one across receiver, MCP HAR and agent HAR without comparable-field conflicts. Unknown fields and four truncated body results keep full HAR acceptance incomplete.
- The user ended further testing at this coverage. The original six replacements, native wx.request success/capture, remaining public MCP cancellation and UNC/cross-volume/symlink cases are unverified. Native wx.request still reports invalid url before reaching the receiver. These results do not claim full Windows acceptance or other native ISAs.

## 0.1.0 (2026-10-17)

Initial consolidated local release. The existing implementation and development-stage changes are included in this release; previous internal version headings are consolidated below.

### Added

- Publish 13 named MCP tools with descriptions for all 55 inputs, structured output schemas, behavior annotations and strict rejection of unknown arguments.
- Embed the P0–P7 execution method in server instructions, tool guidance, an MCP resource and a prompt. Resume from the first unmet condition; static analysis can run independently. Do not maintain version compatibility tables, environment identity archives or persistent evidence models.
- Provide a standard-library-only doctor CLI and unified package/system/WeChat preflight. Check dependencies with the MCP interpreter; treat version labels as optional and report unsupported platform methods explicitly.
- Add bounded Mach-O/ELF/PE inspection, ISA-aware disassembly/xrefs and Mach-O arm64 offset extraction. Recheck cached or imported parameters against the current module rather than guessing offsets.
- Implement cached miniapp discovery, V1MMWX wxapkg decryption, traversal-safe unpacking, JS/WXS/JSON/WXSS/WXML formatting, coverage reporting, source search and bounded source reading.
- Add explicit macOS application maintenance: full .bak backup, exact application-path process stopping, ad-hoc signing of discovered executable units, prepare-only force_resign, verification, host relaunch and checksum-checked restoration. Settle rollback and relaunch on partial failure or cancellation; never run implicit sudo.
- Use client-rendered MCP Form Elicitation for manual login and miniapp reopening, with continue/cancel choices and legacy/modern protocol support. Continuation does not repeat completed maintenance or hooks; unsupported clients receive explicit action hints.
- Implement the 9421 private-protocol engine, raw CDP on 10000 and browser-level Portal on 20000. Support discovery, flattened target attachment, per-client session ownership, request-ID isolation, frame/context mapping and event delivery for agent-browser and Playwright.
- Add a bounded Network ledger and read-only HAR 1.2 export through query_traffic: separate redirect hops, matched ExtraInfo, binary base64 bodies and distinct entity/decoded/transfer byte counts. Limit each body to 256 KiB, total bodies to 2 MiB, entries to 4 MiB and export time to 20 seconds; report omissions and unavailable data explicitly.
- Unify application/cache/state/workspace and explicit module/config/backup paths through bounded ~/$VAR/${VAR} expansion without a shell. Reject empty, unresolved and cyclic configuration before side effects; discover the actual macOS framework instead of assuming Versions/C.

### Fixed

- Recover complete native CDP responses and events before suppressing the native map rewrite (6→0). Avoid forced null→map conversion and the native frameTree crash; deliver Frida callbacks safely to the engine event loop.
- Identify JSON control messages before CBOR decoding. A real close/reopen emits a 67-byte Inspector.detached JSON message, which previously failed as CBOR.
- Count CBOR container depth independently of tag-24 envelopes, with a 300-container limit and a separate 16-tag budget. Decode the captured 1,220,455-byte / 78-level DOM response while continuing to reject malformed encodings, lengths and trailing data.
- Separate input/decode/serialize/forward failures. Retain ten error summaries with 2 KiB details and at most three failed frames / 16 MiB in memory; expose metadata and explicit internal diagnostic access without automatically writing frames to disk.
- Replace interior BL interception with callee-entry interception and BL+4 return-address verification. Emit armed only after all configured hooks and flush succeed; roll back installation failures and report role/address/instruction.
- Wait for each PID's initialization event for up to 5 seconds within the native 30-second deadline. Reject script.load-only success and partial preparation failure; preserve healthy owned sessions for incremental preparation.
- Use event-driven armed, reconnect, Portal and business readiness waits. Business content has one fixed 60-second deadline, including visible-image/font readiness and observer/binding/session cleanup. Ordinary cancellation drains the bounded native phase before rollback; hard deadlines use native cancellation.
- Stop application parents first, then reconcile newly spawned in-scope children after exit events under one deadline. Preserve executable-path checks, refuse signing on stop timeout and relaunch only the WeChat host.
- Give replacement runtimes fresh target IDs; destroy old sessions, pending commands, contexts and traffic IDs. Replay only valid observed contexts after Portal restart and require clients to acquire the current Page/frame.
- Return CDP errors for unsupported browser-root methods and independent Target.createTarget without corrupting existing sessions. Forward Browser.setDownloadBehavior to the runtime so Playwright receives its actual result.
- Preserve redirect response metadata, pair ExtraInfo by protocol flags/hop order and distinguish response entity bytes from total transferred bytes. Do not rewrite agent-browser's own HAR exports.
- Complete owned Portal/listener/hook cleanup on Q&A cancellation, request cancellation and stop; retain failed cleanup ownership and leave external services untouched.

### Verification and remaining limits

- The native end-to-end scope is macOS arm64. Existing functional regression: 266 passed, 1 skipped. Runtime checks cover maintenance, real attach/create_script/load cancellation, business UI operations, native wx.request samples, agent-browser and Playwright.
- A 33-minute-14-second stability window covered six manual miniapp close/reopen cycles, two persistent automation clients, 22 checkpoints and 132 GET/POST/HEAD requests reconciled with receiver logs, MCP HAR exports and one continuous agent HAR. Across 5,823 native messages, Hook and CBOR error counts remained zero.
- A business click triggered an additional runtime replacement. Preserve the one stale-tab acceptance-script failure, fix bounded target rediscovery and resume using the original Browser/Context/agent/HAR; verify bidirectional input readback and restore the test input.
- Reproduce the BL near-redirect failure in a bounded owned native fixture. The exited historical WeChat instance's exact allocation/deflector branch remains unprovable.
- Windows/Linux native injection and maintenance backends, macOS x86_64, platform path/diagnostic gaps, hard native deadlines, hours/days of operation, rapid replacement pressure and memory-leak attribution still require their own work and validation.
- Native wx.request samples do not imply arbitrary-domain, other-miniapp or mmtls/ilink coverage. Independent pages/contexts remain unsupported, and agent-browser's known iframe and HAR size/header/redirect issues remain client limitations.
