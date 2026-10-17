"""Missing or unverified method branches, not a version/environment inventory."""
from __future__ import annotations


def implementation_gaps(platform: str) -> list[dict[str, str]]:
    if platform == "darwin":
        return [{"id": "NATIVE-ISA", "status": "unimplemented",
                 "detail": "Native hook/extraction supports Mach-O arm64 only; macOS x86_64 needs an ABI backend and native acceptance."}]
    common = [{"id": "PATH-09", "status": "unimplemented",
               "detail": "Native listener/proxy diagnostics are missing; unknown does not mean free or disabled."},
              {"id": "PATH-07", "status": "native_validation_pending",
               "detail": "Validate cache overrides and actual cache layout on this OS; current acceptance covers macOS only."},
              {"id": "PATH-08", "status": "native_validation_pending",
               "detail": "Shared ~/$VAR/${VAR} expansion exists; verify native path forms and client env inheritance on this OS. Windows drives/UNC remain untested."},
              {"id": "NATIVE-ABI", "status": "unimplemented",
               "detail": "Hook/extraction and application maintenance backends need implementation and native acceptance; parser fixtures do not establish support."}]
    if platform == "win32":
        return [{"id": "PATH-04", "status": "implemented", "native_validation": "passed",
                 "detail": "Separate app/cache roots and executable-path process scoping are implemented; inaccessible process paths remain errors."},
                {"id": "PATH-05", "status": "implemented", "native_validation": "passed",
                 "detail": "Discovery selects the actual loaded flue.dll or a unique offline module; ambiguous caches and directories are rejected."},
                {"id": "PATH-09", "status": "implemented", "native_validation": "passed",
                 "detail": "Native listener ownership and separate env/WinINET/WinHTTP queries are implemented. Query failures remain unknown; snapshots do not reserve ports or prove reachability."},
                {"id": "PATH-07", "status": "native_validation_pending", "native_validation": "partial",
                 "detail": "Configured cache overrides, legacy Applet/packages discovery and controlled user-scoped layouts have Windows coverage. Other installation/cache layouts and source lifecycle acceptance remain pending."},
                {"id": "PATH-08", "status": "native_validation_pending", "native_validation": "partial",
                 "detail": "Native drive paths, Unicode/spaces, ~/$VAR/${VAR}, child-env inheritance and invalid/cyclic references have Windows coverage. UNC, cross-volume paths and symlink traversal remain unverified."},
                {"id": "NATIVE-ABI", "status": "native_validation_pending", "native_validation": "partial",
                 "detail": "PE x86_64 win64-legacy checks, verified browser targets armed, reconnect/raw, Portal C-04, isolated readiness and JD business-frame evaluation/Chinese input have native coverage. Fingerprint and redirect-size fixes were loaded and calibrated. The user stopped further testing: window 3103.769081 s with one actual replacement; the original six-replacement matrix remains incomplete. Receiver/MCP/real agent HAR cover 44 one-to-one transactions: 616 match/302 unknown/4 truncated, overall incomplete; 302/307 multi-hop and controlled incomplete-response failure were observed. Ordinary Task cancellation inside attach/create_script/load, cleanup and rearm passed; hard deadlines were not covered. Native wx.request still returns invalid url without reaching the receiver. Public MCP X01/X02/X04 and maintenance M02 remain uncovered. Other Windows ISAs are unimplemented."},
                {"id": "NATIVE-MAINTENANCE", "status": "native_validation_pending", "native_validation": "partial",
                 "detail": "Term5 native M-01 prepare completed, main-process launch and user login were accepted, files_modified=false; matching restore succeeded with already_original=true. Original roots and backups match production tree_digest: 67 files/1250835600 bytes per side; vendor files/signatures are preserved. Post-completion legacy login Q&A cancellation returned cancelled and retained completed work; this is not mid-maintenance cancellation. Earlier force_stop E_PERMISSION/WinError 5 failures and the no-TTY harness EOF remain historical records; later success does not establish the earlier API failure cause. M02 remains uncovered. The user ended further testing."}]
    if platform.startswith("linux"):
        return [{"id": "PATH-06", "status": "unimplemented",
                 "detail": "Wire configured installation root into offline module discovery and verify live executable/module containment. Ubuntu is a Linux distribution."}, *common]
    return common
