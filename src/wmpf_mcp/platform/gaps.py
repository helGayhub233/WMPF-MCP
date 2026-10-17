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
        return [{"id": "PATH-04", "status": "unimplemented",
                 "detail": "App/cache roots need distinct runtime discovery and executable-path process scoping; current tasklist is name-only."},
                {"id": "PATH-05", "status": "unimplemented",
                 "detail": "Pass the actual flue.dll into preflight/default analysis; never accept a plugin directory as a module."}, *common]
    if platform.startswith("linux"):
        return [{"id": "PATH-06", "status": "unimplemented",
                 "detail": "Wire configured installation root into offline module discovery and verify live executable/module containment. Ubuntu is a Linux distribution."}, *common]
    return common
