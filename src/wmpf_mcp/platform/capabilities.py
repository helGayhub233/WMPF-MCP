"""Implemented native method branches, separate from parser support and live readiness."""

from __future__ import annotations


# Static analysis can run on a different host; hooks additionally require the
# native platform and (when supplied) the exact configuration ABI.
_BACKENDS = {
    ("Mach-O", "arm64"): {"analysis_module": "extractor", "hook_platform": "darwin", "abi": "darwin-arm64"},
    ("PE", "x86_64"): {"analysis_module": "windows", "hook_platform": "win32", "abi": "win64-legacy"},
}


def analysis_module(binary_format: str, arch: str) -> str | None:
    return _BACKENDS.get((binary_format, arch), {}).get("analysis_module")


def hook_backend_supported(platform: str, binary_format: str, arch: str, abi: str | None = None) -> bool:
    backend = _BACKENDS.get((binary_format, arch))
    return bool(backend and backend["hook_platform"] == platform
                and (abi is None or backend["abi"] == abi))
