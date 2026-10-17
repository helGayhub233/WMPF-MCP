"""macOS adapter.

Runtime paths resolve from the MCP client env (``WMPF_MCP_WECHAT_APP``,
default ``/Applications/WeChat.app``); see ``core.config``.

Version: Info.plist CFBundleVersion — current installs use "7.25800" where the
second dot-segment (``split(".")[1]``) is the WMPF version (25800); older
installs carried a plain 6-digit value (e.g. "269136").
Signature: report SIP/code-signing clues; verify actual attach separately.
"""

from __future__ import annotations

import os
import plistlib
import re
import subprocess
from pathlib import Path

from ..core.config import WeChatPaths, resolve_wechat_paths
from .base import RuntimeInfo, detect_arch

def _run(cmd: list[str], timeout: float = 5.0) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class DarwinAdapter:
    platform = "darwin"

    def __init__(self, paths: WeChatPaths | None = None) -> None:
        self._paths_override = paths

    @property
    def paths(self) -> WeChatPaths:
        """Resolve lazily so client-env configuration applies at call time."""
        return self._paths_override or resolve_wechat_paths()

    # -- runtime -------------------------------------------------------------
    def running_pids(self) -> list[int]:
        from .maintenance import application_processes
        try:
            return [row["pid"] for row in application_processes(self.paths.appex_app)]
        except (OSError, ValueError):
            return []

    def _read_version(self) -> tuple[int | None, str | None]:
        """Return (wmpf_version, raw) from CFBundleVersion."""
        info_plist = self.paths.appex_info_plist
        if not info_plist.exists():
            return None, None
        try:
            with info_plist.open("rb") as fp:
                info = plistlib.load(fp)
        except Exception:
            return None, None
        raw = str(info.get("CFBundleVersion") or "")
        if not raw:
            return None, None
        parts = raw.split(".")
        try:
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]), raw  # "7.25800" -> 25800
            return int(raw), raw  # older plain "269136"
        except ValueError:
            return None, raw

    def locate(self) -> RuntimeInfo:
        installed = self.paths.appex_app.exists()
        version, raw = self._read_version()
        return RuntimeInfo(
            platform=self.platform,
            arch=detect_arch(),
            app_path=str(self.paths.wechat_app) if self.paths.wechat_app.exists() else None,
            runtime_path=str(self.paths.appex_app) if installed else None,
            version=version,
            version_raw=raw,
            running_pids=self.running_pids(),
        )

    # -- permissions ---------------------------------------------------------
    def signing_targets(self) -> list[Path]:
        """Discover executable signing units inside this installed runtime bundle."""
        root = self.paths.appex_app.resolve()
        candidates = [self.paths.appex_bin]
        module = self.paths.main_module
        if module is None:
            raise ValueError("No framework executable in the configured runtime bundle")
        helpers = module.parent / "Helpers"
        for bundle in sorted(helpers.glob("*.app")):
            with (bundle / "Contents/Info.plist").open("rb") as stream:
                executable = plistlib.load(stream).get("CFBundleExecutable")
            if not isinstance(executable, str) or Path(executable).name != executable:
                raise ValueError(f"Invalid helper executable: {bundle.name}")
            candidates.append(bundle / "Contents/MacOS" / executable)
        targets = []
        for candidate in candidates:
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root) or not resolved.is_file():
                raise ValueError(f"Missing or out-of-bundle executable: {candidate}")
            if resolved not in targets:
                targets.append(resolved)
        return targets

    def signature_for(self, binary: Path) -> dict:
        result = {"binary": str(binary), "signed": None, "adhoc": False,
                  "hardened_runtime": False, "team_id": None}
        try:
            proc = _run(["codesign", "-dvvv", str(binary)])
            text = (proc.stdout or "") + "\n" + (proc.stderr or "")
            result["signed"] = proc.returncode == 0
            flags = re.search(r"\bflags=(0x[0-9a-fA-F]+)", text)
            result["hardened_runtime"] = bool(flags and int(flags.group(1), 16) & 0x10000)
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("TeamIdentifier="):
                    result["team_id"] = line.split("=", 1)[1].strip() or None
                elif line.startswith("Signature="):
                    result["adhoc"] = "adhoc" in line.lower()
        except (OSError, subprocess.TimeoutExpired) as error:
            result["error"] = str(error)
        return result

    def _sip_status(self) -> str:
        try:
            result = _run(["csrutil", "status"])
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"
        out = (result.stdout or "").strip()
        if "enabled" in out:
            return "enabled"
        if "disabled" in out:
            return "disabled"
        return "unknown"

    def signature_state(self) -> dict:
        """Report whether Frida injection is currently permitted.

        inject_mode: ``ok`` is a candidate (ad-hoc/root), ``need_signing`` is
        a policy clue under SIP, and incomplete policy observations stay unknown.
        """
        result = {**self.signature_for(self.paths.appex_bin),
                  "sip": self._sip_status(), "euid": os.geteuid()}
        try:
            result["binaries"] = [self.signature_for(path) for path in self.signing_targets()]
        except (OSError, ValueError, plistlib.InvalidFileException) as error:
            result["binaries"] = [self.signature_for(self.paths.appex_bin)]
            result["discovery_error"] = str(error)
        all_adhoc = all(item["adhoc"] and not item["hardened_runtime"] for item in result["binaries"])
        if (os.geteuid() == 0 or all_adhoc) and not result.get("discovery_error"):
            result["inject_mode"] = "ok"
        elif result["sip"] == "enabled":
            result["inject_mode"] = "need_signing"
        else:
            result["inject_mode"] = "unknown"
        result["note"] = "Signing/SIP observations do not prove actual attach permission."
        return result

    def resign_command(self) -> str:
        """The exact command the user must run (the tool never sudo-executes)."""
        return (
            "sudo codesign --force --sign - "
            "--preserve-metadata=identifier,entitlements,requirements "
            f'"{self.paths.appex_bin}"'
        )

    # -- offset extraction ---------------------------------------------------
    def main_module_path(self) -> str | None:
        """Path of the Chromium framework binary carrying the hook sites."""
        module = self.paths.main_module
        return str(module) if module is not None else None
