"""Local listener and proxy observations; unknown must remain unknown."""

from __future__ import annotations

import subprocess
import sys
import re
from typing import Any


def port_state(port: int) -> dict[str, Any]:
    """Return {"state": "free"|"busy"|"unknown", "pid": int|None} for a local TCP port."""
    if sys.platform != "darwin":
        return {"state": "unknown", "pid": None,
                "reason": "PATH-09: native listener diagnostics are not implemented on this platform"}
    cmd = ["/usr/sbin/lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fp"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"state": "unknown", "pid": None, "reason": str(error)}
    lines = (result.stdout or "").splitlines()
    if result.returncode == 1 and not lines and not (result.stderr or "").strip():
        return {"state": "free", "pid": None}
    # -Fp still emits mandatory f (file-set) records. Each process record
    # needs at least one actual listening descriptor, not just a PID label.
    pids, current, files, valid = set(), None, 0, True
    for line in lines:
        if re.fullmatch(r"p[1-9][0-9]*", line):
            if current is not None and not files:
                valid = False
            current, files = int(line[1:]), 0
            pids.add(current)
        elif current is not None and re.fullmatch(r"f[0-9]+", line):
            files += 1
        else:
            valid = False
    if result.returncode == 0 and pids and files and valid and not (result.stderr or "").strip():
        return {"state": "busy", "pid": min(pids), "pids": sorted(pids)}
    return {"state": "unknown", "pid": None,
            "reason": f"lsof failed or returned incomplete output (exit {result.returncode})"}


def port_busy_pid(port: int) -> int | None:
    state = port_state(port)
    return state.get("pid") if state["state"] == "busy" else None


def proxy_state() -> dict[str, Any]:
    """Detect an active system HTTP(S) proxy (which can hijack 127.0.0.1 ws)."""
    if sys.platform != "darwin":
        return {"checked": False, "enabled": None,
                "reason": "PATH-09: native proxy diagnostics are not implemented on this platform"}
    try:
        result = subprocess.run(
            ["/usr/sbin/scutil", "--proxy"], capture_output=True, text=True, timeout=5.0
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"checked": False, "enabled": None, "reason": str(error)}
    output = (result.stdout or "").strip()
    if (result.returncode != 0 or (result.stderr or "").strip()
            or not re.fullmatch(r"<dictionary>\s*\{.*\}", output, re.S)):
        return {"checked": False, "enabled": None, "reason": "scutil failed or returned invalid proxy output"}
    # Only top-level keys describe the global proxy; nested scoped dictionaries
    # must not override them. PAC/WPAD are reported, never evaluated here.
    values, depth, scoped = {}, 0, False
    lines = output.splitlines()
    empty = bool(re.fullmatch(r"<dictionary>\s*\{\s*\}", output))
    if not empty and not re.fullmatch(r"<dictionary>\s*\{", lines[0]):
        return {"checked": False, "enabled": None, "reason": "Invalid scutil dictionary layout"}
    for index, line in enumerate(lines):
        if depth == 1 and line.strip() != "}":
            match = re.fullmatch(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*?)\s*", line)
            if not match:
                return {"checked": False, "enabled": None, "reason": "Invalid scutil dictionary entry"}
            scoped |= match[1] in {"__SCOPED__", "__SERVICES__"}
            if "{" not in match[2]:
                values[match[1]] = match[2]
        depth += line.count("{") - line.count("}")
        if depth < 0 or (depth == 0 and index < len(lines) - 1 and not empty):
            return {"checked": False, "enabled": None, "reason": "Unbalanced scutil proxy output"}
    if depth:
        return {"checked": False, "enabled": None, "reason": "Unbalanced scutil proxy output"}
    flags = {key: values.get(key, "0") for key in
             ("HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable")}
    if any(value not in {"0", "1"} for value in flags.values()):
        return {"checked": False, "enabled": None, "reason": "Invalid scutil proxy enable flag"}
    protocols = {}
    for prefix in ("HTTP", "HTTPS", "SOCKS"):
        active = flags[prefix + "Enable"] == "1"
        protocols[prefix.lower()] = {"enabled": active, "server": values.get(prefix + "Proxy"),
                                     "port": values.get(prefix + "Port")}
    automatic = {"pac": flags["ProxyAutoConfigEnable"] == "1",
                 "discovery": flags["ProxyAutoDiscoveryEnable"] == "1"}
    enabled = any(row["enabled"] for row in protocols.values()) or any(automatic.values())
    primary = next((row for row in protocols.values() if row["enabled"]), {})
    return {"checked": True, "enabled": enabled if enabled or not scoped else None,
            "scoped_configuration_present": scoped, "protocols": protocols,
            "automatic": automatic, **({"server": primary["server"], "port": primary["port"]} if primary else {}),
            "note": "Global configuration observation only; scoped/PAC routes and localhost reachability remain untested."}
