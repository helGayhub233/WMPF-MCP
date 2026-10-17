"""Local listener and proxy observations; unknown must remain unknown."""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import sys
from typing import Any


def port_state(port: int) -> dict[str, Any]:
    """Return {"state": "free"|"busy"|"unknown", "pid": int|None} for a local TCP port."""
    if sys.platform == "win32":
        return _windows_port_state(port)
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


def _listener_result(pids: set[int], source: str) -> dict[str, Any]:
    owned = sorted(pids & {os.getpid()})
    external = sorted(pids - {os.getpid()})
    ownership = "mixed" if owned and external else "owned" if owned else "external" if external else "not_observed"
    return {"state": "busy" if pids else "free", "pid": min(pids) if pids else None,
            "pids": sorted(pids), "ownership": ownership, "owned_pids": owned,
            "external_pids": external, "source": source,
            "note": "Listener snapshot only; no observation does not reserve the port."}


def _windows_port_state(port: int) -> dict[str, Any]:
    if type(port) is not int or not 1 <= port <= 65535:
        return {"state": "unknown", "pid": None, "ownership": "unknown", "reason": "Invalid TCP port"}
    script = ("$ErrorActionPreference='Stop'; $rows=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | "
              f"Where-Object {{ $_.LocalPort -eq {port} }} | Select-Object LocalPort,OwningProcess); "
              "ConvertTo-Json -InputObject @{listeners=$rows} -Compress")
    failures = []
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, timeout=5.0)
        if result.returncode or (result.stderr or "").strip():
            raise ValueError(f"Get-NetTCPConnection failed (exit {result.returncode}): {(result.stderr or '').strip()}")
        data = json.loads(result.stdout)
        if not isinstance(data, dict) or not isinstance(data.get("listeners"), list):
            raise ValueError("Invalid Get-NetTCPConnection listener output")
        pids = set()
        for row in data["listeners"]:
            if (not isinstance(row, dict) or row.get("LocalPort") != port
                    or type(row.get("OwningProcess")) is not int or row["OwningProcess"] <= 0):
                raise ValueError("Incomplete Get-NetTCPConnection listener record")
            pids.add(row["OwningProcess"])
        return _listener_result(pids, "Get-NetTCPConnection")
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        failures.append(str(error))
    try:
        # Do not restrict -p tcp: the full snapshot also includes IPv6 TCP listeners.
        result = subprocess.run(["netstat.exe", "-ano"], capture_output=True, text=True, timeout=5.0)
        if result.returncode or (result.stderr or "").strip():
            raise ValueError(f"netstat failed (exit {result.returncode}): {(result.stderr or '').strip()}")
        pids, observed = set(), False
        states = {"CLOSED", "LISTENING", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "FIN_WAIT_1",
                  "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"}
        for line in (result.stdout or "").splitlines():
            fields = line.split()
            if not fields:
                continue
            if fields[0] == "Proto" and fields[-1] == "PID":
                observed = True
            if fields[0] != "TCP":
                continue
            if (len(fields) != 5 or fields[3] not in states or not fields[4].isdigit()
                    or not re.fullmatch(r"[\da-fA-F.%:\[\]]+:\d+", fields[1])
                    or not re.fullmatch(r"[\da-fA-F.%:\[\]]+:\d+", fields[2])):
                raise ValueError("Invalid netstat TCP record")
            observed = True
            local_port = int(fields[1].rsplit(":", 1)[1])
            if not 0 <= local_port <= 65535:
                raise ValueError("Invalid netstat TCP port")
            if local_port == port and fields[3] == "LISTENING":
                if int(fields[4]) <= 0:
                    raise ValueError("Missing netstat listener PID")
                pids.add(int(fields[4]))
        if not observed:
            raise ValueError("Missing netstat TCP snapshot")
        return {**_listener_result(pids, "netstat"), "fallback_reason": failures[0]}
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        failures.append(str(error))
    return {"state": "unknown", "pid": None, "ownership": "unknown", "reason": "; ".join(failures)}


def _windows_proxy_config(source: str) -> dict[str, Any]:
    """Read WinINET current-user or WinHTTP machine-default settings without evaluating PAC."""
    class ProxyConfig(ctypes.Structure):
        _fields_ = [("flag", ctypes.c_uint32)] + (
            [("pac", ctypes.c_void_p)] if source == "wininet" else []) + [
            ("server", ctypes.c_void_p), ("bypass", ctypes.c_void_p)]

    config = ProxyConfig()
    try:
        winhttp = ctypes.WinDLL("winhttp", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        free = kernel32.GlobalFree
        free.argtypes, free.restype = [ctypes.c_void_p], ctypes.c_void_p
        query = getattr(winhttp, "WinHttpGetIEProxyConfigForCurrentUser" if source == "wininet"
                        else "WinHttpGetDefaultProxyConfiguration")
        query.argtypes, query.restype = [ctypes.POINTER(ProxyConfig)], ctypes.c_int
        try:
            if not query(ctypes.byref(config)):
                raise ctypes.WinError(ctypes.get_last_error())
            server = ctypes.wstring_at(config.server) if config.server else None
            bypass = ctypes.wstring_at(config.bypass) if config.bypass else None
            if source == "wininet":
                pac = ctypes.wstring_at(config.pac) if config.pac else None
                return {"checked": True, "enabled": bool(server or pac or config.flag),
                        "server": server, "bypass": bypass, "pac_url": pac,
                        "automatic": {"pac": bool(pac), "discovery": bool(config.flag)}}
            # WINHTTP_ACCESS_TYPE_NO_PROXY=1 and NAMED_PROXY=3 are query results.
            if config.flag not in {1, 3} or (config.flag == 3 and not server):
                raise ValueError("Invalid WinHTTP default proxy configuration")
            return {"checked": True, "enabled": config.flag == 3, "server": server,
                    "bypass": bypass, "access_type": config.flag,
                    "note": "Machine-default static configuration; per-session/automatic routes are not evaluated."}
        finally:
            for field in ("server", "bypass", "pac") if source == "wininet" else ("server", "bypass"):
                pointer = getattr(config, field)
                if pointer:
                    free(pointer)
    except (OSError, AttributeError, ValueError) as error:
        return {"checked": False, "enabled": None, "reason": str(error)}


def _windows_proxy_state() -> dict[str, Any]:
    variables = {key: value for key, value in os.environ.items()
                 if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
    # Environment URLs can contain credentials; only report a redacted observation.
    redacted = {key: re.sub(r"(//)[^/@\s]*@", r"\1<redacted>@", value) for key, value in variables.items()}
    sources = {"env": {"checked": True, "enabled": any(value.strip() for key, value in variables.items()
                                                        if key.lower() != "no_proxy"), "variables": redacted},
               "wininet": _windows_proxy_config("wininet"), "winhttp": _windows_proxy_config("winhttp")}
    checked = all(row["checked"] for row in sources.values())
    enabled = True if any(row["enabled"] is True for row in sources.values()) else False if checked else None
    return {"checked": checked, "enabled": enabled, "sources": sources,
            "note": "Configuration observations only; source precedence, PAC/WPAD and localhost reachability remain untested."}


def proxy_state() -> dict[str, Any]:
    """Detect an active system HTTP(S) proxy (which can hijack 127.0.0.1 ws)."""
    if sys.platform == "win32":
        return _windows_proxy_state()
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
