"""Dependency diagnostics that run without importing the MCP SDK or native extras."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import platform
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

GOALS = ("automation", "source", "offsets", "traffic", "wx_api")
# Package requirements, not a WeChat compatibility table.
PACKAGES = (
    ("mcp", "mcp", ">=2.3.0,<3", "base"),
    ("aiohttp", "aiohttp", ">=3.9", "base"),
    ("jsbeautifier", "jsbeautifier", ">=1.14", "base"),
    ("pycryptodome", "Crypto", ">=3.19", "base"),
    ("frida", "frida", ">=17", "dynamic"),
    ("capstone", "capstone", ">=5", "extract"),
    ("numpy", "numpy", ">=1.26", "extract"),
)

_IMPORT_CHECK = """import importlib, json, sys
try:
    module = importlib.import_module(sys.argv[1])
    if sys.argv[1] == 'mcp':
        from mcp.server.mcpserver import MCPServer
    elif sys.argv[1] == 'Crypto':
        from Crypto.Cipher import AES
        AES.new(bytes(32), AES.MODE_CBC, iv=bytes(16))
    print(json.dumps({'importable': True, 'module_path': getattr(module, '__file__', None)}))
except Exception as error:
    print(json.dumps({'importable': False, 'error': type(error).__name__ + ': ' + str(error)}))
"""


def _satisfies(version: str | None, requirement: str) -> bool | None:
    """Evaluate the stable numeric bounds used by our own package requirements."""
    if not version or not (match := re.fullmatch(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?([a-zA-Z.+\d-]*)", version)):
        return None
    numbers = tuple(int(v or 0) for v in match.groups()[:3])
    suffix = match.group(4).lower()
    prerelease = bool(re.match(r"^\.?(?:dev|rc|a|b)\d", suffix))
    for bound in requirement.split(","):
        parsed = re.fullmatch(r"(>=|<)(\d+(?:\.\d+)*)", bound)
        if not parsed:
            return None
        parts = tuple(int(v) for v in parsed[2].split("."))
        target = (parts + (0, 0, 0))[:3]
        if (parsed[1] == ">=" and (numbers < target or (numbers == target and prerelease))) or (parsed[1] == "<" and numbers >= target):
            return False
    return True


def package_check(spec: tuple[str, str, str, str]) -> dict:
    distribution, module, requirement, feature = spec
    result = {"package": distribution, "module": module, "requirement": requirement,
              "feature": feature, "installed": False, "importable": False,
              "version": None, "location": None, "requirement_satisfied": None}
    try:
        metadata = importlib.metadata.distribution(distribution)
        result.update(installed=True, version=metadata.version,
                      location=str(metadata.locate_file("")))
    except (importlib.metadata.PackageNotFoundError, OSError, ValueError) as error:
        result["metadata_error"] = str(error)
    try:
        found = importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        found = False
    if not found:
        result["error"] = "Module is absent from the MCP interpreter."
        return result
    result["installed"] = True
    try:
        process = subprocess.run([sys.executable, "-B", "-c", _IMPORT_CHECK, module],
                                 capture_output=True, text=True, timeout=5)
        if process.returncode:
            result["error"] = f"Import subprocess exited {process.returncode}: {process.stderr[-1000:]}"
        else:
            result.update(json.loads(process.stdout.splitlines()[-1]))
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError) as error:
        result["error"] = f"Import could not be verified: {error}"
    result["requirement_satisfied"] = _satisfies(result["version"], requirement)
    if result["requirement_satisfied"] is not True:
        result.setdefault("error", f"Installed version {result['version']} does not establish {requirement}.")
    return result


def startup_version_issues() -> list[str]:
    """Cheap metadata check before importing SDK/native modules on normal startup."""
    issues = []
    if sys.version_info < (3, 11):
        issues.append("Python >=3.11 is required.")
    for distribution, _, requirement, feature in PACKAGES:
        if feature != "base":
            continue
        try:
            version = importlib.metadata.version(distribution)
        except (importlib.metadata.PackageNotFoundError, OSError, ValueError):
            version = None
        if _satisfies(version, requirement) is not True:
            issues.append(f"{distribution}: {version} does not establish {requirement}.")
    return issues


def dependency_report(goal: str = "automation") -> dict:
    if goal not in GOALS:
        raise ValueError(f"Unknown goal: {goal}")
    with ThreadPoolExecutor(max_workers=4) as pool:
        packages = list(pool.map(package_check, PACKAGES))
    required_features = {"base"}
    if goal in {"automation", "traffic", "wx_api"}:
        required_features.add("dynamic")
    # Binary summary/strings remain usable without the extract extras.
    for package in packages:
        package["required_for_goal"] = package["feature"] in required_features
    python_ok = sys.version_info >= (3, 11)
    blockers = [{"check": "package:" + p["package"], "reason": p.get("error", "Import failed."),
                 "feature": p["feature"]} for p in packages
                if p["required_for_goal"] and not (p["importable"] and p["requirement_satisfied"] is True)]
    if not python_ok:
        blockers.insert(0, {"check": "python", "reason": "Python >=3.11 is required.", "feature": "base"})
    return {"goal": goal,
            "python": {"executable": sys.executable, "version": platform.python_version(),
                       "prefix": sys.prefix, "host_arch": platform.machine(), "os": sys.platform},
            "packages": packages, "blockers": blockers,
            "startup_ready": python_ok and all(p["importable"] and p["requirement_satisfied"] is True for p in packages if p["feature"] == "base"),
            "dependencies_ready": not blockers,
            "remedy": {"interpreter": sys.executable,
                       "requirement": "wmpf-mcp[dynamic]" if "dynamic" in required_features else "wmpf-mcp",
                       "extract_extras": "wmpf-mcp[extract]",
                       "instruction": "Use the MCP launcher's environment/package manager; terminal pip may target another interpreter. No installation was performed."}}
