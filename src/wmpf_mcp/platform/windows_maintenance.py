"""Windows maintenance without modifying vendor binaries or their signatures."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from ..core import paths
from ..core.errors import ErrorCode, ToolError
from ..core.path_config import resolve_path
from .maintenance import Maintenance, _parent_first, tree_digest


class _ProcessEntry(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]


def _process_error(error: OSError, pid: int | None, operation: str, *, context: str = "") -> OSError:
    # Keep the native exception class/code: the public tool classifies PermissionError.
    if not hasattr(error, "operation"):
        error.pid, error.operation = pid, operation
        message = (f"{error.strerror or str(error)}; pid={pid}; operation={operation}; "
                   f"native_winerror={getattr(error, 'winerror', None)}")
    else:
        message = error.strerror or str(error)
    error.strerror = f"{context}: {message}" if context else message
    if len(error.args) < 2:
        error.args = (error.strerror,)
    return error


def _process_call(pid: int, operation: str, call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except OSError as error:
        _process_error(error, pid, operation)
        raise


def _process_image(api, pid: int, handle) -> Path | None:
    if _process_call(pid, "WaitForSingleObject", api.wait, handle, 0):
        return None
    try:
        return _process_call(pid, "QueryFullProcessImageNameW", api.image, handle)
    except OSError:
        # QueryFullProcessImageNameW can fail after a natural exit. Only this
        # pinned process handle becoming signaled proves that it can be skipped.
        try:
            if _process_call(pid, "WaitForSingleObject", api.wait, handle, 0):
                return None
        except OSError:
            pass
        raise  # Preserve the image error if the exit proof failed or timed out.


class _WindowsAPI:
    """Handles pin the observed process while checking scope and stopping it."""
    def __init__(self):
        self.lib = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateToolhelp32Snapshot": ([wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE),
            "Process32FirstW": ([wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)], wintypes.BOOL),
            "Process32NextW": ([wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)], wintypes.BOOL),
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "QueryFullProcessImageNameW": ([wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                            ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            "TerminateProcess": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            "CreateFileW": ([wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                              wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE),
        }
        for name, (args, result) in signatures.items():
            getattr(self.lib, name).argtypes = args
            getattr(self.lib, name).restype = result

    def close(self, handle):
        self.lib.CloseHandle(handle)

    def entries(self) -> list[dict]:
        handle = self.lib.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
        if handle == ctypes.c_void_p(-1).value:
            raise _process_error(ctypes.WinError(ctypes.get_last_error()), None, "CreateToolhelp32Snapshot")
        try:
            entry = _ProcessEntry()
            entry.dwSize = ctypes.sizeof(entry)
            operation = "Process32FirstW"
            found = self.lib.Process32FirstW(handle, ctypes.byref(entry))
            result = []
            while found:
                if entry.th32ProcessID and entry.th32ProcessID != os.getpid():
                    result.append({"pid": entry.th32ProcessID, "parent_pid": entry.th32ParentProcessID,
                                   "name": entry.szExeFile})
                operation = "Process32NextW"
                found = self.lib.Process32NextW(handle, ctypes.byref(entry))
            if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
                raise _process_error(ctypes.WinError(ctypes.get_last_error()), None, operation)
            return result
        finally:
            self.close(handle)

    def open_process(self, pid: int, *, stop: bool = False):
        access = 0x101000 | (0x1 if stop else 0)  # QUERY_LIMITED_INFORMATION, SYNCHRONIZE, TERMINATE
        handle = self.lib.OpenProcess(access, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:  # The snapshot process has already exited.
                return None
            raise ctypes.WinError(error)
        return handle

    def image(self, handle) -> Path:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not self.lib.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return Path(buffer.value).resolve()

    def terminate(self, handle):
        if not self.lib.TerminateProcess(handle, 1):
            error = ctypes.get_last_error()
            raise ctypes.WinError(error)

    def wait(self, handle, timeout_ms: int) -> bool:
        result = self.lib.WaitForSingleObject(handle, timeout_ms)
        if result == 0:
            return True
        if result != 258:
            raise ctypes.WinError(ctypes.get_last_error())
        return False

    def check_directory(self, directory: Path, *, create: bool = False):
        # Opening a directory with the requested rights tests the real access token;
        # os.access() alone does not evaluate Windows ACLs.
        access = 0xA1 | (0x4 if create else 0)  # list/traverse/read attributes, add subdirectory
        handle = self.lib.CreateFileW(str(directory), access, 7, None, 3, 0x02000000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        self.close(handle)

    def check_record_write(self, record: Path):
        # OPEN_EXISTING requests the same write access as write_text without
        # truncating the record or changing any file contents during preflight.
        handle = self.lib.CreateFileW(str(record), 0x40000000, 7, None, 3, 0, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        self.close(handle)


def _in_scope(binary: Path, roots: list[Path]) -> bool:
    return any(binary.is_relative_to(root) for root in roots)


def application_processes(roots: list[Path], api=None, *, known_pids: set[int] | None = None) -> list[dict]:
    api = api or _WindowsAPI()
    result = []
    entries = api.entries()
    inaccessible = []
    for row in entries:
        try:
            handle = _process_call(row["pid"], "OpenProcess(query)", api.open_process, row["pid"])
            if handle is None:
                continue
            try:
                image = _process_image(api, row["pid"], handle)
            finally:
                api.close(handle)
        except OSError as error:
            if not isinstance(error, PermissionError):
                raise
            inaccessible.append((row, error))
            continue
        if image is not None and _in_scope(image, roots):
            result.append({"pid": row["pid"], "parent_pid": row["parent_pid"], "binary": str(image)})
    scoped = {row["pid"] for row in result} | (known_pids or set())
    parents = {row["pid"]: row["parent_pid"] for row in entries}
    for row, error in inaccessible:
        ancestor, visited = row["pid"], set()
        while ancestor in parents and ancestor not in visited and ancestor not in scoped:
            visited.add(ancestor)
            ancestor = parents[ancestor]
        if ancestor in scoped or row["name"].casefold() in {"wechat.exe", "weixin.exe", "wechatappex.exe"}:
            raise _process_error(error, row["pid"], error.operation,
                                 context=f"Cannot determine executable scope for {row['name']} PID {row['pid']}")
    return result


def kill_application(roots: list[Path], checkpoint, timeout_s: float = 10, api=None,
                     *, stopped_pids: list[int] | None = None,
                     stop_observations: list[dict] | None = None) -> list[int]:
    """Reconcile children after each exit, using one deadline and no name-based kill."""
    api = api or _WindowsAPI()
    deadline = time.monotonic() + timeout_s
    killed = stopped_pids if stopped_pids is not None else []
    known_pids = set()
    while True:
        checkpoint()
        targets = application_processes(roots, api, known_pids=known_pids)
        known_pids.update(row["pid"] for row in targets)
        if not targets:
            return killed
        if time.monotonic() >= deadline:
            raise TimeoutError("WeChat processes kept appearing or did not exit before the stop deadline")
        ordered = _parent_first(targets, {row["pid"]: row["parent_pid"] for row in targets})
        opened, batch = [], []
        try:
            # Establish stop rights and exact scope for the whole current batch
            # before terminating its first process. Retain every handle until done.
            for row in ordered:
                checkpoint()
                if time.monotonic() >= deadline:
                    raise _process_error(TimeoutError("WeChat processes did not stop before the deadline"),
                                         row["pid"], "OpenProcess(stop)")
                handle = _process_call(row["pid"], "OpenProcess(stop)", api.open_process,
                                       row["pid"], stop=True)
                if handle is None:
                    continue
                opened.append(handle)
                image = _process_image(api, row["pid"], handle)
                # The same handle pins the inspected object despite PID reuse.
                if image is not None and str(image) == row["binary"] and _in_scope(image, roots):
                    batch.append((row, handle))
            for row, handle in batch:
                checkpoint()
                if time.monotonic() >= deadline:
                    raise _process_error(TimeoutError("WeChat processes did not stop before the deadline"),
                                         row["pid"], "TerminateProcess")
                # Stopping a parent can also finish a child whose handle is open.
                if _process_call(row["pid"], "WaitForSingleObject", api.wait, handle, 0):
                    continue
                try:
                    _process_call(row["pid"], "TerminateProcess", api.terminate, handle)
                except OSError as error:
                    if getattr(error, "winerror", None) != 5:
                        raise
                    # The scoped, stop-capable handle may be exiting already.
                    # Only its signal proves exit; keep the original API error
                    # if waiting fails or exhausts this operation's deadline.
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise
                        try:
                            exited = _process_call(row["pid"], "WaitForSingleObject", api.wait,
                                                   handle, min(100, max(1, int(remaining * 1000))))
                        except OSError:
                            raise error from None
                        if exited:
                            break
                    if stop_observations is not None:
                        stop_observations.append({"pid": row["pid"], "operation": "TerminateProcess",
                                                  "native_winerror": 5, "outcome": "exited",
                                                  "proof": "same_handle_signaled"})
                    checkpoint()  # Drain exit proof before honoring cancellation.
                    continue  # A denied termination is not a confirmed kill.
                while not _process_call(row["pid"], "WaitForSingleObject", api.wait, handle,
                                        min(100, max(1, int((deadline - time.monotonic()) * 1000)))):
                    if time.monotonic() >= deadline:
                        raise _process_error(TimeoutError("WeChat processes did not exit before the deadline"),
                                             row["pid"], "WaitForSingleObject")
                killed.append(row["pid"])
                checkpoint()  # Drain the actual termination before honoring cancellation.
        finally:
            for handle in opened:
                api.close(handle)


def _validate_tree(root: Path):
    if not root.is_dir():
        raise ValueError(f"Missing installation directory: {root}")
    # Reject junctions as well as symlinks: following either can escape the backup
    # or the restore scope on Windows, including when pathlib reports no symlink.
    pending = [root]
    while pending:
        item = pending.pop()
        if getattr(item.lstat(), "st_file_attributes", 0) & 0x400 or item.is_symlink():
            raise ValueError(f"Maintenance does not follow reparse points: {item}")
        if item.is_dir():
            pending.extend(item.iterdir())


class WindowsMaintenance(Maintenance):
    """A verified snapshot and bounded restart; no Windows signing operation."""
    def _layout(self) -> tuple[Path, list[Path]]:
        configured = self.adapter.paths.wechat_app.resolve()
        app = configured.parent if configured.is_file() else configured
        _validate_tree(app)
        candidates = ([configured] if configured.is_file() else
                      [path.resolve() for path in app.rglob("*.exe")
                       if path.name.casefold() in {"wechat.exe", "weixin.exe"}])
        direct = [path for path in candidates if path.parent == app]
        candidates = direct or candidates
        if len(candidates) != 1 or candidates[0].name.casefold() not in {"wechat.exe", "weixin.exe"}:
            raise ToolError(ErrorCode.NO_WECHAT, "Configure a unique WeChat.exe or Weixin.exe main executable; selection is ambiguous or missing")
        main = candidates[0]
        if not main.is_file() or not main.is_relative_to(app):
            raise ToolError(ErrorCode.NO_WECHAT, "The main executable is outside the configured installation")
        roots = [app]
        module = self.adapter.main_module_path()
        if module:
            runtime = Path(module).resolve().parent
            if not runtime.is_relative_to(app):
                roots.append(runtime)
        for root in roots[1:]:
            _validate_tree(root)
        return main, roots

    def _permissions(self, roots: list[Path], *, backup_folder: Path | None = None):
        api = _WindowsAPI()
        for root in roots:
            api.check_directory(root)
            for item in root.rglob("*"):
                self.checkpoint()
                if item.is_dir():
                    api.check_directory(item)
                elif item.is_file():
                    with item.open("rb"):
                        pass
        backup_parent = paths.backup_dir()
        while not backup_parent.exists():
            backup_parent = backup_parent.parent
        api.check_directory(backup_parent, create=True)
        if backup_folder is not None:
            api.check_record_write(backup_folder / "restore.json")

    def backup(self, roots: list[Path]) -> tuple[Path, dict]:
        folder = paths.backup_dir() / ("wechat-windows-" + uuid.uuid4().hex)
        if any(folder.resolve().is_relative_to(root) for root in roots):
            raise ToolError(ErrorCode.PARAM, "Backup storage must be outside the installation directories")
        folder.mkdir(parents=True)
        self.detail["backup_path"] = str(folder)
        record = {"format": "windows-1", "state": "backed_up", "roots": []}
        for index, root in enumerate(roots):
            self.checkpoint()
            before = tree_digest(root)
            name = f"tree-{index}.bak"
            shutil.copytree(root, folder / name, copy_function=self._copy_file)
            if tree_digest(folder / name) != before or tree_digest(root) != before:
                raise ValueError("Installation changed during backup or the backup is incomplete")
            record["roots"].append({"path": str(root), "backup": name, "original_digest": before,
                                    "prepared_digest": before})
        self.write_record(folder, record)
        return folder, record

    def _copy_file(self, source, destination):
        self.checkpoint()
        return shutil.copy2(source, destination)

    def _verify_backup(self, folder: Path, roots: list[Path]) -> dict:
        try:
            record = json.loads((folder / "restore.json").read_text(encoding="utf-8"))
            if (record["format"] != "windows-1" or len(record["roots"]) != len(roots)
                    or record["state"] not in {"backed_up", "prepared", "restored"}):
                raise ValueError("This is not a complete matching Windows maintenance backup")
            for index, (row, root) in enumerate(zip(record["roots"], roots)):
                name = f"tree-{index}.bak"
                if row["path"] != str(root) or row["backup"] != name:
                    raise ValueError("Backup installation paths do not match")
                _validate_tree(folder / name)
                if (tree_digest(folder / name) != row["original_digest"]
                        or row["prepared_digest"] != row["original_digest"]
                        or tree_digest(root) != row["original_digest"]):
                    raise ValueError("Backup checksum mismatch or the installation has been updated")
            return record
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise ToolError(ErrorCode.BACKUP_MISMATCH, str(error),
                            remedy="Keep the backup; do not overwrite an updated installation.") from error

    def launch(self, *, cleanup=False, main: Path | None = None):
        if not cleanup:
            self.checkpoint()
        if main is None:
            main, _ = self._layout()
        # An app launch is intentionally detached from the worker's cancellable
        # helper subprocess: cancellation must retain the user's login session.
        child = subprocess.Popen([str(main)], cwd=str(main.parent), close_fds=True)
        return {"requested": True, "main_executable": str(main), "launcher_pid": child.pid,
                "runtime_start_required": True,
                "note": "Main executable launched. Complete the existing login Q&A, then check_environment; runtime and page readiness are not assumed."}

    def execute(self, action: str, backup_path: str | None, dry_run: bool, *, force_resign: bool = False) -> dict:
        if force_resign:
            raise ToolError(ErrorCode.UNSUPPORTED_ANALYSIS, "force_resign is unsupported on Windows; vendor signatures are preserved")
        if action not in {"prepare", "restart", "restore", "launch"}:
            raise ToolError(ErrorCode.PARAM, "Unknown maintenance action")
        if (action == "restore") != bool(backup_path):
            raise ToolError(ErrorCode.PARAM, "backup_path is required only for restore")
        paths.report()
        main, roots = self._layout()
        folder = resolve_path(backup_path, name="backup_path") if backup_path else None
        record = self._verify_backup(folder, roots) if folder else None
        rows = application_processes(roots)
        permissions = {"checked": action in {"prepare", "restore"}, "allowed": True,
                       "required": "read installation and create backup; vendor binaries remain unchanged"}
        try:
            if action in {"prepare", "restore"}:
                self._permissions(roots, backup_folder=folder)
        except PermissionError as error:
            permissions.update(allowed=False, error=str(error))
        plan = {"action": action, "dry_run": dry_run, "force_resign": False, "signatures": [],
                "signed_binaries": [], "app_path": str(roots[0]), "main_executable": str(main),
                "runtime_paths": list(map(str, roots[1:])), "processes": rows, "permissions": permissions,
                "writable": permissions["allowed"],
                "steps": (["backup", "verify_backup", "force_stop", "verify_unchanged", "launch"] if action == "prepare"
                          else ["verify_backup", "force_stop", "verify_original", "launch"] if action == "restore"
                          else ["force_stop", "launch"] if action == "restart" else ["launch"])}
        if folder:
            plan["backup_path"] = str(folder)
        if dry_run:
            return {**plan, "executed": False}
        if not permissions["allowed"]:
            raise ToolError(ErrorCode.PERMISSION, "The current account cannot read the installation or create its backup",
                            remedy_detail={"permissions": permissions})
        self.checkpoint()
        if action == "prepare":
            self.detail["phase"] = "backup"
            folder, record = self.backup(roots)
            self._verify_backup(folder, roots)
            plan["backup_path"] = str(folder)
        self.checkpoint()
        if action != "launch":
            self.detail["phase"] = "force_stop"
            self.detail["killed_pids"] = []
            self.detail["stop_observations"] = []
            plan["killed_pids"] = kill_application(roots, self.checkpoint, stopped_pids=self.detail["killed_pids"],
                                                   stop_observations=self.detail["stop_observations"])
        self.checkpoint()
        if action in {"prepare", "restore"}:
            self.detail["phase"] = "verify_unchanged"
            record = self._verify_backup(folder, roots)
            # prepare performs no Windows application-file mutation. A matching
            # restore is already byte-for-byte original and needs no replacement.
            record["state"] = "prepared" if action == "prepare" else "restored"
            self.write_record(folder, record)
            if action == "restore":
                self.detail.update(restored=True, already_original=True)
        self.detail["phase"] = "launch"
        # Reuse the main verified before stopping. With no running runtime,
        # module discovery may correctly reject several cached DLL versions.
        plan.update(launch=self.launch(main=main), executed=True)
        self.detail["phase"] = "complete"
        return {**plan, **self.detail}
