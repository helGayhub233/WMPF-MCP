"""Explicit macOS application maintenance, with verifiable bundle backups.

Only rollback metadata is persisted: paths and before/after content checksums.
Process observations are used for this operation and are never saved as an inventory.
"""
from __future__ import annotations

import asyncio
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import subprocess
import threading
import time
import uuid

from ..core.asyncio_utils import drain_task
from ..core.errors import ErrorCode, ToolError
from ..core import paths
from ..core.path_config import resolve_path


def tree_digest(root: Path) -> str:
    """Hash file content, modes and symlinks without following bundle symlinks."""
    digest = hashlib.sha256()
    for item in [root, *sorted(root.rglob("*"))]:
        meta = item.lstat()
        digest.update(json.dumps([str(item.relative_to(root)), stat.S_IMODE(meta.st_mode)],
                                 ensure_ascii=False).encode())
        if item.is_symlink():
            digest.update(b"link\0" + os.readlink(item).encode())
        elif item.is_file():
            digest.update(b"file\0")
            content = hashlib.sha256()
            with item.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    content.update(block)
            digest.update(content.digest())
        elif item.is_dir():
            digest.update(b"dir\0")
        else:
            raise ValueError(f"Unsupported bundle entry: {item}")
    return digest.hexdigest()


def application_processes(app: Path) -> list[dict]:
    """Use kernel executable paths, not a name/command-line substring match."""
    lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    lib.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    size = lib.proc_listallpids(None, 0) + 128
    buffer = (ctypes.c_int * size)()
    count = lib.proc_listallpids(buffer, ctypes.sizeof(buffer))
    if count <= 0:
        raise OSError(ctypes.get_errno(), "Cannot enumerate processes")
    root = app.resolve()
    rows = []
    for pid in buffer[:min(count, size)]:
        if pid <= 0 or pid == os.getpid():
            continue
        path_buffer = ctypes.create_string_buffer(4096)
        if lib.proc_pidpath(pid, path_buffer, len(path_buffer)) <= 0:
            continue
        binary = Path(os.fsdecode(path_buffer.value))
        if binary.is_relative_to(root):
            rows.append({"pid": pid, "binary": str(binary)})
    return rows


def _parents_of(pids: set[int], timeout_s: float) -> dict[int, int]:
    """Read temporary parent links for ordering; executable paths define scope."""
    result = subprocess.run(["/bin/ps", "-p", ",".join(map(str, sorted(pids))),
                             "-o", "pid=,ppid="], capture_output=True, text=True,
                            timeout=min(3.0, timeout_s))
    # ps returns 1 when all requested processes disappeared before observation.
    if result.returncode and not (result.returncode == 1 and not result.stdout.strip()):
        raise RuntimeError("Cannot read WeChat parent links: " + result.stderr[-400:])
    return {int(pid): int(parent) for pid, parent in
            (line.split() for line in result.stdout.splitlines() if line.strip())}


def _parent_first(targets: list[dict], parents: dict[int, int]) -> list[dict]:
    scoped = {target["pid"] for target in targets}
    def order(target):
        pid, ancestors = target["pid"], set()
        while parents.get(pid) in scoped and parents[pid] not in ancestors:
            pid = parents[pid]
            ancestors.add(pid)
        return len(ancestors), len(Path(target["binary"]).parts), target["pid"]
    return sorted(targets, key=order)


def kill_application(app: Path, timeout_s: float = 10) -> list[int]:
    """Stop parents first and reconcile births after exits, under one deadline."""
    deadline = time.monotonic() + timeout_s
    killed = []
    queue = select.kqueue()
    try:
        targets = application_processes(app)
        while targets:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("WeChat processes kept appearing or did not exit before the stop deadline")
            ordered = _parent_first(targets, _parents_of({p["pid"] for p in targets}, remaining))
            waiting = set()
            for target in ordered:
                if time.monotonic() >= deadline:
                    raise TimeoutError("WeChat processes did not stop before the deadline")
                pid = target["pid"]
                try:
                    queue.control([select.kevent(pid, filter=select.KQ_FILTER_PROC,
                        flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                        fflags=select.KQ_NOTE_EXIT)], 0, 0)
                    current = {p["pid"]: p["binary"] for p in application_processes(app)}
                    if current.get(pid) != target["binary"]:
                        continue
                    os.kill(pid, signal.SIGKILL)
                    waiting.add(pid)
                    killed.append(pid)
                except ProcessLookupError:
                    continue
            while waiting:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("WeChat processes did not exit before the deadline")
                for event in queue.control(None, len(waiting), remaining):
                    if event.flags & select.KQ_EV_ERROR and event.data != errno.ESRCH:
                        raise OSError(event.data, os.strerror(event.data))
                    waiting.discard(event.ident)
            # Exit events, rather than a sleep/tick, trigger a new scoped snapshot.
            # Drain children born during the previous stop before touching files.
            targets = application_processes(app)
    finally:
        queue.close()
    return killed


class Maintenance:
    """One worker; cancellation interrupts its child and settles rollback first."""
    def __init__(self, adapter):
        self.adapter = adapter
        self.cancelled = threading.Event()
        self._lock = threading.Lock()
        self._child: subprocess.Popen | None = None
        self.detail: dict = {"phase": "preflight", "files_modified": False}

    def cancel(self):
        self.cancelled.set()
        with self._lock:
            if self._child is not None and self._child.poll() is None:
                try:
                    self._child.terminate()
                except ProcessLookupError:
                    pass

    def checkpoint(self):
        if self.cancelled.is_set():
            raise InterruptedError("WeChat maintenance cancelled")

    def run_command(self, args: list[str], timeout: float = 30, *, cleanup=False):
        if not cleanup:
            self.checkpoint()
        with self._lock:
            self._child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if self.cancelled.is_set() and not cleanup:
                self._child.terminate()
            child = self._child
        try:
            try:
                stdout, stderr = child.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                raise TimeoutError(f"Command exceeded {timeout}s: {args[0]}")
            if not cleanup:
                self.checkpoint()
            if child.returncode:
                raise RuntimeError(f"{args[0]} failed: {stderr.decode(errors='replace')[-1200:]}")
            return stdout
        finally:
            with self._lock:
                self._child = None

    def copy_bundle(self, source: Path, destination: Path, *, cleanup=False):
        self.run_command(["/usr/bin/ditto", "--rsrc", "--extattr", "--acl", str(source), str(destination)],
                         timeout=180, cleanup=cleanup)

    def launch(self, *, cleanup=False):
        app = self.adapter.paths.wechat_app
        self.run_command(["/usr/bin/open", str(app)], cleanup=cleanup)
        # Nested runtimes may inherit their sandbox from WeChat. LaunchServices
        # starting that bundle on its own can die in _libsecinit_appsandbox.
        pids = self.adapter.running_pids()
        return {"requested": True, "runtime_pids": pids, "runtime_start_required": not pids,
                "note": "WeChat launch accepted, not runtime/page readiness. Complete login and open MiniPrograms "
                        "through WeChat if needed; do not launch the nested runtime alone. "
                        "Continue check_environment/start_runtime and bounded probes."}

    @staticmethod
    def write_record(folder: Path, record: dict):
        temporary = folder / ".restore.json.tmp"
        temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(folder / "restore.json")

    def backup(self, root: Path) -> tuple[Path, dict]:
        folder = paths.backup_dir() / ("wechat-" + uuid.uuid4().hex)
        folder.mkdir(parents=True, mode=0o700)
        self.detail["backup_path"] = str(folder)
        target = folder / "WeChatAppEx.app.bak"
        before = tree_digest(root)
        self.copy_bundle(root, target)
        if tree_digest(target) != before or tree_digest(root) != before:
            raise ValueError("Bundle changed during backup or the backup is incomplete")
        record = {"format": 1, "runtime_path": str(root), "original_digest": before,
                  "prepared_digest": before, "state": "backed_up"}
        self.write_record(folder, record)
        return folder, record

    def install_backup(self, folder: Path, record: dict):
        root = self.adapter.paths.appex_app.resolve()
        original = folder / "WeChatAppEx.app.bak"
        if original.is_symlink() or tree_digest(original) != record["original_digest"]:
            raise ValueError("Backup checksum mismatch")
        stage = root.parent / (".wmpf-restore-" + uuid.uuid4().hex)
        displaced = root.parent / (".wmpf-displaced-" + uuid.uuid4().hex)
        try:
            self.copy_bundle(original, stage, cleanup=True)
            if tree_digest(stage) != record["original_digest"]:
                raise ValueError("Staged restore checksum mismatch")
            root.rename(displaced)
            try:
                stage.rename(root)
            except BaseException:
                displaced.rename(root)
                raise
            self.detail["files_modified"] = False
            self.detail["restored"] = True
            shutil.rmtree(displaced)
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    def execute(self, action: str, backup_path: str | None, dry_run: bool, *, force_resign: bool = False) -> dict:
        if force_resign and action != "prepare":
            raise ToolError(ErrorCode.PARAM, "force_resign applies only to prepare")
        paths.report()  # Reject invalid storage config before stop/sign/launch.
        app, root = self.adapter.paths.wechat_app.resolve(), self.adapter.paths.appex_app.resolve()
        if not app.is_dir() or not root.is_dir() or not root.is_relative_to(app):
            raise ToolError(ErrorCode.NO_WECHAT, "No contained WeChatAppEx application bundle")
        targets = self.adapter.signing_targets()
        signatures = [self.adapter.signature_for(path) for path in targets]
        process_rows = application_processes(app)
        plan = {"action": action, "dry_run": dry_run, "force_resign": force_resign,
                "signed_binaries": [], "app_path": str(app),
                "signatures": signatures, "processes": process_rows,
                "writable": os.access(root.parent, os.W_OK) and all(os.access(path, os.W_OK) for path in targets),
                "steps": (["backup", "force_stop", "ad_hoc_sign", "verify", "launch"] if action == "prepare"
                          else ["verify_backup", "force_stop", "restore", "launch"] if action == "restore"
                          else ["force_stop", "launch"] if action == "restart" else ["launch"])}
        folder = None
        record = None
        if action == "restore":
            if not backup_path:
                raise ToolError(ErrorCode.PARAM, "restore requires backup_path returned by prepare")
            folder = resolve_path(backup_path, name="backup_path")
            try:
                record = json.loads((folder / "restore.json").read_text())
                if (record["format"] != 1 or record["runtime_path"] != str(root)
                        or tree_digest(folder / "WeChatAppEx.app.bak") != record["original_digest"]
                        or tree_digest(root) not in {record["original_digest"], record["prepared_digest"]}):
                    raise ValueError("Backup or installed bundle differs from the before/after snapshot")
            except (OSError, ValueError, KeyError) as error:
                raise ToolError(ErrorCode.BACKUP_MISMATCH, str(error),
                                remedy="Do not overwrite an updated installation; use its matching backup.") from error
            plan["backup_path"] = str(folder)
        elif backup_path:
            raise ToolError(ErrorCode.PARAM, "backup_path applies only to restore")
        if dry_run:
            return {**plan, "executed": False}
        if action in {"prepare", "restore"} and not plan["writable"]:
            raise ToolError(ErrorCode.PERMISSION, "The current account cannot modify this runtime bundle",
                            remedy="Grant the MCP process access to this application, then retry; no sudo is executed.")
        stopped = False
        try:
            self.checkpoint()
            if action == "prepare":
                self.detail["phase"] = "backup"
                folder, record = self.backup(root)
            self.checkpoint()
            if action != "launch":
                self.detail["phase"] = "force_stop"
                # Restart the app even if cancellation arrives while waiting for exits.
                stopped = True
                plan["killed_pids"] = kill_application(app)
            self.checkpoint()
            if action == "prepare":
                if tree_digest(root) != record["original_digest"]:
                    raise ValueError("Installation changed after backup; refusing to sign")
                self.detail["phase"] = "signing"
                changed = {target for target, signature in zip(targets, signatures)
                           if force_resign or not signature["adhoc"] or signature["hardened_runtime"]}
                if changed:
                    changed.add(targets[0])  # Reseal the containing app after nested signing.
                for target, signature in sorted(zip(targets, signatures), key=lambda item: len(item[0].parts), reverse=True):
                    self.checkpoint()
                    if target not in changed:
                        continue
                    self.detail["files_modified"] = True
                    self.run_command(["/usr/bin/codesign", "--force", "--sign", "-", "--options", "0",
                        "--preserve-metadata=identifier,entitlements,requirements", str(target)])
                    plan["signed_binaries"].append(str(target))
                verified = [self.adapter.signature_for(path) for path in targets]
                if not all(row["adhoc"] and not row["hardened_runtime"] for row in verified):
                    raise RuntimeError("A signing unit remains non-ad-hoc or hardened")
                for target in targets:
                    self.run_command(["/usr/bin/codesign", "--verify", "--strict", str(target)])
                record.update(prepared_digest=tree_digest(root), state="prepared")
                self.write_record(folder, record)
                plan.update(backup_path=str(folder), signatures=verified)
            elif action == "restore":
                self.detail.update(phase="restore", backup_path=str(folder))
                if tree_digest(root) not in {record["original_digest"], record["prepared_digest"]}:
                    raise ValueError("Installation changed while stopping; refusing to restore")
                self.install_backup(folder, record)
                record["state"] = "restored"
                self.write_record(folder, record)
            self.checkpoint()
            self.detail["phase"] = "launch"
            plan.update(launch=self.launch(), executed=True)
            self.detail["phase"] = "complete"
            return {**plan, **self.detail}
        except BaseException:
            if action == "prepare" and self.detail["files_modified"] and folder and record:
                try:
                    self.install_backup(folder, record)
                    record["state"] = "rolled_back"
                    self.write_record(folder, record)
                except Exception as error:
                    self.detail["rollback_error"] = str(error)
            if stopped:
                try:
                    self.detail["relaunch"] = self.launch(cleanup=True)
                except Exception as error:
                    self.detail["relaunch_error"] = str(error)
            raise


async def run_maintenance(worker: Maintenance, action: str, backup_path: str | None, dry_run: bool, *, force_resign: bool = False):
    task = asyncio.create_task(asyncio.to_thread(worker.execute, action, backup_path, dry_run,
                                               force_resign=force_resign))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        worker.cancel()
        try:
            await drain_task(task)
        except Exception:
            pass
        raise
