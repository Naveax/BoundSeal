#!/usr/bin/env python3
"""Windows NXB-153 H2 destination authority broker.

Creates the Rust snapshot with directory/file handles retained from creation,
then monitors the complete snapshot subtree for any post-copy mutation.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time

POLICY = "nxb-153-windows-h2-destination-authority-v1"
MAX_FILES = 65536
MAX_DIRECTORIES = 65536
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
READ_CHUNK = 1024 * 1024
MAX_COMMAND_BYTES = 128

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
SYNCHRONIZE = 0x00100000

FILE_READ_DATA = 0x0001
FILE_LIST_DIRECTORY = 0x0001
FILE_TRAVERSE = 0x0020
FILE_READ_ATTRIBUTES = 0x0080
FILE_ADD_FILE = 0x0002
FILE_ADD_SUBDIRECTORY = 0x0004

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002

CREATE_NEW = 1
OPEN_EXISTING = 3

FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400

FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000

OBJ_CASE_INSENSITIVE = 0x00000040

FILE_SUPERSEDE = 0
FILE_OPEN = 1
FILE_CREATE = 2

FILE_DIRECTORY_FILE = 0x00000001
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_OPEN_REPARSE_POINT = 0x00200000

FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
WATCH_FILTER = (
    FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_DIR_NAME
    | FILE_NOTIFY_CHANGE_ATTRIBUTES
    | FILE_NOTIFY_CHANGE_SIZE
    | FILE_NOTIFY_CHANGE_LAST_WRITE
)

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

WINDOWS_RESERVED_STEMS = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


class BrokerError(RuntimeError):
    pass


def fail(message: str) -> "NoReturn":
    raise BrokerError(message)


def emit(value: dict[str, object]) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if "\n" in data or "\r" in data:
        fail("internal protocol generated multiline JSON")
    print(data, flush=True)


def safe_component(component: str) -> None:
    try:
        component.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        fail("Windows broker admits ASCII destination components only")
    if component in ("", ".", "..") or component.endswith((" ", ".")):
        fail(f"ambiguous Windows path component: {component!r}")
    if component.split(".", 1)[0].upper() in WINDOWS_RESERVED_STEMS:
        fail(f"Windows reserved device stem is not admitted: {component}")
    if any(
        character
        not in (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789._-+"
        )
        for character in component
    ):
        fail(f"Windows broker path contains unsupported character: {component!r}")


def is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attributes & flag)


class Budget:
    def __init__(self) -> None:
        self.files = 0
        self.directories = 0
        self.total_bytes = 0

    def admit_directory(self, relative: str) -> None:
        self.directories += 1
        if self.directories > MAX_DIRECTORIES:
            fail(f"destination exceeds directory bound at {relative or '.'}")

    def admit_file(self, relative: str, size: int) -> None:
        if size < 0 or size > MAX_FILE_BYTES:
            fail(f"source file exceeds per-file bound: {relative}")
        if self.files + 1 > MAX_FILES:
            fail("destination exceeds file-count bound")
        if self.total_bytes + size > MAX_TOTAL_BYTES:
            fail("destination exceeds total-byte bound")
        self.files += 1
        self.total_bytes += size


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID),
    ]


class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
        ("Status", ctypes.c_void_p),
        ("Information", ctypes.c_size_t),
    ]


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", FILETIME),
        ("ftLastAccessTime", FILETIME),
        ("ftLastWriteTime", FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


def filetime_value(value: FILETIME) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def info_identity(info: BY_HANDLE_FILE_INFORMATION) -> tuple[int, int, int, int]:
    file_index = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
    size = (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)
    return (
        int(info.dwVolumeSerialNumber),
        file_index,
        size,
        filetime_value(info.ftLastWriteTime),
    )


class Native:
    def __init__(self) -> None:
        if os.name != "nt":
            fail("Windows H2 destination authority broker must run on Windows")

        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ntdll = ctypes.WinDLL("ntdll")

        self.CreateFileW = self.kernel32.CreateFileW
        self.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self.CreateFileW.restype = wintypes.HANDLE

        self.CloseHandle = self.kernel32.CloseHandle
        self.CloseHandle.argtypes = [wintypes.HANDLE]
        self.CloseHandle.restype = wintypes.BOOL

        self.GetFileInformationByHandle = self.kernel32.GetFileInformationByHandle
        self.GetFileInformationByHandle.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
        ]
        self.GetFileInformationByHandle.restype = wintypes.BOOL

        self.GetFileSizeEx = self.kernel32.GetFileSizeEx
        self.GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
        self.GetFileSizeEx.restype = wintypes.BOOL

        self.ReadFile = self.kernel32.ReadFile
        self.ReadFile.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        self.ReadFile.restype = wintypes.BOOL

        self.WriteFile = self.kernel32.WriteFile
        self.WriteFile.argtypes = [
            wintypes.HANDLE,
            wintypes.LPCVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        self.WriteFile.restype = wintypes.BOOL

        self.FlushFileBuffers = self.kernel32.FlushFileBuffers
        self.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        self.FlushFileBuffers.restype = wintypes.BOOL

        self.CancelIoEx = self.kernel32.CancelIoEx
        self.CancelIoEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        self.CancelIoEx.restype = wintypes.BOOL

        self.ReadDirectoryChangesW = self.kernel32.ReadDirectoryChangesW
        self.ReadDirectoryChangesW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
            wintypes.LPVOID,
        ]
        self.ReadDirectoryChangesW.restype = wintypes.BOOL

        self.NtCreateFile = self.ntdll.NtCreateFile
        self.NtCreateFile.argtypes = [
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.ULONG,
            ctypes.POINTER(OBJECT_ATTRIBUTES),
            ctypes.POINTER(IO_STATUS_BLOCK),
            wintypes.LPVOID,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.LPVOID,
            wintypes.ULONG,
        ]
        self.NtCreateFile.restype = ctypes.c_long

        self.RtlNtStatusToDosError = self.ntdll.RtlNtStatusToDosError
        self.RtlNtStatusToDosError.argtypes = [ctypes.c_long]
        self.RtlNtStatusToDosError.restype = wintypes.ULONG

    def winerror(self, label: str) -> "NoReturn":
        error = ctypes.get_last_error()
        raise OSError(error, f"{label} failed", None, error)

    def close(self, handle: int | None) -> None:
        if handle in (None, 0, INVALID_HANDLE_VALUE):
            return
        if not self.CloseHandle(wintypes.HANDLE(handle)):
            self.winerror("CloseHandle")

    def information(self, handle: int) -> BY_HANDLE_FILE_INFORMATION:
        info = BY_HANDLE_FILE_INFORMATION()
        if not self.GetFileInformationByHandle(
            wintypes.HANDLE(handle), ctypes.byref(info)
        ):
            self.winerror("GetFileInformationByHandle")
        return info

    def open_directory(self, path: str, *, watch: bool = False) -> int:
        desired = (
            FILE_LIST_DIRECTORY
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | FILE_ADD_FILE
            | FILE_ADD_SUBDIRECTORY
            | SYNCHRONIZE
        )
        flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
        handle = self.CreateFileW(
            path,
            desired,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            self.winerror(f"CreateFileW directory {path}")
        info = self.information(int(handle))
        if not (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY):
            self.close(int(handle))
            fail(f"directory handle is not a directory: {path}")
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
            self.close(int(handle))
            fail(f"directory handle resolves to a reparse point: {path}")
        return int(handle)

    def open_source_file(self, path: str) -> int:
        handle = self.CreateFileW(
            path,
            GENERIC_READ | SYNCHRONIZE,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            self.winerror(f"CreateFileW source file {path}")
        info = self.information(int(handle))
        if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT):
            self.close(int(handle))
            fail(f"source file is not a regular non-reparse file: {path}")
        return int(handle)

    def open_guard_file(self, path: str) -> int:
        handle = self.CreateFileW(
            path,
            GENERIC_READ | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            self.winerror(f"CreateFileW destination guard file {path}")
        info = self.information(int(handle))
        if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT):
            self.close(int(handle))
            fail(f"destination guard is not a regular non-reparse file: {path}")
        return int(handle)

    def create_relative(self, parent: int, name: str, *, directory: bool) -> int:
        safe_component(name)
        raw = ctypes.create_unicode_buffer(name)
        unicode_name = UNICODE_STRING(
            Length=len(name.encode("utf-16-le")),
            MaximumLength=(len(name) + 1) * 2,
            Buffer=ctypes.cast(raw, wintypes.LPWSTR),
        )
        attributes = OBJECT_ATTRIBUTES(
            Length=ctypes.sizeof(OBJECT_ATTRIBUTES),
            RootDirectory=wintypes.HANDLE(parent),
            ObjectName=ctypes.pointer(unicode_name),
            Attributes=OBJ_CASE_INSENSITIVE,
            SecurityDescriptor=None,
            SecurityQualityOfService=None,
        )
        status_block = IO_STATUS_BLOCK()
        result = wintypes.HANDLE()
        if directory:
            desired = (
                FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | SYNCHRONIZE
            )
            share = FILE_SHARE_READ | FILE_SHARE_WRITE
            options = (
                FILE_DIRECTORY_FILE
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT
            )
        else:
            desired = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE
            share = FILE_SHARE_READ
            options = (
                FILE_NON_DIRECTORY_FILE
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT
            )
        status = int(
            self.NtCreateFile(
                ctypes.byref(result),
                desired,
                ctypes.byref(attributes),
                ctypes.byref(status_block),
                None,
                0 if directory else FILE_ATTRIBUTE_NORMAL,
                share,
                FILE_CREATE,
                options,
                None,
                0,
            )
        )
        if status < 0:
            error = int(self.RtlNtStatusToDosError(status))
            raise OSError(
                error,
                f"NtCreateFile failed creating {'directory' if directory else 'file'} {name}",
                None,
                error,
            )
        handle = int(result.value)
        info = self.information(handle)
        if bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory:
            self.close(handle)
            fail(f"created destination object type mismatch: {name}")
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
            self.close(handle)
            fail(f"created destination unexpectedly became a reparse point: {name}")
        return handle

    def file_size(self, handle: int) -> int:
        value = ctypes.c_longlong()
        if not self.GetFileSizeEx(wintypes.HANDLE(handle), ctypes.byref(value)):
            self.winerror("GetFileSizeEx")
        return int(value.value)

    def copy_file(self, source: int, destination: int, expected_size: int) -> None:
        buffer = ctypes.create_string_buffer(READ_CHUNK)
        total = 0
        while True:
            read = wintypes.DWORD()
            if not self.ReadFile(
                wintypes.HANDLE(source),
                buffer,
                READ_CHUNK,
                ctypes.byref(read),
                None,
            ):
                self.winerror("ReadFile")
            count = int(read.value)
            if count == 0:
                break
            total += count
            if total > expected_size or total > MAX_FILE_BYTES:
                fail("source file grew during broker copy")
            offset = 0
            while offset < count:
                written = wintypes.DWORD()
                address = ctypes.addressof(buffer) + offset
                remaining = count - offset
                if not self.WriteFile(
                    wintypes.HANDLE(destination),
                    ctypes.c_void_p(address),
                    remaining,
                    ctypes.byref(written),
                    None,
                ):
                    self.winerror("WriteFile")
                advanced = int(written.value)
                if advanced <= 0:
                    fail("destination write made no progress")
                offset += advanced
        if total != expected_size:
            fail("source file changed size during broker copy")
        if not self.FlushFileBuffers(wintypes.HANDLE(destination)):
            self.winerror("FlushFileBuffers")

    def watch_once(self, handle: int, stopping: threading.Event) -> tuple[bool, str]:
        buffer = ctypes.create_string_buffer(65536)
        returned = wintypes.DWORD()
        ok = self.ReadDirectoryChangesW(
            wintypes.HANDLE(handle),
            buffer,
            len(buffer),
            True,
            WATCH_FILTER,
            ctypes.byref(returned),
            None,
            None,
        )
        if stopping.is_set():
            return False, "stopping"
        if not ok:
            error = ctypes.get_last_error()
            return True, f"ReadDirectoryChangesW failed with Win32 error {error}"
        if returned.value == 0:
            return True, "ReadDirectoryChangesW returned an empty/overflow notification"
        return True, "snapshot subtree changed after broker freeze"


class Authority:
    def __init__(self, source_root: Path, validation_dir: Path, destination: Path) -> None:
        self.native = Native()
        self.source_root = source_root
        self.validation_dir = validation_dir
        self.destination = destination
        self.budget = Budget()
        self.validation_handle: int | None = None
        self.directory_handles: list[int] = []
        self.writer_records: list[tuple[int, Path, tuple[int, int, int, int]]] = []
        self.file_handles: list[int] = []
        self.watcher_handle: int | None = None
        self.watcher_thread: threading.Thread | None = None
        self.stopping = threading.Event()
        self.violated = threading.Event()
        self.violation_reason = ""
        self._lock = threading.Lock()

    def _set_violation(self, reason: str) -> None:
        with self._lock:
            if not self.violated.is_set():
                self.violation_reason = reason
                self.violated.set()

    def _watcher_main(self) -> None:
        try:
            assert self.watcher_handle is not None
            violated, reason = self.native.watch_once(
                self.watcher_handle, self.stopping
            )
            if violated:
                self._set_violation(reason)
        except BaseException as error:
            if not self.stopping.is_set():
                self._set_violation(f"watcher failed: {error}")

    def _source_metadata(self, path: Path) -> os.stat_result:
        try:
            metadata = path.lstat()
        except OSError as error:
            fail(f"could not stat source entry {path}: {error}")
        if is_reparse(metadata) or stat.S_ISLNK(metadata.st_mode):
            fail(f"source indirection is not admitted: {path}")
        return metadata

    def _copy_directory(
        self,
        source: Path,
        destination_handle: int,
        relative_prefix: str,
    ) -> None:
        try:
            entries = sorted(
                os.scandir(source),
                key=lambda entry: entry.name.lower(),
            )
        except OSError as error:
            fail(f"could not enumerate source directory {source}: {error}")

        seen: set[str] = set()
        for entry in entries:
            safe_component(entry.name)
            key = entry.name.lower()
            if key in seen:
                fail(f"Windows case-insensitive source collision: {entry.name}")
            seen.add(key)
            relative = (
                f"{relative_prefix}/{entry.name}"
                if relative_prefix
                else entry.name
            )
            source_child = source / entry.name
            metadata = self._source_metadata(source_child)
            if stat.S_ISDIR(metadata.st_mode):
                self.budget.admit_directory(relative)
                child_handle = self.native.create_relative(
                    destination_handle,
                    entry.name,
                    directory=True,
                )
                self.directory_handles.append(child_handle)
                self._copy_directory(
                    source_child,
                    child_handle,
                    relative,
                )
            elif stat.S_ISREG(metadata.st_mode):
                self.budget.admit_file(relative, metadata.st_size)
                source_handle = self.native.open_source_file(str(source_child))
                try:
                    before = self.native.information(source_handle)
                    if info_identity(before)[2] != metadata.st_size:
                        fail(f"source file size changed while opening: {relative}")
                    destination_file = self.native.create_relative(
                        destination_handle,
                        entry.name,
                        directory=False,
                    )
                    self.native.copy_file(
                        source_handle,
                        destination_file,
                        metadata.st_size,
                    )
                    destination_path = self.destination / Path(relative.replace("/", os.sep))
                    destination_identity = info_identity(
                        self.native.information(destination_file)
                    )
                    self.writer_records.append(
                        (destination_file, destination_path, destination_identity)
                    )
                    after = self.native.information(source_handle)
                    if info_identity(after) != info_identity(before):
                        fail(f"source file changed during broker copy: {relative}")
                finally:
                    self.native.close(source_handle)
            else:
                fail(f"special source entry is not admitted: {relative}")

    def _arm_watcher(self) -> None:
        self.watcher_handle = self.native.open_directory(str(self.destination), watch=True)
        self.watcher_thread = threading.Thread(
            target=self._watcher_main,
            name="nxb153-h2-destination-watch",
            daemon=True,
        )
        self.watcher_thread.start()

    def _transition_writers_to_read_guards(self) -> None:
        records = list(self.writer_records)
        self.writer_records.clear()
        for writer, path, expected_identity in records:
            self.native.close(writer)
            guard = self.native.open_guard_file(str(path))
            actual_identity = info_identity(self.native.information(guard))
            if actual_identity != expected_identity:
                self.native.close(guard)
                fail(f"destination object changed during write-to-read guard transition: {path}")
            self.file_handles.append(guard)
            if self.violated.is_set():
                fail(
                    "snapshot changed during write-to-read guard transition: "
                    + self.violation_reason
                )

    def copy_and_freeze(self) -> None:
        source = self.source_root
        validation = self.validation_dir
        destination = self.destination

        if destination.parent != validation:
            fail("destination must be an immediate child of the validation directory")
        safe_component(destination.name)

        source_meta = self._source_metadata(source)
        validation_meta = self._source_metadata(validation)
        if not stat.S_ISDIR(source_meta.st_mode):
            fail("source root must be a normal directory")
        if not stat.S_ISDIR(validation_meta.st_mode):
            fail("validation directory must be a normal directory")
        if destination.exists():
            fail("destination root already exists before broker claim")

        self.validation_handle = self.native.open_directory(str(validation))
        self.budget.admit_directory("")
        root_handle = self.native.create_relative(
            self.validation_handle,
            destination.name,
            directory=True,
        )
        self.directory_handles.append(root_handle)
        self._copy_directory(source, root_handle, "")

        # Arm the kernel subtree watcher before any creator write handle is released.
        # The transition to read-only guard handles is therefore fail-closed even if
        # a same-user actor races the brief close/reopen interval.
        self._arm_watcher()
        self._transition_writers_to_read_guards()
        if self.violated.is_set():
            fail("snapshot changed before broker readiness: " + self.violation_reason)

    def health_record(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "policy": POLICY,
            "status": "violated" if self.violated.is_set() else "healthy",
            "violation": self.violation_reason if self.violated.is_set() else None,
            "snapshot_root": str(self.destination),
            "file_count": self.budget.files,
            "directory_count": self.budget.directories,
            "total_bytes": self.budget.total_bytes,
        }

    def close(self) -> None:
        self.stopping.set()
        if self.watcher_handle is not None:
            try:
                self.native.CancelIoEx(wintypes.HANDLE(self.watcher_handle), None)
            except Exception:
                pass
            try:
                self.native.close(self.watcher_handle)
            except OSError:
                pass
            self.watcher_handle = None
        if self.watcher_thread is not None:
            self.watcher_thread.join(timeout=5)
            self.watcher_thread = None

        errors: list[str] = []
        for handle, _, _ in reversed(self.writer_records):
            try:
                self.native.close(handle)
            except OSError as error:
                errors.append(f"writer handle close failed: {error}")
        self.writer_records.clear()
        for handle in reversed(self.file_handles):
            try:
                self.native.close(handle)
            except OSError as error:
                errors.append(f"file handle close failed: {error}")
        self.file_handles.clear()
        for handle in reversed(self.directory_handles):
            try:
                self.native.close(handle)
            except OSError as error:
                errors.append(f"directory handle close failed: {error}")
        self.directory_handles.clear()
        if self.validation_handle is not None:
            try:
                self.native.close(self.validation_handle)
            except OSError as error:
                errors.append(f"validation handle close failed: {error}")
            self.validation_handle = None
        if errors:
            fail("broker cleanup failed: " + " | ".join(errors))


def read_command() -> str | None:
    raw = sys.stdin.buffer.readline(MAX_COMMAND_BYTES + 1)
    if not raw:
        return None
    if len(raw) > MAX_COMMAND_BYTES or not raw.endswith(b"\n"):
        fail("broker command exceeds the supported envelope")
    try:
        value = raw[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        fail("broker command is not strict ASCII")
    return value


def broker_mode(source: Path, validation: Path, destination: Path) -> None:
    authority = Authority(source, validation, destination)
    try:
        authority.copy_and_freeze()
        emit({"phase": "ready", **authority.health_record()})
        while True:
            command = read_command()
            if command is None:
                fail("broker control pipe closed before STOP")
            if command == "CHECK":
                emit(authority.health_record())
                continue
            if command == "STOP":
                final = authority.health_record()
                authority.close()
                emit({"phase": "stopped", **final})
                if final["status"] != "healthy":
                    raise SystemExit(3)
                return
            fail(f"unsupported broker command: {command!r}")
    finally:
        try:
            authority.close()
        except Exception:
            if sys.exc_info()[0] is None:
                raise


def self_test() -> None:
    if os.name != "nt":
        fail("Windows broker self-test requires Windows")
    with tempfile.TemporaryDirectory(prefix="nxb153-h2-broker-") as temporary:
        root = Path(temporary)
        source = root / "source"
        validation = root / "validation"
        source.mkdir()
        validation.mkdir()
        (source / "bin").mkdir()
        trusted = source / "bin" / "trusted.txt"
        trusted.write_text("trusted", encoding="utf-8")
        destination = validation / "snapshot"

        authority = Authority(source, validation, destination)
        try:
            authority.copy_and_freeze()
            copied = destination / "bin" / "trusted.txt"
            if copied.read_text(encoding="utf-8") != "trusted":
                fail("self-test copied bytes mismatch")

            delete_succeeded = False
            try:
                copied.unlink()
                delete_succeeded = True
            except OSError:
                pass
            if delete_succeeded:
                fail("self-test retained destination handle allowed delete")

            injected = destination / "injected.txt"
            injected.write_text("x", encoding="utf-8")
            deadline = time.monotonic() + 5.0
            while not authority.violated.is_set() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not authority.violated.is_set():
                fail("self-test subtree watcher did not detect injection")
        finally:
            authority.close()
    emit({"policy": POLICY, "status": "self-test-passed"})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("self-test")

    broker = subparsers.add_parser("broker")
    broker.add_argument("source_root")
    broker.add_argument("validation_directory")
    broker.add_argument("destination_root")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "self-test":
            self_test()
            return 0
        if args.command == "broker":
            broker_mode(
                Path(os.path.abspath(args.source_root)),
                Path(os.path.abspath(args.validation_directory)),
                Path(os.path.abspath(args.destination_root)),
            )
            return 0
        fail("unknown broker command")
    except BrokerError as error:
        print(f"NXB-153 Windows H2 destination broker failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
