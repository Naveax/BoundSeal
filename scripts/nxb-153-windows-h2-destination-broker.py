#!/usr/bin/env python3
"""Verified launcher and bounded watcher-settlement patch for the NXB-153 H2 broker."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
from pathlib import Path
import sys

CORE_NAME = "nxb-153-windows-h2-destination-broker-core.py"
CORE_GIT_BLOB_SHA1 = "2cd3f9bd6ee36892a0adeb9cb40d940c8e3a73f6"
WATCH_SETTLEMENT_TIMEOUT_MS = 250
MAX_WATCH_SETTLEMENT_GENERATIONS = 8


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def load_verified_core():
    core_path = Path(__file__).with_name(CORE_NAME)
    raw = core_path.read_bytes()
    git_object = f"blob {len(raw)}\0".encode("ascii") + raw
    try:
        digest = hashlib.sha1(git_object, usedforsecurity=False).hexdigest()
    except TypeError:
        digest = hashlib.sha1(git_object).hexdigest()
    if digest != CORE_GIT_BLOB_SHA1:
        fail(
            "NXB-153 Windows H2 broker core Git-blob identity mismatch: "
            f"expected={CORE_GIT_BLOB_SHA1} actual={digest}"
        )

    spec = importlib.util.spec_from_file_location("nxb153_h2_destination_broker_core", core_path)
    if spec is None or spec.loader is None:
        fail("NXB-153 Windows H2 broker core import spec could not be created")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = load_verified_core()


def change_notification_signaled(self, handle: int, timeout_ms: int = 0) -> bool:
    result = int(self.WaitForSingleObject(wintypes.HANDLE(handle), timeout_ms))
    if result == core.WAIT_OBJECT_0:
        return True
    if result == core.WAIT_TIMEOUT:
        return False
    if result == core.WAIT_FAILED:
        self.winerror("WaitForSingleObject change notification")
    core.fail(f"unexpected change-notification wait result: {result}")


core.Native.change_notification_signaled = change_notification_signaled

_original_authority_init = core.Authority.__init__


def authority_init(self, source_root: Path, validation_dir: Path, destination: Path) -> None:
    _original_authority_init(self, source_root, validation_dir, destination)
    self.guard_records: list[tuple[Path, tuple[int, int, int, int], str, int]] = []


def transition_writers_to_read_guards(self) -> None:
    records = list(self.writer_records)
    for record in records:
        writer, path, expected_identity, expected_sha256 = record
        expected_attributes = int(self.native.information(writer).dwFileAttributes)
        self.native.close(writer)
        self.writer_records.remove(record)

        guard = self.native.open_guard_file(str(path))
        self.file_handles.append(guard)
        actual_information = self.native.information(guard)
        actual_identity = core.info_identity(actual_information)
        if actual_identity != expected_identity:
            core.fail(f"destination object changed during write-to-read guard transition: {path}")
        if int(actual_information.dwFileAttributes) != expected_attributes:
            core.fail(f"destination attributes changed during write-to-read guard transition: {path}")
        actual_sha256 = self.native.sha256_file(guard, expected_identity[2])
        if actual_sha256 != expected_sha256:
            core.fail(f"destination bytes changed during write-to-read guard transition: {path}")
        self.guard_records.append(
            (path, expected_identity, expected_sha256, expected_attributes)
        )
        self._refresh_transition_notification_violation()
        if self.violated.is_set():
            core.fail(
                "snapshot changed during write-to-read guard transition: "
                + self.violation_reason
            )


def verify_guard_records(self) -> None:
    for path, expected_identity, expected_sha256, expected_attributes in self.guard_records:
        guard = self.native.open_guard_file(str(path))
        try:
            actual_information = self.native.information(guard)
            actual_identity = core.info_identity(actual_information)
            if actual_identity != expected_identity:
                core.fail(f"destination guard identity drifted during watcher settlement: {path}")
            if int(actual_information.dwFileAttributes) != expected_attributes:
                core.fail(f"destination guard attributes drifted during watcher settlement: {path}")
            actual_sha256 = self.native.sha256_file(guard, expected_identity[2])
            if actual_sha256 != expected_sha256:
                core.fail(f"destination guard bytes drifted during watcher settlement: {path}")
        finally:
            self.native.close(guard)


def stabilize_change_notification(self) -> None:
    for _generation in range(1, MAX_WATCH_SETTLEMENT_GENERATIONS + 1):
        if self.change_notification_handle is not None:
            core.fail("full snapshot change sentinel already exists before settlement generation")
        handle = self.native.begin_change_notification(str(self.destination), core.WATCH_FILTER)
        self.change_notification_handle = handle

        self._verify_guard_records()
        self._verify_destination_namespace()
        self._refresh_transition_notification_violation()
        if self.violated.is_set():
            core.fail(
                "snapshot changed while establishing full watcher settlement: "
                + self.violation_reason
            )

        signaled = self.native.change_notification_signaled(
            handle, WATCH_SETTLEMENT_TIMEOUT_MS
        )

        self._verify_guard_records()
        self._verify_destination_namespace()
        self._refresh_transition_notification_violation()
        if self.violated.is_set():
            core.fail(
                "snapshot changed while validating full watcher settlement: "
                + self.violation_reason
            )

        if not signaled and not self.native.change_notification_signaled(handle):
            return

        self.native.close_change_notification(handle)
        self.change_notification_handle = None

    core.fail(
        "full snapshot change watcher did not reach a clean bounded settlement generation"
    )


def arm_watcher(self) -> None:
    if self.change_notification_handle is None:
        self.change_notification_handle = self.native.begin_change_notification(
            str(self.destination), core.WATCH_FILTER
        )
    self.watcher_handle = self.native.open_directory(str(self.destination), watch=True)
    self.watcher_thread = core.threading.Thread(
        target=self._watcher_main,
        name="nxb153-h2-destination-watch",
        daemon=True,
    )
    self.watcher_thread.start()


core.Authority.__init__ = authority_init
core.Authority._transition_writers_to_read_guards = transition_writers_to_read_guards
core.Authority._verify_guard_records = verify_guard_records
core.Authority._stabilize_change_notification = stabilize_change_notification
core.Authority._arm_watcher = arm_watcher

_original_arm_watcher = core.Authority._arm_watcher


def settled_arm_watcher(self) -> None:
    self._stabilize_change_notification()
    _original_arm_watcher(self)
    self._verify_guard_records()
    self._verify_destination_namespace()
    self._refresh_transition_notification_violation()
    self._refresh_change_notification_violation()
    if self.violated.is_set():
        core.fail("snapshot changed while arming settled full watcher: " + self.violation_reason)


core.Authority._arm_watcher = settled_arm_watcher


if __name__ == "__main__":
    raise SystemExit(core.main())
