#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys

MAXIMUM_TOOL_BYTES = 512 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"NXB-153 sealed Linux tool runner failed: {message}")


def require_linux_primitives() -> None:
    if not sys.platform.startswith("linux"):
        fail("sealed validation-tool execution is supported only on Linux")
    if not hasattr(os, "memfd_create"):
        fail("os.memfd_create is unavailable")
    if not hasattr(os, "MFD_ALLOW_SEALING"):
        fail("MFD_ALLOW_SEALING is unavailable")
    for name in (
        "F_ADD_SEALS",
        "F_GET_SEALS",
        "F_SEAL_WRITE",
        "F_SEAL_GROW",
        "F_SEAL_SHRINK",
        "F_SEAL_SEAL",
    ):
        if not hasattr(fcntl, name):
            fail(f"required Linux sealing primitive {name} is unavailable")
    if not hasattr(os, "O_NOFOLLOW"):
        fail("O_NOFOLLOW is unavailable")
    if not pathlib.Path("/proc/self/fd").is_dir():
        fail("/proc/self/fd is unavailable")


def stable_tool_bytes(path: pathlib.Path) -> tuple[bytes, os.stat_result]:
    absolute = pathlib.Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(absolute, flags)
    except OSError as error:
        fail(f"could not open validation tool {absolute}: {error}")

    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            fail(f"validation tool must be a regular file: {absolute}")
        if before.st_size <= 0 or before.st_size > MAXIMUM_TOOL_BYTES:
            fail(
                f"validation tool size is outside 1..{MAXIMUM_TOOL_BYTES} bytes: "
                f"{absolute} ({before.st_size})"
            )
        if before.st_mode & 0o111 == 0:
            fail(f"validation tool is not executable: {absolute}")

        value = bytearray()
        while len(value) <= MAXIMUM_TOOL_BYTES:
            remaining = MAXIMUM_TOOL_BYTES + 1 - len(value)
            chunk = os.read(fd, min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            value.extend(chunk)

        after = os.fstat(fd)
        if len(value) != before.st_size or len(value) > MAXIMUM_TOOL_BYTES:
            fail(f"validation tool changed size while being read: {absolute}")
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or getattr(after, "st_mtime_ns", None) != getattr(before, "st_mtime_ns", None)
            or getattr(after, "st_ctime_ns", None) != getattr(before, "st_ctime_ns", None)
        ):
            fail(f"validation tool metadata changed while being read: {absolute}")
        raw = bytes(value)
        if not raw.startswith(b"\x7fELF"):
            fail(f"validation tool is not an ELF executable: {absolute}")
        return raw, before
    finally:
        os.close(fd)


def create_sealed_snapshot(raw: bytes, label: str) -> int:
    try:
        fd = os.memfd_create(label, flags=os.MFD_ALLOW_SEALING)
    except OSError as error:
        fail(f"could not create memfd snapshot: {error}")

    try:
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                fail("could not write complete memfd snapshot")
            offset += written
        os.fchmod(fd, 0o500)
        os.lseek(fd, 0, os.SEEK_SET)

        seals = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        try:
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            actual = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        except OSError as error:
            fail(f"could not seal memfd snapshot: {error}")
        if actual & seals != seals:
            fail(f"memfd snapshot did not retain all required seals: {actual:#x}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def exact_version_token(version_output: str, expected: str) -> bool:
    return expected in version_output.split()


def snapshot_tool(
    path: pathlib.Path,
    expected_version: str,
    expected_sha256: str | None,
) -> tuple[int, str, str]:
    raw, _ = stable_tool_bytes(path)
    sha256 = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None:
        if len(expected_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in expected_sha256
        ):
            fail("expected tool SHA-256 is not canonical lowercase hex")
        if sha256 != expected_sha256:
            fail(
                f"validation tool SHA-256 mismatch: expected {expected_sha256}, found {sha256}"
            )

    snapshot_fd = create_sealed_snapshot(raw, "nxb-153-validation-tool")
    snapshot_path = f"/proc/self/fd/{snapshot_fd}"
    try:
        version_process = subprocess.run(
            [snapshot_path, "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            pass_fds=(snapshot_fd,),
        )
    except (OSError, UnicodeError) as error:
        os.close(snapshot_fd)
        fail(f"could not execute sealed validation-tool version probe: {error}")

    version_output = version_process.stdout.strip()
    if version_process.returncode != 0:
        stderr = version_process.stderr.strip()
        os.close(snapshot_fd)
        fail(
            "sealed validation-tool version probe failed with "
            f"exit {version_process.returncode}: {stderr}"
        )
    if not exact_version_token(version_output, expected_version):
        os.close(snapshot_fd)
        fail(
            f"sealed validation-tool version mismatch: expected exact token "
            f"{expected_version}, found {version_output!r}"
        )
    return snapshot_fd, version_output, sha256


def inspect_tool(path: pathlib.Path, expected_version: str) -> None:
    fd, version, sha256 = snapshot_tool(path, expected_version, None)
    try:
        print(
            json.dumps(
                {"version": version, "sha256": sha256},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    finally:
        os.close(fd)


def run_tool(
    path: pathlib.Path,
    expected_version: str,
    expected_sha256: str,
    arguments: list[str],
) -> int:
    if not arguments:
        fail("run mode requires validation-tool arguments")
    fd, _, _ = snapshot_tool(path, expected_version, expected_sha256)
    snapshot_path = f"/proc/self/fd/{fd}"
    try:
        process = subprocess.run(
            [snapshot_path, *arguments],
            check=False,
            pass_fds=(fd,),
        )
        return process.returncode
    finally:
        os.close(fd)


def self_test() -> None:
    source = pathlib.Path("/bin/echo")
    raw, _ = stable_tool_bytes(source)
    fd = create_sealed_snapshot(raw, "nxb-153-sealed-tool-self-test")
    try:
        required = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        actual = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        if actual & required != required:
            fail("self-test sealed snapshot is missing required seals")

        try:
            os.pwrite(fd, b"X", 0)
        except OSError as error:
            if error.errno not in (errno.EPERM, errno.EACCES):
                fail(f"self-test sealed write failed with unexpected errno {error.errno}")
        else:
            fail("self-test unexpectedly mutated a sealed snapshot")

        process = subprocess.run(
            [f"/proc/self/fd/{fd}", "NXB153_SEALED_OK"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            pass_fds=(fd,),
        )
        if process.returncode != 0 or process.stdout.strip() != "NXB153_SEALED_OK":
            fail("self-test could not execute the sealed ELF snapshot")
    finally:
        os.close(fd)
    print("NXB-153 sealed Linux validation-tool self-test passed.")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    subparsers.add_parser("self-test")

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("path", type=pathlib.Path)
    inspect_parser.add_argument("expected_version")

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("path", type=pathlib.Path)
    run_parser.add_argument("expected_version")
    run_parser.add_argument("expected_sha256")
    run_parser.add_argument("arguments", nargs=argparse.REMAINDER)
    return parser.parse_args()


def main() -> int:
    require_linux_primitives()
    arguments = parse_arguments()
    if arguments.mode == "self-test":
        self_test()
        return 0
    if arguments.mode == "inspect":
        inspect_tool(arguments.path, arguments.expected_version)
        return 0
    if arguments.mode == "run":
        tool_arguments = list(arguments.arguments)
        if tool_arguments and tool_arguments[0] == "--":
            tool_arguments = tool_arguments[1:]
        return run_tool(
            arguments.path,
            arguments.expected_version,
            arguments.expected_sha256,
            tool_arguments,
        )
    fail("unknown mode")


if __name__ == "__main__":
    raise SystemExit(main())
