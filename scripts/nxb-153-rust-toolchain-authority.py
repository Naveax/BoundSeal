#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import struct
import sys
import tempfile
from dataclasses import dataclass
from typing import Iterable

POLICY = "nxb-153-host-rust-toolchain-tree-authority-v1"
MAX_FILES = 65536
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024

WINDOWS_RESERVED_STEMS = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


class AuthorityError(RuntimeError):
    pass


@dataclass(frozen=True)
class FileRecord:
    relative: bytes
    sort_key: bytes
    mode_class: bytes
    size: int
    sha256: bytes


@dataclass(frozen=True)
class TreeSummary:
    platform_model: str
    file_count: int
    total_bytes: int
    tree_sha256: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema_version": 1,
                "policy": POLICY,
                "platform_model": self.platform_model,
                "file_count": self.file_count,
                "total_bytes": self.total_bytes,
                "tree_sha256": self.tree_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attributes & flag)


def require_plain_directory(path: pathlib.Path, label: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as error:
        raise AuthorityError(f"{label} is missing: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise AuthorityError(f"{label} must be a normal non-indirection directory: {path}")
    return metadata


def windows_relative_bytes(relative: str) -> tuple[bytes, bytes]:
    try:
        raw = relative.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise AuthorityError(
            "Windows toolchain authority currently admits ASCII relative paths only"
        ) from error

    if not raw or raw.startswith(b"/") or b"\\" in raw:
        raise AuthorityError("invalid Windows relative path")
    components = relative.split("/")
    for component in components:
        if component in ("", ".", ".."):
            raise AuthorityError("ambiguous Windows relative path component")
        if component.endswith((" ", ".")):
            raise AuthorityError("Windows relative path has trailing dot/space component")
        stem = component.split(".", 1)[0].upper()
        if stem in WINDOWS_RESERVED_STEMS:
            raise AuthorityError(f"Windows reserved device stem is not admitted: {component}")
        for character in component:
            if character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-+":
                raise AuthorityError(
                    f"Windows toolchain authority path contains unsupported character: {component!r}"
                )

    return raw, raw.lower()


def linux_relative_bytes(relative: str) -> tuple[bytes, bytes]:
    raw = os.fsencode(relative)
    if not raw or raw.startswith(b"/"):
        raise AuthorityError("invalid Linux relative path")
    components = raw.split(b"/")
    if any(component in (b"", b".", b"..") for component in components):
        raise AuthorityError("ambiguous Linux relative path component")
    if b"\0" in raw:
        raise AuthorityError("NUL is not admitted in a relative path")
    return raw, raw


def classify_relative(relative: str, platform_model: str) -> tuple[bytes, bytes]:
    if platform_model == "windows":
        return windows_relative_bytes(relative)
    if platform_model == "linux":
        return linux_relative_bytes(relative)
    raise AuthorityError(f"unsupported platform model: {platform_model}")


def stable_file_record(
    root: pathlib.Path,
    path: pathlib.Path,
    platform_model: str,
) -> FileRecord:
    relative_text = path.relative_to(root).as_posix()
    relative, sort_key = classify_relative(relative_text, platform_model)

    try:
        before = os.lstat(path)
    except FileNotFoundError as error:
        raise AuthorityError(f"toolchain file disappeared before hashing: {relative_text}") from error

    if stat.S_ISLNK(before.st_mode) or is_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise AuthorityError(f"toolchain entry is not a regular non-indirection file: {relative_text}")
    if before.st_size < 0 or before.st_size > MAX_FILE_BYTES:
        raise AuthorityError(f"toolchain file exceeds per-file bound: {relative_text}")

    mode_class = b"x" if (platform_model == "linux" and before.st_mode & 0o111) else b"f"
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb", buffering=0) as handle:
            opened = os.fstat(handle.fileno())
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_size != before.st_size
            ):
                raise AuthorityError(f"toolchain file changed while being opened: {relative_text}")
            while True:
                chunk = handle.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FILE_BYTES:
                    raise AuthorityError(f"toolchain file exceeds per-file bound: {relative_text}")
                digest.update(chunk)
            after = os.fstat(handle.fileno())
    except OSError as error:
        raise AuthorityError(f"could not stably read toolchain file {relative_text}: {error}") from error

    if (
        total != before.st_size
        or after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or getattr(after, "st_mtime_ns", None) != getattr(before, "st_mtime_ns", None)
        or getattr(after, "st_ctime_ns", None) != getattr(before, "st_ctime_ns", None)
    ):
        raise AuthorityError(f"toolchain file changed while hashing: {relative_text}")

    return FileRecord(
        relative=relative,
        sort_key=sort_key,
        mode_class=mode_class,
        size=total,
        sha256=digest.digest(),
    )


def iter_plain_files(root: pathlib.Path, platform_model: str) -> Iterable[pathlib.Path]:
    require_plain_directory(root, "toolchain root")
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = pathlib.Path(current)

        safe_dirs: list[str] = []
        for name in dirnames:
            child = current_path / name
            relative_text = child.relative_to(root).as_posix()
            classify_relative(relative_text, platform_model)
            metadata = os.lstat(child)
            if stat.S_ISLNK(metadata.st_mode) or is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
                raise AuthorityError(
                    f"toolchain directory is not a normal non-indirection directory: {relative_text}"
                )
            safe_dirs.append(name)
        dirnames[:] = safe_dirs

        for name in filenames:
            child = current_path / name
            yield child


def digest_tree(
    root: pathlib.Path,
    platform_model: str,
    *,
    max_files: int = MAX_FILES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> TreeSummary:
    root = pathlib.Path(os.path.abspath(os.fspath(root)))
    records: list[FileRecord] = []
    seen: set[bytes] = set()
    total_bytes = 0

    for path in iter_plain_files(root, platform_model):
        record = stable_file_record(root, path, platform_model)
        if record.sort_key in seen:
            raise AuthorityError(
                "toolchain tree contains duplicate/colliding relative names under the platform model"
            )
        seen.add(record.sort_key)
        records.append(record)
        if len(records) > max_files:
            raise AuthorityError("toolchain tree exceeds file-count bound")
        total_bytes += record.size
        if total_bytes > max_total_bytes:
            raise AuthorityError("toolchain tree exceeds total-byte bound")

    if not records:
        raise AuthorityError("toolchain tree contains no regular files")

    records.sort(key=lambda item: item.sort_key)
    digest = hashlib.sha256()
    digest.update(b"NXB153-RUST-TOOLCHAIN-TREE-V1\0")
    digest.update(platform_model.encode("ascii") + b"\0")
    for record in records:
        digest.update(struct.pack(">I", len(record.relative)))
        digest.update(record.relative)
        digest.update(record.mode_class)
        digest.update(struct.pack(">Q", record.size))
        digest.update(record.sha256)

    return TreeSummary(
        platform_model=platform_model,
        file_count=len(records),
        total_bytes=total_bytes,
        tree_sha256=digest.hexdigest(),
    )


def require_sha256(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise AuthorityError("expected tree SHA-256 must be lowercase 64-hex")
    return value


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="nxb-153-rust-tree-") as temporary:
        base = pathlib.Path(temporary)
        first = base / "first"
        second = base / "second"
        first.mkdir()
        second.mkdir()

        # Same logical tree, deliberately created in different enumeration order.
        (first / "bin").mkdir()
        (first / "lib").mkdir()
        (first / "bin" / "rustc").write_bytes(b"rustc-bytes\n")
        (first / "lib" / "core.rlib").write_bytes(b"core-bytes\n")

        (second / "lib").mkdir()
        (second / "bin").mkdir()
        (second / "lib" / "core.rlib").write_bytes(b"core-bytes\n")
        (second / "bin" / "rustc").write_bytes(b"rustc-bytes\n")

        first_linux = digest_tree(first, "linux")
        second_linux = digest_tree(second, "linux")
        if first_linux.tree_sha256 != second_linux.tree_sha256:
            raise AuthorityError("self-test enumeration-order independence failed")

        original = first_linux.tree_sha256
        (first / "lib" / "core.rlib").write_bytes(b"mutated\n")
        if digest_tree(first, "linux").tree_sha256 == original:
            raise AuthorityError("self-test mutation did not change tree identity")

        bounded = base / "bounded"
        bounded.mkdir()
        (bounded / "one").write_bytes(b"1")
        (bounded / "two").write_bytes(b"2")
        try:
            digest_tree(bounded, "linux", max_files=1)
        except AuthorityError:
            pass
        else:
            raise AuthorityError("self-test file-count bound did not fail closed")

        windows_collision = base / "windows-collision"
        windows_collision.mkdir()
        (windows_collision / "Tool.exe").write_bytes(b"A")
        (windows_collision / "tool.exe").write_bytes(b"B")
        try:
            digest_tree(windows_collision, "windows")
        except AuthorityError:
            pass
        else:
            raise AuthorityError("self-test Windows case collision was not rejected")

        symlink_root = base / "symlink"
        symlink_root.mkdir()
        (symlink_root / "real").write_bytes(b"trusted")
        try:
            os.symlink("real", symlink_root / "alias")
        except (OSError, NotImplementedError):
            pass
        else:
            try:
                digest_tree(symlink_root, "linux")
            except AuthorityError:
                pass
            else:
                raise AuthorityError("self-test symlink substitution was not rejected")

    print("NXB-153 host Rust toolchain tree authority self-test passed.")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("self-test")

    digest_parser = subparsers.add_parser("digest")
    digest_parser.add_argument("root")
    digest_parser.add_argument("--platform-model", choices=("linux", "windows"), required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("root")
    verify_parser.add_argument("expected_sha256")
    verify_parser.add_argument("--platform-model", choices=("linux", "windows"), required=True)

    arguments = parser.parse_args()
    try:
        if arguments.command == "self-test":
            self_test()
            return

        summary = digest_tree(pathlib.Path(arguments.root), arguments.platform_model)
        if arguments.command == "verify":
            expected = require_sha256(arguments.expected_sha256)
            if summary.tree_sha256 != expected:
                raise AuthorityError(
                    f"toolchain tree SHA-256 mismatch: expected {expected}, found {summary.tree_sha256}"
                )
        print(summary.to_json())
    except AuthorityError as error:
        raise SystemExit(f"NXB-153 host Rust toolchain authority failed: {error}") from error


if __name__ == "__main__":
    main()
