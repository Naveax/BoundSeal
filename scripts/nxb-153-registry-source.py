#!/usr/bin/env python3
"""Fail-closed registry/dependency-source authority checks for NXB-153."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tomllib
from typing import NoReturn

CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
MAX_LOCK_BYTES = 8 * 1024 * 1024
MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_CHECKSUM_BYTES = 16 * 1024 * 1024
MAX_VENDOR_FILES = 200_000
MAX_VENDOR_BYTES = 4 * 1024 * 1024 * 1024


class AuthorityError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise AuthorityError(message)


def is_lower_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def read_regular_bytes(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        fail(f"could not stat {label}: {error}")
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        fail(f"{label} must be a regular non-symlink file")
    if before.st_size <= 0 or before.st_size > maximum:
        fail(f"{label} size is outside the supported envelope")

    try:
        with path.open("rb") as handle:
            value = handle.read(maximum + 1)
            after = os.fstat(handle.fileno())
    except OSError as error:
        fail(f"could not read {label}: {error}")

    if len(value) != before.st_size or len(value) > maximum:
        fail(f"{label} changed size while being read")
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or getattr(after, "st_mtime_ns", None) != getattr(before, "st_mtime_ns", None)
        or getattr(after, "st_ctime_ns", None) != getattr(before, "st_ctime_ns", None)
    ):
        fail(f"{label} metadata changed while being read")
    return value


def parse_lock(path: Path) -> dict[tuple[str, str], str]:
    raw = read_regular_bytes(path, MAX_LOCK_BYTES, "Cargo.lock")
    try:
        payload = tomllib.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"Cargo.lock is not strict UTF-8 TOML: {error}")

    packages = payload.get("package")
    if not isinstance(packages, list) or not packages:
        fail("Cargo.lock contains no package records")

    registry: dict[tuple[str, str], str] = {}
    for package in packages:
        if not isinstance(package, dict):
            fail("Cargo.lock contains a non-table package record")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            fail("Cargo.lock package name/version is invalid")
        if source is None:
            continue
        if source != CRATES_IO_SOURCE:
            fail(f"unsupported dependency source for {name} {version}: {source!r}")
        checksum = package.get("checksum")
        if not is_lower_sha256(checksum):
            fail(f"registry package {name} {version} lacks a canonical SHA-256 checksum")
        key = (name, version)
        if key in registry:
            fail(f"duplicate crates.io package identity in Cargo.lock: {name} {version}")
        registry[key] = checksum

    if not registry:
        fail("Cargo.lock contains no checksum-bearing crates.io registry packages")
    return registry


def safe_relative(value: str, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        fail(f"{label} is not a canonical relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
        or path.as_posix() != value
    ):
        fail(f"{label} is not a canonical relative path: {value!r}")
    return path


def sha256_file(path: Path, label: str) -> str:
    try:
        before = path.lstat()
    except OSError as error:
        fail(f"could not stat {label}: {error}")
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        fail(f"{label} must be a regular non-symlink file")
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
            after = os.fstat(handle.fileno())
    except OSError as error:
        fail(f"could not hash {label}: {error}")
    if total != before.st_size:
        fail(f"{label} changed size while hashing")
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or getattr(after, "st_mtime_ns", None) != getattr(before, "st_mtime_ns", None)
        or getattr(after, "st_ctime_ns", None) != getattr(before, "st_ctime_ns", None)
    ):
        fail(f"{label} metadata changed while hashing")
    return digest.hexdigest()


def validate_lock(lock_path: Path) -> None:
    registry = parse_lock(lock_path)
    print(json.dumps({"registry_packages": len(registry)}, sort_keys=True))


def validate_metadata(source_root: Path) -> None:
    try:
        source_stat = source_root.lstat()
    except OSError as error:
        fail(f"could not stat immutable source root: {error}")
    if not stat.S_ISDIR(source_stat.st_mode) or stat.S_ISLNK(source_stat.st_mode):
        fail("immutable source root must be a real directory")
    source_abs = os.path.abspath(os.fspath(source_root))

    raw = sys.stdin.buffer.read(MAX_METADATA_BYTES + 1)
    if not raw or len(raw) > MAX_METADATA_BYTES:
        fail("cargo metadata payload size is invalid")
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cargo metadata is invalid strict UTF-8 JSON: {error}")

    packages = payload.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("cargo metadata contains no packages")

    local_count = 0
    registry_count = 0
    for package in packages:
        if not isinstance(package, dict):
            fail("cargo metadata contains a non-object package")
        source = package.get("source")
        manifest = package.get("manifest_path")
        if not isinstance(manifest, str) or not manifest:
            fail("cargo metadata package manifest_path is invalid")
        if source is None:
            manifest_abs = os.path.abspath(manifest)
            try:
                common = os.path.commonpath((source_abs, manifest_abs))
            except ValueError as error:
                fail(f"local package manifest is outside the immutable source volume: {error}")
            if os.path.normcase(common) != os.path.normcase(source_abs):
                fail(f"local/path package escapes the immutable exact-head source root: {manifest}")
            manifest_path = Path(manifest_abs)
            try:
                metadata = manifest_path.lstat()
            except OSError as error:
                fail(f"local package manifest is unavailable: {error}")
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                fail(f"local package manifest is not a regular non-symlink file: {manifest}")
            local_count += 1
        elif source == CRATES_IO_SOURCE:
            registry_count += 1
        else:
            fail(f"cargo metadata reports unsupported dependency source: {source!r}")

    print(
        json.dumps(
            {"local_packages": local_count, "registry_packages": registry_count},
            sort_keys=True,
        )
    )


def validate_vendor(lock_path: Path, vendor_root: Path) -> None:
    registry = parse_lock(lock_path)
    try:
        vendor_stat = vendor_root.lstat()
    except OSError as error:
        fail(f"could not stat vendor root: {error}")
    if not stat.S_ISDIR(vendor_stat.st_mode) or stat.S_ISLNK(vendor_stat.st_mode):
        fail("vendor root must be a real directory")

    expected_directories = {
        f"{name}-{version}": (name, version, checksum)
        for (name, version), checksum in registry.items()
    }
    if len(expected_directories) != len(registry):
        fail("versioned vendor directory names collide")

    try:
        root_entries = list(os.scandir(vendor_root))
    except OSError as error:
        fail(f"could not enumerate vendor root: {error}")

    actual_directories: dict[str, Path] = {}
    for entry in root_entries:
        try:
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                fail(f"vendor root contains unsupported non-directory entry: {entry.name}")
        except OSError as error:
            fail(f"could not classify vendor root entry {entry.name!r}: {error}")
        if entry.name in actual_directories:
            fail(f"duplicate vendor package directory: {entry.name}")
        actual_directories[entry.name] = Path(entry.path)

    if set(actual_directories) != set(expected_directories):
        unexpected = sorted(set(actual_directories) - set(expected_directories))[:8]
        missing = sorted(set(expected_directories) - set(actual_directories))[:8]
        fail(
            f"vendor package set differs from Cargo.lock: "
            f"unexpected={unexpected!r} missing={missing!r}"
        )

    total_files = 0
    total_bytes = 0
    manifest_digest = hashlib.sha256()

    for directory_name in sorted(expected_directories):
        name, version, expected_package_checksum = expected_directories[directory_name]
        package_root = actual_directories[directory_name]
        checksum_path = package_root / ".cargo-checksum.json"
        raw_checksum = read_regular_bytes(
            checksum_path,
            MAX_CHECKSUM_BYTES,
            f"{directory_name}/.cargo-checksum.json",
        )
        try:
            checksum_payload = json.loads(raw_checksum.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"invalid .cargo-checksum.json for {directory_name}: {error}")
        if not isinstance(checksum_payload, dict) or set(checksum_payload) != {"files", "package"}:
            fail(f"unexpected checksum schema for {directory_name}")
        if checksum_payload.get("package") != expected_package_checksum:
            fail(f"vendored package checksum does not match Cargo.lock for {name} {version}")
        files = checksum_payload.get("files")
        if not isinstance(files, dict):
            fail(f"vendored file checksum map is invalid for {directory_name}")

        expected_files: dict[str, str] = {}
        for relative, digest in files.items():
            if not is_lower_sha256(digest):
                fail(f"invalid vendored file SHA-256 for {directory_name}/{relative}")
            canonical = safe_relative(
                relative,
                f"vendored path {directory_name}/{relative}",
            ).as_posix()
            if canonical in expected_files:
                fail(f"duplicate vendored checksum path: {directory_name}/{canonical}")
            expected_files[canonical] = digest

        actual_files: dict[str, Path] = {}
        for current_root, dirnames, filenames in os.walk(
            package_root,
            topdown=True,
            followlinks=False,
        ):
            current = Path(current_root)
            for dirname in list(dirnames):
                candidate = current / dirname
                try:
                    metadata = candidate.lstat()
                except OSError as error:
                    fail(f"could not stat vendor directory {candidate}: {error}")
                if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    fail(f"vendor package contains unsupported directory object: {candidate}")
            for filename in filenames:
                candidate = current / filename
                relative = candidate.relative_to(package_root).as_posix()
                safe_relative(relative, f"vendored file {directory_name}/{relative}")
                try:
                    metadata = candidate.lstat()
                except OSError as error:
                    fail(f"could not stat vendored file {candidate}: {error}")
                if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    fail(f"vendor package contains unsupported file object: {candidate}")
                if relative == ".cargo-checksum.json":
                    continue
                if relative in actual_files:
                    fail(f"duplicate vendored file path: {directory_name}/{relative}")
                actual_files[relative] = candidate
                total_files += 1
                total_bytes += metadata.st_size
                if total_files > MAX_VENDOR_FILES or total_bytes > MAX_VENDOR_BYTES:
                    fail("vendored dependency snapshot exceeds the supported file/byte envelope")

        if set(actual_files) != set(expected_files):
            unexpected = sorted(set(actual_files) - set(expected_files))[:8]
            missing = sorted(set(expected_files) - set(actual_files))[:8]
            fail(
                f"vendored file set differs from Cargo checksum map for {directory_name}: "
                f"unexpected={unexpected!r} missing={missing!r}"
            )

        manifest_digest.update(directory_name.encode("utf-8"))
        manifest_digest.update(b"\0")
        manifest_digest.update(expected_package_checksum.encode("ascii"))
        manifest_digest.update(b"\0")
        for relative in sorted(expected_files):
            digest = sha256_file(
                actual_files[relative],
                f"vendored file {directory_name}/{relative}",
            )
            if digest != expected_files[relative]:
                fail(
                    f"vendored file bytes differ from Cargo checksum map: "
                    f"{directory_name}/{relative}"
                )
            manifest_digest.update(relative.encode("utf-8"))
            manifest_digest.update(b"\0")
            manifest_digest.update(digest.encode("ascii"))
            manifest_digest.update(b"\0")

    print(
        json.dumps(
            {
                "registry_packages": len(registry),
                "vendor_bytes": total_bytes,
                "vendor_files": total_files,
                "vendor_manifest_sha256": manifest_digest.hexdigest(),
            },
            sort_keys=True,
        )
    )


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        fail("mode is required")
    mode = argv[1]
    if mode == "validate-lock":
        if len(argv) != 3:
            fail("validate-lock requires Cargo.lock path")
        validate_lock(Path(argv[2]))
    elif mode == "validate-metadata":
        if len(argv) != 3:
            fail("validate-metadata requires immutable source root")
        validate_metadata(Path(argv[2]))
    elif mode == "validate-vendor":
        if len(argv) != 4:
            fail("validate-vendor requires Cargo.lock and vendor root")
        validate_vendor(Path(argv[2]), Path(argv[3]))
    else:
        fail(f"unknown mode: {mode}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except AuthorityError as error:
        print(f"NXB-153 registry source authority failed: {error}", file=sys.stderr)
        raise SystemExit(1)
