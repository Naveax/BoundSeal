#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import stat
import sys
import tempfile
from typing import Any

EXPECTED_LOCK_SHA256 = "f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"
MAXIMUM_BYTES = 65536


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"NXB-153 secure evidence launcher failed: {message}")


def absolute_without_resolution(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def require_linux_openat_primitives() -> None:
    if not sys.platform.startswith("linux"):
        fail("descriptor-anchored evidence review is supported only on Linux")
    for name in ("O_DIRECTORY", "O_NOFOLLOW"):
        if not hasattr(os, name):
            fail(f"required Linux openat primitive {name} is unavailable")


def open_directory_anchored(path: pathlib.Path, label: str) -> int:
    absolute = absolute_without_resolution(path)
    parts = absolute.parts
    if not parts or parts[0] != os.path.sep:
        fail(f"{label} must be an absolute POSIX path")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        current_fd = os.open(os.path.sep, flags)
    except OSError as error:
        fail(f"could not open filesystem root for {label}: {error}")

    try:
        for component in parts[1:]:
            if component in ("", ".", ".."):
                fail(f"{label} contains an invalid path component")
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError as error:
                fail(f"could not securely open {label} component {component!r}: {error}")
            os.close(current_fd)
            current_fd = next_fd
            metadata = os.fstat(current_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                fail(f"{label} component is not a directory: {component}")
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def relative_parts(path: pathlib.Path, anchor: pathlib.Path, label: str) -> tuple[str, ...]:
    absolute = absolute_without_resolution(path)
    try:
        relative = absolute.relative_to(anchor)
    except ValueError:
        fail(f"{label} escapes its anchored directory: {absolute}")
    parts = relative.parts
    if not parts:
        fail(f"{label} must identify a file below its anchored directory")
    if any(component in ("", ".", "..") for component in parts):
        fail(f"{label} contains an invalid relative component")
    return parts


def open_regular_relative(
    anchor_fd: int,
    parts: tuple[str, ...],
    label: str,
    write_flags: int = 0,
    mode: int = 0o600,
) -> int:
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    )
    current_fd = os.dup(anchor_fd)
    try:
        for component in parts[:-1]:
            try:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            except OSError as error:
                fail(f"could not securely traverse {label} component {component!r}: {error}")
            os.close(current_fd)
            current_fd = next_fd
            metadata = os.fstat(current_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                fail(f"{label} parent component is not a directory: {component}")

        final_flags = (
            (write_flags or os.O_RDONLY)
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        if write_flags:
            return os.open(parts[-1], final_flags, mode, dir_fd=current_fd)
        return os.open(parts[-1], final_flags, dir_fd=current_fd)
    finally:
        os.close(current_fd)


def read_fd_bytes(
    fd: int,
    label: str,
    maximum_bytes: int = MAXIMUM_BYTES,
) -> tuple[bytes, os.stat_result]:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        fail(f"{label} must be a regular file")
    if before.st_size <= 0 or before.st_size > maximum_bytes:
        fail(f"{label} size is invalid")

    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining > 0:
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    value = b"".join(chunks)
    after = os.fstat(fd)

    if len(value) != before.st_size or len(value) > maximum_bytes:
        fail(f"{label} changed size while being read")
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or getattr(after, "st_mtime_ns", None) != getattr(before, "st_mtime_ns", None)
        or getattr(after, "st_ctime_ns", None) != getattr(before, "st_ctime_ns", None)
    ):
        fail(f"{label} metadata changed while being read")
    return value, before


def decode_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        decoded = raw.decode("utf-8", errors="strict")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is invalid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} root must be an object")
    return value


def load_implementation(script_path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("nxb153_evidence_impl", script_path)
    if spec is None or spec.loader is None:
        fail(f"could not load evidence implementation: {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def self_test() -> None:
    require_linux_openat_primitives()
    with tempfile.TemporaryDirectory(prefix="nxb-153-secure-review-") as temporary:
        root = pathlib.Path(temporary)
        evidence = root / "evidence"
        replacement = root / "replacement"
        evidence.mkdir()
        replacement.mkdir()
        trusted = evidence / "record.json"
        trusted.write_bytes(b'{"trusted":true}\n')
        (replacement / "record.json").write_bytes(b'{"trusted":false}\n')

        evidence_fd = open_directory_anchored(evidence, "self-test evidence directory")
        try:
            file_fd = open_regular_relative(
                evidence_fd,
                ("record.json",),
                "self-test record",
            )
            try:
                raw, _ = read_fd_bytes(file_fd, "self-test record")
            finally:
                os.close(file_fd)
            if raw != b'{"trusted":true}\n':
                fail("self-test trusted record bytes mismatch")

            link = evidence / "link.json"
            link.symlink_to(trusted)
            try:
                link_fd = open_regular_relative(
                    evidence_fd,
                    ("link.json",),
                    "self-test symlink",
                )
            except OSError:
                pass
            else:
                os.close(link_fd)
                fail("self-test final symlink was unexpectedly opened")

            moved = root / "evidence-pinned"
            evidence.rename(moved)
            os.symlink(replacement, evidence)
            anchored_fd = open_regular_relative(
                evidence_fd,
                ("record.json",),
                "self-test anchored record",
            )
            try:
                anchored_raw, _ = read_fd_bytes(
                    anchored_fd,
                    "self-test anchored record",
                )
            finally:
                os.close(anchored_fd)
            if anchored_raw != b'{"trusted":true}\n':
                fail("self-test parent replacement redirected anchored read")
        finally:
            os.close(evidence_fd)

    print("NXB-153 Linux descriptor-anchored evidence primitive self-test passed.")


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return

    require_linux_openat_primitives()

    launcher_path = pathlib.Path(__file__).absolute()
    default_root = launcher_path.parent.parent
    repo_root = absolute_without_resolution(
        pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else default_root
    )
    evidence_directory = absolute_without_resolution(
        pathlib.Path(sys.argv[2])
        if len(sys.argv) > 2
        else repo_root / "target" / "nxb-validation"
    )
    if len(sys.argv) > 3:
        fail(
            "usage: review-nxb-153-evidence-linux-secure.py "
            "[repo-root] [evidence-directory]"
        )

    repo_fd = open_directory_anchored(repo_root, "repository root")
    evidence_fd = -1
    try:
        evidence_fd = open_directory_anchored(evidence_directory, "evidence directory")
        implementation = load_implementation(
            repo_root / "scripts" / "review-nxb-153-evidence-linux.py"
        )

        def anchor_for(
            path: pathlib.Path,
            label: str,
        ) -> tuple[int, pathlib.Path, tuple[str, ...]]:
            absolute = absolute_without_resolution(path)
            try:
                parts = relative_parts(absolute, evidence_directory, label)
                return evidence_fd, evidence_directory, parts
            except SystemExit:
                pass
            parts = relative_parts(absolute, repo_root, label)
            return repo_fd, repo_root, parts

        def secure_require_regular(path: pathlib.Path, label: str):
            anchor_fd, _, parts = anchor_for(path, label)
            try:
                fd = open_regular_relative(anchor_fd, parts, label)
            except FileNotFoundError:
                implementation.fail(f"missing {label}: {path}")
            try:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode):
                    implementation.fail(
                        f"{label} must be a regular non-indirection file"
                    )
                if (
                    metadata.st_size <= 0
                    or metadata.st_size > implementation.MAXIMUM_BYTES
                ):
                    implementation.fail(f"{label} size is invalid")
                return metadata
            finally:
                os.close(fd)

        def secure_read_bytes(path: pathlib.Path, label: str) -> bytes:
            anchor_fd, _, parts = anchor_for(path, label)
            try:
                fd = open_regular_relative(anchor_fd, parts, label)
            except FileNotFoundError:
                implementation.fail(f"missing {label}: {path}")
            try:
                raw, _ = read_fd_bytes(
                    fd,
                    label,
                    implementation.MAXIMUM_BYTES,
                )
                return raw
            finally:
                os.close(fd)

        def secure_sha256_file(path: pathlib.Path) -> str:
            raw = secure_read_bytes(path, "Cargo.lock")
            return implementation.sha256_bytes(raw)

        def secure_publish_closure_create_only(
            path: pathlib.Path,
            value: dict[str, Any],
        ) -> None:
            canonical = (json.dumps(value, indent=2) + "\n").encode("utf-8")
            parts = relative_parts(path, evidence_directory, "closure evidence")

            def read_existing(label: str) -> dict[str, Any]:
                existing_fd = open_regular_relative(evidence_fd, parts, label)
                try:
                    raw, _ = read_fd_bytes(
                        existing_fd,
                        label,
                        implementation.MAXIMUM_BYTES,
                    )
                finally:
                    os.close(existing_fd)
                return decode_json(raw, label)

            create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            try:
                descriptor = open_regular_relative(
                    evidence_fd,
                    parts,
                    "closure evidence",
                    write_flags=create_flags,
                    mode=0o600,
                )
            except FileExistsError:
                existing = read_existing("existing closure evidence")
                if existing != value:
                    implementation.fail(
                        "existing closure evidence differs from deterministic review result"
                    )
                return

            try:
                offset = 0
                while offset < len(canonical):
                    written = os.write(descriptor, canonical[offset:])
                    if written <= 0:
                        raise OSError(
                            "closure evidence write made no forward progress"
                        )
                    offset += written
                os.fsync(descriptor)
            except Exception:
                # A create-new destination may now be partially visible. Never delete it by
                # pathname; explicit recovery owns this state.
                raise
            finally:
                os.close(descriptor)

            os.fsync(evidence_fd)
            try:
                verify_fd = open_regular_relative(
                    evidence_fd,
                    parts,
                    "published closure evidence",
                )
            except FileNotFoundError:
                implementation.fail(
                    "published closure evidence disappeared after create-only claim"
                )
            try:
                persisted, _ = read_fd_bytes(
                    verify_fd,
                    "published closure evidence",
                    implementation.MAXIMUM_BYTES,
                )
            finally:
                os.close(verify_fd)
            if persisted != canonical:
                implementation.fail(
                    "published closure evidence bytes differ from deterministic canonical review result"
                )

        implementation.require_regular = secure_require_regular
        implementation.read_bytes = secure_read_bytes
        implementation.sha256_file = secure_sha256_file
        implementation.publish_closure_create_only = secure_publish_closure_create_only
        implementation.main()
    finally:
        if evidence_fd >= 0:
            os.close(evidence_fd)
        os.close(repo_fd)


if __name__ == "__main__":
    main()
