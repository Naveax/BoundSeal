#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import pathlib
import stat
import struct
import tempfile

POLICY = "nxb-153-host-rust-toolchain-tree-authority-v1"
MAX_FILES = 65536
MAX_DIRECTORIES = 65536
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024

WINDOWS_RESERVED_STEMS = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


class AuthorityError(RuntimeError):
    pass


def is_reparse(metadata):
    attributes = getattr(metadata, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attributes & flag)


def metadata_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", None),
        getattr(metadata, "st_ctime_ns", None),
    )


def require_plain_directory(path, label):
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as error:
        raise AuthorityError(f"{label} is missing: {path}") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or is_reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise AuthorityError(
            f"{label} must be a normal non-indirection directory: {path}"
        )
    return metadata


def windows_relative_bytes(relative):
    try:
        raw = relative.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise AuthorityError(
            "Windows toolchain authority currently admits ASCII relative paths only"
        ) from error
    if not raw or raw.startswith(b"/") or b"\\" in raw:
        raise AuthorityError("invalid Windows relative path")
    for component in relative.split("/"):
        if component in ("", ".", ".."):
            raise AuthorityError("ambiguous Windows relative path component")
        if component.endswith((" ", ".")):
            raise AuthorityError(
                "Windows relative path has trailing dot/space component"
            )
        if component.split(".", 1)[0].upper() in WINDOWS_RESERVED_STEMS:
            raise AuthorityError(
                f"Windows reserved device stem is not admitted: {component}"
            )
        if any(
            ch not in (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789._-+"
            )
            for ch in component
        ):
            raise AuthorityError(
                "Windows toolchain authority path contains unsupported "
                f"character: {component!r}"
            )
    return raw, raw.lower()


def linux_relative_bytes(relative):
    raw = os.fsencode(relative)
    if not raw or raw.startswith(b"/") or b"\0" in raw:
        raise AuthorityError("invalid Linux relative path")
    if any(part in (b"", b".", b"..") for part in raw.split(b"/")):
        raise AuthorityError("ambiguous Linux relative path component")
    return raw, raw


def classify_relative(relative, platform_model):
    if platform_model == "linux":
        return linux_relative_bytes(relative)
    if platform_model == "windows":
        return windows_relative_bytes(relative)
    raise AuthorityError(f"unsupported platform model: {platform_model}")


class Budget:
    def __init__(self, max_files, max_directories, max_total_bytes):
        if max_files < 1 or max_directories < 1 or max_total_bytes < 0:
            raise AuthorityError("invalid tree budget")
        self.max_files = max_files
        self.max_directories = max_directories
        self.max_total_bytes = max_total_bytes
        self.file_count = 0
        self.directory_count = 0
        self.total_bytes = 0

    def directory(self, relative):
        self.directory_count += 1
        if self.directory_count > self.max_directories:
            raise AuthorityError(
                f"toolchain tree exceeds directory-count bound at {relative or '.'}"
            )

    def file(self, relative, size):
        if size < 0 or size > MAX_FILE_BYTES:
            raise AuthorityError(f"toolchain file exceeds per-file bound: {relative}")
        if self.file_count + 1 > self.max_files:
            raise AuthorityError("toolchain tree exceeds file-count bound")
        if self.total_bytes + size > self.max_total_bytes:
            raise AuthorityError("toolchain tree exceeds total-byte bound")
        self.file_count += 1
        self.total_bytes += size


def read_fd_record(fd, expected, relative, platform_model):
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode):
        raise AuthorityError(f"toolchain entry is not a regular file: {relative}")
    if metadata_identity(opened) != metadata_identity(expected):
        raise AuthorityError(f"toolchain file changed while opening: {relative}")
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, READ_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > expected.st_size or total > MAX_FILE_BYTES:
            raise AuthorityError(f"toolchain file grew while hashing: {relative}")
        digest.update(chunk)
    after = os.fstat(fd)
    if total != expected.st_size or metadata_identity(after) != metadata_identity(expected):
        raise AuthorityError(f"toolchain file changed while hashing: {relative}")
    raw, sort_key = classify_relative(relative, platform_model)
    mode_class = b"x" if platform_model == "linux" and expected.st_mode & 0o111 else b"f"
    return (raw, sort_key, mode_class, total, digest.digest())


def linux_records(root, budget):
    if os.name == "nt":
        raise AuthorityError("Linux descriptor authority cannot run on Windows")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise AuthorityError(
            "Linux descriptor authority requires O_NOFOLLOW and O_DIRECTORY"
        )
    dir_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(os.fsencode(root), dir_flags)
    except OSError as error:
        raise AuthorityError(
            f"could not pin Linux toolchain root descriptor: {error}"
        ) from error

    records = []
    seen_directories = set()

    def walk(directory_fd, prefix):
        before = os.fstat(directory_fd)
        if not stat.S_ISDIR(before.st_mode):
            raise AuthorityError("Linux toolchain directory descriptor is not a directory")
        key = (before.st_dev, before.st_ino)
        if key in seen_directories:
            raise AuthorityError(
                "Linux toolchain directory object appeared more than once"
            )
        seen_directories.add(key)
        budget.directory(os.fsdecode(prefix) if prefix else "")
        try:
            names = sorted(os.listdir(directory_fd), key=os.fsencode)
        except OSError as error:
            raise AuthorityError(
                f"could not enumerate pinned Linux toolchain directory: {error}"
            ) from error

        for name in names:
            encoded = os.fsencode(name)
            if encoded in (b"", b".", b"..") or b"/" in encoded or b"\0" in encoded:
                raise AuthorityError("invalid Linux toolchain directory entry name")
            relative_raw = encoded if not prefix else prefix + b"/" + encoded
            relative = os.fsdecode(relative_raw)
            try:
                entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise AuthorityError(
                    f"could not stat Linux toolchain entry {relative}: {error}"
                ) from error
            if stat.S_ISLNK(entry.st_mode) or is_reparse(entry):
                raise AuthorityError(
                    f"Linux toolchain indirection is not admitted: {relative}"
                )
            if stat.S_ISDIR(entry.st_mode):
                try:
                    child_fd = os.open(name, dir_flags, dir_fd=directory_fd)
                except OSError as error:
                    raise AuthorityError(
                        f"could not descriptor-open Linux toolchain directory {relative}: {error}"
                    ) from error
                try:
                    opened = os.fstat(child_fd)
                    if (
                        opened.st_dev != entry.st_dev
                        or opened.st_ino != entry.st_ino
                        or not stat.S_ISDIR(opened.st_mode)
                    ):
                        raise AuthorityError(
                            f"Linux toolchain directory changed while opening: {relative}"
                        )
                    walk(child_fd, relative_raw)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(entry.st_mode):
                budget.file(relative, entry.st_size)
                try:
                    file_fd = os.open(name, file_flags, dir_fd=directory_fd)
                except OSError as error:
                    raise AuthorityError(
                        f"could not descriptor-open Linux toolchain file {relative}: {error}"
                    ) from error
                try:
                    records.append(
                        read_fd_record(file_fd, entry, relative, "linux")
                    )
                finally:
                    os.close(file_fd)
            else:
                raise AuthorityError(
                    f"Linux toolchain special entry is not admitted: {relative}"
                )

        after = os.fstat(directory_fd)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or getattr(after, "st_mtime_ns", None) != getattr(before, "st_mtime_ns", None)
            or getattr(after, "st_ctime_ns", None) != getattr(before, "st_ctime_ns", None)
        ):
            raise AuthorityError(
                "Linux toolchain directory changed during descriptor traversal"
            )

    try:
        walk(root_fd, b"")
        return records
    finally:
        os.close(root_fd)


def windows_records(root, budget):
    root = pathlib.Path(root)
    require_plain_directory(root, "toolchain root")
    records = []
    seen_keys = set()
    budget.directory("")

    def walk(current, prefix):
        try:
            before = os.lstat(current)
            entries = sorted(os.scandir(current), key=lambda item: item.name.lower())
        except OSError as error:
            raise AuthorityError(
                f"could not enumerate Windows-model toolchain directory: {error}"
            ) from error
        if (
            stat.S_ISLNK(before.st_mode)
            or is_reparse(before)
            or not stat.S_ISDIR(before.st_mode)
        ):
            raise AuthorityError(
                f"toolchain directory is not a normal non-indirection directory: {prefix or '.'}"
            )
        for item in entries:
            relative = f"{prefix}/{item.name}" if prefix else item.name
            _, sort_key = windows_relative_bytes(relative)
            if sort_key in seen_keys:
                raise AuthorityError(
                    "toolchain tree contains duplicate/colliding relative names "
                    "under the Windows platform model"
                )
            seen_keys.add(sort_key)
            try:
                entry = item.stat(follow_symlinks=False)
            except OSError as error:
                raise AuthorityError(
                    f"could not inspect toolchain entry {relative}: {error}"
                ) from error
            if item.is_symlink() or is_reparse(entry):
                raise AuthorityError(
                    f"toolchain indirection is not admitted: {relative}"
                )
            child = current / item.name
            if stat.S_ISDIR(entry.st_mode):
                budget.directory(relative)
                walk(child, relative)
            elif stat.S_ISREG(entry.st_mode):
                budget.file(relative, entry.st_size)
                try:
                    handle = child.open("rb", buffering=0)
                except OSError as error:
                    raise AuthorityError(
                        f"could not open toolchain file {relative}: {error}"
                    ) from error
                try:
                    records.append(
                        read_fd_record(handle.fileno(), entry, relative, "windows")
                    )
                finally:
                    handle.close()
            else:
                raise AuthorityError(
                    f"toolchain special entry is not admitted: {relative}"
                )
        try:
            after = os.lstat(current)
        except OSError as error:
            raise AuthorityError(
                f"could not re-inspect Windows-model directory {prefix or '.'}: {error}"
            ) from error
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or getattr(after, "st_mtime_ns", None) != getattr(before, "st_mtime_ns", None)
            or getattr(after, "st_ctime_ns", None) != getattr(before, "st_ctime_ns", None)
        ):
            raise AuthorityError(
                f"Windows-model toolchain directory changed during traversal: {prefix or '.'}"
            )

    walk(root, "")
    return records


def digest_tree(
    root,
    platform_model,
    *,
    max_files=MAX_FILES,
    max_directories=MAX_DIRECTORIES,
    max_total_bytes=MAX_TOTAL_BYTES,
):
    root = pathlib.Path(os.path.abspath(os.fspath(root)))
    budget = Budget(max_files, max_directories, max_total_bytes)
    if platform_model == "linux":
        records = linux_records(root, budget)
    elif platform_model == "windows":
        records = windows_records(root, budget)
    else:
        raise AuthorityError(f"unsupported platform model: {platform_model}")

    if not records:
        raise AuthorityError("toolchain tree contains no regular files")
    records.sort(key=lambda record: record[1])

    digest = hashlib.sha256()
    digest.update(b"NXB153-RUST-TOOLCHAIN-TREE-V1\0")
    digest.update(platform_model.encode("ascii") + b"\0")
    for relative, _, mode_class, size, file_sha in records:
        digest.update(struct.pack(">I", len(relative)))
        digest.update(relative)
        digest.update(mode_class)
        digest.update(struct.pack(">Q", size))
        digest.update(file_sha)

    return {
        "schema_version": 1,
        "policy": POLICY,
        "platform_model": platform_model,
        "file_count": budget.file_count,
        "total_bytes": budget.total_bytes,
        "tree_sha256": digest.hexdigest(),
    }


def require_sha256(value):
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise AuthorityError("expected tree SHA-256 must be lowercase 64-hex")
    return value


def self_test():
    with tempfile.TemporaryDirectory(prefix="nxb-153-rust-tree-") as temporary:
        base = pathlib.Path(temporary)
        first = base / "first"
        second = base / "second"
        first.mkdir()
        second.mkdir()
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
        if first_linux["tree_sha256"] != second_linux["tree_sha256"]:
            raise AuthorityError("self-test enumeration-order independence failed")

        original = first_linux["tree_sha256"]
        (first / "lib" / "core.rlib").write_bytes(b"mutated\n")
        if digest_tree(first, "linux")["tree_sha256"] == original:
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
        try:
            digest_tree(bounded, "linux", max_total_bytes=1)
        except AuthorityError:
            pass
        else:
            raise AuthorityError("self-test total-byte bound did not fail closed")

        directory_bound = base / "directory-bound"
        directory_bound.mkdir()
        (directory_bound / "child").mkdir()
        (directory_bound / "child" / "file").write_bytes(b"x")
        try:
            digest_tree(directory_bound, "linux", max_directories=1)
        except AuthorityError:
            pass
        else:
            raise AuthorityError(
                "self-test directory-count bound did not fail closed"
            )

        collision = base / "windows-collision"
        collision.mkdir()
        (collision / "Tool.exe").write_bytes(b"A")
        (collision / "tool.exe").write_bytes(b"B")
        try:
            digest_tree(collision, "windows")
        except AuthorityError:
            pass
        else:
            raise AuthorityError(
                "self-test Windows case collision was not rejected"
            )

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
                raise AuthorityError(
                    "self-test symlink substitution was not rejected"
                )
    print("NXB-153 host Rust toolchain tree authority self-test passed.")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")
    digest_parser = subparsers.add_parser("digest")
    digest_parser.add_argument("root")
    digest_parser.add_argument(
        "--platform-model", choices=("linux", "windows"), required=True
    )
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("root")
    verify_parser.add_argument("expected_sha256")
    verify_parser.add_argument(
        "--platform-model", choices=("linux", "windows"), required=True
    )
    arguments = parser.parse_args()
    try:
        if arguments.command == "self-test":
            self_test()
            return
        summary = digest_tree(
            pathlib.Path(arguments.root), arguments.platform_model
        )
        if arguments.command == "verify":
            expected = require_sha256(arguments.expected_sha256)
            if summary["tree_sha256"] != expected:
                raise AuthorityError(
                    "toolchain tree SHA-256 mismatch: "
                    f"expected {expected}, found {summary['tree_sha256']}"
                )
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    except AuthorityError as error:
        raise SystemExit(
            f"NXB-153 host Rust toolchain authority failed: {error}"
        ) from error


if __name__ == "__main__":
    main()
