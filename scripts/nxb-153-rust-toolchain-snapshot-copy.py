#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import stat
import tempfile

POLICY = "nxb-153-rust-toolchain-snapshot-copy-v1"
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


class SnapshotCopyError(RuntimeError):
    pass


def is_reparse(metadata):
    attributes = getattr(metadata, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attributes & flag)


def file_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", None),
        getattr(metadata, "st_ctime_ns", None),
    )


class CopyBudget:
    def __init__(
        self,
        max_files=MAX_FILES,
        max_directories=MAX_DIRECTORIES,
        max_file_bytes=MAX_FILE_BYTES,
        max_total_bytes=MAX_TOTAL_BYTES,
    ):
        if (
            max_files < 1
            or max_directories < 1
            or max_file_bytes < 0
            or max_total_bytes < 0
        ):
            raise SnapshotCopyError("invalid snapshot-copy budget")
        self.max_files = max_files
        self.max_directories = max_directories
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.file_count = 0
        self.directory_count = 0
        self.total_bytes = 0

    def admit_directory(self, relative):
        self.directory_count += 1
        if self.directory_count > self.max_directories:
            raise SnapshotCopyError(
                f"source tree exceeds directory-count bound at {relative or '.'}"
            )

    def admit_file(self, relative, size):
        if size < 0 or size > self.max_file_bytes:
            raise SnapshotCopyError(
                f"source file exceeds per-file bound: {relative}"
            )
        if self.file_count + 1 > self.max_files:
            raise SnapshotCopyError("source tree exceeds file-count bound")
        if self.total_bytes + size > self.max_total_bytes:
            raise SnapshotCopyError("source tree exceeds total-byte bound")
        self.file_count += 1
        self.total_bytes += size

    def to_json(self, platform_model):
        return json.dumps(
            {
                "schema_version": 1,
                "policy": POLICY,
                "platform_model": platform_model,
                "file_count": self.file_count,
                "total_bytes": self.total_bytes,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def validate_windows_component(component):
    try:
        component.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise SnapshotCopyError(
            "Windows snapshot copy currently admits ASCII relative paths only"
        ) from error
    if component in ("", ".", "..") or component.endswith((" ", ".")):
        raise SnapshotCopyError(
            f"ambiguous Windows path component: {component!r}"
        )
    if component.split(".", 1)[0].upper() in WINDOWS_RESERVED_STEMS:
        raise SnapshotCopyError(
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
        raise SnapshotCopyError(
            f"Windows snapshot path contains unsupported character: {component!r}"
        )


def require_plain_directory(path, label):
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as error:
        raise SnapshotCopyError(f"{label} is missing: {path}") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or is_reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise SnapshotCopyError(
            f"{label} must be a normal non-indirection directory"
        )
    return metadata


def require_empty_destination(destination):
    require_plain_directory(destination, "destination root")
    try:
        with os.scandir(destination) as entries:
            if next(entries, None) is not None:
                raise SnapshotCopyError("destination root must be empty")
    except OSError as error:
        raise SnapshotCopyError(
            f"could not inspect destination root: {error}"
        ) from error


def copy_regular_file_linux(
    source_fd,
    destination_fd,
    name,
    relative,
    metadata,
    budget,
):
    budget.admit_file(relative, metadata.st_size)
    source_handle = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=source_fd,
    )
    try:
        opened = os.fstat(source_handle)
        if (
            not stat.S_ISREG(opened.st_mode)
            or file_identity(opened) != file_identity(metadata)
        ):
            raise SnapshotCopyError(
                f"source file changed while opening: {relative}"
            )
        mode = 0o755 if opened.st_mode & 0o111 else 0o644
        destination_handle = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode,
            dir_fd=destination_fd,
        )
        try:
            total = 0
            while True:
                chunk = os.read(source_handle, READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if (
                    total > metadata.st_size
                    or total > budget.max_file_bytes
                ):
                    raise SnapshotCopyError(
                        f"source file grew during copy: {relative}"
                    )
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_handle, view)
                    if written <= 0:
                        raise SnapshotCopyError(
                            f"destination write stalled: {relative}"
                        )
                    view = view[written:]
            os.fsync(destination_handle)
        finally:
            os.close(destination_handle)
        after = os.fstat(source_handle)
        if (
            total != metadata.st_size
            or file_identity(after) != file_identity(metadata)
        ):
            raise SnapshotCopyError(
                f"source file changed during copy: {relative}"
            )
    finally:
        os.close(source_handle)


def copy_directory_linux(
    source_fd,
    destination_fd,
    relative_prefix,
    budget,
):
    before = os.fstat(source_fd)
    try:
        names = sorted(os.listdir(source_fd), key=os.fsencode)
    except OSError as error:
        raise SnapshotCopyError(
            f"could not enumerate source directory: {error}"
        ) from error

    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    for name in names:
        if name in ("", ".", "..") or "/" in name or "\0" in name:
            raise SnapshotCopyError(
                f"ambiguous Linux path component: {name!r}"
            )
        relative = (
            f"{relative_prefix}/{name}" if relative_prefix else name
        )
        try:
            metadata = os.stat(
                name,
                dir_fd=source_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise SnapshotCopyError(
                f"could not inspect source entry {relative}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode) or is_reparse(metadata):
            raise SnapshotCopyError(
                f"source indirection is not admitted: {relative}"
            )
        if stat.S_ISDIR(metadata.st_mode):
            budget.admit_directory(relative)
            os.mkdir(name, 0o755, dir_fd=destination_fd)
            child_source = os.open(
                name, directory_flags, dir_fd=source_fd
            )
            child_destination = os.open(
                name, directory_flags, dir_fd=destination_fd
            )
            try:
                opened = os.fstat(child_source)
                if (
                    opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                    or not stat.S_ISDIR(opened.st_mode)
                ):
                    raise SnapshotCopyError(
                        f"source directory changed while opening: {relative}"
                    )
                copy_directory_linux(
                    child_source,
                    child_destination,
                    relative,
                    budget,
                )
            finally:
                os.close(child_destination)
                os.close(child_source)
        elif stat.S_ISREG(metadata.st_mode):
            copy_regular_file_linux(
                source_fd,
                destination_fd,
                name,
                relative,
                metadata,
                budget,
            )
        else:
            raise SnapshotCopyError(
                f"special source entry is not admitted: {relative}"
            )

    after = os.fstat(source_fd)
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or getattr(after, "st_mtime_ns", None)
        != getattr(before, "st_mtime_ns", None)
        or getattr(after, "st_ctime_ns", None)
        != getattr(before, "st_ctime_ns", None)
    ):
        raise SnapshotCopyError(
            "source directory changed during copy traversal"
        )


def copy_tree_linux(source, destination, budget):
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise SnapshotCopyError(
            "Linux snapshot copy requires O_DIRECTORY and O_NOFOLLOW"
        )
    source_fd = os.open(
        source,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    destination_fd = os.open(
        destination,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        if not stat.S_ISDIR(os.fstat(source_fd).st_mode):
            raise SnapshotCopyError("source root must be a directory")
        if not stat.S_ISDIR(os.fstat(destination_fd).st_mode):
            raise SnapshotCopyError("destination root must be a directory")
        budget.admit_directory("")
        copy_directory_linux(
            source_fd, destination_fd, "", budget
        )
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)


def copy_regular_file_windows(
    source,
    destination,
    relative,
    metadata,
    budget,
):
    budget.admit_file(relative, metadata.st_size)
    try:
        source_handle = source.open("rb", buffering=0)
    except OSError as error:
        raise SnapshotCopyError(
            f"could not open source file {relative}: {error}"
        ) from error
    try:
        opened = os.fstat(source_handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or is_reparse(opened)
            or file_identity(opened) != file_identity(metadata)
        ):
            raise SnapshotCopyError(
                f"source file changed while opening: {relative}"
            )
        try:
            destination_handle = destination.open("xb", buffering=0)
        except OSError as error:
            raise SnapshotCopyError(
                f"could not create destination file {relative}: {error}"
            ) from error
        try:
            total = 0
            while True:
                chunk = source_handle.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if (
                    total > metadata.st_size
                    or total > budget.max_file_bytes
                ):
                    raise SnapshotCopyError(
                        f"source file grew during copy: {relative}"
                    )
                destination_handle.write(chunk)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
        finally:
            destination_handle.close()
        after = os.fstat(source_handle.fileno())
        if (
            total != metadata.st_size
            or file_identity(after) != file_identity(metadata)
        ):
            raise SnapshotCopyError(
                f"source file changed during copy: {relative}"
            )
    finally:
        source_handle.close()


def copy_directory_windows(
    source,
    destination,
    relative_prefix,
    budget,
):
    try:
        before = os.lstat(source)
        entries = sorted(
            os.scandir(source),
            key=lambda entry: entry.name.lower(),
        )
    except OSError as error:
        raise SnapshotCopyError(
            f"could not enumerate source directory: {error}"
        ) from error
    seen = set()
    for entry in entries:
        validate_windows_component(entry.name)
        key = entry.name.lower()
        if key in seen:
            raise SnapshotCopyError(
                f"Windows case-insensitive path collision: {entry.name}"
            )
        seen.add(key)
        relative = (
            f"{relative_prefix}/{entry.name}"
            if relative_prefix
            else entry.name
        )
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as error:
            raise SnapshotCopyError(
                f"could not inspect source entry {relative}: {error}"
            ) from error
        if entry.is_symlink() or is_reparse(metadata):
            raise SnapshotCopyError(
                f"source indirection is not admitted: {relative}"
            )
        source_child = source / entry.name
        destination_child = destination / entry.name
        if stat.S_ISDIR(metadata.st_mode):
            budget.admit_directory(relative)
            destination_child.mkdir(mode=0o755)
            copy_directory_windows(
                source_child,
                destination_child,
                relative,
                budget,
            )
        elif stat.S_ISREG(metadata.st_mode):
            copy_regular_file_windows(
                source_child,
                destination_child,
                relative,
                metadata,
                budget,
            )
        else:
            raise SnapshotCopyError(
                f"special source entry is not admitted: {relative}"
            )
    try:
        after = os.lstat(source)
    except OSError as error:
        raise SnapshotCopyError(
            f"could not re-inspect source directory: {error}"
        ) from error
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or getattr(after, "st_mtime_ns", None)
        != getattr(before, "st_mtime_ns", None)
        or getattr(after, "st_ctime_ns", None)
        != getattr(before, "st_ctime_ns", None)
    ):
        raise SnapshotCopyError(
            "source directory changed during copy traversal"
        )


def copy_tree_windows(source, destination, budget):
    require_plain_directory(source, "source root")
    budget.admit_directory("")
    copy_directory_windows(source, destination, "", budget)


def copy_tree(
    source,
    destination,
    platform_model,
    *,
    max_files=MAX_FILES,
    max_directories=MAX_DIRECTORIES,
    max_file_bytes=MAX_FILE_BYTES,
    max_total_bytes=MAX_TOTAL_BYTES,
):
    source = pathlib.Path(os.path.abspath(os.fspath(source)))
    destination = pathlib.Path(
        os.path.abspath(os.fspath(destination))
    )
    if source == destination:
        raise SnapshotCopyError(
            "source and destination must differ"
        )
    require_plain_directory(source, "source root")
    require_empty_destination(destination)
    budget = CopyBudget(
        max_files=max_files,
        max_directories=max_directories,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
    )
    if platform_model == "linux":
        copy_tree_linux(source, destination, budget)
    elif platform_model == "windows":
        copy_tree_windows(source, destination, budget)
    else:
        raise SnapshotCopyError(
            f"unsupported platform model: {platform_model}"
        )
    return budget


def self_test():
    with tempfile.TemporaryDirectory(
        prefix="nxb-153-rust-copy-"
    ) as temporary:
        root = pathlib.Path(temporary)
        source = root / "source"
        destination = root / "destination"
        source.mkdir()
        destination.mkdir()
        (source / "bin").mkdir()
        tool = source / "bin" / "rustc"
        tool.write_bytes(b"rustc-bytes\n")
        if os.name != "nt":
            tool.chmod(0o755)
        (source / "lib").mkdir()
        (source / "lib" / "core.rlib").write_bytes(
            b"core-bytes\n"
        )

        model = "windows" if os.name == "nt" else "linux"
        budget = copy_tree(source, destination, model)
        if (
            budget.file_count != 2
            or budget.directory_count != 3
            or budget.total_bytes
            != len(b"rustc-bytes\ncore-bytes\n")
        ):
            raise SnapshotCopyError(
                "self-test normal copy accounting failed"
            )
        if (
            destination / "bin" / "rustc"
        ).read_bytes() != b"rustc-bytes\n":
            raise SnapshotCopyError(
                "self-test normal copy bytes differ"
            )

        bounded_source = root / "bounded-source"
        bounded_destination = root / "bounded-destination"
        bounded_source.mkdir()
        bounded_destination.mkdir()
        (bounded_source / "one").write_bytes(b"1")
        (bounded_source / "two").write_bytes(b"2")
        try:
            copy_tree(
                bounded_source,
                bounded_destination,
                model,
                max_files=1,
            )
        except SnapshotCopyError:
            pass
        else:
            raise SnapshotCopyError(
                "self-test file-count bound did not fail closed"
            )

        total_source = root / "total-source"
        total_destination = root / "total-destination"
        total_source.mkdir()
        total_destination.mkdir()
        (total_source / "one").write_bytes(b"1")
        (total_source / "two").write_bytes(b"2")
        try:
            copy_tree(
                total_source,
                total_destination,
                model,
                max_total_bytes=1,
            )
        except SnapshotCopyError:
            pass
        else:
            raise SnapshotCopyError(
                "self-test total-byte bound did not fail closed"
            )

        directory_source = root / "directory-source"
        directory_destination = root / "directory-destination"
        directory_source.mkdir()
        directory_destination.mkdir()
        (directory_source / "child").mkdir()
        (directory_source / "child" / "file").write_bytes(b"x")
        try:
            copy_tree(
                directory_source,
                directory_destination,
                model,
                max_directories=1,
            )
        except SnapshotCopyError:
            pass
        else:
            raise SnapshotCopyError(
                "self-test directory-count bound did not fail closed"
            )

        symlink_source = root / "symlink-source"
        symlink_destination = root / "symlink-destination"
        symlink_source.mkdir()
        symlink_destination.mkdir()
        (symlink_source / "real").write_bytes(b"trusted")
        try:
            os.symlink("real", symlink_source / "alias")
        except (OSError, NotImplementedError):
            pass
        else:
            try:
                copy_tree(
                    symlink_source,
                    symlink_destination,
                    model,
                )
            except SnapshotCopyError:
                pass
            else:
                raise SnapshotCopyError(
                    "self-test symlink copy was not rejected"
                )

    print(
        "NXB-153 bounded Rust toolchain snapshot-copy self-test passed."
    )


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(
        dest="command", required=True
    )
    subparsers.add_parser("self-test")
    copy_parser = subparsers.add_parser("copy")
    copy_parser.add_argument("source")
    copy_parser.add_argument("destination")
    copy_parser.add_argument(
        "--platform-model",
        choices=("linux", "windows"),
        required=True,
    )
    arguments = parser.parse_args()
    try:
        if arguments.command == "self-test":
            self_test()
            return
        budget = copy_tree(
            pathlib.Path(arguments.source),
            pathlib.Path(arguments.destination),
            arguments.platform_model,
        )
        print(budget.to_json(arguments.platform_model))
    except SnapshotCopyError as error:
        raise SystemExit(
            f"NXB-153 Rust snapshot copy failed: {error}"
        ) from error


if __name__ == "__main__":
    main()
