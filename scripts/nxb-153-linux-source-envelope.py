#!/usr/bin/env python3
"""Bound exact-head Linux source/tree/archive availability for NXB-153."""

from __future__ import annotations

import io
import json
import sys
from typing import BinaryIO

POLICY = "nxb-153-linux-source-envelope-v1"
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_TREE_RECORDS = 8192
MAX_TRACKED_FILES = 4096
MAX_TRACKED_DIRECTORIES = 4096
MAX_TRACKED_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_RECORD_BYTES = 8192
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
READ_CHUNK = 64 * 1024
HEX = frozenset(b"0123456789abcdef")
RESERVED_ROOTS = frozenset(
    {
        b"target",
        b".nxb-153-tmp",
        b".nxb-153-fetch-home",
        b".nxb-153-vendor",
        b".nxb-153-cargo-home",
        b".nxb-153-config",
    }
)


class EnvelopeError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise EnvelopeError(message)


def is_lower_hex_sha1(value: bytes) -> bool:
    return len(value) == 40 and all(byte in HEX for byte in value)


def iter_nul_records(
    stream: BinaryIO,
    *,
    max_manifest_bytes: int = MAX_MANIFEST_BYTES,
    max_record_bytes: int = MAX_RECORD_BYTES,
):
    buffered = bytearray()
    total = 0
    while True:
        chunk = stream.read(READ_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > max_manifest_bytes:
            fail(f"Git tree manifest exceeds {max_manifest_bytes} bytes")
        buffered.extend(chunk)
        while True:
            offset = buffered.find(b"\0")
            if offset < 0:
                if len(buffered) > max_record_bytes:
                    fail(f"Git tree record exceeds {max_record_bytes} bytes")
                break
            if offset > max_record_bytes:
                fail(f"Git tree record exceeds {max_record_bytes} bytes")
            record = bytes(buffered[:offset])
            del buffered[: offset + 1]
            if not record:
                fail("Git tree manifest contains an empty record")
            yield record, total
    if buffered:
        fail("Git tree manifest is not NUL-terminated")


def validate_tree_stream(
    stream: BinaryIO,
    *,
    max_manifest_bytes: int = MAX_MANIFEST_BYTES,
    max_tree_records: int = MAX_TREE_RECORDS,
    max_files: int = MAX_TRACKED_FILES,
    max_directories: int = MAX_TRACKED_DIRECTORIES,
    max_tracked_bytes: int = MAX_TRACKED_BYTES,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_path_bytes: int = MAX_PATH_BYTES,
    max_record_bytes: int = MAX_RECORD_BYTES,
) -> dict[str, int | str]:
    records = 0
    files = 0
    directories = 0
    tracked_bytes = 0
    manifest_bytes = 0
    seen_paths: set[bytes] = set()

    for record, observed_manifest_bytes in iter_nul_records(
        stream,
        max_manifest_bytes=max_manifest_bytes,
        max_record_bytes=max_record_bytes,
    ):
        manifest_bytes = observed_manifest_bytes
        records += 1
        if records > max_tree_records:
            fail(f"Git tree contains more than {max_tree_records} entries")

        try:
            metadata, path = record.split(b"\t", 1)
        except ValueError:
            fail("Git tree record is missing its pathname separator")
        fields = metadata.split()
        if len(fields) != 4:
            fail("Git tree record metadata does not contain mode/type/object/size")
        mode, object_type, object_id, size_field = fields
        if not is_lower_hex_sha1(object_id):
            fail("Git tree record contains a non-canonical object id")

        if not path or len(path) > max_path_bytes or path.startswith(b"/"):
            fail(f"Git tree pathname is outside the {max_path_bytes}-byte relative-path envelope")
        components = path.split(b"/")
        if any(component in (b"", b".", b"..") for component in components):
            fail("Git tree pathname contains an ambiguous component")
        if components[0] in RESERVED_ROOTS:
            fail("Git tree collides with a reserved validation runtime root")
        if path in seen_paths:
            fail("Git tree contains a duplicate full pathname")
        seen_paths.add(path)

        if mode == b"040000" and object_type == b"tree" and size_field == b"-":
            directories += 1
            if directories > max_directories:
                fail(f"Git tree contains more than {max_directories} directories")
            continue

        if mode not in (b"100644", b"100755") or object_type != b"blob":
            fail(f"unsupported Git source entry mode/type: {mode!r}/{object_type!r}")
        if not size_field.isdigit():
            fail("Git blob size is not canonical decimal")
        size = int(size_field, 10)
        if size > max_file_bytes:
            fail(f"Git blob exceeds the {max_file_bytes}-byte per-file envelope")
        files += 1
        if files > max_files:
            fail(f"Git tree contains more than {max_files} tracked files")
        tracked_bytes += size
        if tracked_bytes > max_tracked_bytes:
            fail(f"Git tracked bytes exceed {max_tracked_bytes}")

    if records == 0 or files == 0:
        fail("Git tree envelope is empty")
    return {
        "policy": POLICY,
        "manifest_bytes": manifest_bytes,
        "tree_records": records,
        "tracked_files": files,
        "tracked_directories": directories,
        "tracked_bytes": tracked_bytes,
        "archive_byte_limit": MAX_ARCHIVE_BYTES,
    }


def validate_archive_stream(
    stream: BinaryIO,
    *,
    max_archive_bytes: int = MAX_ARCHIVE_BYTES,
) -> dict[str, int | str]:
    total = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_archive_bytes:
            fail(f"Git archive exceeds {max_archive_bytes} bytes")
    if total <= 0:
        fail("Git archive is empty")
    if total % 512 != 0:
        fail("Git archive size is not aligned to a 512-byte tar block")
    return {"policy": POLICY, "archive_bytes": total, "archive_byte_limit": max_archive_bytes}


def tree_record(mode: bytes, kind: bytes, object_id: bytes, size: bytes, path: bytes) -> bytes:
    return b" ".join((mode, kind, object_id, size)) + b"\t" + path + b"\0"


def expect_rejected(function, *args, **kwargs) -> None:
    try:
        function(*args, **kwargs)
    except EnvelopeError:
        return
    fail("self-test expected rejection but validation succeeded")


def self_test() -> None:
    oid = b"0" * 40
    valid = b"".join(
        (
            tree_record(b"040000", b"tree", oid, b"-", b"src"),
            tree_record(b"100644", b"blob", oid, b"2", b"src/lib.rs"),
            tree_record(b"100755", b"blob", oid, b"1", b"tool.sh"),
        )
    )
    summary = validate_tree_stream(io.BytesIO(valid))
    if summary["tracked_files"] != 2 or summary["tracked_directories"] != 1 or summary["tracked_bytes"] != 3:
        fail("self-test valid tree returned incorrect accounting")

    expect_rejected(
        validate_tree_stream,
        io.BytesIO(valid),
        max_files=1,
    )
    expect_rejected(
        validate_tree_stream,
        io.BytesIO(valid),
        max_directories=0,
    )
    expect_rejected(
        validate_tree_stream,
        io.BytesIO(valid),
        max_tracked_bytes=2,
    )
    expect_rejected(
        validate_tree_stream,
        io.BytesIO(tree_record(b"120000", b"blob", oid, b"1", b"link")),
    )
    expect_rejected(
        validate_tree_stream,
        io.BytesIO(tree_record(b"100644", b"blob", oid, b"1", b"abcd")),
        max_path_bytes=3,
    )
    expect_rejected(
        validate_tree_stream,
        io.BytesIO(tree_record(b"100644", b"blob", oid, b"1", b"target/file")),
    )

    archive = b"\0" * 1024
    archive_summary = validate_archive_stream(io.BytesIO(archive), max_archive_bytes=2048)
    if archive_summary["archive_bytes"] != 1024:
        fail("self-test archive accounting is incorrect")
    expect_rejected(validate_archive_stream, io.BytesIO(b""), max_archive_bytes=2048)
    expect_rejected(validate_archive_stream, io.BytesIO(b"\0" * 1536), max_archive_bytes=1024)
    expect_rejected(validate_archive_stream, io.BytesIO(b"\0" * 513), max_archive_bytes=2048)

    print("NXB-153 Linux source-envelope self-test passed.")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        fail("exactly one mode is required")
    mode = argv[1]
    if mode == "self-test":
        self_test()
    elif mode == "validate-tree":
        print(json.dumps(validate_tree_stream(sys.stdin.buffer), sort_keys=True, separators=(",", ":")))
    elif mode == "validate-archive":
        print(json.dumps(validate_archive_stream(sys.stdin.buffer), sort_keys=True, separators=(",", ":")))
    else:
        fail(f"unknown mode: {mode}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except EnvelopeError as error:
        print(f"NXB-153 Linux source envelope failed: {error}", file=sys.stderr)
        raise SystemExit(1)
