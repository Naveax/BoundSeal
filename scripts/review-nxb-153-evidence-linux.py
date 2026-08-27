#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
from typing import Any

EXPECTED_LOCK_SHA256 = "f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"
EXPECTED_AUDIT_VERSION = "0.22.2"
EXPECTED_DENY_VERSION = "0.20.2"
MAXIMUM_BYTES = 65536
EXPECTED_EVIDENCE_FIELDS = {
    "schema_version",
    "milestone",
    "gate",
    "platform",
    "head_sha",
    "rustc",
    "cargo",
    "cargo_audit",
    "cargo_audit_sha256",
    "cargo_deny",
    "cargo_deny_sha256",
    "tooling_receipt",
    "tooling_receipt_sha256",
    "tooling_receipt_verified",
    "cargo_lock_sha256",
    "cargo_lock_expected_sha256",
    "lockfile_pinned_and_unchanged",
    "fmt",
    "nxb_policy_check_clippy_tests",
    "nxb_core_check_clippy_unit_tests",
    "focused_target_tests",
    "workspace_check_clippy_tests_all_features",
    "rustsec",
    "cargo_deny_checks",
    "test_threads",
    "network_activity",
    "validated_at",
}
EXPECTED_RECEIPT_FIELDS = {
    "schema_version",
    "milestone",
    "gate",
    "platform",
    "head_sha",
    "rust_toolchain",
    "cargo_audit",
    "cargo_audit_sha256",
    "cargo_deny",
    "cargo_deny_sha256",
    "tools_root",
    "network_activity",
    "prepared_at",
}


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"NXB-153 evidence closure failed: {message}")


def run_git(repo_root: pathlib.Path, *arguments: str) -> str:
    try:
        process = subprocess.run(
            ["git", *arguments],
            cwd=repo_root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
    except FileNotFoundError:
        fail("git is unavailable")
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        fail(f"git {' '.join(arguments)} failed: {detail}")
    return process.stdout.strip()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_lower_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def absolute_without_resolution(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def assert_no_indirection_components(path: pathlib.Path, label: str) -> None:
    absolute = absolute_without_resolution(path)
    parts = absolute.parts
    if not parts:
        fail(f"{label} has no filesystem components")

    current = pathlib.Path(parts[0])
    for part in parts[1:]:
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode) or is_reparse(metadata):
            fail(f"{label} contains a symbolic-link or reparse-point component: {current}")


def require_regular(path: pathlib.Path, label: str) -> os.stat_result:
    assert_no_indirection_components(path, label)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        fail(f"missing {label}: {path}")
    if stat.S_ISLNK(metadata.st_mode) or is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a regular non-indirection file")
    if metadata.st_size <= 0 or metadata.st_size > MAXIMUM_BYTES:
        fail(f"{label} size is invalid")
    return metadata


def read_bytes(path: pathlib.Path, label: str) -> bytes:
    metadata = require_regular(path, label)
    with path.open("rb") as handle:
        value = handle.read(MAXIMUM_BYTES + 1)
    if len(value) != metadata.st_size or len(value) > MAXIMUM_BYTES:
        fail(f"{label} changed size while being read")
    return value


def read_json(path: pathlib.Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = read_bytes(path, label)
    try:
        decoded = raw.decode("utf-8", errors="strict")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is invalid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} root must be an object")
    return value, raw


def canonical_utc(value: object, label: str) -> str:
    if not isinstance(value, str):
        fail(f"{label} must be a string")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as error:
        fail(f"{label} is not canonical UTC: {error}")
    if parsed > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        fail(f"{label} is unreasonably in the future")
    return value


def token_has_version(value: object, expected: str) -> bool:
    return isinstance(value, str) and expected in value.split()


def read_receipt(
    evidence_directory: pathlib.Path,
    platform: str,
    head_sha: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    expected_relative = f"target/nxb-validation/nxb-153-tooling-{platform}-{head_sha}.json"
    if evidence["tooling_receipt"] != expected_relative:
        fail(f"{platform} evidence tooling receipt path is not canonical")

    path = evidence_directory / f"nxb-153-tooling-{platform}-{head_sha}.json"
    receipt, raw = read_json(path, f"{platform} tooling receipt")
    if set(receipt) != EXPECTED_RECEIPT_FIELDS:
        fail(f"{platform} tooling receipt field mismatch")
    expected_tools_root = f"target/nxb-tools/{platform}/{head_sha}"
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or receipt["milestone"] != "NXB-153"
        or receipt["gate"] != "validation_tool_bootstrap"
        or receipt["platform"] != platform
        or receipt["head_sha"] != head_sha
        or receipt["tools_root"] != expected_tools_root
        or receipt["network_activity"] != "rustup_and_crates_io_tool_installation_only"
    ):
        fail(f"{platform} tooling receipt identity is invalid")
    if receipt["rust_toolchain"] != evidence["rustc"]:
        fail(f"{platform} tooling receipt Rust version differs from validation evidence")
    for field in ("cargo_audit", "cargo_audit_sha256", "cargo_deny", "cargo_deny_sha256"):
        if receipt[field] != evidence[field]:
            fail(f"{platform} tooling receipt differs from evidence on {field}")
    for field in ("cargo_audit_sha256", "cargo_deny_sha256"):
        if not is_lower_sha256(receipt[field]):
            fail(f"{platform} tooling receipt {field} is not a lowercase SHA-256")
    if sha256_bytes(raw) != evidence["tooling_receipt_sha256"]:
        fail(f"{platform} tooling receipt SHA-256 does not match evidence")
    canonical_utc(receipt["prepared_at"], f"{platform} tooling receipt prepared_at")
    return receipt


def read_evidence(
    evidence_directory: pathlib.Path,
    platform: str,
    head_sha: str,
) -> dict[str, Any]:
    path = evidence_directory / f"nxb-153-{platform}-{head_sha}.json"
    evidence, raw = read_json(path, f"{platform} validation evidence")
    if set(evidence) != EXPECTED_EVIDENCE_FIELDS:
        missing = sorted(EXPECTED_EVIDENCE_FIELDS - set(evidence))
        unknown = sorted(set(evidence) - EXPECTED_EVIDENCE_FIELDS)
        fail(f"{platform} evidence field mismatch; missing={missing}, unknown={unknown}")
    if type(evidence["schema_version"]) is not int or type(evidence["test_threads"]) is not int:
        fail(f"{platform} evidence integer fields are invalid")
    for field in ("tooling_receipt_verified", "lockfile_pinned_and_unchanged"):
        if type(evidence[field]) is not bool:
            fail(f"{platform} evidence field {field} must be boolean")
    if (
        evidence["schema_version"] != 1
        or evidence["milestone"] != "NXB-153"
        or evidence["gate"] != "guided_target_authorization_setup"
        or evidence["platform"] != platform
        or evidence["head_sha"] != head_sha
        or evidence["test_threads"] != 1
    ):
        fail(f"{platform} evidence identity does not match NXB-153 closure")
    if not isinstance(evidence["rustc"], str) or not evidence["rustc"].startswith("rustc 1.97.1 "):
        fail(f"{platform} evidence reports an unsupported Rust toolchain")
    if not isinstance(evidence["cargo"], str) or not evidence["cargo"].startswith("cargo "):
        fail(f"{platform} evidence reports an invalid Cargo version")
    if not token_has_version(evidence["cargo_audit"], EXPECTED_AUDIT_VERSION):
        fail(f"{platform} evidence reports unsupported cargo-audit")
    if not token_has_version(evidence["cargo_deny"], EXPECTED_DENY_VERSION):
        fail(f"{platform} evidence reports unsupported cargo-deny")
    for field in (
        "cargo_audit_sha256",
        "cargo_deny_sha256",
        "tooling_receipt_sha256",
        "cargo_lock_sha256",
        "cargo_lock_expected_sha256",
    ):
        if not is_lower_sha256(evidence[field]):
            fail(f"{platform} evidence field {field} is not a lowercase SHA-256")
    if (
        evidence["cargo_lock_sha256"] != EXPECTED_LOCK_SHA256
        or evidence["cargo_lock_expected_sha256"] != EXPECTED_LOCK_SHA256
        or evidence["tooling_receipt_verified"] is not True
        or evidence["lockfile_pinned_and_unchanged"] is not True
        or evidence["fmt"] != "passed"
        or evidence["nxb_policy_check_clippy_tests"] != "passed"
        or evidence["nxb_core_check_clippy_unit_tests"] != "passed"
        or evidence["focused_target_tests"] != "passed"
        or evidence["workspace_check_clippy_tests_all_features"] != "passed"
        or evidence["rustsec"] != "passed"
        or evidence["cargo_deny_checks"] != "passed"
        or evidence["network_activity"] != "cargo_dependency_and_advisory_sources_only"
    ):
        fail(f"{platform} evidence contains a failed or unsupported gate value")
    canonical_utc(evidence["validated_at"], f"{platform} validated_at")
    read_receipt(evidence_directory, platform, head_sha, evidence)
    return {
        "platform": platform,
        "file_name": path.name,
        "evidence_sha256": sha256_bytes(raw),
        "validated_at": evidence["validated_at"],
        "rustc": evidence["rustc"],
        "cargo": evidence["cargo"],
        "cargo_audit": evidence["cargo_audit"],
        "cargo_audit_sha256": evidence["cargo_audit_sha256"],
        "cargo_deny": evidence["cargo_deny"],
        "cargo_deny_sha256": evidence["cargo_deny_sha256"],
        "tooling_receipt_sha256": evidence["tooling_receipt_sha256"],
        "cargo_lock_sha256": evidence["cargo_lock_sha256"],
    }


def fsync_directory(path: pathlib.Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_closure_create_only(path: pathlib.Path, value: dict[str, Any]) -> None:
    canonical = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    assert_no_indirection_components(path, "closure evidence")

    if path.exists():
        existing, _ = read_json(path, "existing closure evidence")
        if existing != value:
            fail("existing closure evidence differs from deterministic review result")
        return

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        existing, _ = read_json(path, "racing closure evidence")
        if existing != value:
            fail("racing closure evidence differs from deterministic review result")
        return

    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(canonical)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        # The create-new destination may now be partially visible. Do not delete it by path:
        # a later reviewer must inspect/recover that explicit state.
        raise

    fsync_directory(path.parent)
    persisted = read_bytes(path, "published closure evidence")
    if persisted != canonical:
        fail("published closure evidence bytes differ from deterministic canonical review result")


def main() -> None:
    script_path = pathlib.Path(__file__).absolute()
    default_root = script_path.parent.parent
    repo_root = absolute_without_resolution(
        pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else default_root
    )
    evidence_directory = absolute_without_resolution(
        pathlib.Path(sys.argv[2])
        if len(sys.argv) > 2
        else repo_root / "target" / "nxb-validation"
    )
    if len(sys.argv) > 3:
        fail("usage: review-nxb-153-evidence-linux.py [repo-root] [evidence-directory]")

    assert_no_indirection_components(repo_root, "repository root")
    try:
        repo_metadata = os.lstat(repo_root)
    except FileNotFoundError:
        fail(f"repository root is missing: {repo_root}")
    if (
        stat.S_ISLNK(repo_metadata.st_mode)
        or is_reparse(repo_metadata)
        or not stat.S_ISDIR(repo_metadata.st_mode)
    ):
        fail("repository root must be a normal non-indirection directory")

    head_sha = run_git(repo_root, "rev-parse", "HEAD")
    if len(head_sha) != 40 or any(character not in "0123456789abcdef" for character in head_sha):
        fail("exact Git HEAD could not be resolved")
    if run_git(repo_root, "status", "--porcelain=v1", "--untracked-files=all"):
        fail("working tree must be clean before evidence review")

    lock_path = repo_root / "Cargo.lock"
    require_regular(lock_path, "Cargo.lock")
    lock_sha256 = sha256_file(lock_path)
    if lock_sha256 != EXPECTED_LOCK_SHA256:
        fail(
            "Cargo.lock SHA-256 mismatch: "
            f"expected {EXPECTED_LOCK_SHA256}, found {lock_sha256}"
        )

    assert_no_indirection_components(evidence_directory, "evidence directory")
    if evidence_directory.exists():
        metadata = os.lstat(evidence_directory)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or is_reparse(metadata)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            fail("evidence directory must be a normal non-indirection directory")
    else:
        evidence_directory.mkdir(parents=True, mode=0o700)
        assert_no_indirection_components(evidence_directory, "evidence directory")

    linux = read_evidence(evidence_directory, "linux", head_sha)
    windows = read_evidence(evidence_directory, "windows", head_sha)
    for field in ("rustc", "cargo", "cargo_audit", "cargo_deny", "cargo_lock_sha256"):
        if linux[field] != windows[field]:
            fail(f"Linux and Windows evidence disagree on {field}")

    closure = {
        "schema_version": 1,
        "milestone": "NXB-153",
        "gate": "dual_platform_evidence_closure",
        "status": "dual_platform_validation_passed",
        "admission": "blocker_review_required",
        "head_sha": head_sha,
        "cargo_lock_sha256": lock_sha256,
        "rustc": windows["rustc"],
        "cargo": windows["cargo"],
        "cargo_audit": windows["cargo_audit"],
        "cargo_deny": windows["cargo_deny"],
        "platforms": ["linux", "windows"],
        "evidence": [linux, windows],
        "requirements": {
            "same_exact_head": "passed",
            "canonical_lockfile": "passed",
            "fresh_tool_bootstrap_receipts": "passed",
            "package_and_workspace_gates": "passed",
            "focused_nxb153_tests": "passed",
            "rustsec": "passed",
            "cargo_deny": "passed",
        },
        "network_activity": "none",
    }
    closure_path = evidence_directory / f"nxb-153-closure-{head_sha}.json"
    publish_closure_create_only(closure_path, closure)

    print("NXB-153 dual-platform evidence closure passed.")
    print("Admission remains blocker_review_required.")
    print(f"HEAD: {head_sha}")
    print(f"Cargo.lock SHA-256: {lock_sha256}")
    print(f"Closure: {closure_path}")


if __name__ == "__main__":
    main()
