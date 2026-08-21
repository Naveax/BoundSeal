#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
evidence_directory="${2:-$repo_root/target/nxb-validation}"
expected_lock_sha256="f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"

cd "$repo_root"

fail() {
    printf 'NXB-153 evidence closure failed: %s\n' "$1" >&2
    exit 1
}

command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v python3 >/dev/null 2>&1 || fail 'python3 is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'

head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD could not be resolved'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree must be clean before evidence review'
[[ -f Cargo.lock ]] || fail 'Cargo.lock is missing'
lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
[[ "$lock_sha256" == "$expected_lock_sha256" ]] ||
    fail "Cargo.lock SHA-256 mismatch: expected $expected_lock_sha256, found $lock_sha256"

python3 - "$repo_root" "$evidence_directory" "$head_sha" "$lock_sha256" <<'PY'
import datetime as dt
import hashlib
import json
import os
import pathlib
import stat
import sys

repo_root = pathlib.Path(sys.argv[1]).resolve(strict=True)
requested = pathlib.Path(sys.argv[2])
if not requested.is_absolute():
    requested = repo_root / requested
evidence_directory = requested.absolute()
head_sha = sys.argv[3]
lock_sha256 = sys.argv[4]
expected_lock_sha256 = "f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"
expected_audit_version = "0.22.2"
expected_deny_version = "0.20.2"
maximum_bytes = 65536
expected_evidence_fields = {
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
expected_receipt_fields = {
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


def fail(message: str) -> None:
    raise SystemExit(f"NXB-153 evidence closure failed: {message}")


def is_lower_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def assert_no_symlink_components(path: pathlib.Path, label: str) -> None:
    absolute = path.absolute()
    current = pathlib.Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"{label} contains a symbolic-link component: {current}")


def require_regular(path: pathlib.Path, label: str) -> os.stat_result:
    assert_no_symlink_components(path, label)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"missing {label}: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
        fail(f"{label} size is invalid")
    return metadata


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: pathlib.Path, label: str) -> dict[str, object]:
    require_regular(path, label)
    try:
        value = json.loads(path.read_bytes().decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is invalid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} root must be an object")
    return value


def canonical_utc(value: object, label: str) -> str:
    if not isinstance(value, str):
        fail(f"{label} must be a string")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        fail(f"{label} is not canonical UTC: {error}")
    if parsed > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        fail(f"{label} is unreasonably in the future")
    return value


def read_receipt(platform: str, evidence: dict[str, object]) -> dict[str, object]:
    expected_relative = f"target/nxb-validation/nxb-153-tooling-{platform}-{head_sha}.json"
    if evidence["tooling_receipt"] != expected_relative:
        fail(f"{platform} evidence tooling receipt path is not canonical")
    path = evidence_directory / f"nxb-153-tooling-{platform}-{head_sha}.json"
    receipt = read_json(path, f"{platform} tooling receipt")
    if set(receipt) != expected_receipt_fields:
        fail(f"{platform} tooling receipt field mismatch")
    if (
        receipt["schema_version"] != 1
        or receipt["milestone"] != "NXB-153"
        or receipt["gate"] != "validation_tool_bootstrap"
        or receipt["platform"] != platform
        or receipt["head_sha"] != head_sha
        or receipt["tools_root"] != "target/nxb-tools"
        or receipt["network_activity"] != "rustup_and_crates_io_tool_installation_only"
    ):
        fail(f"{platform} tooling receipt identity is invalid")
    if receipt["rust_toolchain"] != evidence["rustc"]:
        fail(f"{platform} tooling receipt Rust version differs from validation evidence")
    for field in ("cargo_audit", "cargo_audit_sha256", "cargo_deny", "cargo_deny_sha256"):
        if receipt[field] != evidence[field]:
            fail(f"{platform} tooling receipt differs from evidence on {field}")
    if sha256_file(path) != evidence["tooling_receipt_sha256"]:
        fail(f"{platform} tooling receipt SHA-256 does not match evidence")
    canonical_utc(receipt["prepared_at"], f"{platform} tooling receipt prepared_at")
    return receipt


def read_evidence(platform: str) -> dict[str, object]:
    path = evidence_directory / f"nxb-153-{platform}-{head_sha}.json"
    evidence = read_json(path, f"{platform} validation evidence")
    if set(evidence) != expected_evidence_fields:
        missing = sorted(expected_evidence_fields - set(evidence))
        unknown = sorted(set(evidence) - expected_evidence_fields)
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
    if expected_audit_version not in str(evidence["cargo_audit"]).split():
        fail(f"{platform} evidence reports unsupported cargo-audit")
    if expected_deny_version not in str(evidence["cargo_deny"]).split():
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
        evidence["cargo_lock_sha256"] != expected_lock_sha256
        or evidence["cargo_lock_expected_sha256"] != expected_lock_sha256
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
    read_receipt(platform, evidence)
    return {
        "platform": platform,
        "file_name": path.name,
        "evidence_sha256": sha256_file(path),
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


assert_no_symlink_components(evidence_directory, "evidence directory")
if evidence_directory.exists():
    metadata = evidence_directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("evidence directory must be a regular non-symlink directory")
else:
    evidence_directory.mkdir(parents=True, mode=0o700)

linux = read_evidence("linux")
windows = read_evidence("windows")
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
bytes_value = (json.dumps(closure, indent=2) + "\n").encode("utf-8")
closure_path = evidence_directory / f"nxb-153-closure-{head_sha}.json"
pending_path = closure_path.with_suffix(closure_path.suffix + ".pending")

assert_no_symlink_components(closure_path, "closure evidence")
if closure_path.exists():
    existing = read_json(closure_path, "existing closure evidence")
    if existing != closure:
        fail("existing closure evidence differs from deterministic review result")
else:
    assert_no_symlink_components(pending_path, "pending closure evidence")
    if pending_path.exists():
        fail("pending closure evidence already exists; manual recovery is required")
    descriptor = os.open(pending_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(bytes_value)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            pending_path.unlink()
        except FileNotFoundError:
            pass
        raise
    os.replace(pending_path, closure_path)
    directory_fd = os.open(evidence_directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)

print("NXB-153 dual-platform evidence closure passed.")
print("Admission remains blocker_review_required.")
print(f"HEAD: {head_sha}")
print(f"Cargo.lock SHA-256: {lock_sha256}")
print(f"Closure: {closure_path}")
PY
