#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
evidence_directory="${2:-$repo_root/target/nxb-validation}"
expected_lock_sha256="f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"

cd "$repo_root"

fail() {
    printf 'NXB-150 evidence closure failed: %s\n' "$1" >&2
    exit 1
}

command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v python3 >/dev/null 2>&1 || fail 'python3 is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'

head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD could not be resolved'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || fail 'working tree must be clean before evidence review'
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

repo_root = pathlib.Path(sys.argv[1]).resolve()
evidence_directory = pathlib.Path(sys.argv[2]).resolve()
head_sha = sys.argv[3]
lock_sha256 = sys.argv[4]
expected_lock_sha256 = "f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"
expected_audit_version = "0.22.2"
expected_deny_version = "0.20.2"
maximum_evidence_bytes = 65536
expected_fields = {
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
    "cargo_lock_sha256",
    "lockfile_reproduced_without_diff",
    "package_fmt_check_clippy_tests",
    "vault_provider_regressions",
    "workspace_check_clippy_tests",
    "rustsec",
    "cargo_deny_checks",
    "process_fixture_serial",
    "network_activity",
    "validated_at",
}


def fail(message: str) -> None:
    raise SystemExit(f"NXB-150 evidence closure failed: {message}")


def is_lower_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_evidence(platform: str) -> dict[str, object]:
    path = evidence_directory / f"nxb-150-{platform}-{head_sha}.json"
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"missing {platform} evidence: {path}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{platform} evidence must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > maximum_evidence_bytes:
        fail(f"{platform} evidence size is invalid")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
        evidence = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{platform} evidence is invalid UTF-8 JSON: {error}")
    if not isinstance(evidence, dict):
        fail(f"{platform} evidence root must be an object")
    actual_fields = set(evidence)
    if actual_fields != expected_fields:
        missing = sorted(expected_fields - actual_fields)
        unknown = sorted(actual_fields - expected_fields)
        fail(f"{platform} evidence field mismatch; missing={missing}, unknown={unknown}")
    if (
        evidence["schema_version"] != 2
        or evidence["milestone"] != "NXB-150"
        or evidence["gate"] != "pinned_process_evidence_key_provider"
        or evidence["platform"] != platform
        or evidence["head_sha"] != head_sha
    ):
        fail(f"{platform} evidence identity does not match the closure contract")
    if not isinstance(evidence["rustc"], str) or not evidence["rustc"].startswith("rustc 1.97.1 "):
        fail(f"{platform} evidence reports an unsupported Rust toolchain")
    if not isinstance(evidence["cargo"], str) or not evidence["cargo"].startswith("cargo "):
        fail(f"{platform} evidence reports an invalid Cargo version")
    if expected_audit_version not in str(evidence["cargo_audit"]).split():
        fail(f"{platform} evidence reports an unsupported cargo-audit version")
    if expected_deny_version not in str(evidence["cargo_deny"]).split():
        fail(f"{platform} evidence reports an unsupported cargo-deny version")
    for field in ("cargo_audit_sha256", "cargo_deny_sha256", "cargo_lock_sha256"):
        if not is_lower_sha256(evidence[field]):
            fail(f"{platform} evidence field {field} is not a lowercase SHA-256")
    if (
        evidence["cargo_lock_sha256"] != expected_lock_sha256
        or evidence["lockfile_reproduced_without_diff"] is not True
        or evidence["package_fmt_check_clippy_tests"] != "passed"
        or evidence["vault_provider_regressions"] != "passed"
        or evidence["workspace_check_clippy_tests"] != "passed"
        or evidence["rustsec"] != "passed"
        or evidence["cargo_deny_checks"] != "passed"
        or evidence["process_fixture_serial"] is not True
        or evidence["network_activity"] != "dependency_and_advisory_sources_only"
    ):
        fail(f"{platform} evidence contains a failed or unsupported gate value")
    try:
        parsed = dt.datetime.strptime(str(evidence["validated_at"]), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        fail(f"{platform} evidence validated_at is not canonical UTC: {error}")
    parsed = parsed.replace(tzinfo=dt.timezone.utc)
    if parsed > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        fail(f"{platform} evidence validated_at is unreasonably in the future")
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
        "cargo_lock_sha256": evidence["cargo_lock_sha256"],
    }


linux = read_evidence("linux")
windows = read_evidence("windows")
for field in ("rustc", "cargo", "cargo_audit", "cargo_deny", "cargo_lock_sha256"):
    if linux[field] != windows[field]:
        fail(f"Linux and Windows evidence disagree on {field}")

closure = {
    "schema_version": 1,
    "milestone": "NXB-150",
    "gate": "dual_platform_evidence_closure",
    "status": "ready_for_manual_pr_review",
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
        "package_and_workspace_gates": "passed",
        "rustsec": "passed",
        "cargo_deny": "passed",
        "serial_process_fixture": "passed",
    },
    "network_activity": "none",
}
bytes_value = (json.dumps(closure, indent=2, sort_keys=False) + "\n").encode("utf-8")
evidence_directory.mkdir(parents=True, exist_ok=True)
closure_path = evidence_directory / f"nxb-150-closure-{head_sha}.json"
if closure_path.exists():
    if closure_path.read_bytes() != bytes_value:
        fail("existing closure evidence differs from the deterministic review result")
else:
    pending_path = closure_path.with_suffix(closure_path.suffix + ".pending")
    if pending_path.exists():
        pending_path.unlink()
    pending_path.write_bytes(bytes_value)
    os.replace(pending_path, closure_path)

print("NXB-150 dual-platform evidence closure passed.")
print(f"HEAD: {head_sha}")
print(f"Cargo.lock SHA-256: {lock_sha256}")
print(f"Closure: {closure_path}")
PY
