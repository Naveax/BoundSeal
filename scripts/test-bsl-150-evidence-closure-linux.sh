#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
closure_source="$repo_root/scripts/review-bsl-150-evidence-linux.sh"
expected_lock_sha256="f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"

fail() {
    printf 'BSL-150 closure self-test failed: %s\n' "$1" >&2
    exit 1
}

command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v python3 >/dev/null 2>&1 || fail 'python3 is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'
[[ -f "$closure_source" ]] || fail "closure source is missing: $closure_source"
[[ -f "$repo_root/Cargo.lock" ]] || fail 'Cargo.lock is missing'
actual_lock_sha256="$(sha256sum "$repo_root/Cargo.lock" | awk '{print $1}')"
[[ "$actual_lock_sha256" == "$expected_lock_sha256" ]] ||
    fail "Cargo.lock SHA-256 mismatch: expected $expected_lock_sha256, found $actual_lock_sha256"

sandbox="$(mktemp -d)"
trap 'rm -rf "$sandbox"' EXIT
fixture_repo="$sandbox/repository"
evidence_directory="$sandbox/evidence"
mkdir -p "$fixture_repo/scripts" "$evidence_directory"
cp "$repo_root/Cargo.lock" "$fixture_repo/Cargo.lock"
cp "$closure_source" "$fixture_repo/scripts/review-bsl-150-evidence-linux.sh"
chmod +x "$fixture_repo/scripts/review-bsl-150-evidence-linux.sh"

git -C "$fixture_repo" init -q
git -C "$fixture_repo" config user.name 'BSL Closure Self-Test'
git -C "$fixture_repo" config user.email 'bsl-closure-self-test@example.invalid'
git -C "$fixture_repo" add Cargo.lock scripts/review-bsl-150-evidence-linux.sh
git -C "$fixture_repo" commit -qm 'Create BSL-150 closure fixture'
head_sha="$(git -C "$fixture_repo" rev-parse HEAD)"
closure_path="$evidence_directory/bsl-150-closure-$head_sha.json"
pending_path="$closure_path.pending"

write_valid_evidence() {
    rm -rf "$evidence_directory"
    mkdir -p "$evidence_directory"
    python3 - "$evidence_directory" "$head_sha" "$expected_lock_sha256" <<'PY'
import datetime as dt
import json
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
head_sha = sys.argv[2]
lock_sha256 = sys.argv[3]
validated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
for platform, audit_marker, deny_marker in (
    ("linux", "1", "3"),
    ("windows", "2", "4"),
):
    evidence = {
        "schema_version": 2,
        "milestone": "BSL-150",
        "gate": "pinned_process_evidence_key_provider",
        "platform": platform,
        "head_sha": head_sha,
        "rustc": "rustc 1.97.1 (fixture 2026-08-01)",
        "cargo": "cargo 1.97.1 (fixture 2026-08-01)",
        "cargo_audit": "cargo-audit 0.22.2",
        "cargo_audit_sha256": audit_marker * 64,
        "cargo_deny": "cargo-deny 0.20.2",
        "cargo_deny_sha256": deny_marker * 64,
        "cargo_lock_sha256": lock_sha256,
        "lockfile_reproduced_without_diff": True,
        "package_fmt_check_clippy_tests": "passed",
        "vault_provider_regressions": "passed",
        "workspace_check_clippy_tests": "passed",
        "rustsec": "passed",
        "cargo_deny_checks": "passed",
        "process_fixture_serial": True,
        "network_activity": "dependency_and_advisory_sources_only",
        "validated_at": validated_at,
    }
    path = directory / f"bsl-150-{platform}-{head_sha}.json"
    path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
PY
}

mutate_evidence() {
    local platform="$1"
    local operation="$2"
    python3 - "$evidence_directory/bsl-150-$platform-$head_sha.json" "$operation" <<'PY'
import datetime as dt
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
operation = sys.argv[2]
evidence = json.loads(path.read_text(encoding="utf-8"))
if operation == "mixed-head":
    evidence["head_sha"] = "0" * 40
elif operation == "unknown-field":
    evidence["unexpected"] = "blocked"
elif operation == "wrong-type":
    evidence["process_fixture_serial"] = "true"
elif operation == "future-time":
    evidence["validated_at"] = (
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
elif operation == "failed-gate":
    evidence["rustsec"] = "failed"
else:
    raise SystemExit(f"unknown mutation: {operation}")
path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
PY
}

run_closure() {
    bash "$fixture_repo/scripts/review-bsl-150-evidence-linux.sh" \
        "$fixture_repo" \
        "$evidence_directory"
}

run_closure_with_directory() {
    local directory="$1"
    bash "$fixture_repo/scripts/review-bsl-150-evidence-linux.sh" \
        "$fixture_repo" \
        "$directory"
}

expect_failure() {
    local label="$1"
    shift
    if "$@" >"$sandbox/$label.stdout" 2>"$sandbox/$label.stderr"; then
        fail "$label unexpectedly passed"
    fi
}

write_valid_evidence
run_closure >/dev/null
first_closure_sha256="$(sha256sum "$closure_path" | awk '{print $1}')"
run_closure >/dev/null
second_closure_sha256="$(sha256sum "$closure_path" | awk '{print $1}')"
[[ "$first_closure_sha256" == "$second_closure_sha256" ]] ||
    fail 'idempotent closure output changed'

for operation in mixed-head unknown-field wrong-type future-time failed-gate; do
    write_valid_evidence
    mutate_evidence windows "$operation"
    expect_failure "$operation" run_closure
done

write_valid_evidence
linux_path="$evidence_directory/bsl-150-linux-$head_sha.json"
mv "$linux_path" "$linux_path.real"
ln -s "$(basename "$linux_path.real")" "$linux_path"
expect_failure evidence-symlink run_closure

write_valid_evidence
real_evidence_directory="$sandbox/evidence-real"
mv "$evidence_directory" "$real_evidence_directory"
ln -s "$(basename "$real_evidence_directory")" "$evidence_directory"
expect_failure evidence-directory-symlink run_closure_with_directory "$evidence_directory"
rm -f "$evidence_directory"
mv "$real_evidence_directory" "$evidence_directory"

write_valid_evidence
run_closure >/dev/null
cp "$closure_path" "$evidence_directory/expected-closure.json"
rm -f "$closure_path"
ln -s expected-closure.json "$closure_path"
expect_failure closure-symlink run_closure

write_valid_evidence
printf '{"tampered":true}\n' > "$closure_path"
expect_failure closure-tamper run_closure

write_valid_evidence
printf 'orphan\n' > "$pending_path"
expect_failure orphan-pending run_closure

write_valid_evidence
ln -s nowhere "$pending_path"
expect_failure pending-symlink run_closure

printf 'BSL-150 Linux evidence closure self-test passed.\n'
printf 'Fixture HEAD: %s\n' "$head_sha"
printf '%s\n' 'Cases: success, idempotency, mixed head, unknown field, wrong type, future time, failed gate, evidence symlink, evidence-directory symlink, closure symlink, closure tamper, orphan pending, pending symlink.'
