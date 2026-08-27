#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
rust_toolchain="1.97.1"
cargo_audit_version="0.22.2"
cargo_deny_version="0.20.2"
expected_lock_sha256="f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"
focused_tests=(
    target_setup_cli
    target_activation_cli
    target_activation_recovery_cli
    target_guided_artifact_cli
    target_import_cli
    target_import_failclosed_cli
    target_path_binding_cli
    target_scope_failclosed_cli
    target_subdomain_failclosed_cli
    target_persistence_envelope_cli
    target_unicode_path_failclosed_cli
)
sealed_tool_object=''

# The first chdir establishes the repository CWD object inherited by every Git
# command in this process. Callers may safely pass '.' to preserve an already
# pinned repository CWD instead of reopening an absolute repository pathname.
cd "$repo_root"

fail() {
    printf 'NXB-153 Linux validation failed: %s\n' "$1" >&2
    exit 1
}

json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '%s' "$value"
}

json_field() {
    local payload="$1"
    local field="$2"
    python3 - "$payload" "$field" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
field = sys.argv[2]
value = payload.get(field)
if not isinstance(value, str) or not value:
    raise SystemExit(f"missing or invalid JSON field: {field}")
print(value)
PY
}

fsync_file() {
    python3 - "$1" <<'PY'
import os
import sys

path = sys.argv[1]
fd = os.open(path, os.O_RDONLY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

fsync_directory() {
    python3 - "$1" <<'PY'
import os
import sys

path = sys.argv[1]
fd = os.open(path, os.O_RDONLY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

cargo_run() {
    rustup run "$rust_toolchain" cargo "$@"
}

resolve_committed_blob() {
    local relative_path="$1"
    local label="$2"
    local object
    local object_type
    local object_size

    object="$(git rev-parse "$head_sha:$relative_path")" ||
        fail "$label is not committed at exact head $head_sha: $relative_path"
    object_type="$(git cat-file -t "$object")" ||
        fail "could not resolve committed $label object type"
    [[ "$object_type" == 'blob' ]] || fail "committed $label is not a Git blob"
    object_size="$(git cat-file -s "$object")" ||
        fail "could not resolve committed $label object size"
    [[ "$object_size" =~ ^[0-9]+$ && "$object_size" -gt 0 && "$object_size" -le 1048576 ]] ||
        fail "committed $label size is outside the supported 1..1048576-byte envelope"
    printf '%s' "$object"
}

run_sealed_tool() {
    [[ -n "$sealed_tool_object" ]] || fail 'sealed Linux validation-tool helper object is unresolved'
    git cat-file blob "$sealed_tool_object" | python3 - "$@"
}

verify_tooling_receipt_snapshot() {
    local path="$1"
    local expected_head="$2"
    local rustc_version="$3"
    local audit_version="$4"
    local audit_sha256="$5"
    local deny_version="$6"
    local deny_sha256="$7"
    local expected_tools_root="$8"

    python3 - \
        "$path" \
        "$expected_head" \
        "$rustc_version" \
        "$audit_version" \
        "$audit_sha256" \
        "$deny_version" \
        "$deny_sha256" \
        "$expected_tools_root" <<'PY'
import datetime as dt
import hashlib
import json
import os
import stat
import sys

(
    receipt_path,
    head_sha,
    rustc_version,
    audit_version,
    audit_sha256,
    deny_version,
    deny_sha256,
    expected_tools_root,
) = sys.argv[1:]

if not hasattr(os, "O_NOFOLLOW"):
    raise SystemExit("O_NOFOLLOW is unavailable for tooling receipt verification")
flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
try:
    fd = os.open(receipt_path, flags)
except OSError as error:
    raise SystemExit(f"could not open tooling receipt without following links: {error}")

try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise SystemExit("tooling receipt must be a regular file")
    if before.st_size <= 0 or before.st_size > 65536:
        raise SystemExit("tooling receipt size is invalid")

    value = bytearray()
    while len(value) <= 65536:
        chunk = os.read(fd, min(65537 - len(value), 65536))
        if not chunk:
            break
        value.extend(chunk)
    after = os.fstat(fd)
    if len(value) != before.st_size or len(value) > 65536:
        raise SystemExit("tooling receipt changed size while being read")
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or getattr(after, "st_mtime_ns", None) != getattr(before, "st_mtime_ns", None)
        or getattr(after, "st_ctime_ns", None) != getattr(before, "st_ctime_ns", None)
    ):
        raise SystemExit("tooling receipt metadata changed while being read")
    raw = bytes(value)
finally:
    os.close(fd)

try:
    receipt = json.loads(raw.decode("utf-8", errors="strict"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"tooling receipt is invalid UTF-8 JSON: {error}")

expected_fields = {
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
if not isinstance(receipt, dict) or set(receipt) != expected_fields:
    raise SystemExit("tooling receipt fields do not match the NXB-153 bootstrap contract")
expected = {
    "schema_version": 1,
    "milestone": "NXB-153",
    "gate": "validation_tool_bootstrap",
    "platform": "linux",
    "head_sha": head_sha,
    "rust_toolchain": rustc_version,
    "cargo_audit": audit_version,
    "cargo_audit_sha256": audit_sha256,
    "cargo_deny": deny_version,
    "cargo_deny_sha256": deny_sha256,
    "tools_root": expected_tools_root,
    "network_activity": "rustup_and_crates_io_tool_installation_only",
}
for field, expected_value in expected.items():
    if receipt.get(field) != expected_value:
        raise SystemExit(f"tooling receipt mismatch for {field}")
for field in ("cargo_audit_sha256", "cargo_deny_sha256"):
    field_value = receipt[field]
    if len(field_value) != 64 or any(character not in "0123456789abcdef" for character in field_value):
        raise SystemExit(f"tooling receipt {field} is not a lowercase SHA-256")
try:
    prepared_at = dt.datetime.strptime(receipt["prepared_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    )
except (TypeError, ValueError) as error:
    raise SystemExit(f"tooling receipt prepared_at is invalid: {error}")
if prepared_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
    raise SystemExit("tooling receipt prepared_at is unreasonably in the future")

print(hashlib.sha256(raw).hexdigest())
PY
}

validation_lock_directory=''
validation_lock_claimed=false
cleanup_validation_lock() {
    if [[ "$validation_lock_claimed" == true && -n "$validation_lock_directory" ]]; then
        rmdir "$validation_lock_directory" 2>/dev/null || true
    fi
}
trap cleanup_validation_lock EXIT

command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v rustup >/dev/null 2>&1 || fail 'rustup is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'
command -v python3 >/dev/null 2>&1 || fail 'python3 is unavailable for committed sealed validation-tool execution, tooling-receipt verification and durable evidence publication'
command -v stat >/dev/null 2>&1 || fail 'stat is unavailable'
command -v awk >/dev/null 2>&1 || fail 'awk is unavailable'

head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD could not be resolved'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || fail 'working tree must be clean'

# Bind the helper implementation to the exact initial Git object graph. Every
# inspect/run invocation streams the committed blob directly into Python; no
# mutable scripts pathname is reopened after the authority head is fixed.
sealed_tool_object="$(resolve_committed_blob 'scripts/nxb-153-sealed-tool.py' 'sealed Linux validation-tool helper')"
run_sealed_tool self-test >/dev/null ||
    fail 'committed sealed Linux validation-tool primitive self-test failed before validation'

validation_directory="$repo_root/target/nxb-validation"
mkdir -p "$validation_directory"
evidence_path="$validation_directory/nxb-153-linux-$head_sha.json"
if [[ -e "$evidence_path" ]]; then
    fail "exact-head Linux validation evidence already exists; validation gates were not rerun: $evidence_path; use the evidence reviewer or perform explicit recovery"
fi

validation_lock_directory="$validation_directory/.nxb-153-validation-linux-$head_sha.lock"
if ! mkdir "$validation_lock_directory" 2>/dev/null; then
    if [[ -e "$evidence_path" ]]; then
        fail "exact-head Linux validation evidence appeared before lock acquisition; validation gates were not rerun: $evidence_path"
    fi
    fail "exact-head Linux validation is already in progress or requires explicit stale-lock recovery: $validation_lock_directory"
fi
validation_lock_claimed=true
fsync_directory "$validation_directory" || fail 'could not sync validation directory after exact-head validation lock claim'
if [[ -e "$evidence_path" ]]; then
    fail "exact-head Linux validation evidence appeared while claiming the validation lock; heavy validation was not started: $evidence_path"
fi

tools_relative="target/nxb-tools/linux/$head_sha"
tools_root="$repo_root/$tools_relative"
tools_bin="$tools_root/bin"
audit_path="$tools_bin/cargo-audit"
deny_path="$tools_bin/cargo-deny"
[[ -d "$tools_root" ]] || fail "exact-head Linux tools root is missing: $tools_root; run scripts/prepare-and-validate-nxb-153-linux.sh first"
[[ -f "$audit_path" && ! -L "$audit_path" ]] || fail 'cargo-audit must be a regular non-symlink exact-head tool file'
[[ -f "$deny_path" && ! -L "$deny_path" ]] || fail 'cargo-deny must be a regular non-symlink exact-head tool file'

# Inspect current tool bytes through stable O_NOFOLLOW reads and sealed snapshots.
# Both the inspection algorithm and the resulting version/SHA pair are bound to
# the exact committed helper object selected from the initial validation head.
audit_inspection="$(run_sealed_tool inspect "$audit_path" "$cargo_audit_version")" ||
    fail 'cargo-audit committed sealed inspection failed'
deny_inspection="$(run_sealed_tool inspect "$deny_path" "$cargo_deny_version")" ||
    fail 'cargo-deny committed sealed inspection failed'
audit_version="$(json_field "$audit_inspection" version)" || fail 'cargo-audit version result is invalid'
audit_sha256="$(json_field "$audit_inspection" sha256)" || fail 'cargo-audit SHA-256 result is invalid'
deny_version="$(json_field "$deny_inspection" version)" || fail 'cargo-deny version result is invalid'
deny_sha256="$(json_field "$deny_inspection" sha256)" || fail 'cargo-deny SHA-256 result is invalid'

rustc_version="$(rustup run "$rust_toolchain" rustc --version)" ||
    fail "Rust toolchain $rust_toolchain is unavailable"
[[ "$rustc_version" == rustc\ 1.97.1\ * ]] ||
    fail "expected rustc 1.97.1, found '$rustc_version'"
cargo_version="$(cargo_run --version)" || fail 'could not resolve pinned Cargo version'

receipt_path="$validation_directory/nxb-153-tooling-linux-$head_sha.json"
[[ -f "$receipt_path" ]] ||
    fail "exact-head tooling receipt is missing; run scripts/prepare-and-validate-nxb-153-linux.sh first"

# Open/read/hash/parse one O_NOFOLLOW receipt object. The SHA embedded in platform
# evidence is therefore the SHA of the exact receipt bytes that were semantically
# verified, not a separate pathname opening that could be transiently substituted.
receipt_sha256="$(verify_tooling_receipt_snapshot \
    "$receipt_path" \
    "$head_sha" \
    "$rustc_version" \
    "$audit_version" \
    "$audit_sha256" \
    "$deny_version" \
    "$deny_sha256" \
    "$tools_relative")" || fail 'exact-head tooling receipt stable-object verification failed'
[[ "$receipt_sha256" =~ ^[0-9a-f]{64}$ ]] || fail 'tooling receipt snapshot SHA-256 is invalid'

[[ -f Cargo.lock ]] || fail 'Cargo.lock is missing'
lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
[[ "$lock_sha256" == "$expected_lock_sha256" ]] ||
    fail "Cargo.lock SHA-256 mismatch: expected $expected_lock_sha256, found $lock_sha256"
git diff --exit-code -- Cargo.lock >/dev/null ||
    fail 'committed Cargo.lock differs before locked validation'

cargo_run metadata --format-version 1 --locked --no-deps >/dev/null
git diff --exit-code -- Cargo.lock >/dev/null ||
    fail 'Cargo.lock changed during cargo metadata --locked'

cargo_run fmt --all -- --check

cargo_run check -p nxb-policy --all-targets --locked
cargo_run clippy -p nxb-policy --all-targets --locked -- -D warnings
cargo_run test -p nxb-policy --locked -- --test-threads=1

cargo_run check -p nxb-core --all-targets --locked
cargo_run clippy -p nxb-core --all-targets --locked -- -D warnings
cargo_run test -p nxb-core --lib --locked -- --test-threads=1
for test_name in "${focused_tests[@]}"; do
    cargo_run test -p nxb-core --test "$test_name" --locked -- --test-threads=1
done

cargo_run check --workspace --all-targets --all-features --locked
cargo_run clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo_run test --workspace --all-features --locked -- --test-threads=1

# Immediately before each security gate, re-open the canonical executable with
# O_NOFOLLOW, require the receipt-admitted SHA, seal those exact bytes and execute
# the immutable snapshot. The helper implementation itself is the committed blob.
run_sealed_tool run "$audit_path" "$cargo_audit_version" "$audit_sha256" -- audit ||
    fail 'RustSec cargo-audit committed sealed gate failed'
run_sealed_tool run "$deny_path" "$cargo_deny_version" "$deny_sha256" -- check ||
    fail 'cargo-deny committed sealed gate failed'

final_lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
[[ "$final_lock_sha256" == "$expected_lock_sha256" ]] ||
    fail 'Cargo.lock bytes changed during validation'
git diff --exit-code -- Cargo.lock >/dev/null ||
    fail 'Cargo.lock Git diff appeared during validation'

final_head="$(git rev-parse HEAD)"
[[ "$final_head" == "$head_sha" ]] || fail 'Git HEAD changed during validation'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree changed during validation'

final_audit_path_sha256="$(sha256sum "$audit_path" | awk '{print $1}')"
final_deny_path_sha256="$(sha256sum "$deny_path" | awk '{print $1}')"
[[ "$final_audit_path_sha256" == "$audit_sha256" ]] || fail 'cargo-audit pathname no longer names the validated sealed bytes'
[[ "$final_deny_path_sha256" == "$deny_sha256" ]] || fail 'cargo-deny pathname no longer names the validated sealed bytes'
final_receipt_sha256="$(sha256sum "$receipt_path" | awk '{print $1}')"
[[ "$final_receipt_sha256" == "$receipt_sha256" ]] || fail 'tooling receipt pathname no longer names the semantically verified receipt bytes'

validated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
rustc_json="$(json_escape "$rustc_version")"
cargo_json="$(json_escape "$cargo_version")"
audit_json="$(json_escape "$audit_version")"
deny_json="$(json_escape "$deny_version")"
evidence_temp="$(mktemp "$validation_directory/.nxb-153-linux-$head_sha.XXXXXX.tmp")"
chmod 600 "$evidence_temp"

cat > "$evidence_temp" <<JSON
{
  "schema_version": 1,
  "milestone": "NXB-153",
  "gate": "guided_target_authorization_setup",
  "platform": "linux",
  "head_sha": "$head_sha",
  "rustc": "$rustc_json",
  "cargo": "$cargo_json",
  "cargo_audit": "$audit_json",
  "cargo_audit_sha256": "$audit_sha256",
  "cargo_deny": "$deny_json",
  "cargo_deny_sha256": "$deny_sha256",
  "tooling_receipt": "target/nxb-validation/nxb-153-tooling-linux-$head_sha.json",
  "tooling_receipt_sha256": "$receipt_sha256",
  "tooling_receipt_verified": true,
  "cargo_lock_sha256": "$lock_sha256",
  "cargo_lock_expected_sha256": "$expected_lock_sha256",
  "lockfile_pinned_and_unchanged": true,
  "fmt": "passed",
  "nxb_policy_check_clippy_tests": "passed",
  "nxb_core_check_clippy_unit_tests": "passed",
  "focused_target_tests": "passed",
  "workspace_check_clippy_tests_all_features": "passed",
  "rustsec": "passed",
  "cargo_deny_checks": "passed",
  "test_threads": 1,
  "network_activity": "cargo_dependency_and_advisory_sources_only",
  "validated_at": "$validated_at"
}
JSON

evidence_size="$(stat -c '%s' "$evidence_temp")" || fail 'could not resolve validation evidence size'
[[ "$evidence_size" -gt 0 && "$evidence_size" -le 65536 ]] || fail 'Linux validation evidence size is invalid'
fsync_file "$evidence_temp" || fail 'could not sync validation evidence temporary file before namespace claim'
if ln "$evidence_temp" "$evidence_path" 2>/dev/null; then
    cleanup_error=''
    if ! rm -f "$evidence_temp"; then
        cleanup_error='could not remove claimed validation evidence temporary link'
    fi
    fsync_directory "$validation_directory" || fail 'could not sync validation directory after evidence finalization'
    [[ -z "$cleanup_error" ]] || fail "$cleanup_error"
else
    cleanup_error=''
    if ! rm -f "$evidence_temp"; then
        cleanup_error='could not remove unclaimed validation evidence temporary file'
    fi
    fsync_directory "$validation_directory" || fail 'could not sync validation directory after evidence cleanup attempt'
    [[ -z "$cleanup_error" ]] || fail "$cleanup_error"
    if [[ -e "$evidence_path" ]]; then
        fail "exact-head Linux validation evidence already exists and will not be overwritten: $evidence_path; review/remove it explicitly before validating again"
    fi
    fail 'could not create-only claim exact-head Linux validation evidence'
fi

rmdir "$validation_lock_directory" || fail 'could not release exact-head Linux validation lock after evidence publication'
validation_lock_claimed=false
fsync_directory "$validation_directory" || fail 'could not sync validation directory after exact-head validation lock release'
trap - EXIT

printf 'NXB-153 Linux validation passed with committed sealed security-tool authority.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Tool root: %s\n' "$tools_relative"
printf 'Cargo.lock SHA-256: %s\n' "$lock_sha256"
printf 'Tooling receipt SHA-256: %s\n' "$receipt_sha256"
printf 'Evidence: %s\n' "$evidence_path"
