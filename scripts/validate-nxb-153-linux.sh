#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
rust_toolchain="1.97.1"
cargo_audit_version="0.22.2"
cargo_deny_version="0.20.2"
expected_lock_sha256="f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"
sealed_tool_object=''
immutable_source_object=''
repo_fd=''
validation_fd=''

# The first chdir establishes the repository CWD object inherited by every Git
# command in this process. Preparation may pass '.' so this child never reopens a
# configured absolute repository pathname after the parent has fixed authority.
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

blob_sha256() {
    local object="$1"
    git cat-file blob "$object" | sha256sum | awk '{print $1}'
}

run_sealed_tool() {
    [[ -n "$sealed_tool_object" ]] || fail 'sealed Linux validation-tool helper object is unresolved'
    git cat-file blob "$sealed_tool_object" | python3 - "$@"
}

run_immutable_source() {
    [[ -n "$immutable_source_object" ]] || fail 'immutable Linux source runner object is unresolved'
    git cat-file blob "$immutable_source_object" | bash -s -- "$@"
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

for required_command in git rustup sha256sum python3 stat awk bash; do
    command -v "$required_command" >/dev/null 2>&1 || fail "$required_command is unavailable"
done
[[ -d /proc/self/fd ]] || fail '/proc/self/fd is unavailable for repository-object authority'

head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD could not be resolved'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || fail 'working tree must be clean'

# Pin the repository directory object. All mutable validation/tool/evidence paths
# below are rooted through this descriptor instead of the configured pathname.
exec {repo_fd}<. || fail 'could not pin repository directory object'
repo_anchor="/proc/self/fd/$repo_fd"
[[ -d "$repo_anchor" ]] || fail 'pinned repository descriptor is unavailable'

sealed_tool_object="$(resolve_committed_blob 'scripts/nxb-153-sealed-tool.py' 'sealed Linux validation-tool helper')"
immutable_source_object="$(resolve_committed_blob 'scripts/nxb-153-linux-immutable-source.sh' 'immutable Linux source runner')"
lock_object="$(resolve_committed_blob 'Cargo.lock' 'Cargo.lock')"
sealed_helper_sha256="$(blob_sha256 "$sealed_tool_object")" || fail 'could not hash committed sealed-tool helper bytes'
lock_sha256="$(blob_sha256 "$lock_object")" || fail 'could not hash exact-head Cargo.lock bytes'
[[ "$sealed_helper_sha256" =~ ^[0-9a-f]{64}$ ]] || fail 'committed sealed-tool helper SHA-256 is invalid'
[[ "$lock_sha256" == "$expected_lock_sha256" ]] ||
    fail "exact-head Cargo.lock SHA-256 mismatch: expected $expected_lock_sha256, found $lock_sha256"

# Pin the exact validation directory object as well. Publication and lock paths
# remain attached to this object even if a concurrent rename occurs; a final
# namespace-binding check prevents success if the canonical name was redirected.
mkdir -p "$repo_anchor/target/nxb-validation"
exec {validation_fd}<"$repo_anchor/target/nxb-validation" || fail 'could not pin validation evidence directory object'
validation_directory="/proc/self/fd/$validation_fd"
validation_identity="$(stat -Lc '%d:%i' "$validation_directory")" || fail 'could not identify pinned validation directory'
evidence_relative="target/nxb-validation/nxb-153-linux-$head_sha.json"
evidence_path="$validation_directory/nxb-153-linux-$head_sha.json"
if [[ -e "$evidence_path" ]]; then
    fail "exact-head Linux validation evidence already exists; validation gates were not rerun: $evidence_relative; use the evidence reviewer or perform explicit recovery"
fi

validation_lock_directory="$validation_directory/.nxb-153-validation-linux-$head_sha.lock"
if ! mkdir "$validation_lock_directory" 2>/dev/null; then
    if [[ -e "$evidence_path" ]]; then
        fail "exact-head Linux validation evidence appeared before lock acquisition; validation gates were not rerun: $evidence_relative"
    fi
    fail "exact-head Linux validation is already in progress or requires explicit stale-lock recovery: target/nxb-validation/.nxb-153-validation-linux-$head_sha.lock"
fi
validation_lock_claimed=true
fsync_directory "$validation_directory" || fail 'could not sync validation directory after exact-head validation lock claim'
if [[ -e "$evidence_path" ]]; then
    fail "exact-head Linux validation evidence appeared while claiming the validation lock; heavy validation was not started: $evidence_relative"
fi

# Primitive requirements are tested only after lock ownership so a duplicate
# same-platform/head validator does not repeat namespace or sealing probes.
run_sealed_tool self-test >/dev/null ||
    fail 'committed sealed Linux validation-tool primitive self-test failed before validation'
run_immutable_source self-test >/dev/null ||
    fail 'committed immutable Linux source primitive self-test failed before validation'

tools_relative="target/nxb-tools/linux/$head_sha"
tools_root="$repo_anchor/$tools_relative"
tools_bin="$tools_root/bin"
audit_path="$tools_bin/cargo-audit"
deny_path="$tools_bin/cargo-deny"
[[ -d "$tools_root" ]] || fail "exact-head Linux tools root is missing: $tools_relative; run scripts/prepare-and-validate-nxb-153-linux.sh first"
[[ -f "$audit_path" && ! -L "$audit_path" ]] || fail 'cargo-audit must be a regular non-symlink exact-head tool file'
[[ -f "$deny_path" && ! -L "$deny_path" ]] || fail 'cargo-deny must be a regular non-symlink exact-head tool file'

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
cargo_version="$(rustup run "$rust_toolchain" cargo --version)" || fail 'could not resolve pinned Cargo version'

receipt_relative="target/nxb-validation/nxb-153-tooling-linux-$head_sha.json"
receipt_path="$validation_directory/nxb-153-tooling-linux-$head_sha.json"
[[ -f "$receipt_path" ]] ||
    fail "exact-head tooling receipt is missing: $receipt_relative; run scripts/prepare-and-validate-nxb-153-linux.sh first"

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

# Heavy validation is executed only against an exact-head Git archive extracted
# into a namespace-private tmpfs that is remounted read-only. Writable target,
# temporary and Cargo-home state live on separate private tmpfs mounts. The child
# receives the pinned repository descriptor only for receipt-hash-checked tool
# access; it does not compile/test the mutable working tree.
run_immutable_source validate \
    "$head_sha" \
    "$repo_fd" \
    "$rust_toolchain" \
    "$cargo_audit_version" \
    "$cargo_deny_version" \
    "$audit_sha256" \
    "$deny_sha256" \
    "$lock_sha256" \
    "$sealed_helper_sha256" \
    "$tools_relative" || fail 'immutable exact-head Linux Cargo/security gate sequence failed'

final_head="$(git rev-parse HEAD)"
[[ "$final_head" == "$head_sha" ]] || fail 'Git HEAD changed during validation'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree changed during validation'

final_audit_path_sha256="$(sha256sum "$audit_path" | awk '{print $1}')"
final_deny_path_sha256="$(sha256sum "$deny_path" | awk '{print $1}')"
[[ "$final_audit_path_sha256" == "$audit_sha256" ]] || fail 'cargo-audit anchored path no longer names the validated sealed bytes'
[[ "$final_deny_path_sha256" == "$deny_sha256" ]] || fail 'cargo-deny anchored path no longer names the validated sealed bytes'
final_receipt_sha256="$(sha256sum "$receipt_path" | awk '{print $1}')"
[[ "$final_receipt_sha256" == "$receipt_sha256" ]] || fail 'tooling receipt path no longer names the semantically verified receipt bytes'

# The canonical repository namespace must still bind target/nxb-validation to the
# directory object used for lock/evidence publication. A drift failure after a
# create-only claim leaves the visible artifact for explicit recovery.
final_validation_identity="$(stat -Lc '%d:%i' "$repo_anchor/target/nxb-validation")" ||
    fail 'canonical validation directory namespace disappeared during validation'
[[ "$final_validation_identity" == "$validation_identity" ]] ||
    fail 'canonical validation directory namespace no longer names the pinned evidence directory object'

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
  "tooling_receipt": "$receipt_relative",
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
        fail "exact-head Linux validation evidence already exists and will not be overwritten: $evidence_relative; review/remove it explicitly before validating again"
    fi
    fail 'could not create-only claim exact-head Linux validation evidence'
fi

# Recheck the canonical namespace after publication as well. No PASS output is
# emitted if the evidence directory was renamed/replaced during finalization.
final_validation_identity="$(stat -Lc '%d:%i' "$repo_anchor/target/nxb-validation")" ||
    fail 'canonical validation directory namespace disappeared after evidence publication'
[[ "$final_validation_identity" == "$validation_identity" ]] ||
    fail 'canonical validation directory namespace drifted after evidence publication'

rmdir "$validation_lock_directory" || fail 'could not release exact-head Linux validation lock after evidence publication'
validation_lock_claimed=false
fsync_directory "$validation_directory" || fail 'could not sync validation directory after exact-head validation lock release'
trap - EXIT

printf 'NXB-153 Linux validation passed from an immutable exact-head private source snapshot.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Tool root: %s\n' "$tools_relative"
printf 'Cargo.lock SHA-256: %s\n' "$lock_sha256"
printf 'Tooling receipt SHA-256: %s\n' "$receipt_sha256"
printf 'Evidence: %s\n' "$evidence_relative"

exec {validation_fd}<&-
exec {repo_fd}<&-
