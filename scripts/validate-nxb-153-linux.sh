#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
rust_toolchain="1.97.1"
cargo_audit_version="0.22.2"
cargo_deny_version="0.20.2"
expected_lock_sha256="f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"
tools_bin="$repo_root/target/nxb-tools/bin"
audit_path="$tools_bin/cargo-audit"
deny_path="$tools_bin/cargo-deny"
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
)

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

cargo_run() {
    rustup run "$rust_toolchain" cargo "$@"
}

tool_version() {
    local path="$1"
    local expected="$2"
    local label="$3"
    [[ -x "$path" ]] ||
        fail "$label is unavailable at $path; run scripts/prepare-and-validate-nxb-153-linux.sh first"
    local value
    value="$($path --version)" || fail "$label version could not be resolved"
    printf '%s\n' "$value" | grep -Eq "(^|[[:space:]])${expected}($|[[:space:]])" ||
        fail "$label version mismatch: expected $expected, found '$value'"
    printf '%s' "$value"
}

command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v rustup >/dev/null 2>&1 || fail 'rustup is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'
command -v python3 >/dev/null 2>&1 || fail 'python3 is unavailable for tooling-receipt verification'

head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD could not be resolved'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || fail 'working tree must be clean'

rustc_version="$(rustup run "$rust_toolchain" rustc --version)" ||
    fail "Rust toolchain $rust_toolchain is unavailable"
[[ "$rustc_version" == rustc\ 1.97.1\ * ]] ||
    fail "expected rustc 1.97.1, found '$rustc_version'"
cargo_version="$(cargo_run --version)" || fail 'could not resolve pinned Cargo version'
audit_version="$(tool_version "$audit_path" "$cargo_audit_version" 'cargo-audit')"
deny_version="$(tool_version "$deny_path" "$cargo_deny_version" 'cargo-deny')"
audit_sha256="$(sha256sum "$audit_path" | awk '{print $1}')"
deny_sha256="$(sha256sum "$deny_path" | awk '{print $1}')"

validation_directory="$repo_root/target/nxb-validation"
receipt_path="$validation_directory/nxb-153-tooling-linux-$head_sha.json"
[[ -f "$receipt_path" ]] ||
    fail "exact-head tooling receipt is missing; run scripts/prepare-and-validate-nxb-153-linux.sh first"
receipt_sha256="$(sha256sum "$receipt_path" | awk '{print $1}')"

python3 - \
    "$receipt_path" \
    "$head_sha" \
    "$rustc_version" \
    "$audit_version" \
    "$audit_sha256" \
    "$deny_version" \
    "$deny_sha256" <<'PY'
import datetime as dt
import json
import pathlib
import stat
import sys

(
    receipt_text,
    head_sha,
    rustc_version,
    audit_version,
    audit_sha256,
    deny_version,
    deny_sha256,
) = sys.argv[1:]
path = pathlib.Path(receipt_text)
try:
    metadata = path.lstat()
except FileNotFoundError:
    raise SystemExit("tooling receipt disappeared during validation")
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("tooling receipt must be a regular non-symlink file")
if metadata.st_size <= 0 or metadata.st_size > 65536:
    raise SystemExit("tooling receipt size is invalid")
try:
    receipt = json.loads(path.read_bytes().decode("utf-8", errors="strict"))
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
    "tools_root": "target/nxb-tools",
    "network_activity": "rustup_and_crates_io_tool_installation_only",
}
for field, value in expected.items():
    if receipt.get(field) != value:
        raise SystemExit(f"tooling receipt mismatch for {field}")
for field in ("cargo_audit_sha256", "cargo_deny_sha256"):
    value = receipt[field]
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SystemExit(f"tooling receipt {field} is not a lowercase SHA-256")
try:
    prepared_at = dt.datetime.strptime(receipt["prepared_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    )
except (TypeError, ValueError) as error:
    raise SystemExit(f"tooling receipt prepared_at is invalid: {error}")
if prepared_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
    raise SystemExit("tooling receipt prepared_at is unreasonably in the future")
PY

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

"$audit_path" audit
"$deny_path" check

final_lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
[[ "$final_lock_sha256" == "$expected_lock_sha256" ]] ||
    fail 'Cargo.lock bytes changed during validation'
git diff --exit-code -- Cargo.lock >/dev/null ||
    fail 'Cargo.lock Git diff appeared during validation'

final_head="$(git rev-parse HEAD)"
[[ "$final_head" == "$head_sha" ]] || fail 'Git HEAD changed during validation'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree changed during validation'

final_audit_sha256="$(sha256sum "$audit_path" | awk '{print $1}')"
final_deny_sha256="$(sha256sum "$deny_path" | awk '{print $1}')"
[[ "$final_audit_sha256" == "$audit_sha256" ]] || fail 'cargo-audit bytes changed during validation'
[[ "$final_deny_sha256" == "$deny_sha256" ]] || fail 'cargo-deny bytes changed during validation'
final_receipt_sha256="$(sha256sum "$receipt_path" | awk '{print $1}')"
[[ "$final_receipt_sha256" == "$receipt_sha256" ]] || fail 'tooling receipt changed during validation'

mkdir -p "$validation_directory"
evidence_path="$validation_directory/nxb-153-linux-$head_sha.json"
validated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
rustc_json="$(json_escape "$rustc_version")"
cargo_json="$(json_escape "$cargo_version")"
audit_json="$(json_escape "$audit_version")"
deny_json="$(json_escape "$deny_version")"

cat > "$evidence_path" <<JSON
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

printf 'NXB-153 Linux validation passed.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Cargo.lock SHA-256: %s\n' "$lock_sha256"
printf 'Tooling receipt SHA-256: %s\n' "$receipt_sha256"
printf 'Evidence: %s\n' "$evidence_path"
