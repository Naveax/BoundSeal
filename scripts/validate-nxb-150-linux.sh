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

cd "$repo_root"

fail() {
    printf 'NXB-150 Linux validation failed: %s\n' "$1" >&2
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
        fail "$label is unavailable at $path; run prepare-and-validate-nxb-150-linux.sh first"
    local value
    value="$($path --version)" || fail "$label version could not be resolved"
    printf '%s\n' "$value" | grep -Eq "(^|[[:space:]])${expected}($|[[:space:]])" ||
        fail "$label version mismatch: expected $expected, found '$value'"
    printf '%s' "$value"
}

command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v rustup >/dev/null 2>&1 || fail 'rustup is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'

head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD could not be resolved'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || fail 'working tree must be clean'

rustc_version="$(rustup run "$rust_toolchain" rustc --version)"
[[ "$rustc_version" == rustc\ 1.97.1\ * ]] || fail "expected rustc 1.97.1, found '$rustc_version'"
cargo_version="$(cargo_run --version)"
audit_version="$(tool_version "$audit_path" "$cargo_audit_version" 'cargo-audit')"
deny_version="$(tool_version "$deny_path" "$cargo_deny_version" 'cargo-deny')"
audit_sha256="$(sha256sum "$audit_path" | awk '{print $1}')"
deny_sha256="$(sha256sum "$deny_path" | awk '{print $1}')"

[[ -f Cargo.lock ]] || fail 'Cargo.lock is missing'
lock_backup="$(mktemp)"
cp Cargo.lock "$lock_backup"
cleanup() {
    cp "$lock_backup" Cargo.lock
    rm -f "$lock_backup"
}
trap cleanup EXIT

cargo_run generate-lockfile
if ! cmp -s "$lock_backup" Cargo.lock; then
    git --no-pager diff -- Cargo.lock >&2 || true
    fail 'cargo generate-lockfile changed the committed Cargo.lock'
fi

lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
[[ "$lock_sha256" == "$expected_lock_sha256" ]] ||
    fail "Cargo.lock SHA-256 mismatch: expected $expected_lock_sha256, found $lock_sha256"

git diff --exit-code -- Cargo.lock >/dev/null || fail 'Cargo.lock differs after reproduction'
cargo_run metadata --format-version 1 --locked --no-deps >/dev/null

cargo_run fmt --all -- --check
cargo_run check -p nxb-evidence-key-provider-process --all-features --locked
cargo_run clippy -p nxb-evidence-key-provider-process --all-targets --all-features --locked -- -D warnings
cargo_run test -p nxb-evidence-key-provider-process --all-features --locked -- --test-threads=1
cargo_run test -p nxb-vault-provider --locked -- --test-threads=1

cargo_run check --workspace --all-targets --all-features --locked
cargo_run clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo_run test --workspace --all-features --locked -- --test-threads=1

"$audit_path"
"$deny_path" check

final_head="$(git rev-parse HEAD)"
[[ "$final_head" == "$head_sha" ]] || fail 'Git HEAD changed during validation'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || fail 'working tree changed during validation'

validation_directory="$repo_root/target/nxb-validation"
mkdir -p "$validation_directory"
evidence_path="$validation_directory/nxb-150-linux-$head_sha.json"
validated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

rustc_json="$(json_escape "$rustc_version")"
cargo_json="$(json_escape "$cargo_version")"
audit_json="$(json_escape "$audit_version")"
deny_json="$(json_escape "$deny_version")"

cat > "$evidence_path" <<JSON
{
  "schema_version": 2,
  "milestone": "NXB-150",
  "gate": "pinned_process_evidence_key_provider",
  "platform": "linux",
  "head_sha": "$head_sha",
  "rustc": "$rustc_json",
  "cargo": "$cargo_json",
  "cargo_audit": "$audit_json",
  "cargo_audit_sha256": "$audit_sha256",
  "cargo_deny": "$deny_json",
  "cargo_deny_sha256": "$deny_sha256",
  "cargo_lock_sha256": "$lock_sha256",
  "lockfile_reproduced_without_diff": true,
  "package_fmt_check_clippy_tests": "passed",
  "vault_provider_regressions": "passed",
  "workspace_check_clippy_tests": "passed",
  "rustsec": "passed",
  "cargo_deny_checks": "passed",
  "process_fixture_serial": true,
  "network_activity": "dependency_and_advisory_sources_only",
  "validated_at": "$validated_at"
}
JSON

printf 'NXB-150 Linux validation passed.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Cargo.lock SHA-256: %s\n' "$lock_sha256"
printf 'Evidence: %s\n' "$evidence_path"
