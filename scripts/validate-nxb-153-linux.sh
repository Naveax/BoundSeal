#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
rust_toolchain="1.97.1"
focused_tests=(
    target_setup_cli
    target_activation_cli
    target_guided_artifact_cli
    target_import_cli
    target_import_failclosed_cli
    target_path_binding_cli
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

command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v rustup >/dev/null 2>&1 || fail 'rustup is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'

head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD could not be resolved'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || fail 'working tree must be clean'

rustc_version="$(rustup run "$rust_toolchain" rustc --version)" ||
    fail "Rust toolchain $rust_toolchain is unavailable"
[[ "$rustc_version" == rustc\ 1.97.1\ * ]] ||
    fail "expected rustc 1.97.1, found '$rustc_version'"
cargo_version="$(cargo_run --version)" || fail 'could not resolve pinned Cargo version'

[[ -f Cargo.lock ]] || fail 'Cargo.lock is missing'
lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
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
for test_name in "${focused_tests[@]}"; do
    cargo_run test -p nxb-core --test "$test_name" --locked -- --test-threads=1
done

cargo_run check --workspace --all-targets --all-features --locked
cargo_run clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo_run test --workspace --all-features --locked -- --test-threads=1

final_lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
[[ "$final_lock_sha256" == "$lock_sha256" ]] ||
    fail 'Cargo.lock bytes changed during validation'
git diff --exit-code -- Cargo.lock >/dev/null ||
    fail 'Cargo.lock Git diff appeared during validation'

final_head="$(git rev-parse HEAD)"
[[ "$final_head" == "$head_sha" ]] || fail 'Git HEAD changed during validation'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree changed during validation'

validation_directory="$repo_root/target/nxb-validation"
mkdir -p "$validation_directory"
evidence_path="$validation_directory/nxb-153-linux-$head_sha.json"
validated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
rustc_json="$(json_escape "$rustc_version")"
cargo_json="$(json_escape "$cargo_version")"

cat > "$evidence_path" <<JSON
{
  "schema_version": 1,
  "milestone": "NXB-153",
  "gate": "guided_target_authorization_setup",
  "platform": "linux",
  "head_sha": "$head_sha",
  "rustc": "$rustc_json",
  "cargo": "$cargo_json",
  "cargo_lock_sha256": "$lock_sha256",
  "lockfile_unchanged": true,
  "fmt": "passed",
  "nxb_policy_check_clippy_tests": "passed",
  "nxb_core_check_clippy": "passed",
  "focused_target_tests": "passed",
  "workspace_check_clippy_tests_all_features": "passed",
  "test_threads": 1,
  "network_activity": "cargo_dependency_resolution_only",
  "validated_at": "$validated_at"
}
JSON

printf 'NXB-153 Linux validation passed.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Cargo.lock SHA-256: %s\n' "$lock_sha256"
printf 'Evidence: %s\n' "$evidence_path"
