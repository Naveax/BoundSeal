#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
evidence_directory="${2:-$repo_root/target/nxb-validation}"
expected_lock_sha256="f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"
secure_launcher="$repo_root/scripts/review-nxb-153-evidence-linux-secure.py"

fail() {
    printf 'NXB-153 guarded evidence closure failed: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'python3 is unavailable'
command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'
[[ -f "$secure_launcher" ]] || fail "secure Linux evidence launcher is missing: $secure_launcher"

cd "$repo_root"
initial_head="$(git rev-parse HEAD)"
[[ "$initial_head" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD could not be resolved before evidence review'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree must be clean before evidence review'
[[ -f Cargo.lock ]] || fail 'Cargo.lock is missing before evidence review'
initial_lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
[[ "$initial_lock_sha256" == "$expected_lock_sha256" ]] ||
    fail "Cargo.lock SHA-256 mismatch before evidence review: expected $expected_lock_sha256, found $initial_lock_sha256"

self_test_output="$(python3 "$secure_launcher" --self-test)"
review_output="$(python3 \
    "$secure_launcher" \
    "$repo_root" \
    "$evidence_directory")"

final_head="$(git rev-parse HEAD)"
[[ "$final_head" == "$initial_head" ]] ||
    fail "Git HEAD changed during evidence review: initial=$initial_head final=$final_head; any newly published closure requires explicit recovery/review"
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree changed during evidence review; any newly published closure requires explicit recovery/review'
final_lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
[[ "$final_lock_sha256" == "$initial_lock_sha256" ]] ||
    fail 'Cargo.lock bytes changed during evidence review; any newly published closure requires explicit recovery/review'

if [[ -n "$self_test_output" ]]; then
    printf '%s\n' "$self_test_output"
fi
if [[ -n "$review_output" ]]; then
    printf '%s\n' "$review_output"
fi
printf 'NXB-153 guarded Linux closure authority remained stable.\n'
printf 'HEAD: %s\n' "$initial_head"
printf 'Cargo.lock SHA-256: %s\n' "$initial_lock_sha256"
