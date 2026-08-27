#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
prepare_only="${NXB_PREPARE_ONLY:-0}"
rust_toolchain="1.97.1"
cargo_audit_version="0.22.2"
cargo_deny_version="0.20.2"
install_root=''
prep_lock=''
validation_directory=''

fail() {
    printf 'NXB-153 Linux tool preparation failed: %s\n' "$1" >&2
    exit 1
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

cleanup() {
    if [[ -n "$install_root" && -d "$install_root" ]]; then
        rm -rf "$install_root" || true
    fi
    if [[ -n "$prep_lock" && -d "$prep_lock" ]]; then
        rmdir "$prep_lock" || true
        if [[ -n "$validation_directory" && -d "$validation_directory" ]]; then
            fsync_directory "$validation_directory" >/dev/null 2>&1 || true
        fi
    fi
}
trap cleanup EXIT

command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v rustup >/dev/null 2>&1 ||
    fail 'rustup is unavailable; install rustup from the official Rust distribution first'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'
command -v python3 >/dev/null 2>&1 || fail 'python3 is unavailable for durable tooling-receipt publication'

cd "$repo_root"
head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD could not be resolved'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree must be clean before tool preparation'

validation_directory="$repo_root/target/nxb-validation"
mkdir -p "$validation_directory"
fsync_directory "$repo_root/target" || fail 'could not sync target directory after validation-directory preparation'
receipt_path="$validation_directory/nxb-153-tooling-linux-$head_sha.json"
if [[ -e "$receipt_path" ]]; then
    fail "exact-head tooling receipt already exists; tool bytes were not mutated: $receipt_path; run the validator directly with the existing receipt, or review/remove it explicitly before preparing again"
fi

prep_lock="$validation_directory/.nxb-153-tool-prep-$head_sha.lock"
if ! mkdir "$prep_lock" 2>/dev/null; then
    fail "exact-head tool preparation is already in progress or requires explicit stale-lock recovery: $prep_lock"
fi
fsync_directory "$validation_directory" || fail 'could not sync validation directory after preparation-lock claim'
if [[ -e "$receipt_path" ]]; then
    fail "exact-head tooling receipt appeared while claiming the preparation lock; tool bytes were not mutated: $receipt_path"
fi

tools_relative="target/nxb-tools/linux/$head_sha"
tools_root="$repo_root/$tools_relative"
tools_bin="$tools_root/bin"
if [[ -e "$tools_root" ]]; then
    fail "exact-head Linux tools root already exists without an admitted tooling receipt; explicit recovery is required: $tools_root"
fi

rustup toolchain install "$rust_toolchain" \
    --profile minimal \
    --component rustfmt \
    --component clippy

audit_path="$tools_bin/cargo-audit"
deny_path="$tools_bin/cargo-deny"

tool_has_version() {
    local path="$1"
    local expected="$2"
    [[ -x "$path" ]] || return 1
    "$path" --version 2>/dev/null | grep -Eq "(^|[[:space:]])${expected}($|[[:space:]])"
}

install_root="$(mktemp -d)"
cd "$install_root"

rustup run "$rust_toolchain" cargo install \
    --locked \
    --force \
    --version "$cargo_audit_version" \
    --root "$tools_root" \
    cargo-audit

rustup run "$rust_toolchain" cargo install \
    --locked \
    --force \
    --version "$cargo_deny_version" \
    --root "$tools_root" \
    cargo-deny

cd "$repo_root"
tool_has_version "$audit_path" "$cargo_audit_version" ||
    fail 'fresh cargo-audit installation is invalid'
tool_has_version "$deny_path" "$cargo_deny_version" ||
    fail 'fresh cargo-deny installation is invalid'

final_head="$(git rev-parse HEAD)"
[[ "$final_head" == "$head_sha" ]] || fail 'Git HEAD changed during tool preparation'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree changed during tool preparation'

rustc_version="$(rustup run "$rust_toolchain" rustc --version)"
audit_version="$($audit_path --version)"
deny_version="$($deny_path --version)"
audit_sha256="$(sha256sum "$audit_path" | awk '{print $1}')"
deny_sha256="$(sha256sum "$deny_path" | awk '{print $1}')"
prepared_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
receipt_temp="$(mktemp "$validation_directory/.nxb-153-tooling-linux-$head_sha.XXXXXX.tmp")"
chmod 600 "$receipt_temp"

cat > "$receipt_temp" <<JSON
{
  "schema_version": 1,
  "milestone": "NXB-153",
  "gate": "validation_tool_bootstrap",
  "platform": "linux",
  "head_sha": "$head_sha",
  "rust_toolchain": "$rustc_version",
  "cargo_audit": "$audit_version",
  "cargo_audit_sha256": "$audit_sha256",
  "cargo_deny": "$deny_version",
  "cargo_deny_sha256": "$deny_sha256",
  "tools_root": "$tools_relative",
  "network_activity": "rustup_and_crates_io_tool_installation_only",
  "prepared_at": "$prepared_at"
}
JSON

receipt_size="$(stat -c '%s' "$receipt_temp")" || fail 'could not resolve tooling receipt size'
[[ "$receipt_size" -gt 0 && "$receipt_size" -le 65536 ]] || fail 'tooling receipt size is invalid'
fsync_file "$receipt_temp" || fail 'could not sync tooling receipt temporary file before namespace claim'
if ln "$receipt_temp" "$receipt_path" 2>/dev/null; then
    cleanup_error=''
    if ! rm -f "$receipt_temp"; then
        cleanup_error='could not remove claimed tooling receipt temporary link'
    fi
    fsync_directory "$validation_directory" || fail 'could not sync validation directory after tooling receipt finalization'
    [[ -z "$cleanup_error" ]] || fail "$cleanup_error"
else
    cleanup_error=''
    if ! rm -f "$receipt_temp"; then
        cleanup_error='could not remove unclaimed tooling receipt temporary file'
    fi
    fsync_directory "$validation_directory" || fail 'could not sync validation directory after tooling receipt cleanup attempt'
    [[ -z "$cleanup_error" ]] || fail "$cleanup_error"
    if [[ -e "$receipt_path" ]]; then
        fail "exact-head tooling receipt was claimed by another process and will not be overwritten: $receipt_path"
    fi
    fail 'could not create-only claim the exact-head tooling receipt'
fi

rm -rf "$install_root" || fail 'could not remove tool-installation temporary directory'
install_root=''
rmdir "$prep_lock" || fail 'could not release exact-head tool-preparation lock'
prep_lock=''
fsync_directory "$validation_directory" || fail 'could not sync validation directory after preparation-lock release'

printf 'NXB-153 fresh pinned Linux validation tools are ready.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Tool root: %s\n' "$tools_relative"
printf 'Tooling receipt: %s\n' "$receipt_path"

if [[ "$prepare_only" != "1" ]]; then
    exec bash "$repo_root/scripts/validate-nxb-153-linux.sh" "$repo_root"
fi
