#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
prepare_only="${NXB_PREPARE_ONLY:-0}"
rust_toolchain="1.97.1"
cargo_audit_version="0.22.2"
cargo_deny_version="0.20.2"
tools_root="$repo_root/target/nxb-tools"
tools_bin="$tools_root/bin"

fail() {
    printf 'NXB-153 Linux tool preparation failed: %s\n' "$1" >&2
    exit 1
}

command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v rustup >/dev/null 2>&1 ||
    fail 'rustup is unavailable; install rustup from the official Rust distribution first'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'

cd "$repo_root"
head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD could not be resolved'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree must be clean before tool preparation'

rustup toolchain install "$rust_toolchain" \
    --profile minimal \
    --component rustfmt \
    --component clippy

mkdir -p "$tools_root"
audit_path="$tools_bin/cargo-audit"
deny_path="$tools_bin/cargo-deny"

tool_has_version() {
    local path="$1"
    local expected="$2"
    [[ -x "$path" ]] || return 1
    "$path" --version 2>/dev/null | grep -Eq "(^|[[:space:]])${expected}($|[[:space:]])"
}

install_root="$(mktemp -d)"
cleanup() {
    rm -rf "$install_root"
}
trap cleanup EXIT
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

validation_directory="$repo_root/target/nxb-validation"
mkdir -p "$validation_directory"
receipt_path="$validation_directory/nxb-153-tooling-linux-$head_sha.json"
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
  "tools_root": "target/nxb-tools",
  "network_activity": "rustup_and_crates_io_tool_installation_only",
  "prepared_at": "$prepared_at"
}
JSON

if ln "$receipt_temp" "$receipt_path" 2>/dev/null; then
    rm -f "$receipt_temp" || fail 'could not remove claimed tooling receipt temporary link'
else
    rm -f "$receipt_temp" || fail 'could not remove unclaimed tooling receipt temporary file'
    if [[ -e "$receipt_path" ]]; then
        fail "exact-head tooling receipt already exists and will not be overwritten: $receipt_path; run the validator directly with the existing receipt, or review/remove it explicitly before preparing again"
    fi
    fail 'could not create-only claim the exact-head tooling receipt'
fi

printf 'NXB-153 fresh pinned Linux validation tools are ready.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Tooling receipt: %s\n' "$receipt_path"

if [[ "$prepare_only" != "1" ]]; then
    exec bash "$repo_root/scripts/validate-nxb-153-linux.sh" "$repo_root"
fi
