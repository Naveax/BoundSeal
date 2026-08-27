#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'NXB-153 immutable Linux source wrapper failed: %s\n' "$1" >&2
    exit 1
}

resolve_blob() {
    local repo_anchor="$1"
    local head_sha="$2"
    local relative_path="$3"
    local label="$4"
    local object
    local object_type
    local object_size

    object="$(git -C "$repo_anchor" rev-parse "$head_sha:$relative_path")" ||
        fail "$label is not committed at exact head $head_sha: $relative_path"
    object_type="$(git -C "$repo_anchor" cat-file -t "$object")" ||
        fail "could not resolve committed $label object type"
    [[ "$object_type" == 'blob' ]] || fail "committed $label is not a Git blob"
    object_size="$(git -C "$repo_anchor" cat-file -s "$object")" ||
        fail "could not resolve committed $label object size"
    [[ "$object_size" =~ ^[0-9]+$ && "$object_size" -gt 0 && "$object_size" -le 1048576 ]] ||
        fail "committed $label size is outside the supported 1..1048576-byte envelope"
    printf '%s' "$object"
}

run_python_blob() {
    local repo_anchor="$1"
    local object="$2"
    shift 2
    git -C "$repo_anchor" cat-file blob "$object" | python3 -I - "$@"
}

run_bash_blob() {
    local repo_anchor="$1"
    local object="$2"
    shift 2
    git -C "$repo_anchor" cat-file blob "$object" | bash -s -- "$@"
}

json_tree_sha256() {
    local payload="$1"
    python3 -I - "$payload" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
value = payload.get("tree_sha256")
if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
    raise SystemExit("invalid toolchain tree SHA-256")
print(value)
PY
}

[[ "$#" -ge 1 ]] || fail 'mode is required'
mode="$1"

if [[ "$mode" == 'self-test' ]]; then
    [[ "$#" -eq 1 ]] || fail 'self-test mode takes no arguments'
    head_sha="$(git rev-parse HEAD)" || fail 'could not resolve exact Git HEAD for self-test'
    [[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD is not canonical 40-hex'
    inner_object="$(resolve_blob '.' "$head_sha" 'scripts/nxb-153-linux-immutable-source-inner.sh' 'immutable Linux inner source runner')"
    authority_object="$(resolve_blob '.' "$head_sha" 'scripts/nxb-153-rust-toolchain-authority.py' 'host Rust toolchain authority helper')"
    run_python_blob '.' "$authority_object" self-test >/dev/null ||
        fail 'host Rust toolchain authority helper self-test failed'
    run_bash_blob '.' "$inner_object" self-test
    exit 0
fi

[[ "$mode" == 'validate' ]] || fail "unknown mode: $mode"
[[ "$#" -eq 11 ]] || fail 'validate mode requires 10 arguments after the mode'

head_sha="$2"
repo_fd="$3"
rust_toolchain="$4"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact head is not canonical 40-hex SHA-1'
[[ "$repo_fd" =~ ^[0-9]+$ ]] || fail 'repository descriptor number is invalid'
repo_anchor="/proc/self/fd/$repo_fd"
[[ -d "$repo_anchor" ]] || fail 'inherited repository descriptor is unavailable'

for required_command in git rustup python3 bash; do
    command -v "$required_command" >/dev/null 2>&1 || fail "$required_command is unavailable"
done

inner_object="$(resolve_blob "$repo_anchor" "$head_sha" 'scripts/nxb-153-linux-immutable-source-inner.sh' 'immutable Linux inner source runner')"
authority_object="$(resolve_blob "$repo_anchor" "$head_sha" 'scripts/nxb-153-rust-toolchain-authority.py' 'host Rust toolchain authority helper')"

run_python_blob "$repo_anchor" "$authority_object" self-test >/dev/null ||
    fail 'host Rust toolchain authority helper self-test failed before heavy gates'

sysroot_before="$(rustup run "$rust_toolchain" rustc --print sysroot)" ||
    fail "could not resolve Rust $rust_toolchain sysroot before heavy gates"
[[ -n "$sysroot_before" && -d "$sysroot_before" ]] ||
    fail 'Rust sysroot before heavy gates is unavailable'

toolchain_before_json="$(run_python_blob "$repo_anchor" "$authority_object" digest "$sysroot_before" --platform-model linux)" ||
    fail 'could not compute pre-gate Rust toolchain tree identity'
toolchain_before_sha256="$(json_tree_sha256 "$toolchain_before_json")" ||
    fail 'pre-gate Rust toolchain tree identity is invalid'

run_bash_blob "$repo_anchor" "$inner_object" "$@" ||
    fail 'immutable exact-head Linux source/dependency gate sequence failed'

sysroot_after="$(rustup run "$rust_toolchain" rustc --print sysroot)" ||
    fail "could not resolve Rust $rust_toolchain sysroot after heavy gates"
[[ "$sysroot_after" == "$sysroot_before" ]] ||
    fail 'Rust sysroot path changed across heavy gates'

run_python_blob "$repo_anchor" "$authority_object" verify \
    "$sysroot_after" \
    "$toolchain_before_sha256" \
    --platform-model linux >/dev/null ||
    fail 'Rust toolchain tree changed across heavy gates'

printf 'NXB-153 Linux host Rust toolchain H1 pre/post identity check passed; gate-lifetime immutability remains pending.\n'
