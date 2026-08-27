#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'NXB-153 bounded Linux H2 entrypoint failed: %s\n' "$1" >&2
    exit 1
}

resolve_blob() {
    local repo_anchor="$1" head_sha="$2" relative_path="$3" label="$4"
    local object object_type object_size
    object="$(git -C "$repo_anchor" rev-parse "$head_sha:$relative_path")" ||
        fail "$label is not committed at exact head: $relative_path"
    object_type="$(git -C "$repo_anchor" cat-file -t "$object")" ||
        fail "could not resolve committed $label object type"
    [[ "$object_type" == blob ]] || fail "committed $label is not a Git blob"
    object_size="$(git -C "$repo_anchor" cat-file -s "$object")" ||
        fail "could not resolve committed $label object size"
    [[ "$object_size" =~ ^[0-9]+$ && "$object_size" -gt 0 && "$object_size" -le 2097152 ]] ||
        fail "committed $label size is outside the supported implementation envelope"
    printf '%s' "$object"
}

[[ "$#" -ge 1 ]] || fail 'mode is required'
mode="$1"

for required_command in git python3 bash; do
    command -v "$required_command" >/dev/null 2>&1 || fail "$required_command is unavailable"
done

if [[ "$mode" == self-test ]]; then
    [[ "$#" -eq 1 ]] || fail 'self-test mode takes no arguments'
    repo_anchor="$(pwd -P)"
    head_sha="$(git -C "$repo_anchor" rev-parse HEAD)" || fail 'could not resolve exact Git HEAD'
elif [[ "$mode" == validate ]]; then
    [[ "$#" -eq 11 ]] || fail 'validate mode requires 10 arguments after the mode'
    head_sha="$2"
    repo_fd="$3"
    [[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact head is not canonical 40-hex SHA-1'
    [[ "$repo_fd" =~ ^[0-9]+$ ]] || fail 'repository descriptor number is invalid'
    repo_anchor="/proc/self/fd/$repo_fd"
    [[ -d "$repo_anchor" ]] || fail 'inherited repository descriptor is unavailable'
else
    fail "unknown mode: $mode"
fi

[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact head is not canonical 40-hex SHA-1'

inner_object="$(resolve_blob "$repo_anchor" "$head_sha" 'scripts/nxb-153-linux-immutable-source-h2-copy-inner.sh' 'Linux H2 inner runner')"
copy_object="$(resolve_blob "$repo_anchor" "$head_sha" 'scripts/nxb-153-rust-toolchain-snapshot-copy.py' 'bounded Rust snapshot-copy helper')"

git -C "$repo_anchor" cat-file blob "$copy_object" | python3 -I - self-test >/dev/null ||
    fail 'bounded Rust snapshot-copy helper self-test failed'

export NXB_H2_COPY_REPO_ANCHOR="$repo_anchor"
export NXB_H2_COPY_OBJECT="$copy_object"

cp() {
    if [[ "$#" -ne 4 || "$1" != '-a' || "$2" != '--no-preserve=ownership' ]]; then
        printf 'NXB-153 bounded Linux H2 copy shim rejected unexpected cp invocation\n' >&2
        return 91
    fi
    local source="$3"
    local destination="$4"
    local status=0
    git -C "${NXB_H2_COPY_REPO_ANCHOR:?}" cat-file blob "${NXB_H2_COPY_OBJECT:?}" |
        python3 -I - copy "$source" "$destination" --platform-model linux || status=$?
    unset -f cp
    return "$status"
}
export -f cp

git -C "$repo_anchor" cat-file blob "$inner_object" | bash -s -- "$@" ||
    fail 'bounded Linux H2 inner gate sequence failed'
