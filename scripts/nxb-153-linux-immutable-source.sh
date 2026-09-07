#!/usr/bin/env -S bash -p
set -euo pipefail

fail() {
    builtin printf 'NXB-153 bounded Linux H2 entrypoint failed: %s\n' "$1" >&2
    builtin exit 1
}

[[ "$-" == *p* ]] || fail 'Linux immutable-source entrypoint requires privileged Bash mode (-p)'

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
    builtin printf '%s' "$object"
}

read_blob_text_exact() {
    local repo_anchor="$1" object="$2" label="$3" output_name="$4"
    local payload sentinel=$'\036' captured_object
    [[ "$output_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || fail "$label output variable name is invalid"
    payload="$({
        git -C "$repo_anchor" cat-file blob "$object" || exit $?
        builtin printf '%s' "$sentinel"
    })" || fail "could not load exact-head $label bytes"
    [[ "${payload: -1}" == "$sentinel" ]] || fail "$label capture sentinel is missing"
    payload="${payload%$sentinel}"
    [[ -n "$payload" ]] || fail "$label source is empty"
    captured_object="$(builtin printf '%s' "$payload" | git -C "$repo_anchor" hash-object --stdin)" ||
        fail "could not hash captured exact-head $label bytes"
    [[ "$captured_object" == "$object" ]] ||
        fail "$label captured bytes differ from the selected exact-head Git blob"
    builtin printf -v "$output_name" '%s' "$payload"
}

[[ "$#" -ge 1 ]] || fail 'mode is required'
mode="$1"

for required_command in git python3 bash; do
    command -v "$required_command" >/dev/null 2>&1 || fail "$required_command is unavailable"
done
bash_application="$(type -P bash)" || fail 'bash executable could not be resolved'

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

environment_object="$(resolve_blob "$repo_anchor" "$head_sha" 'scripts/nxb-153-validation-environment.py' 'validation environment authority helper')"
envelope_object="$(resolve_blob "$repo_anchor" "$head_sha" 'scripts/nxb-153-linux-source-envelope.py' 'Linux source-envelope helper')"
inner_object="$(resolve_blob "$repo_anchor" "$head_sha" 'scripts/nxb-153-linux-immutable-source-h2-copy-inner.sh' 'Linux H2 inner runner')"
copy_object="$(resolve_blob "$repo_anchor" "$head_sha" 'scripts/nxb-153-rust-toolchain-snapshot-copy.py' 'bounded Rust snapshot-copy helper')"

# This runner is a canonical entrypoint in its own right. Re-audit the exact-head
# environment policy before any later non-privileged Bash child is allowed to import
# the intentionally exported trusted cp shim. In the normal validator path this is a
# redundant fail-closed check after the parent audit; for direct invocation it prevents
# BASH_ENV/exported-function startup authority from being deferred to the inner child.
git -C "$repo_anchor" cat-file blob "$environment_object" | python3 -I - self-test >/dev/null ||
    fail 'validation environment authority self-test failed at immutable-source entry'
git -C "$repo_anchor" cat-file blob "$environment_object" | python3 -I - audit >/dev/null ||
    fail 'ambient validation environment is not admitted at immutable-source entry'

envelope_code=''
read_blob_text_exact "$repo_anchor" "$envelope_object" 'Linux source-envelope helper' envelope_code
python3 -I -c "$envelope_code" self-test >/dev/null ||
    fail 'Linux source-envelope helper self-test failed'

git -C "$repo_anchor" ls-tree -r -t -l -z --full-tree "$head_sha" |
    python3 -I -c "$envelope_code" validate-tree >/dev/null ||
    fail 'exact-head Linux source tree exceeds the admitted source envelope'

git -C "$repo_anchor" archive --format=tar "$head_sha" |
    python3 -I -c "$envelope_code" validate-archive >/dev/null ||
    fail 'exact-head Linux source archive exceeds the admitted archive envelope'
unset envelope_code

git -C "$repo_anchor" cat-file blob "$copy_object" | python3 -I - self-test >/dev/null ||
    fail 'bounded Rust snapshot-copy helper self-test failed'

export NXB_H2_COPY_REPO_ANCHOR="$repo_anchor"
export NXB_H2_COPY_OBJECT="$copy_object"

cp() {
    if [[ "$#" -ne 4 || "$1" != '-a' || "$2" != '--no-preserve=ownership' ]]; then
        builtin printf 'NXB-153 bounded Linux H2 copy shim rejected unexpected cp invocation\n' >&2
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

# This child is intentionally non-privileged so it imports the exact trusted cp shim
# created above. Ambient Bash startup/function authority was rejected immediately
# before the shim was created, so the only admitted exported function is the one this
# exact-head runner intentionally supplies.
git -C "$repo_anchor" cat-file blob "$inner_object" | "$bash_application" -s -- "$@" ||
    fail 'bounded Linux H2 inner gate sequence failed'
