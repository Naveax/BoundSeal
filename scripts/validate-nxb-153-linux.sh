#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'NXB-153 Linux validation status guard failed: %s\n' "$1" >&2
    exit 1
}

read_blob_text_exact() {
    local object="$1" label="$2" output_name="$3"
    local payload sentinel=$'\036' captured_object
    [[ "$output_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || fail "$label output variable name is invalid"
    payload="$({
        "$nxb_guard_git_application" cat-file blob "$object" || exit $?
        printf '%s' "$sentinel"
    })" || fail "could not load exact-head $label bytes"
    [[ "${payload: -1}" == "$sentinel" ]] || fail "$label capture sentinel is missing"
    payload="${payload%$sentinel}"
    [[ -n "$payload" ]] || fail "$label source is empty"
    captured_object="$(printf '%s' "$payload" | "$nxb_guard_git_application" hash-object --stdin)" ||
        fail "could not hash captured exact-head $label bytes"
    [[ "$captured_object" == "$object" ]] ||
        fail "$label captured bytes differ from the selected exact-head Git blob"
    printf -v "$output_name" '%s' "$payload"
}

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$repo_root"

for required_command in git bash python3; do
    type -P "$required_command" >/dev/null 2>&1 || fail "$required_command executable is unavailable"
done

nxb_guard_git_application="$(type -P git)"
nxb_guard_head_sha="$("$nxb_guard_git_application" rev-parse HEAD)" ||
    fail 'exact Git HEAD could not be resolved'
[[ "$nxb_guard_head_sha" =~ ^[0-9a-f]{40}$ ]] ||
    fail 'exact Git HEAD is not canonical SHA-1'

nxb_guard_inner_relative='scripts/validate-nxb-153-linux-inner.sh'
nxb_guard_inner_object="$("$nxb_guard_git_application" rev-parse "$nxb_guard_head_sha:$nxb_guard_inner_relative")" ||
    fail 'committed Linux validator inner implementation is missing'
[[ "$nxb_guard_inner_object" =~ ^[0-9a-f]{40}$ ]] ||
    fail 'Linux validator inner object is not canonical SHA-1'
[[ "$("$nxb_guard_git_application" cat-file -t "$nxb_guard_inner_object")" == blob ]] ||
    fail 'Linux validator inner implementation is not a Git blob'
nxb_guard_inner_size="$("$nxb_guard_git_application" cat-file -s "$nxb_guard_inner_object")" ||
    fail 'could not resolve Linux validator inner implementation size'
[[ "$nxb_guard_inner_size" =~ ^[0-9]+$ && "$nxb_guard_inner_size" -gt 0 && "$nxb_guard_inner_size" -le 1048576 ]] ||
    fail 'Linux validator inner implementation size is outside the supported envelope'

nxb_guard_inner_source=''
read_blob_text_exact "$nxb_guard_inner_object" 'Linux validator inner implementation' nxb_guard_inner_source

python3() {
    command python3 -I "$@"
}
python3 -c 'import sys; raise SystemExit(0 if sys.flags.isolated == 1 else 71)' ||
    fail 'Python isolated-mode shim self-test failed'

nxb_filter_git_status() {
    local byte_limit="${1:-67108864}"
    local record_limit="${2:-4096}"
    python3 -c '
import sys

try:
    byte_limit = int(sys.argv[1], 10)
    record_limit = int(sys.argv[2], 10)
except ValueError:
    raise SystemExit(70)
if byte_limit <= 0 or record_limit <= 0:
    raise SystemExit(70)

total = 0
records = 0
dirty = False
last_ended_with_newline = True
while True:
    chunk = sys.stdin.buffer.read(65536)
    if not chunk:
        break
    dirty = True
    total += len(chunk)
    if total > byte_limit:
        print(
            f"NXB-153 Linux Git status stdout exceeds {byte_limit} bytes",
            file=sys.stderr,
        )
        raise SystemExit(72)
    records += chunk.count(b"\n")
    last_ended_with_newline = chunk.endswith(b"\n")
    if records > record_limit:
        print(
            f"NXB-153 Linux Git status stdout exceeds {record_limit} records",
            file=sys.stderr,
        )
        raise SystemExit(73)

if dirty and not last_ended_with_newline:
    records += 1
    if records > record_limit:
        print(
            f"NXB-153 Linux Git status stdout exceeds {record_limit} records",
            file=sys.stderr,
        )
        raise SystemExit(73)

if dirty:
    sys.stdout.write("__NXB153_DIRTY__\n")
' "$byte_limit" "$record_limit"
}

[[ -z "$(printf '' | nxb_filter_git_status)" ]] ||
    fail 'bounded Git status filter changed clean-output semantics'
[[ "$(printf '?? probe\n' | nxb_filter_git_status)" == '__NXB153_DIRTY__' ]] ||
    fail 'bounded Git status filter changed dirty-output semantics'
if printf 'abcde' | nxb_filter_git_status 4 4096 >/dev/null 2>&1; then
    fail 'bounded Git status filter did not reject oversized byte output'
fi
if printf 'a\nb\n' | nxb_filter_git_status 67108864 1 >/dev/null 2>&1; then
    fail 'bounded Git status filter did not reject excess records'
fi

git() {
    if [[ "$#" -eq 3 && "$1" == 'status' && "$2" == '--porcelain=v1' && "$3" == '--untracked-files=all' ]]; then
        if "$nxb_guard_git_application" "$@" | nxb_filter_git_status; then
            return 0
        fi
        printf '__NXB153_GIT_STATUS_INVALID__\n'
        return 0
    fi
    "$nxb_guard_git_application" "$@"
}

# Source only the complete, size-bounded exact-head validator bytes captured above.
# Git cat-file is no longer the asynchronous process-substitution producer, so a
# producer failure cannot degrade into a successfully sourced partial validator.
source <(printf '%s' "$nxb_guard_inner_source") '.'
unset nxb_guard_inner_source

nxb_guard_final_object="$("$nxb_guard_git_application" rev-parse "$nxb_guard_head_sha:$nxb_guard_inner_relative")" ||
    fail 'could not re-resolve Linux validator inner authority after validation'
[[ "$nxb_guard_final_object" == "$nxb_guard_inner_object" ]] ||
    fail 'Linux validator inner Git authority changed during validation'
