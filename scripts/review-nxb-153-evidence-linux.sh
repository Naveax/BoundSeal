#!/usr/bin/env -S bash -p
set -euo pipefail

nxb_guard_fail() {
    builtin printf 'NXB-153 Linux evidence-review status guard failed: %s\n' "$1" >&2
    builtin exit 1
}

[[ "$-" == *p* ]] || nxb_guard_fail 'canonical Linux evidence review requires privileged Bash mode (-p)'

nxb_guard_git_environment=("${!GIT_@}")
[[ "${#nxb_guard_git_environment[@]}" -eq 0 ]] ||
    nxb_guard_fail "ambient Git authority variables are not admitted before exact-head resolution: ${nxb_guard_git_environment[*]}"
builtin unset nxb_guard_git_environment

read_blob_text_exact() {
    local object="$1" label="$2" output_name="$3"
    local payload sentinel=$'\036' captured_object
    [[ "$output_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || nxb_guard_fail "$label output variable name is invalid"
    payload="$({
        "$nxb_guard_git_application" cat-file blob "$object" || exit $?
        builtin printf '%s' "$sentinel"
    })" || nxb_guard_fail "could not load exact-head $label bytes"
    [[ "${payload: -1}" == "$sentinel" ]] || nxb_guard_fail "$label capture sentinel is missing"
    payload="${payload%$sentinel}"
    [[ -n "$payload" ]] || nxb_guard_fail "$label source is empty"
    captured_object="$(builtin printf '%s' "$payload" | "$nxb_guard_git_application" hash-object --stdin)" ||
        nxb_guard_fail "could not hash captured exact-head $label bytes"
    [[ "$captured_object" == "$object" ]] ||
        nxb_guard_fail "$label captured bytes differ from the selected exact-head Git blob"
    builtin printf -v "$output_name" '%s' "$payload"
}

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
evidence_directory="${2:-$repo_root/target/nxb-validation}"
cd "$repo_root"

for required_command in git bash python3; do
    type -P "$required_command" >/dev/null 2>&1 || nxb_guard_fail "$required_command executable is unavailable"
done

nxb_guard_git_application="$(type -P git)"
nxb_guard_python_application="$(type -P python3)"
nxb_guard_head_sha="$("$nxb_guard_git_application" rev-parse HEAD)" ||
    nxb_guard_fail 'exact Git HEAD could not be resolved'
[[ "$nxb_guard_head_sha" =~ ^[0-9a-f]{40}$ ]] ||
    nxb_guard_fail 'exact Git HEAD is not canonical SHA-1'

nxb_guard_inner_relative='scripts/review-nxb-153-evidence-linux-inner.sh'
nxb_guard_inner_object="$("$nxb_guard_git_application" rev-parse "$nxb_guard_head_sha:$nxb_guard_inner_relative")" ||
    nxb_guard_fail 'committed Linux evidence-review inner implementation is missing'
[[ "$nxb_guard_inner_object" =~ ^[0-9a-f]{40}$ ]] ||
    nxb_guard_fail 'Linux evidence-review inner object is not canonical SHA-1'
[[ "$("$nxb_guard_git_application" cat-file -t "$nxb_guard_inner_object")" == blob ]] ||
    nxb_guard_fail 'Linux evidence-review inner implementation is not a Git blob'
nxb_guard_inner_size="$("$nxb_guard_git_application" cat-file -s "$nxb_guard_inner_object")" ||
    nxb_guard_fail 'could not resolve Linux evidence-review inner implementation size'
[[ "$nxb_guard_inner_size" =~ ^[0-9]+$ && "$nxb_guard_inner_size" -gt 0 && "$nxb_guard_inner_size" -le 1048576 ]] ||
    nxb_guard_fail 'Linux evidence-review inner implementation size is outside the supported envelope'

nxb_guard_inner_source=''
read_blob_text_exact "$nxb_guard_inner_object" 'Linux evidence-review inner implementation' nxb_guard_inner_source

nxb_filter_git_status() {
    local byte_limit="${1:-67108864}"
    local record_limit="${2:-4096}"
    "$nxb_guard_python_application" -I -c '
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

[[ -z "$(builtin printf '' | nxb_filter_git_status)" ]] ||
    nxb_guard_fail 'bounded Git status filter changed clean-output semantics'
[[ "$(builtin printf '?? probe\n' | nxb_filter_git_status)" == '__NXB153_DIRTY__' ]] ||
    nxb_guard_fail 'bounded Git status filter changed dirty-output semantics'
if builtin printf 'abcde' | nxb_filter_git_status 4 4096 >/dev/null 2>&1; then
    nxb_guard_fail 'bounded Git status filter did not reject oversized byte output'
fi
if builtin printf 'a\nb\n' | nxb_filter_git_status 67108864 1 >/dev/null 2>&1; then
    nxb_guard_fail 'bounded Git status filter did not reject excess records'
fi

git() {
    if [[ "$#" -eq 3 && "$1" == 'status' && "$2" == '--porcelain=v1' && "$3" == '--untracked-files=all' ]]; then
        if "$nxb_guard_git_application" "$@" | nxb_filter_git_status; then
            return 0
        fi
        builtin printf '__NXB153_GIT_STATUS_INVALID__\n'
        return 0
    fi
    "$nxb_guard_git_application" "$@"
}

# Execute the exact captured/OID-verified review implementation from the same
# in-memory string. Positional arguments reproduce the former source-with-args
# contract without creating another asynchronous producer.
set -- "$repo_root" "$evidence_directory"
builtin eval "$nxb_guard_inner_source"
builtin unset nxb_guard_inner_source

nxb_guard_final_object="$("$nxb_guard_git_application" rev-parse "$nxb_guard_head_sha:$nxb_guard_inner_relative")" ||
    nxb_guard_fail 'could not re-resolve Linux evidence-review inner authority after review'
[[ "$nxb_guard_final_object" == "$nxb_guard_inner_object" ]] ||
    nxb_guard_fail 'Linux evidence-review inner Git authority changed during review'
