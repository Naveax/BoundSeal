#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'NXB-153 Linux preparation authority wrapper failed: %s\n' "$1" >&2
    exit 1
}

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$repo_root"

for required_command in git bash python3; do
    type -P "$required_command" >/dev/null 2>&1 || fail "$required_command executable is unavailable"
done

git_application="$(type -P git)"
head_sha="$("$git_application" rev-parse HEAD)" || fail 'exact Git HEAD could not be resolved'
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD is not canonical SHA-1'
inner_object="$("$git_application" rev-parse "$head_sha:scripts/prepare-and-validate-nxb-153-linux-inner.sh")" ||
    fail 'committed Linux preparation inner implementation is missing'
[[ "$("$git_application" cat-file -t "$inner_object")" == blob ]] || fail 'Linux preparation inner implementation is not a Git blob'
inner_size="$("$git_application" cat-file -s "$inner_object")" || fail 'could not resolve Linux preparation inner implementation size'
[[ "$inner_size" =~ ^[0-9]+$ && "$inner_size" -gt 0 && "$inner_size" -le 1048576 ]] ||
    fail 'Linux preparation inner implementation size is outside the supported envelope'

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
        if "$git_application" "$@" | nxb_filter_git_status; then
            return 0
        fi
        printf '__NXB153_GIT_STATUS_INVALID__\n'
        return 0
    fi
    "$git_application" "$@"
}

# Source the exact committed implementation in this shell so every Python bootstrap,
# including legacy fsync/json helpers, is forced through the isolated-mode shim and
# both exact Git-status cleanliness checks are reduced to a bounded sentinel stream.
source <("$git_application" cat-file blob "$inner_object") '.'
