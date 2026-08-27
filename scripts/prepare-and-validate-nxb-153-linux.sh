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

head_sha="$(git rev-parse HEAD)" || fail 'exact Git HEAD could not be resolved'
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD is not canonical SHA-1'
inner_object="$(git rev-parse "$head_sha:scripts/prepare-and-validate-nxb-153-linux-inner.sh")" ||
    fail 'committed Linux preparation inner implementation is missing'
[[ "$(git cat-file -t "$inner_object")" == blob ]] || fail 'Linux preparation inner implementation is not a Git blob'
inner_size="$(git cat-file -s "$inner_object")" || fail 'could not resolve Linux preparation inner implementation size'
[[ "$inner_size" =~ ^[0-9]+$ && "$inner_size" -gt 0 && "$inner_size" -le 1048576 ]] ||
    fail 'Linux preparation inner implementation size is outside the supported envelope'

python3() {
    command python3 -I "$@"
}
python3 -c 'import sys; raise SystemExit(0 if sys.flags.isolated == 1 else 71)' ||
    fail 'Python isolated-mode shim self-test failed'

# Source the exact committed implementation in this shell so every Python bootstrap,
# including legacy fsync/json helpers, is forced through the isolated-mode shim.
source <(git cat-file blob "$inner_object") '.'
