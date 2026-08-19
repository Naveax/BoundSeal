#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
legacy=""
orphan=""
cleanup() {
  [[ -n "$legacy" ]] && rm -rf -- "$legacy"
  [[ -n "$orphan" ]] && rm -rf -- "$orphan"
}
trap cleanup EXIT

cd "$repo_root"
head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'invalid Git HEAD' >&2; exit 1; }
[[ -z "$(git status --porcelain=v1)" ]] || { echo 'working tree must be clean' >&2; exit 1; }
[[ "$(rustc --version)" == rustc\ 1.97.1\ * ]] || { echo 'rustc 1.97.1 is required' >&2; exit 1; }

cargo fmt --all -- --check
cargo check -p bsl-core --bin bsl --all-features --locked
cargo clippy -p bsl-core --bin bsl --all-features --locked -- -D warnings
cargo test -p bsl-core --all-features --locked -- --test-threads=1
cargo build -p bsl-core --bin bsl --all-features --locked

bsl="$repo_root/target/debug/bsl"
fixture="$repo_root/fixtures/bsl-151/workspace-v0.json"
[[ -x "$bsl" && -f "$fixture" ]] || { echo 'migration acceptance inputs are missing' >&2; exit 1; }

legacy="$(mktemp -d -t bsl-151-migrate-XXXXXX)"
rmdir -- "$legacy"
"$bsl" workspace init --workspace "$legacy" --name 'Legacy Migration Acceptance' --json >/dev/null
cp -- "$fixture" "$legacy/workspace.json"
chmod 600 "$legacy/workspace.json"
"$bsl" workspace migrate status --workspace "$legacy" --json
"$bsl" workspace migrate apply --workspace "$legacy" --json
"$bsl" workspace migrate status --workspace "$legacy" --json

grep -q '"schema_version": 1' "$legacy/workspace.json"
grep -q '"secret_storage": "external_provider_only"' "$legacy/workspace.json"
[[ "$(find "$legacy/state/migrations" -maxdepth 1 -type f -name 'bsl-migration-*.json' | wc -l)" -eq 1 ]]
for transient in migration-active.json migration-source.json migration-applied.json; do
  [[ ! -e "$legacy/state/$transient" ]] || { echo "transient file remained: $transient" >&2; exit 1; }
done

orphan="$(mktemp -d -t bsl-151-orphan-XXXXXX)"
rmdir -- "$orphan"
"$bsl" workspace init --workspace "$orphan" --name 'Orphan Recovery Acceptance' --json >/dev/null
cp -- "$fixture" "$orphan/workspace.json"
chmod 600 "$orphan/workspace.json"
cp -- "$orphan/workspace.json" "$orphan/state/migration-source.json"
chmod 600 "$orphan/state/migration-source.json"
"$bsl" workspace migrate recover --workspace "$orphan" --json
"$bsl" workspace migrate status --workspace "$orphan" --json

grep -q '"schema_version": 1' "$orphan/workspace.json"
[[ "$(find "$orphan/state/migrations" -maxdepth 1 -type f -name 'bsl-migration-*.json' | wc -l)" -eq 1 ]]

output="$repo_root/target/bsl-validation/bsl-151-migration-linux-$head_sha.json"
mkdir -p "$(dirname "$output")"
python3 - "$output" "$head_sha" "$bsl" <<'PY'
import hashlib, json, pathlib, sys
out, head, binary = sys.argv[1:]
pathlib.Path(out).write_text(json.dumps({
    "schema_version": 1,
    "milestone": "BSL-151-migration",
    "platform": "linux",
    "head_sha": head,
    "bsl_binary_sha256": hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),
    "gates": [
        "fmt", "check", "clippy", "tests",
        "schema_0_to_1", "orphan_backup_recovery", "receipt_cleanup",
        "single_binary_dispatch"
    ]
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "BSL-151 single-binary migration Linux validation passed."
echo "HEAD: $head_sha"
echo "Evidence: $output"
