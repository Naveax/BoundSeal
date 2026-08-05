#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
workspace=""
output_dir=""
cleanup() {
  [[ -n "$workspace" ]] && rm -rf -- "$workspace"
  [[ -n "$output_dir" ]] && rm -rf -- "$output_dir"
}
trap cleanup EXIT

cd "$repo_root"
head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'invalid Git HEAD' >&2; exit 1; }
[[ -z "$(git status --porcelain=v1)" ]] || { echo 'working tree must be clean' >&2; exit 1; }
rustc_version="$(rustc --version)"
[[ "$rustc_version" == rustc\ 1.97.1\ * ]] || {
  printf 'expected rustc 1.97.1, found %s\n' "$rustc_version" >&2
  exit 1
}

cargo fmt --all -- --check
cargo check -p nxb-core --all-targets --all-features --locked
cargo clippy -p nxb-core --all-targets --all-features --locked -- -D warnings
cargo test -p nxb-core --all-features --locked -- --test-threads=1
cargo build -p nxb-core --bin nxb --all-features --locked

nxb="$repo_root/target/debug/nxb"
[[ -x "$nxb" ]] || { echo 'nxb binary is missing' >&2; exit 1; }

workspace="$(mktemp -d -t nxb-151-target-XXXXXX)"
rmdir -- "$workspace"
output_dir="$(mktemp -d -t nxb-151-target-output-XXXXXX)"

expect_exit() {
  local expected="$1"
  shift
  set +e
  "$@" >"$output_dir/expected-$expected.out" 2>"$output_dir/expected-$expected.err"
  local actual=$?
  set -e
  [[ $actual -eq $expected ]] || {
    printf 'command returned %s; expected %s: %q\n' "$actual" "$expected" "$*" >&2
    cat "$output_dir/expected-$expected.err" >&2 || true
    exit 1
  }
}

"$nxb" workspace init \
  --workspace "$workspace" \
  --name 'Target Linux Acceptance' \
  --json >"$output_dir/init.json"

"$nxb" target create \
  --workspace "$workspace" \
  --id example-app \
  --name 'Example App' \
  --origin 'https://example.org' \
  --include-path /api \
  --exclude-path /api/logout \
  --json >"$output_dir/create.json"
"$nxb" target list --workspace "$workspace" --json >"$output_dir/list.json"
"$nxb" target show --workspace "$workspace" --id example-app --json >"$output_dir/show.json"

python3 - "$output_dir" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
created = json.loads((root / 'create.json').read_text())
listed = json.loads((root / 'list.json').read_text())
shown = json.loads((root / 'show.json').read_text())
assert created['status'] == 'active'
assert created['origin'] == 'https://example.org'
assert created['allowed_methods'] == ['GET', 'HEAD', 'OPTIONS']
assert listed['status'] == 'ready'
assert listed['network_activity'] == 'none'
assert listed['count'] == 1
assert shown['target_id'] == 'example-app'
assert shown['include_paths'] == ['/api']
assert shown['exclude_paths'] == ['/api/logout']
PY

for origin in \
  'http://example.org' \
  'https://user@example.org' \
  'https://127.0.0.1' \
  'https://service.internal' \
  'https://*.example.org'; do
  expect_exit 50 "$nxb" target create \
    --workspace "$workspace" \
    --id invalid-origin \
    --name 'Invalid Origin' \
    --origin "$origin" \
    --json
done
expect_exit 50 "$nxb" target create \
  --workspace "$workspace" \
  --id invalid-path \
  --name 'Invalid Path' \
  --origin 'https://example.org' \
  --include-path '/api%2fadmin' \
  --json

profile="$workspace/targets/example-app.json"
receipt="$workspace/targets/example-app.disabled.json"
[[ "$(stat -c '%a' "$profile")" == '600' ]] || { echo 'target profile mode is not 0600' >&2; exit 1; }
cp -- "$profile" "$output_dir/profile.original"
python3 - "$profile" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
value['origin'] = 'https://attacker.invalid'
path.write_text(json.dumps(value, indent=2) + '\n')
PY
chmod 600 "$profile"
expect_exit 52 "$nxb" target show --workspace "$workspace" --id example-app --json
cp -- "$output_dir/profile.original" "$profile"
chmod 600 "$profile"

"$nxb" target disable \
  --workspace "$workspace" \
  --id example-app \
  --reason operator-hold \
  --json >"$output_dir/disable.json"
"$nxb" target list --workspace "$workspace" --json >"$output_dir/active.json"
"$nxb" target list --workspace "$workspace" --include-disabled --json >"$output_dir/all.json"
[[ "$(stat -c '%a' "$receipt")" == '600' ]] || { echo 'disable receipt mode is not 0600' >&2; exit 1; }

python3 - "$output_dir" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
disabled = json.loads((root / 'disable.json').read_text())
active = json.loads((root / 'active.json').read_text())
all_targets = json.loads((root / 'all.json').read_text())
assert disabled['status'] == 'disabled'
assert disabled['disabled_reason'] == 'operator_hold'
assert active['count'] == 0
assert all_targets['count'] == 1
assert all_targets['targets'][0]['status'] == 'disabled'
PY

cp -- "$receipt" "$output_dir/receipt.original"
python3 - "$receipt" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
value['profile_sha256'] = '0' * 64
path.write_text(json.dumps(value, indent=2) + '\n')
PY
chmod 600 "$receipt"
expect_exit 52 "$nxb" target show --workspace "$workspace" --id example-app --json
cp -- "$output_dir/receipt.original" "$receipt"
chmod 600 "$receipt"

printf '{}\n' >"$workspace/state/migration-active.json"
chmod 600 "$workspace/state/migration-active.json"
expect_exit 51 "$nxb" target list --workspace "$workspace" --json
rm -f -- "$workspace/state/migration-active.json"
"$nxb" target show --workspace "$workspace" --id example-app --json >/dev/null

validation_dir="$repo_root/target/nxb-validation"
mkdir -p -- "$validation_dir"
evidence="$validation_dir/nxb-151-target-linux-$head_sha.json"
python3 - "$evidence" "$head_sha" "$rustc_version" "$nxb" <<'PY'
import hashlib, json, pathlib, sys
output, head, rustc, binary = sys.argv[1:]
value = {
    'schema_version': 1,
    'milestone': 'NXB-151',
    'gate': 'target_profiles',
    'platform': 'linux',
    'head_sha': head,
    'rustc': rustc,
    'binary_sha256': hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),
    'checks': {
        'create_list_show_disable': 'passed',
        'origin_and_path_rejection': 'passed',
        'profile_tamper_rejection': 'passed',
        'receipt_tamper_rejection': 'passed',
        'pending_migration_exit_51': 'passed',
        'private_file_modes': 'passed',
        'network_activity': 'none',
    },
}
pathlib.Path(output).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
PY

printf 'NXB-151 target Linux validation passed.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Evidence: %s\n' "$evidence"
