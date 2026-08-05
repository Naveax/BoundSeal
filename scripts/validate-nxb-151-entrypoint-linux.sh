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
cargo build -p nxb-core --bins --all-features --locked

nxb="$repo_root/target/debug/nxb"
product="$repo_root/target/debug/nxb-product"
migrate="$repo_root/target/debug/nxb-workspace-migrate"
for binary in "$nxb" "$product" "$migrate"; do
  [[ -x "$binary" ]] || { printf 'required binary is missing: %s\n' "$binary" >&2; exit 1; }
done

workspace="$(mktemp -d -t nxb-151-entrypoint-XXXXXX)"
rmdir -- "$workspace"
output_dir="$(mktemp -d -t nxb-151-entrypoint-output-XXXXXX)"

"$nxb" workspace init --workspace "$workspace" --name 'Unified Linux Acceptance' --json > "$output_dir/init.json"
"$nxb" workspace doctor --workspace "$workspace" --json > "$output_dir/doctor.json"
"$nxb" workspace status --workspace "$workspace" --json > "$output_dir/status.json"
"$nxb" workspace migrate status --workspace "$workspace" --json > "$output_dir/migration.json"

python3 - "$output_dir" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
doctor = json.loads((root / 'doctor.json').read_text())
status = json.loads((root / 'status.json').read_text())
migration = json.loads((root / 'migration.json').read_text())
assert doctor['status'] == 'healthy'
assert doctor['migration']['status'] == 'stable'
assert any(check['name'] == 'migration_state' and check['status'] == 'pass' for check in doctor['checks'])
assert status['status'] == 'ready'
assert status['migration']['status'] == 'stable'
assert migration['status'] == 'stable'
PY

printf '{}\n' > "$workspace/state/migration-active.json"
chmod 0600 "$workspace/state/migration-active.json"
set +e
"$nxb" workspace doctor --workspace "$workspace" --json > "$output_dir/doctor-pending.json" 2> "$output_dir/doctor-pending.err"
doctor_exit=$?
"$nxb" workspace status --workspace "$workspace" --json > "$output_dir/status-pending.json" 2> "$output_dir/status-pending.err"
status_exit=$?
set -e
[[ $doctor_exit -eq 20 ]] || { printf 'pending doctor returned %s; expected 20\n' "$doctor_exit" >&2; exit 1; }
[[ $status_exit -eq 30 ]] || { printf 'pending status returned %s; expected 30\n' "$status_exit" >&2; exit 1; }
python3 - "$output_dir" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
doctor = json.loads((root / 'doctor-pending.json').read_text())
status = json.loads((root / 'status-pending.json').read_text())
assert doctor['status'] == 'unhealthy'
assert doctor['migration']['status'] == 'recovery_required'
assert any(check['name'] == 'migration_state' and check['status'] == 'fail' for check in doctor['checks'])
assert status['status'] == 'recovery_required'
assert status['migration']['status'] == 'recovery_required'
PY
rm -f -- "$workspace/state/migration-active.json"
"$nxb" workspace doctor --workspace "$workspace" --json > /dev/null

validation_dir="$repo_root/target/nxb-validation"
mkdir -p -- "$validation_dir"
evidence="$validation_dir/nxb-151-entrypoint-linux-$head_sha.json"
python3 - "$evidence" "$head_sha" "$rustc_version" "$nxb" "$product" "$migrate" <<'PY'
import hashlib
import json
import pathlib
import sys
output, head, rustc, *binaries = sys.argv[1:]
def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
value = {
    'schema_version': 1,
    'milestone': 'NXB-151',
    'gate': 'unified_entrypoint',
    'platform': 'linux',
    'head_sha': head,
    'rustc': rustc,
    'binaries': {pathlib.Path(path).name: digest(path) for path in binaries},
    'checks': {
        'workspace_init': 'passed',
        'combined_doctor': 'passed',
        'combined_status': 'passed',
        'migration_status': 'passed',
        'pending_doctor_exit_20': 'passed',
        'pending_status_exit_30': 'passed',
    },
}
pathlib.Path(output).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
PY

printf 'NXB-151 unified Linux entrypoint validation passed.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Evidence: %s\n' "$evidence"
