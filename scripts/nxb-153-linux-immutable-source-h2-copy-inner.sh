#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'NXB-153 Linux Rust H2 snapshot wrapper failed: %s\n' "$1" >&2
    exit 1
}

resolve_blob() {
    local repo_anchor="$1" head_sha="$2" relative_path="$3" label="$4"
    local object object_type object_size
    object="$(git -C "$repo_anchor" rev-parse "$head_sha:$relative_path")" || fail "$label is not committed at exact head"
    object_type="$(git -C "$repo_anchor" cat-file -t "$object")" || fail "could not resolve $label type"
    [[ "$object_type" == blob ]] || fail "$label is not a Git blob"
    object_size="$(git -C "$repo_anchor" cat-file -s "$object")" || fail "could not resolve $label size"
    [[ "$object_size" =~ ^[0-9]+$ && "$object_size" -gt 0 && "$object_size" -le 1048576 ]] || fail "$label size is outside the supported envelope"
    printf '%s' "$object"
}

run_python_blob() {
    local repo_anchor="$1" object="$2"
    shift 2
    git -C "$repo_anchor" cat-file blob "$object" | python3 -I - "$@"
}

run_bash_blob() {
    local repo_anchor="$1" object="$2"
    shift 2
    git -C "$repo_anchor" cat-file blob "$object" | bash -s -- "$@"
}

json_tree_sha256() {
    local payload="$1"
    python3 -I - "$payload" <<'PY'
import json, sys
value = json.loads(sys.argv[1]).get("tree_sha256")
if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
    raise SystemExit("invalid tree SHA-256")
print(value)
PY
}

snapshot_primitive_self_test() {
    local root host snapshot shim
    root="$(mktemp -d)" || fail 'could not create H2 self-test root'
    host="$root/host"
    snapshot="$root/snapshot"
    shim="$root/shim"
    mkdir -p "$host/bin" "$host/lib" "$snapshot" "$shim"
    cat > "$host/bin/rustc" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
case "${1:-}" in
  --version) printf 'rustc 1.97.1 (fake)\n' ;;
  --print) [[ "${2:-}" == sysroot ]] || exit 70; printf '%s\n' "$root" ;;
  *) exit 71 ;;
esac
SH
    cat > "$host/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${RUSTC:-}" == "${NXB_RUST_SNAPSHOT_ROOT:?}/bin/rustc" ]] || exit 72
printf 'SNAPSHOT_CARGO_OK\n'
SH
    for component in rustdoc rustfmt cargo-fmt cargo-clippy clippy-driver; do
        printf '#!/usr/bin/env bash\nexit 0\n' > "$host/bin/$component"
    done
    printf trusted > "$host/lib/core.rlib"
    chmod +x "$host/bin/"*

    if ! unshare --user --map-root-user --mount --pid --fork bash -s -- "$host" "$snapshot" "$shim" <<'CHILD'
set -euo pipefail
host="$1"; snapshot="$2"; shim="$3"
mount --make-rprivate /
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$snapshot"
cp -a --no-preserve=ownership "$host/." "$snapshot/"
[[ "$(cat "$snapshot/lib/core.rlib")" == trusted ]]
printf changed > "$host/lib/core.rlib"
[[ "$(cat "$snapshot/lib/core.rlib")" == trusted ]]
mount -o remount,ro,nosuid,nodev "$snapshot"
if touch "$snapshot/.write-probe" 2>/dev/null; then exit 73; fi
if unshare --user --map-root-user --mount --pid --fork bash -c 'mount -o remount,rw "$1" 2>/dev/null' bash "$snapshot"; then exit 77; fi
[[ "$("$snapshot/bin/rustc" --print sysroot)" == "$snapshot" ]]
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$shim"
cat > "$shim/rustup" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -ge 3 && "$1" == run && "$2" == "${NXB_RUST_TOOLCHAIN:?}" ]] || exit 74
tool="$3"; shift 3
case "$tool" in
  rustc) exec "${NXB_RUST_SNAPSHOT_ROOT:?}/bin/rustc" "$@" ;;
  cargo)
    export RUSTC="${NXB_RUST_SNAPSHOT_ROOT:?}/bin/rustc"
    export RUSTDOC="${NXB_RUST_SNAPSHOT_ROOT:?}/bin/rustdoc"
    export PATH="${NXB_RUST_SNAPSHOT_ROOT:?}/bin:${NXB_H2_HOST_PATH:?}"
    exec "${NXB_RUST_SNAPSHOT_ROOT:?}/bin/cargo" "$@"
    ;;
  *) exit 75 ;;
esac
SHIM
chmod 755 "$shim/rustup"
mount -o remount,ro,nosuid,nodev "$shim"
if printf x >> "$shim/rustup" 2>/dev/null; then exit 76; fi
export NXB_RUST_SNAPSHOT_ROOT="$snapshot" NXB_RUST_TOOLCHAIN='1.97.1' NXB_H2_HOST_PATH="$PATH"
export PATH="$shim:$snapshot/bin:$PATH"
[[ "$(rustup run 1.97.1 rustc --print sysroot)" == "$snapshot" ]]
[[ "$(rustup run 1.97.1 cargo --version)" == SNAPSHOT_CARGO_OK ]]
CHILD
    then
        rm -rf "$root"
        fail 'H2 private snapshot/shim primitive self-test failed'
    fi
    [[ ! -e "$snapshot/bin/rustc" ]] || { rm -rf "$root"; fail 'H2 private snapshot leaked into caller mount namespace'; }
    rmdir "$snapshot" "$shim" || { rm -rf "$root"; fail 'H2 self-test mountpoint cleanup failed'; }
    rm -rf "$root"
}

[[ "$#" -ge  1 ]] || fail 'mode is required'
mode="$1"

for required_command in git bash python3 unshare mount cp mktemp; do
    command -v "$required_command" >/dev/null 2>&1 || fail "$required_command is unavailable"
done

if [[ "$mode" == self-test ]]; then
    [[ "$#" -eq 1 ]] || fail 'self-test mode takes no arguments'
    head_sha="$(git rev-parse HEAD)" || fail 'could not resolve exact Git HEAD'
    h1_object="$(resolve_blob '.' "$head_sha" 'scripts/nxb-153-linux-immutable-source-h1-inner.sh' 'Linux H1 wrapper')"
    authority_object="$(resolve_blob '.' "$head_sha" 'scripts/nxb-153-rust-toolchain-authority.py' 'host Rust authority helper')"
    run_python_blob '.' "$authority_object" self-test >/dev/null || fail 'host Rust authority self-test failed'
    run_bash_blob '.' "$h1_object" self-test >/dev/null || fail 'Linux H1 wrapper self-test failed'
    snapshot_primitive_self_test
    printf 'NXB-153 Linux Rust H2 private snapshot primitive self-test passed.\n'
    exit 0
fi

[[ "$mode" == validate ]] || fail "unknown mode: $mode"
command -v rustup >/dev/null 2>&1 || fail 'rustup is unavaile'
[[ "$#" -eq 11 ]] || fail 'validate mode requires 10 arguments after the mode'
head_sha="$2"; repo_fd="$3"; rust_toolchain="$4"
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact head is not canonical SHA-1'
[[ "$repo_fd" =~ ^[0-9]+$ ]] || fail 'repository descriptor is invalid'
[[ "$rust_toolchain" == 1.97.1 ]] || fail 'only Rust 1.97.1 is admitted'
repo_anchor="/proc/self/fd/$repo_fd"
[[ -d "$repo_anchor" ]] || fail 'repository descriptor is unavailable'

h1_object="$(resolve_blob "$repo_anchor" "$head_sha" 'scripts/nxb-153-linux-immutable-source-h1-inner.sh' 'Linux H1 wrapper')"
authority_object="$(resolve_blob "$repo_anchor" "$head_sha" 'scripts/nxb-153-rust-toolchain-authority.py' 'host Rust authority helper')"
run_python_blob "$repo_anchor" "$authority_object" self-test >/dev/null || fail 'host Rust authority self-test failed before H2 capture'

host_rustup="$(type -P rustup)" || fail 'host rustup executable could not be resolved'
host_sysroot="$("$host_rustup" run "$rust_toolchain" rustc --print sysroot)" || fail 'could not resolve host Rust sysroot'
[[ "$host_sysroot" == /* && -d "$host_sysroot" ]] || fail 'host Rust sysroot is not an absolute directory'
host_json="$(run_python_blob "$repo_anchor" "$authority_object" digest "$host_sysroot" --platform-model linux)" || fail 'could not digest host Rust tree before H2 capture'
expected_sha="$(json_tree_sha256 "$host_json")" || fail 'host Rust tree digest is invalid'

snapshot_mount="$(mktemp -d)" || fail 'could not create H2 snapshot mountpoint'
shim_mount="$(mktemp -d)" || { rmdir "$snapshot_mount"; fail 'could not create H2 shim mountpoint'; }
cleanup_mountpoints() {
    local rc=0
    rmdir "$snapshot_mount" 2>/dev/null || rc=1
    rmdir "$shim_mount" 2>/dev/null || rc=1
    return "$rc"
}
trap 'cleanup_mountpoints || true' EXIT

unshare --user --map-root-user --mount --pid --fork bash -s -- \
    "$host_sysroot" "$snapshot_mount" "$shim_mount" "$expected_sha" "$rust_toolchain" \
    "$repo_fd" "$authority_object" "$h1_object" "$@" <<'CHILD'
set -euo pipefail
host_sysroot="$1"; snapshot="$2"; shim="$3"; expected_sha="$4"; rust_toolchain="$5"
repo_fd="$6"; authority_object="$7"; h1_object="$8"; shift 8
inner_args=("$@")
repo_anchor="/proc/self/fd/$repo_fd"
[[ -d "$repo_anchor" ]] || { echo 'H2 child lost repository descriptor' >&2; exit 80; }
mount --make-rprivate /
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$snapshot"
cp -a --no-preserve=ownership "$host_sysroot/." "$snapshot/"
git -C "$repo_anchor" cat-file blob "$authority_object" | python3 -I - verify "$snapshot" "$expected_sha" --platform-model linux >/dev/null
for component in cargo rustc rustdoc rustfmt cargo-fmt cargo-clippy clippy-driver; do
    [[ -f "$snapshot/bin/$component" && -x "$snapshot/bin/$component" && ! -L "$snapshot/bin/$component" ]] || {
        echo "H2 snapshot missing regular executable component: $component" >&2; exit 81;
    }
done
mount -o remount,ro,nosuid,nodev "$snapshot"
if touch "$snapshot/.nxb-h2-write-probe" 2>/dev/null; then echo 'H2 Rust snapshot remained writable' >&2; exit 82; fi
if unshare --user --map-root-user --mount --pid --fork bash -c 'mount -o remount,rw "$1" 2>/dev/null' bash "$snapshot"; then
    echo 'nested validation namespace could remount parent H2 Rust snapshot writable' >&2; exit 88
fi
snapshot_sysroot="$("$snapshot/bin/rustc" --print sysroot)"
[[ "$snapshot_sysroot" == "$snapshot" ]] || { echo "relocated rustc sysroot escaped H2 snapshot: $snapshot_sysroot" >&2; exit 83; }
[[ "$("$snapshot/bin/rustc" --version)" == rustc\ 1.97.1\ * ]] || { echo 'snapshot rustc version mismatch' >&2; exit 84; }

mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$shim"
cat > "$shim/rustup" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -ge 3 && "$1" == run && "$2" == "${NXB_RUST_TOOLCHAIN:?}" ]] || exit 90
tool="$3"; shift 3
case "$tool" in
  rustc) exec "${NXB_RUST_SNAPSHOT_ROOT:?}/bin/rustc" "$@" ;;
  cargo)
    export RUSTC="${NXB_RUST_SNAPSHOT_ROOT:?}/bin/rustc"
    export RUSTDOC="${NXB_RUST_SNAPSHOT_ROOT:?}/bin/rustdoc"
    export PATH="${NXB_RUST_SNAPSHOT_ROOT:?}/bin:${NXB_H2_HOST_PATH:?}"
    exec "${NXB_RUST_SNAPSHOT_ROOT:?}/bin/cargo" "$@"
    ;;
  *) exit 91 ;;
esac
SHIM
chmod 755 "$shim/rustup"
mount -o remount,ro,nosuid,nodev "$shim"
if printf x >> "$shim/rustup" 2>/dev/null; then echo 'H2 rustup shim remained writable' >&2; exit 85; fi

export NXB_RUST_SNAPSHOT_ROOT="$snapshot"
export NXB_RUST_TOOLCHAIN="$rust_toolchain"
export NXB_H2_HOST_PATH="$PATH"
export PATH="$shim:$snapshot/bin:$PATH"
[[ "$(rustup run "$rust_toolchain" rustc --print sysroot)" == "$snapshot" ]] || { echo 'H2 hard rustup shim did not resolve snapshot rustc' >&2; exit 86; }
git -C "$repo_anchor" cat-file blob "$h1_object" | bash -s -- "${inner_args[@]}"
git -C "$repo_anchor" cat-file blob "$authority_object" | python3 -I - verify "$snapshot" "$expected_sha" --platform-model linux >/dev/null
if touch "$snapshot/.nxb-h2-final-write-probe" 2>/dev/null; then echo 'H2 Rust snapshot became writable after gates' >&2; exit 87; fi
CHILD

cleanup_mountpoints || fail 'H2 private mountpoint cleanup failed after validation'
trap - EXIT
printf 'NXB-153 Linux H2 heavy gates consumed a verified private read-only Rust toolchain snapshot.\n'
printf 'Host capture tree SHA-256: %s\n' "$expected_sha"
