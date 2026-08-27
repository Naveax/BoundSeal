#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'NXB-153 immutable Linux source runner failed: %s\n' "$1" >&2
    exit 1
}

require_commands() {
    local required_command
    for required_command in git unshare mount tar find grep sha256sum awk touch python3 rustup; do
        command -v "$required_command" >/dev/null 2>&1 || fail "$required_command is unavailable"
    done
}

cleanup_mountpoint() {
    local path="$1"
    [[ -n "$path" ]] || return 0
    rm -rf "$path" 2>/dev/null || true
}

self_test() {
    require_commands
    local mountpoint
    mountpoint="$(mktemp -d)" || fail 'could not create primitive self-test mountpoint'
    trap 'cleanup_mountpoint "$mountpoint"' RETURN

    unshare --user --map-root-user --mount --pid --fork bash -c '
        set -euo pipefail
        mountpoint="$1"
        mount --make-rprivate /
        mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs "$mountpoint"
        printf trusted > "$mountpoint/trusted.txt"
        mkdir "$mountpoint/target" "$mountpoint/tmp"
        mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs "$mountpoint/target"
        mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs "$mountpoint/tmp"
        mount -o remount,ro,nosuid,nodev "$mountpoint"
        [[ "$(cat "$mountpoint/trusted.txt")" == trusted ]]
        if printf changed > "$mountpoint/trusted.txt" 2>/dev/null; then
            exit 71
        fi
        printf build > "$mountpoint/target/build.txt"
        printf temporary > "$mountpoint/tmp/temp.txt"
        [[ "$(cat "$mountpoint/target/build.txt")" == build ]]
        [[ "$(cat "$mountpoint/tmp/temp.txt")" == temporary ]]
    ' bash "$mountpoint" || fail 'user/mount namespace private read-only tmpfs self-test failed'

    [[ ! -e "$mountpoint/trusted.txt" ]] ||
        fail 'namespace-private tmpfs unexpectedly leaked into the caller mount namespace'

    cleanup_mountpoint "$mountpoint"
    trap - RETURN
    printf 'NXB-153 immutable Linux source primitive self-test passed.\n'
}

validate_tree_modes() {
    local head_sha="$1"
    local record
    local mode
    local type_and_rest
    local object_type

    while IFS= read -r -d '' record; do
        mode="${record%% *}"
        type_and_rest="${record#* }"
        object_type="${type_and_rest%% *}"
        [[ "$object_type" == blob ]] ||
            fail "exact-head tree contains unsupported non-blob entry mode=$mode type=$object_type"
        case "$mode" in
            100644|100755) ;;
            *) fail "exact-head tree contains unsupported mode $mode (symlink/gitlink/special source authority is not admitted)" ;;
        esac
    done < <(git ls-tree -rz "$head_sha")
}

validate_snapshot_namespace() {
    local source_root="$1"
    local repo_fd="$2"
    local head_sha="$3"
    local phase="$4"

    [[ "$phase" == pre || "$phase" == post ]] || fail 'snapshot namespace phase is invalid'

    python3 -c '
import os
import sys

source_root = os.fsencode(sys.argv[1])
phase = sys.argv[2]
raw = sys.stdin.buffer.read()
parts = raw.split(b"\0")
if parts and parts[-1] == b"":
    parts.pop()
if not parts:
    raise SystemExit("exact-head namespace manifest is empty")
if len(parts) != len(set(parts)):
    raise SystemExit("exact-head namespace manifest contains duplicate paths")

runtime_roots = {b"target", b".nxb-153-tmp", b".nxb-153-cargo-home"}
expected_files = set(parts)
expected_dirs = set()
for path in expected_files:
    if not path or path.startswith(b"/") or b"\0" in path:
        raise SystemExit("exact-head namespace manifest contains an invalid path")
    components = path.split(b"/")
    if any(component in (b"", b".", b"..") for component in components):
        raise SystemExit("exact-head namespace manifest contains an ambiguous path")
    for index in range(1, len(components)):
        expected_dirs.add(b"/".join(components[:index]))

actual_files = set()
actual_dirs = set()
for current_root, dirnames, filenames in os.walk(source_root, topdown=True, followlinks=False):
    relative_root = os.path.relpath(current_root, source_root)
    if relative_root == b".":
        relative_root = b""

    if phase == "post" and relative_root == b"":
        dirnames[:] = [name for name in dirnames if os.fsencode(name) not in runtime_roots]

    for dirname in dirnames:
        encoded = os.fsencode(dirname)
        relative = encoded if not relative_root else relative_root + b"/" + encoded
        actual_dirs.add(relative)
    for filename in filenames:
        encoded = os.fsencode(filename)
        relative = encoded if not relative_root else relative_root + b"/" + encoded
        actual_files.add(relative)

unexpected_files = actual_files - expected_files
missing_files = expected_files - actual_files
unexpected_dirs = actual_dirs - expected_dirs
missing_dirs = expected_dirs - actual_dirs
if unexpected_files or missing_files or unexpected_dirs or missing_dirs:
    def render(values):
        return [os.fsdecode(value) for value in sorted(values)[:8]]
    raise SystemExit(
        "snapshot namespace mismatch: "
        f"unexpected_files={render(unexpected_files)!r} "
        f"missing_files={render(missing_files)!r} "
        f"unexpected_dirs={render(unexpected_dirs)!r} "
        f"missing_dirs={render(missing_dirs)!r}"
    )
' "$source_root" "$phase" < <(
        git -C "/proc/self/fd/$repo_fd" -c core.quotePath=false ls-tree -rz --name-only "$head_sha"
    ) || fail "exact-head $phase snapshot namespace differs from the Git manifest"
}

validate_snapshot() {
    require_commands

    [[ "$#" -eq 10 ]] || fail 'validate mode requires 10 arguments'
    local head_sha="$1"
    local repo_fd="$2"
    local rust_toolchain="$3"
    local cargo_audit_version="$4"
    local cargo_deny_version="$5"
    local audit_sha256="$6"
    local deny_sha256="$7"
    local expected_lock_sha256="$8"
    local sealed_helper_sha256="$9"
    local tools_relative="${10}"

    [[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact head is not canonical 40-hex SHA-1'
    [[ "$repo_fd" =~ ^[0-9]+$ ]] || fail 'repository descriptor number is invalid'
    [[ -d "/proc/self/fd/$repo_fd" ]] || fail 'inherited repository descriptor is unavailable'
    for digest in "$audit_sha256" "$deny_sha256" "$expected_lock_sha256" "$sealed_helper_sha256"; do
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail 'one or more expected SHA-256 values are invalid'
    done
    [[ "$tools_relative" == "target/nxb-tools/linux/$head_sha" ]] ||
        fail 'tools relative root does not match the exact Linux head'

    validate_tree_modes "$head_sha"

    local mountpoint
    mountpoint="$(mktemp -d)" || fail 'could not create immutable validation mountpoint'
    trap 'cleanup_mountpoint "$mountpoint"' RETURN

    git archive --format=tar "$head_sha" | \
        unshare --user --map-root-user --mount --pid --fork bash -c '
            set -euo pipefail
            source_root="$1"
            repo_fd="$2"
            rust_toolchain="$3"
            cargo_audit_version="$4"
            cargo_deny_version="$5"
            audit_sha256="$6"
            deny_sha256="$7"
            expected_lock_sha256="$8"
            sealed_helper_sha256="$9"
            tools_relative="${10}"

            die() {
                printf "NXB-153 immutable validation child failed: %s\n" "$1" >&2
                exit 1
            }

            validate_namespace() {
                local phase="$1"
                python3 -c '\''
import os
import sys
source_root = os.fsencode(sys.argv[1])
phase = sys.argv[2]
raw = sys.stdin.buffer.read()
parts = raw.split(b"\0")
if parts and parts[-1] == b"": parts.pop()
if not parts or len(parts) != len(set(parts)):
    raise SystemExit("invalid exact-head namespace manifest")
runtime_roots = {b"target", b".nxb-153-tmp", b".nxb-153-cargo-home"}
expected_files = set(parts)
expected_dirs = set()
for path in expected_files:
    components = path.split(b"/")
    if not path or path.startswith(b"/") or any(c in (b"", b".", b"..") for c in components):
        raise SystemExit("ambiguous exact-head namespace path")
    for i in range(1, len(components)):
        expected_dirs.add(b"/".join(components[:i]))
actual_files = set()
actual_dirs = set()
for root, dirs, files in os.walk(source_root, topdown=True, followlinks=False):
    relroot = os.path.relpath(root, source_root)
    if relroot == b".": relroot = b""
    if phase == "post" and relroot == b"":
        dirs[:] = [name for name in dirs if os.fsencode(name) not in runtime_roots]
    for name in dirs:
        enc = os.fsencode(name)
        actual_dirs.add(enc if not relroot else relroot + b"/" + enc)
    for name in files:
        enc = os.fsencode(name)
        actual_files.add(enc if not relroot else relroot + b"/" + enc)
if actual_files != expected_files or actual_dirs != expected_dirs:
    raise SystemExit("snapshot namespace differs from exact-head Git manifest")
'\'' "$source_root" "$phase" < <(
                    git -C "/proc/self/fd/$repo_fd" -c core.quotePath=false ls-tree -rz --name-only "$head_sha"
                ) || die "$phase snapshot namespace differs from exact-head Git manifest"
            }

            mount --make-rprivate /
            mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs "$source_root"
            tar -xf - -C "$source_root"

            if find "$source_root" -type l -print -quit | grep -q .; then
                die "exact-head archive unexpectedly contains a symlink"
            fi
            validate_namespace pre

            [[ -f "$source_root/Cargo.lock" && ! -L "$source_root/Cargo.lock" ]] ||
                die "exact-head immutable snapshot is missing regular Cargo.lock"
            [[ -f "$source_root/scripts/nxb-153-sealed-tool.py" && ! -L "$source_root/scripts/nxb-153-sealed-tool.py" ]] ||
                die "immutable snapshot is missing the sealed-tool helper"

            lock_sha256="$(sha256sum "$source_root/Cargo.lock" | awk "{print \$1}")"
            [[ "$lock_sha256" == "$expected_lock_sha256" ]] ||
                die "immutable snapshot Cargo.lock does not match the admitted exact-head SHA-256"
            helper_sha256="$(sha256sum "$source_root/scripts/nxb-153-sealed-tool.py" | awk "{print \$1}")"
            [[ "$helper_sha256" == "$sealed_helper_sha256" ]] ||
                die "immutable snapshot sealed-tool helper differs from the committed authority bytes"

            for runtime_path in target .nxb-153-tmp .nxb-153-cargo-home; do
                [[ ! -e "$source_root/$runtime_path" ]] ||
                    die "exact-head tree already contains reserved runtime path $runtime_path"
                mkdir "$source_root/$runtime_path"
            done

            mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs "$source_root/target"
            mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs "$source_root/.nxb-153-tmp"
            mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs "$source_root/.nxb-153-cargo-home"
            mount -o remount,ro,nosuid,nodev "$source_root"

            if touch "$source_root/.nxb-153-write-probe" 2>/dev/null; then
                die "immutable source root remained writable after remount"
            fi
            validate_namespace post

            export CARGO_TARGET_DIR="$source_root/target"
            export CARGO_HOME="$source_root/.nxb-153-cargo-home"
            export TMPDIR="$source_root/.nxb-153-tmp"
            cd "$source_root"

            cargo_run() {
                rustup run "$rust_toolchain" cargo "$@"
            }

            cargo_run metadata --format-version 1 --locked --no-deps >/dev/null
            cargo_run fmt --all -- --check

            cargo_run check -p nxb-policy --all-targets --locked
            cargo_run clippy -p nxb-policy --all-targets --locked -- -D warnings
            cargo_run test -p nxb-policy --locked -- --test-threads=1

            cargo_run check -p nxb-core --all-targets --locked
            cargo_run clippy -p nxb-core --all-targets --locked -- -D warnings
            cargo_run test -p nxb-core --lib --locked -- --test-threads=1
            for test_name in \
                target_setup_cli \
                target_activation_cli \
                target_activation_recovery_cli \
                target_guided_artifact_cli \
                target_import_cli \
                target_import_failclosed_cli \
                target_path_binding_cli \
                target_scope_failclosed_cli \
                target_subdomain_failclosed_cli \
                target_persistence_envelope_cli \
                target_unicode_path_failclosed_cli
            do
                cargo_run test -p nxb-core --test "$test_name" --locked -- --test-threads=1
            done

            cargo_run check --workspace --all-targets --all-features --locked
            cargo_run clippy --workspace --all-targets --all-features --locked -- -D warnings
            cargo_run test --workspace --all-features --locked -- --test-threads=1

            audit_path="/proc/self/fd/$repo_fd/$tools_relative/bin/cargo-audit"
            deny_path="/proc/self/fd/$repo_fd/$tools_relative/bin/cargo-deny"
            [[ -f "$audit_path" && ! -L "$audit_path" ]] || die "anchored cargo-audit path is unavailable"
            [[ -f "$deny_path" && ! -L "$deny_path" ]] || die "anchored cargo-deny path is unavailable"

            python3 scripts/nxb-153-sealed-tool.py run \
                "$audit_path" "$cargo_audit_version" "$audit_sha256" -- audit ||
                die "receipt-hash-checked sealed cargo-audit gate failed inside immutable source snapshot"
            python3 scripts/nxb-153-sealed-tool.py run \
                "$deny_path" "$cargo_deny_version" "$deny_sha256" -- check ||
                die "receipt-hash-checked sealed cargo-deny gate failed inside immutable source snapshot"

            final_lock_sha256="$(sha256sum Cargo.lock | awk "{print \$1}")"
            [[ "$final_lock_sha256" == "$expected_lock_sha256" ]] ||
                die "immutable snapshot Cargo.lock changed during validation"
            validate_namespace post

            printf "NXB-153 exact-head Linux gates passed inside immutable private source snapshot.\n"
        ' bash \
            "$mountpoint" \
            "$repo_fd" \
            "$rust_toolchain" \
            "$cargo_audit_version" \
            "$cargo_deny_version" \
            "$audit_sha256" \
            "$deny_sha256" \
            "$expected_lock_sha256" \
            "$sealed_helper_sha256" \
            "$tools_relative" || fail 'immutable exact-head Linux validation child failed'

    [[ -z "$(find "$mountpoint" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
        fail 'namespace-private validation mounts leaked content into the caller namespace'

    cleanup_mountpoint "$mountpoint"
    trap - RETURN
}

main() {
    [[ "$#" -ge 1 ]] || fail 'mode is required'
    local mode="$1"
    shift
    case "$mode" in
        self-test)
            [[ "$#" -eq 0 ]] || fail 'self-test mode takes no arguments'
            self_test
            ;;
        validate)
            validate_snapshot "$@"
            ;;
        *)
            fail "unknown mode: $mode"
            ;;
    esac
}

main "$@"
