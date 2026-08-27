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
        for runtime_path in target tmp fetch-home vendor cargo-home config; do
            mkdir "$mountpoint/$runtime_path"
            mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs "$mountpoint/$runtime_path"
        done
        printf dependency > "$mountpoint/vendor/dependency.txt"
        printf "[source.crates-io]\nreplace-with = \"nxb-vendored-sources\"\n" > "$mountpoint/config/config.toml"
        mount -o remount,ro,nosuid,nodev "$mountpoint/vendor"
        mount -o remount,ro,nosuid,nodev "$mountpoint/config"
        touch "$mountpoint/cargo-home/config.toml"
        mount --bind "$mountpoint/config/config.toml" "$mountpoint/cargo-home/config.toml"
        mount -o remount,bind,ro "$mountpoint/cargo-home/config.toml"
        mount -o remount,ro,nosuid,nodev "$mountpoint"

        [[ "$(cat "$mountpoint/trusted.txt")" == trusted ]]
        if printf changed > "$mountpoint/trusted.txt" 2>/dev/null; then
            exit 71
        fi
        if touch "$mountpoint/injected.txt" 2>/dev/null; then
            exit 72
        fi
        if printf changed > "$mountpoint/vendor/dependency.txt" 2>/dev/null; then
            exit 73
        fi
        if printf changed > "$mountpoint/cargo-home/config.toml" 2>/dev/null; then
            exit 74
        fi

        printf build > "$mountpoint/target/build.txt"
        printf temporary > "$mountpoint/tmp/temp.txt"
        printf cache > "$mountpoint/fetch-home/cache.txt"
        printf gate > "$mountpoint/cargo-home/state.txt"
        [[ "$(cat "$mountpoint/target/build.txt")" == build ]]
        [[ "$(cat "$mountpoint/tmp/temp.txt")" == temporary ]]
        [[ "$(cat "$mountpoint/fetch-home/cache.txt")" == cache ]]
        [[ "$(cat "$mountpoint/cargo-home/state.txt")" == gate ]]
    ' bash "$mountpoint" || fail 'user/mount namespace private read-only dependency/source self-test failed'

    [[ ! -e "$mountpoint/trusted.txt" ]] ||
        fail 'namespace-private tmpfs unexpectedly leaked into the caller mount namespace'

    cleanup_mountpoint "$mountpoint"
    trap - RETURN
    printf 'NXB-153 immutable Linux source/dependency primitive self-test passed.\n'
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
            head_sha="$3"
            rust_toolchain="$4"
            cargo_audit_version="$5"
            cargo_deny_version="$6"
            audit_sha256="$7"
            deny_sha256="$8"
            expected_lock_sha256="$9"
            sealed_helper_sha256="${10}"
            tools_relative="${11}"

            die() {
                printf "NXB-153 immutable validation child failed: %s\n" "$1" >&2
                exit 1
            }

            validate_namespace() {
                local phase="$1"
                python3 -I -c '\''
import os
import sys

source_root = os.fsencode(sys.argv[1])
phase = sys.argv[2]
raw = sys.stdin.buffer.read()
parts = raw.split(b"\0")
if parts and parts[-1] == b"":
    parts.pop()
if not parts or len(parts) != len(set(parts)):
    raise SystemExit("invalid exact-head namespace manifest")

runtime_roots = {
    b"target",
    b".nxb-153-tmp",
    b".nxb-153-fetch-home",
    b".nxb-153-vendor",
    b".nxb-153-cargo-home",
    b".nxb-153-config",
}
expected_files = set(parts)
expected_dirs = set()
for path in expected_files:
    components = path.split(b"/")
    if not path or path.startswith(b"/") or any(component in (b"", b".", b"..") for component in components):
        raise SystemExit("ambiguous exact-head namespace path")
    if components[0] in runtime_roots:
        raise SystemExit("exact-head tree collides with a reserved validation runtime root")
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
        actual_dirs.add(encoded if not relative_root else relative_root + b"/" + encoded)
    for filename in filenames:
        encoded = os.fsencode(filename)
        actual_files.add(encoded if not relative_root else relative_root + b"/" + encoded)

if actual_files != expected_files or actual_dirs != expected_dirs:
    def render(values):
        return [os.fsdecode(value) for value in sorted(values)[:8]]
    raise SystemExit(
        "snapshot namespace differs from exact-head Git manifest: "
        f"unexpected_files={render(actual_files - expected_files)!r} "
        f"missing_files={render(expected_files - actual_files)!r} "
        f"unexpected_dirs={render(actual_dirs - expected_dirs)!r} "
        f"missing_dirs={render(expected_dirs - actual_dirs)!r}"
    )
'\'' "$source_root" "$phase" < <(
                    git -C "/proc/self/fd/$repo_fd" -c core.quotePath=false ls-tree -rz --name-only "$head_sha"
                ) || die "$phase snapshot namespace differs from exact-head Git manifest"
            }

            cargo_raw() {
                rustup run "$rust_toolchain" cargo "$@"
            }

            cargo_gate() {
                rustup run "$rust_toolchain" cargo --offline "$@"
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
            [[ -f "$source_root/scripts/nxb-153-registry-source.py" && ! -L "$source_root/scripts/nxb-153-registry-source.py" ]] ||
                die "immutable snapshot is missing the registry source authority helper"
            [[ -f "$source_root/scripts/nxb-153-validation-environment.py" && ! -L "$source_root/scripts/nxb-153-validation-environment.py" ]] ||
                die "immutable snapshot is missing the validation environment authority helper"

            lock_sha256="$(sha256sum "$source_root/Cargo.lock" | awk "{print \$1}")"
            [[ "$lock_sha256" == "$expected_lock_sha256" ]] ||
                die "immutable snapshot Cargo.lock does not match the admitted exact-head SHA-256"
            helper_sha256="$(sha256sum "$source_root/scripts/nxb-153-sealed-tool.py" | awk "{print \$1}")"
            [[ "$helper_sha256" == "$sealed_helper_sha256" ]] ||
                die "immutable snapshot sealed-tool helper differs from the committed authority bytes"

            python3 -I "$source_root/scripts/nxb-153-validation-environment.py" self-test >/dev/null ||
                die "validation environment authority self-test failed"
            python3 -I "$source_root/scripts/nxb-153-validation-environment.py" audit >/dev/null ||
                die "ambient Rust/Cargo/Python authority variables are not admitted for immutable validation"
            python3 -I "$source_root/scripts/nxb-153-registry-source.py" self-test >/dev/null ||
                die "registry source authority self-test failed"
            python3 -I "$source_root/scripts/nxb-153-registry-source.py" validate-lock "$source_root/Cargo.lock" >/dev/null ||
                die "Cargo.lock registry-source contract is unsupported"

            for runtime_path in \
                target \
                .nxb-153-tmp \
                .nxb-153-fetch-home \
                .nxb-153-vendor \
                .nxb-153-cargo-home \
                .nxb-153-config
            do
                [[ ! -e "$source_root/$runtime_path" ]] ||
                    die "exact-head tree already contains reserved runtime path $runtime_path"
                mkdir "$source_root/$runtime_path"
                mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs "$source_root/$runtime_path"
            done
            mount -o remount,ro,nosuid,nodev "$source_root"

            if touch "$source_root/.nxb-153-write-probe" 2>/dev/null; then
                die "immutable source root remained writable after remount"
            fi
            for runtime_path in \
                target \
                .nxb-153-tmp \
                .nxb-153-fetch-home \
                .nxb-153-vendor \
                .nxb-153-cargo-home \
                .nxb-153-config
            do
                printf probe > "$source_root/$runtime_path/.nxb-153-runtime-probe"
                [[ "$(cat "$source_root/$runtime_path/.nxb-153-runtime-probe")" == probe ]] ||
                    die "runtime mount $runtime_path failed write/read probe"
                rm -f "$source_root/$runtime_path/.nxb-153-runtime-probe"
            done
            validate_namespace post

            target_root="$source_root/target"
            tmp_root="$source_root/.nxb-153-tmp"
            fetch_home="$source_root/.nxb-153-fetch-home"
            vendor_root="$source_root/.nxb-153-vendor"
            gate_home="$source_root/.nxb-153-cargo-home"
            config_root="$source_root/.nxb-153-config"

            export CARGO_TARGET_DIR="$target_root"
            export TMPDIR="$tmp_root"
            cd "$source_root"

            CARGO_HOME="$fetch_home" cargo_raw fetch --locked ||
                die "cargo fetch --locked failed while preparing checksum-bound dependency sources"
            CARGO_HOME="$fetch_home" cargo_raw metadata --format-version 1 --locked | \
                python3 -I scripts/nxb-153-registry-source.py validate-metadata "$source_root" >/dev/null ||
                die "cargo metadata contains an unsupported external/local dependency source"

            CARGO_HOME="$fetch_home" CARGO_NET_OFFLINE=true \
                cargo_raw vendor --locked --versioned-dirs "$vendor_root" >/dev/null ||
                die "offline cargo vendor failed from the fetched locked dependency cache"
            vendor_summary="$(python3 -I scripts/nxb-153-registry-source.py validate-vendor Cargo.lock "$vendor_root")" ||
                die "vendored dependency snapshot differs from Cargo.lock/checksum authority"
            [[ -n "$vendor_summary" ]] || die "vendored dependency authority summary is empty"

            mount -o remount,ro,nosuid,nodev "$vendor_root"
            if touch "$vendor_root/.nxb-153-vendor-write-probe" 2>/dev/null; then
                die "vendored dependency snapshot remained writable after remount"
            fi

            cat > "$config_root/config.toml" <<EOF
[source.crates-io]
replace-with = "nxb-vendored-sources"

[source.nxb-vendored-sources]
directory = "$vendor_root"
EOF
            config_sha256="$(sha256sum "$config_root/config.toml" | awk "{print \$1}")"
            [[ "$config_sha256" =~ ^[0-9a-f]{64}$ ]] || die "gate Cargo config SHA-256 is invalid"
            mount -o remount,ro,nosuid,nodev "$config_root"
            if printf changed > "$config_root/config.toml" 2>/dev/null; then
                die "gate Cargo config root remained writable after remount"
            fi

            touch "$gate_home/config.toml"
            mount --bind "$config_root/config.toml" "$gate_home/config.toml"
            mount -o remount,bind,ro "$gate_home/config.toml"
            if printf changed > "$gate_home/config.toml" 2>/dev/null; then
                die "gate CARGO_HOME config binding remained writable"
            fi
            printf state > "$gate_home/.nxb-153-gate-home-probe"
            [[ "$(cat "$gate_home/.nxb-153-gate-home-probe")" == state ]] ||
                die "gate CARGO_HOME did not remain writable outside the pinned config file"
            rm -f "$gate_home/.nxb-153-gate-home-probe"

            export CARGO_HOME="$gate_home"
            cargo_gate metadata --format-version 1 --locked >/dev/null ||
                die "offline metadata failed against the immutable vendored dependency source"
            cargo_gate fmt --all -- --check

            cargo_gate check -p nxb-policy --all-targets --locked
            cargo_gate clippy -p nxb-policy --all-targets --locked -- -D warnings
            cargo_gate test -p nxb-policy --locked -- --test-threads=1

            cargo_gate check -p nxb-core --all-targets --locked
            cargo_gate clippy -p nxb-core --all-targets --locked -- -D warnings
            cargo_gate test -p nxb-core --lib --locked -- --test-threads=1
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
                cargo_gate test -p nxb-core --test "$test_name" --locked -- --test-threads=1
            done

            cargo_gate check --workspace --all-targets --all-features --locked
            cargo_gate clippy --workspace --all-targets --all-features --locked -- -D warnings
            cargo_gate test --workspace --all-features --locked -- --test-threads=1

            audit_path="/proc/self/fd/$repo_fd/$tools_relative/bin/cargo-audit"
            deny_path="/proc/self/fd/$repo_fd/$tools_relative/bin/cargo-deny"
            [[ -f "$audit_path" && ! -L "$audit_path" ]] || die "anchored cargo-audit path is unavailable"
            [[ -f "$deny_path" && ! -L "$deny_path" ]] || die "anchored cargo-deny path is unavailable"

            python3 -I scripts/nxb-153-sealed-tool.py run \
                "$audit_path" "$cargo_audit_version" "$audit_sha256" -- audit ||
                die "receipt-hash-checked sealed cargo-audit gate failed inside immutable source snapshot"
            python3 -I scripts/nxb-153-sealed-tool.py run \
                "$deny_path" "$cargo_deny_version" "$deny_sha256" -- check ||
                die "receipt-hash-checked sealed cargo-deny gate failed inside immutable source snapshot"

            final_lock_sha256="$(sha256sum Cargo.lock | awk "{print \$1}")"
            [[ "$final_lock_sha256" == "$expected_lock_sha256" ]] ||
                die "immutable snapshot Cargo.lock changed during validation"
            [[ "$(sha256sum "$config_root/config.toml" | awk "{print \$1}")" == "$config_sha256" ]] ||
                die "gate Cargo source-replacement config changed during validation"
            python3 -I scripts/nxb-153-registry-source.py validate-vendor Cargo.lock "$vendor_root" >/dev/null ||
                die "vendored dependency snapshot failed final checksum/namespace verification"
            validate_namespace post

            printf "NXB-153 exact-head Linux gates passed inside immutable workspace/dependency snapshots.\n"
        ' bash \
            "$mountpoint" \
            "$repo_fd" \
            "$head_sha" \
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
