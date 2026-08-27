# NXB-153 Host Rust Toolchain H2 Snapshot Authority

## Status

This document records the source-staged H2 host-Rust snapshot model for NXB-153.

H2 is **not admitted**. The current validation evidence must continue to record:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

until the same exact source head completes real supported Linux and Windows execution and the evidence/reviewer/closure contract is deliberately migrated to a stronger state.

## Goal

H1 proves deterministic Rust-toolchain tree identity at two observation points. H2 removes the mutable host/rustup toolchain tree from the heavy-gate consumption lifetime.

The host Rust 1.97.1 installation is therefore only a capture/provisioning source. Heavy fmt/check/Clippy/test gates must consume a verified private snapshot whose bytes cannot be changed through the ordinary mutable host toolchain path during validation.

## Linux H2 source model

Canonical entrypoint:

`scripts/nxb-153-linux-immutable-source.sh`

The previous H1 wrapper is retained as:

`scripts/nxb-153-linux-immutable-source-h1-inner.sh`

The pre-H1 workspace/dependency runner remains:

`scripts/nxb-153-linux-immutable-source-inner.sh`

The H2 wrapper:

1. resolves the exact-head H1 inner wrapper and Rust authority helper as Git blobs;
2. runs the H2 primitive self-test before heavy gates;
3. resolves Rust 1.97.1 host sysroot and computes its deterministic H1 tree SHA-256;
4. enters a private user/mount namespace;
5. creates a private tmpfs Rust snapshot and copies the host sysroot into it;
6. verifies the copied tree against the pre-capture H1 digest;
7. requires cargo, rustc, rustdoc, rustfmt, cargo-fmt, cargo-clippy and clippy-driver inside the snapshot;
8. remounts the snapshot read-only;
9. proves a nested validation user/mount namespace cannot remount the parent H2 Rust snapshot writable;
10. requires relocated rustc to report the snapshot root as its sysroot and report Rust 1.97.1;
11. installs a private read-only rustup shim that accepts only `rustup run <exact-toolchain> <tool> ...` and dispatches Rust tools from the snapshot;
12. binds Cargo to snapshot rustc/rustdoc and snapshot bin dispatch;
13. runs the H1 wrapper plus immutable workspace/dependency/security-tool gate chain under the H2 snapshot authority;
14. re-verifies the H1 tree identity after gates;
15. requires final snapshot write denial and fail-closed namespace cleanup.

Narrow Linux primitives have demonstrated private-copy independence, read-only remount behavior, relocated fake-rustc sysroot behavior, snapshot shim dispatch and nested-namespace remount denial. These are not complete Rust 1.97.1 admission evidence.

## Windows H2 source model

Canonical entrypoint:

`scripts/nxb-153-windows-immutable-source.ps1`

The previous H1 wrapper is retained byte-for-byte as:

`scripts/nxb-153-windows-immutable-source-h1-inner.ps1`

The Windows H2 wrapper:

1. pins and Git-object-verifies the H1 inner wrapper and Rust authority helper;
2. resolves the host Rust 1.97.1 sysroot and computes deterministic Windows-model tree identity;
3. creates a unique validation-local snapshot directory;
4. copies the host sysroot and rejects reparse-point authority;
5. requires copied snapshot identity to equal the host capture digest;
6. pins every snapshot directory with native directory handles that omit delete sharing;
7. pins every snapshot file with read-only `FileStream` handles that omit write/delete sharing;
8. applies current-user write/create/delete denial to snapshot directories while preserving read/execute behavior;
9. probes each source directory for denied file and subdirectory injection;
10. re-verifies tree identity after pinning/ACL application;
11. requires snapshot rustc/cargo/rustdoc and requires relocated rustc to report the snapshot root and Rust 1.97.1;
12. installs a PowerShell `rustup` shim that admits only the exact toolchain and dispatches Cargo/rustc/other Rust components from the snapshot;
13. runs the H1 wrapper and existing immutable workspace/dependency/security-tool chain under that snapshot authority;
14. re-verifies tree identity and post-gate write denial;
15. treats ACL restoration, handle disposal and snapshot deletion as part of success.

The canonical H2 script itself is opened read-only and Git-object-verified by `validate-nxb-153-windows.ps1` before execution.

## Windows runtime boundary

The current execution environment has no PowerShell runtime, so no Windows H2 syntax/runtime PASS is claimed here.

Real supported Windows/NTFS validation must prove at least:

- PowerShell parsing and parameter/scope behavior;
- snapshot copy behavior for the installed Rust 1.97.1 tree;
- native directory handle sharing behavior;
- file `FileShare.Read` mutation/delete denial;
- ACL file/subdirectory injection denial while normal process creation still works;
- snapshot rustc/cargo/rustfmt/Clippy execution;
- DLL/sysroot/library loading from the copied snapshot;
- PowerShell rustup-shim visibility through the nested H1/inner runner calls;
- ACL restoration and snapshot cleanup on success and failure.

## Evidence boundary

Source staging alone does not change schema-v2 host-Rust evidence from `pending`.

A future stronger evidence state must be introduced atomically across:

- Linux platform producer;
- Windows platform producer;
- Python semantic reviewer;
- PowerShell semantic reviewer;
- dual-platform closure contract.

Historical evidence containing `version_pinned_object_identity_pending` must never be reinterpreted as H2 proof.

## Admission acceptance

H2 can be admitted only after the exact same final NXB-153 Git head has real Linux and Windows evidence proving that all heavy Rust gates consumed only the verified immutable/pinned Rust snapshot, final snapshot identity/cleanup succeeded and all other #90-#98 gates remain satisfied.