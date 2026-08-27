# NXB-153 Host Rust Toolchain H2 Snapshot Authority

## Status

This document records the source-staged H2 host-Rust snapshot model for NXB-153.

H2 is **not admitted**. Platform evidence must continue to record:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

until the same exact source head completes real supported Linux and Windows execution and producers/reviewers/closure are deliberately migrated to a stronger state.

## Goal

H1 provides deterministic Rust-toolchain tree identity. H2 removes the mutable host/rustup toolchain tree from the heavy-gate consumption lifetime by running those gates from a verified private snapshot.

The installed Rust 1.97.1 tree is a capture/provisioning source, not the admitted heavy-gate authority.

## Linux H2

Layering:

```text
nxb-153-linux-immutable-source.sh            H2 snapshot wrapper
  -> nxb-153-linux-immutable-source-h1-inner.sh
     -> nxb-153-linux-immutable-source-inner.sh
```

The canonical Linux H2 path:

1. resolves the H1 wrapper and Rust authority helper from exact-head Git objects;
2. runs the H2 primitive self-test;
3. resolves Rust 1.97.1 host sysroot and computes deterministic H1 tree identity;
4. enters a private user/mount namespace;
5. creates a private tmpfs Rust snapshot and copies the host sysroot;
6. verifies snapshot identity against the host capture digest;
7. requires cargo, rustc, rustdoc, rustfmt, cargo-fmt, cargo-clippy and clippy-driver in the snapshot;
8. remounts the snapshot read-only;
9. proves a nested validation user/mount namespace cannot remount the parent H2 Rust snapshot writable;
10. requires relocated rustc to report the snapshot root as sysroot and Rust 1.97.1;
11. installs a private read-only rustup shim that accepts only the exact toolchain and dispatches Rust components from the snapshot;
12. binds Cargo to snapshot rustc/rustdoc and snapshot bin dispatch;
13. runs the H1 + immutable workspace/dependency/security-tool chain under H2 authority;
14. re-verifies tree identity after gates;
15. requires final write denial and fail-closed namespace cleanup.

Narrow Linux primitives have demonstrated private-copy independence, read-only remount behavior, relocated fake-rustc sysroot behavior, snapshot shim dispatch and nested-namespace rw-remount denial. These are not the complete current-head Rust 1.97.1 admission run.

## Windows H2

Layering:

```text
nxb-153-windows-immutable-source.ps1         canonical H2 primitive/authority entrypoint
  -> nxb-153-windows-immutable-source-h2-inner.ps1
     -> nxb-153-windows-immutable-source-h1-inner.ps1
        -> nxb-153-windows-immutable-source-inner.ps1
```

The outer Windows validator pins and exact-Git-object verifies the canonical H2 entrypoint before execution. The canonical H2 entrypoint in turn pins and exact-Git-object verifies its H2 inner runner.

### Windows H2 primitive self-test

`-SelfTest` now exercises Windows-specific authority primitives before delegating to the H2/H1 source self-test chain:

- a regular file is opened with `FileShare.Read` and concurrent write access must fail;
- delete of that pinned file must fail;
- a directory is opened with native `CreateFileW` while delete sharing is withheld and rename/delete authority must fail;
- a current-user ACL denies write/create/delete while preserving read/execute;
- file injection under the guarded directory must fail;
- subdirectory injection must fail;
- a copied executable must still launch successfully under the deny policy and active authority handles;
- ACL restoration, handle disposal and temporary-tree deletion are fail-closed parts of self-test success.

The self-test is source-staged but has **not** executed in the current environment because no PowerShell runtime is available here.

### Windows heavy-gate snapshot

The H2 inner runner:

1. pins and Git-object-verifies the H1 inner wrapper and Rust authority helper;
2. resolves the host Rust 1.97.1 sysroot and computes deterministic Windows-model tree identity;
3. creates a unique validation-local snapshot;
4. copies the host sysroot and rejects reparse-point authority;
5. requires copied snapshot identity to equal the host capture digest;
6. pins snapshot directories with native directory handles that omit delete sharing;
7. pins snapshot files with read-only `FileStream` handles that omit write/delete sharing;
8. applies current-user write/create/delete denial and probes directory injection denial;
9. re-verifies deterministic snapshot identity;
10. requires snapshot rustc/cargo/rustdoc and relocated rustc reporting the snapshot root and Rust 1.97.1;
11. installs a PowerShell rustup shim restricted to the exact toolchain and snapshot components;
12. runs the H1/workspace/dependency/security-tool chain under snapshot authority;
13. re-verifies snapshot identity and post-gate write denial;
14. treats ACL restoration, handle disposal and snapshot deletion as part of success.

## Windows runtime boundary

No Windows H2 syntax/runtime PASS is claimed from the current execution environment.

Real supported Windows/NTFS validation must prove at least:

- PowerShell parsing, function scope and nested script invocation;
- H2 primitive self-test behavior;
- snapshot copy behavior for the installed Rust 1.97.1 tree;
- native directory-handle sharing and file `FileShare.Read` semantics;
- ACL mutation/injection denial while process creation remains functional;
- snapshot rustc/cargo/rustfmt/Clippy execution;
- DLL/sysroot/library loading from the copied snapshot;
- rustup-shim visibility through nested H1/inner calls;
- ACL restoration and snapshot cleanup on success and failure.

## Evidence boundary

Source staging does not change schema-v2 host-Rust evidence from:

`version_pinned_object_identity_pending`

A stronger state must be introduced atomically across both platform producers, both semantic reviewers and the dual-platform closure contract. Historical pending evidence must never be reinterpreted as H2 proof.

## Admission acceptance

H2 can be admitted only after the exact same final NXB-153 Git head has real Linux and Windows evidence proving that heavy Rust gates consumed only the verified immutable/pinned Rust snapshot, final snapshot identity/cleanup succeeded and all other #90-#98 gates remain satisfied.