# NXB-153 Host Rust Toolchain H2 Snapshot Authority

## Status

This document records the source-staged H2 host-Rust snapshot model for NXB-153.

H2 is **not admitted**. Platform evidence must continue to record:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

until the same exact source head completes real supported Linux and Windows execution and producers/reviewers/closure are deliberately migrated to a stronger state.

## Goal

H1 provides deterministic Rust-toolchain tree identity. H2 removes the mutable host/rustup toolchain tree from the heavy-gate consumption lifetime by running those gates from a verified private snapshot.

The installed Rust 1.97.1 tree is a capture/provisioning source, not the admitted heavy-gate authority.

H2 capture is also availability-bounded. The snapshot copier must reject an oversized or structurally ambiguous host tree **while copying**, rather than consuming arbitrary RAM/disk and discovering drift only at the later identity check.

## Bounded snapshot-copy authority

Canonical helper:

`scripts/nxb-153-rust-toolchain-snapshot-copy.py`

Policy:

`nxb-153-rust-toolchain-snapshot-copy-v1`

Current source-staged helper Git blob at the bounded-copy milestone:

`2b0a5cda82f8b67754e2c3a2ec78252c7625c232`

The helper enforces the H1 envelope during capture:

- at most 65,536 regular files;
- at most 512 MiB per regular file;
- at most 4 GiB total admitted regular-file bytes;
- empty, non-indirection destination root;
- no source symlink/reparse-point authority;
- no special files;
- create-new destination files/directories rather than overwrite;
- source size/object stability checks while opening/copying;
- fail-closed growth detection during copy.

Linux additionally uses descriptor-relative `O_DIRECTORY` / `O_NOFOLLOW` traversal. Windows-model traversal rejects case-insensitive collisions, reserved device stems and currently admits only the deliberately narrow ASCII component grammar needed by the Rust sysroot contract.

The exact helper blob above was reconstructed byte-for-byte from Git authority in the current execution environment, its Git blob OID was independently reproduced, Python compilation passed, and its Linux-model self-test passed for normal copy accounting, file-count bound rejection and symlink rejection. This is **not** a Windows-model runtime result and is **not** a full Rust 1.97.1 H2 admission run.

## Linux H2

Layering:

```text
nxb-153-linux-immutable-source.sh                 canonical bounded H2 entrypoint
  -> nxb-153-linux-immutable-source-h2-copy-inner.sh
     -> nxb-153-linux-immutable-source-h1-inner.sh
        -> nxb-153-linux-immutable-source-inner.sh
```

The canonical Linux entrypoint exact-Git-object resolves both the H2 inner runner and bounded-copy helper. It executes the helper self-test before delegating.

The existing H2 inner runner still contains its narrow `cp -a --no-preserve=ownership` capture site. The canonical entrypoint exposes a one-use exported `cp` function only to the H2 child process. That function accepts only the exact expected capture signature, delegates the copy to the exact-head bounded helper and removes itself immediately after the capture call, so Cargo/build-script processes do not inherit a generic copy-command override.

The Linux H2 path therefore:

1. resolves the H2 inner runner and bounded-copy helper from exact-head Git objects;
2. runs the bounded-copy helper self-test;
3. delegates to the exact H2 inner runner with only the expected sysroot-copy command intercepted;
4. resolves the H1 wrapper and Rust authority helper from exact-head Git objects;
5. runs the H2 primitive self-test;
6. resolves Rust 1.97.1 host sysroot and computes deterministic H1 tree identity;
7. enters a private user/mount namespace;
8. creates a private tmpfs Rust snapshot and copies the host sysroot through the bounded helper;
9. verifies snapshot identity against the host capture digest;
10. requires cargo, rustc, rustdoc, rustfmt, cargo-fmt, cargo-clippy and clippy-driver in the snapshot;
11. remounts the snapshot read-only;
12. proves a nested validation user/mount namespace cannot remount the parent H2 Rust snapshot writable;
13. requires relocated rustc to report the snapshot root as sysroot and Rust 1.97.1;
14. installs a private read-only rustup shim that accepts only the exact toolchain and dispatches Rust components from the snapshot;
15. binds Cargo to snapshot rustc/rustdoc and snapshot bin dispatch;
16. runs the H1 + immutable workspace/dependency/security-tool chain under H2 authority;
17. re-verifies tree identity after gates;
18. requires final write denial and fail-closed namespace cleanup.

Narrow Linux primitives have demonstrated private-copy independence, read-only remount behavior, relocated fake-rustc sysroot behavior, snapshot shim dispatch and nested-namespace rw-remount denial. Those historical/narrow checks plus the bounded-helper self-test are not the complete current-head Rust 1.97.1 admission run.

## Windows H2

Layering:

```text
nxb-153-windows-immutable-source.ps1                    canonical bounded H2 entrypoint
  -> nxb-153-windows-immutable-source-h2-entry-inner.ps1
     -> nxb-153-windows-immutable-source-h2-inner.ps1
        -> nxb-153-windows-immutable-source-h1-inner.ps1
           -> nxb-153-windows-immutable-source-inner.ps1
```

The outer Windows validator pins and exact-Git-object verifies the canonical H2 entrypoint before execution.

The canonical bounded entrypoint then:

- pins and exact-Git-object verifies the H2 entry-inner runner and bounded-copy helper;
- pins the `scripts` namespace with a native directory handle that withholds delete sharing, preventing entry/helper pathname replacement through ancestor rename;
- runs the exact helper self-test;
- leaves `-SelfTest` delegation unmodified so the primitive self-test uses the native `Copy-Item` command for its executable probe;
- during real validation only, installs a narrow `Copy-Item` function visible to the nested H2 capture path;
- requires the exact `-LiteralPath ... -Destination ... -Recurse -Force` capture shape;
- derives and enumerates the one host-sysroot root, calls the bounded helper **once for the entire sysroot**, and treats the H2 inner runner's remaining top-level loop calls as verified consumption of that same enumeration;
- rejects duplicate/unexpected top-level entries, a second source root, a second destination root, missing bounded-copy invocation or incomplete loop consumption;
- removes the temporary function before returning and re-verifies the pinned entry/helper Git objects after execution.

This preserves the 4 GiB aggregate budget across the whole Windows sysroot rather than accidentally applying a separate 4 GiB budget to each top-level directory.

### Windows H2 primitive self-test

The entry-inner `-SelfTest` exercises Windows-specific authority primitives before delegating to the H2/H1 source self-test chain:

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
4. reaches its existing `Copy-Item` capture loop, which the canonical bounded entrypoint converts into one whole-sysroot bounded helper copy;
5. rejects reparse-point authority and requires copied snapshot identity to equal the host capture digest;
6. pins snapshot directories with native directory handles that omit delete sharing;
7. pins snapshot files with read-only `FileStream` handles that omit write/delete sharing;
8. applies current-user write/create/delete denial and probes file/directory injection denial;
9. deliberately does **not** deny `ChangePermissions` or `TakeOwnership`, keeping ACL restoration available while file/directory mutation remains blocked by the narrower deny set plus open authority handles;
10. re-verifies deterministic snapshot identity;
11. requires snapshot rustc/cargo/rustdoc and relocated rustc reporting the snapshot root and Rust 1.97.1;
12. installs a PowerShell rustup shim restricted to the exact toolchain and snapshot components;
13. runs the H1/workspace/dependency/security-tool chain under snapshot authority;
14. re-verifies snapshot identity and post-gate write denial;
15. treats ACL restoration, handle disposal and snapshot deletion as part of success.

## Windows runtime boundary

No Windows H2 syntax/runtime PASS is claimed from the current execution environment.

Real supported Windows/NTFS validation must prove at least:

- PowerShell parsing, function scope and nested script invocation for the bounded `Copy-Item` interception;
- whole-sysroot bounded-copy accounting under the Windows model;
- H2 primitive self-test behavior;
- snapshot copy behavior for the installed Rust 1.97.1 tree;
- native directory-handle sharing and file `FileShare.Read` semantics;
- ACL mutation/injection denial while process creation and ACL restoration remain functional;
- snapshot rustc/cargo/rustfmt/Clippy execution;
- DLL/sysroot/library loading from the copied snapshot;
- rustup-shim visibility through nested H1/inner calls;
- ACL restoration and snapshot cleanup on success and failure.

## Evidence boundary

Source staging does not change schema-v2 host-Rust evidence from:

`version_pinned_object_identity_pending`

A stronger state must be introduced atomically across both platform producers, both semantic reviewers and the dual-platform closure contract. Historical pending evidence must never be reinterpreted as H2 proof.

## Admission acceptance

H2 can be admitted only after the exact same final NXB-153 Git head has real Linux and Windows evidence proving that heavy Rust gates consumed only the verified immutable/pinned and bounded-capture Rust snapshot, final snapshot identity/cleanup succeeded and all other #90-#98 gates remain satisfied.
