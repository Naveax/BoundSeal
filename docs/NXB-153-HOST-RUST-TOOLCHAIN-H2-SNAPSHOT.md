# NXB-153 Host Rust Toolchain H2 Snapshot Authority

## Status

This document records the source-staged H2 host-Rust snapshot model for NXB-153.

H2 is **not admitted**. Platform evidence must continue to record:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

until the same exact source head completes real supported Linux and Windows execution and producers/reviewers/closure are deliberately migrated to a stronger state.

## Goal

H1 provides deterministic Rust-toolchain tree identity. H2 removes the mutable host/rustup toolchain tree from the heavy-gate consumption lifetime by running those gates from a verified private snapshot.

The installed Rust 1.97.1 tree is a capture/provisioning source, not the admitted heavy-gate authority.

H2 capture and the H1 pre/post digest are availability-bounded. File, directory and byte budgets must fail closed **during traversal/copy**, rather than after arbitrary metadata or file-byte consumption.

## Canonical host-Rust tree authority

Canonical helper:

`scripts/nxb-153-rust-toolchain-authority.py`

Policy:

`nxb-153-host-rust-toolchain-tree-authority-v1`

Current exact Git blob:

`d3e392a41509f6e3c71e152681f0830514511686`

The valid-tree digest format remains v1 and still binds sorted relative path bytes, mode class, exact file size and SHA-256 of stable file bytes. The hardening does not reinterpret historical tree digests.

Traversal now enforces, before unbounded work can accumulate:

- at most 65,536 regular files;
- at most 65,536 source directories, including the source root;
- at most 512 MiB per regular file;
- at most 4 GiB total admitted regular-file bytes;
- no symlink/reparse/special-file authority;
- stable file object/size/time metadata during reads;
- directory object stability during traversal;
- Linux descriptor-relative `O_DIRECTORY` / `O_NOFOLLOW` traversal;
- conservative Windows pathname grammar and case-collision rejection.

The exact helper source used for this milestone compiled and its Linux-host self-test passed locally. The self-test includes enumeration-order independence, mutation detection, early file-count rejection, early total-byte rejection, directory-count rejection, Windows-model case-collision rejection and symlink rejection.

This is narrow helper evidence, not a full Rust 1.97.1 H2 platform admission run.

## Canonical bounded snapshot-copy authority

Canonical helper:

`scripts/nxb-153-rust-toolchain-snapshot-copy.py`

Policy:

`nxb-153-rust-toolchain-snapshot-copy-v1`

Current exact Git blob:

`023e277eac38fe03659a5234a0e9d1825b3a0ae6`

Snapshot capture uses the same availability envelope:

- at most 65,536 regular files;
- at most 65,536 source directories, including the source root;
- at most 512 MiB per regular file;
- at most 4 GiB total admitted regular-file bytes;
- empty, non-indirection destination root;
- no source symlink/reparse/special-file authority;
- create-new destination files/directories rather than overwrite;
- file identity/size/time stability checks while opening/copying;
- source directory stability checks during traversal;
- fail-closed source growth detection.

Linux additionally uses descriptor-relative `O_DIRECTORY` / `O_NOFOLLOW` traversal. Windows-model traversal rejects case-insensitive sibling collisions, reserved device stems and the deliberately narrow ASCII component grammar used by this contract.

The exact helper source used for this milestone compiled and its Linux-host self-test passed locally. The self-test covers normal copy accounting, file-count rejection, total-byte rejection, directory-count rejection and symlink rejection.

The Linux-host helper results do **not** establish Windows runtime behavior.

## Linux H2

Layering:

```text
nxb-153-linux-immutable-source.sh                 canonical bounded H2 entrypoint
  -> nxb-153-linux-immutable-source-h2-copy-inner.sh
     -> nxb-153-linux-immutable-source-h1-inner.sh
        -> nxb-153-linux-immutable-source-inner.sh
```

The canonical Linux entrypoint exact-Git-object resolves the H2 inner runner and bounded-copy helper, runs helper self-test, then delegates to the exact inner runner.

The preserved H2 inner runner contains the narrow capture call:

`cp -a --no-preserve=ownership "$host_sysroot/." "$snapshot/"`

The canonical entrypoint exports a one-use `cp` function only to the H2 child process. It accepts only that exact call shape, delegates the complete sysroot copy to the exact-head bounded helper and removes itself immediately after capture, so Cargo/build-script processes do not retain a generic copy-command override.

The H2 inner flow then:

1. resolves H1 and tree-authority helpers from exact-head Git objects;
2. runs authority self-test;
3. resolves Rust 1.97.1 host sysroot;
4. computes the bounded deterministic host tree identity;
5. enters private user/mount namespace authority;
6. creates a private tmpfs snapshot and performs bounded capture;
7. verifies snapshot identity against the host capture digest;
8. requires cargo, rustc, rustdoc, rustfmt, cargo-fmt, cargo-clippy and clippy-driver in the snapshot;
9. remounts the snapshot read-only;
10. proves a nested validation namespace cannot remount the parent H2 snapshot writable;
11. requires relocated rustc to report the snapshot root and Rust 1.97.1;
12. installs a private read-only rustup shim restricted to the exact toolchain;
13. runs the H1 + immutable workspace/dependency/security-tool chain under snapshot authority;
14. re-verifies tree identity after gates;
15. requires final write denial and fail-closed cleanup.

Narrow Linux primitive/helper tests are not the complete current-head Rust 1.97.1 admission run.

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
- pins the `scripts` namespace with a native directory handle that withholds delete sharing;
- runs the exact bounded-copy helper self-test;
- leaves `-SelfTest` delegation unmodified so the primitive executable probe uses native `Copy-Item`;
- during real validation only, installs a narrow `Copy-Item` function visible to the nested H2 capture path;
- requires the exact recursive/force capture shape;
- derives one host-sysroot root and calls the bounded helper once for the entire sysroot;
- treats the preserved H2 inner runner's top-level loop as verified consumption of that same source enumeration;
- rejects duplicate/unexpected top-level entries, second roots/destinations, missing bounded copy or incomplete loop consumption;
- removes the temporary function and re-verifies pinned entry/helper Git objects after execution.

This preserves one global file/directory/byte budget for the Windows sysroot rather than granting a separate budget to every top-level directory.

### Windows H2 primitive self-test

The entry-inner `-SelfTest` source-stages checks for:

- `FileShare.Read` concurrent write denial;
- pinned-file delete denial;
- native directory-handle rename/delete denial;
- current-user write/create/delete ACL denial while read/execute remains available;
- file and subdirectory injection denial;
- executable launch under the deny policy and active handles;
- fail-closed ACL restoration, handle disposal and temporary-tree cleanup.

The H2 deny mask deliberately does **not** deny `ChangePermissions` or `TakeOwnership`; ACL restoration authority remains available while write/create/delete mutation is blocked by the narrower deny set plus active file/directory handles.

The self-test is source-staged but has **not** executed in the current environment because no supported PowerShell/Windows runtime is available here.

## Windows runtime boundary

No Windows H2 syntax/runtime PASS is claimed from the current execution environment.

Real supported Windows/NTFS validation must prove at least:

- PowerShell parsing, function scope and nested invocation for bounded `Copy-Item` interception;
- whole-sysroot file/directory/byte accounting under the Windows model;
- H2 primitive self-test behavior;
- installed Rust 1.97.1 snapshot capture;
- native directory-handle and file-share semantics;
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

H2 can be admitted only after the exact same final NXB-153 Git head has real Linux and Windows evidence proving that heavy Rust gates consumed only the verified immutable/pinned, directory-bounded and byte-bounded snapshot, final identity/cleanup succeeded and all other #90-#98 gates remain satisfied.
