# NXB-153 Host Rust Toolchain H2 Snapshot Authority

## Status

This document records the current **source-staged, not admitted** H2 host-Rust authority model for NXB-153.

Platform evidence must continue to record:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

until one exact final Git head completes real supported Linux and Windows execution and the producers, reviewers and dual-platform closure are deliberately migrated to a stronger evidence state.

Historical Pass A-D evidence does not validate this current Pass E authority delta.

## Goal

H1 gives a deterministic identity to the installed Rust 1.97.1 tree. H2 prevents that mutable host/rustup tree from remaining heavy-gate authority by copying it into a private verified snapshot and consuming the snapshot instead.

Availability controls are part of authority. File bytes, directory traversal, PowerShell object enumeration, Git stdout and PowerShell string capture must fail closed before unbounded work can accumulate.

## Canonical Rust tree authority

Helper:

`scripts/nxb-153-rust-toolchain-authority.py`

Exact Git blob:

`d3e392a41509f6e3c71e152681f0830514511686`

Policy:

`nxb-153-host-rust-toolchain-tree-authority-v1`

The tree digest binds sorted relative path bytes, mode class, exact file size and SHA-256 of stable file bytes.

Traversal limits:

- at most 65,536 regular files;
- at most 65,536 source directories including root;
- at most 512 MiB per regular file;
- at most 4 GiB total regular-file bytes;
- no symlink/reparse/special-file authority;
- stable file identity/size/mtime/ctime across reads;
- stable directory identity during traversal;
- Linux descriptor-relative `O_DIRECTORY` / `O_NOFOLLOW` traversal;
- conservative Windows pathname grammar and case-collision rejection.

The helper was Python-compiled and self-tested on the available Linux host. Those narrow helper checks are not full Rust 1.97.1 platform admission and do not prove Windows runtime behavior.

## Canonical bounded snapshot-copy authority

Helper:

`scripts/nxb-153-rust-toolchain-snapshot-copy.py`

Exact Git blob:

`023e277eac38fe03659a5234a0e9d1825b3a0ae6`

Policy:

`nxb-153-rust-toolchain-snapshot-copy-v1`

The copier applies the same 65,536-file, 65,536-directory, 512 MiB/file and 4 GiB total-byte envelope. It requires an empty non-indirection destination, rejects source indirection/special files, uses create-new destination objects, checks stable source object metadata and rejects source growth.

Linux additionally uses descriptor-relative `O_DIRECTORY` / `O_NOFOLLOW`. The Windows model rejects case-insensitive collisions, Win32 reserved device stems and paths outside the deliberately narrow ASCII component grammar.

## Linux H2

Layering:

```text
nxb-153-linux-immutable-source.sh
  -> nxb-153-linux-immutable-source-h2-copy-inner.sh
     -> nxb-153-linux-immutable-source-h1-inner.sh
        -> nxb-153-linux-immutable-source-inner.sh
```

The canonical Linux wrapper exact-object resolves the bounded-copy helper and preserved H2 runner. Its one-use `cp` interception admits only the expected complete sysroot capture call and is removed before Cargo/build-script lifetime.

The H2 chain then:

1. resolves exact-head H1/tree helpers;
2. computes bounded deterministic host-tree identity;
3. enters private user/mount namespace authority;
4. creates a private tmpfs Rust snapshot;
5. performs bounded copy and verifies snapshot identity;
6. requires the expected Rust/Cargo/rustfmt/Clippy components;
7. remounts the Rust snapshot read-only;
8. proves a nested validation namespace cannot remount it writable;
9. requires relocated rustc to report the snapshot root and Rust 1.97.1;
10. runs H1, immutable workspace, frozen dependency and security-tool gates from snapshot authority;
11. re-verifies identity, final write denial and cleanup.

No current-head full Linux Rust 1.97.1 H2 admission is claimed.

## Windows H2

### Current layering

```text
nxb-153-windows-immutable-source.ps1
  -> nxb-153-windows-immutable-source-git-output-inner.ps1
     -> nxb-153-windows-immutable-source-enumeration-inner.ps1
        -> nxb-153-windows-immutable-source-bounded-inner.ps1
           -> nxb-153-windows-immutable-source-h2-entry-inner.ps1
              -> nxb-153-windows-immutable-source-h2-inner.ps1
                 -> nxb-153-windows-immutable-source-h1-inner.ps1
                    -> nxb-153-windows-immutable-source-inner.ps1
```

Current outer availability/object layers:

- canonical bounded string-capture guard: `scripts/nxb-153-windows-immutable-source.ps1` → `f768e3b8a7899b7f63555f380e5a96ae3c8c6ac2`;
- preserved bounded Git-output guard: `scripts/nxb-153-windows-immutable-source-git-output-inner.ps1` → `7ffbaadb69ecffec8fcc9961c585fcb3644df422`;
- preserved PowerShell enumeration guard: `scripts/nxb-153-windows-immutable-source-enumeration-inner.ps1` → `b586f5c8557f8a08f56f9616c9580b983be0d16f`;
- preserved bounded-copy entrypoint: `scripts/nxb-153-windows-immutable-source-bounded-inner.ps1` → `699ffb90752c23919c83d8ad2193167792b55b40`.

Each outer layer pins the `scripts` namespace, exact-Git-object verifies the next inner layer, delegates through a deliberately narrow temporary proxy and re-verifies the pinned inner object before success. Cleanup failures fail closed.

### Bounded PowerShell string capture

The canonical outer layer installs a scope-visible `Out-String` proxy for the NXB-153 H2 chain.

The current contract deliberately preserves pipeline-level formatting rather than formatting each input object separately:

- accepted pipeline objects are limited to `String`, `InformationRecord` and `ErrorRecord`, matching the current NXB-153 capture surface;
- future arbitrary PowerShell objects fail closed instead of silently receiving different formatting semantics;
- at most 4,096 pipeline objects are admitted per capture;
- strict UTF-8 input probe bytes are limited to 64 MiB before buffering;
- the complete admitted object sequence is passed **once** to module-qualified `Microsoft.PowerShell.Utility\Out-String`, preserving grouping/order semantics of the real cmdlet;
- the final formatted string is independently limited to 64 MiB strict UTF-8;
- the proxy is removed in `finally`;
- exact-Git-object authority for the preserved Git-output wrapper is checked before and after delegation.

Static call-surface review found native/helper strings everywhere except the Windows closure-review path, where `Write-Host` output redirected with `6>&1` can enter the success stream as `InformationRecord`. The source-staged self-test therefore compares the bounded proxy **byte-for-byte** with module-qualified real `Out-String` for both a multi-string pipeline and a mixed string + redirected `InformationRecord` pipeline. It also forces byte-limit rejection, object-count rejection and unsupported-object rejection.

This bounds captures such as `cargo metadata --locked | Out-String`, helper JSON capture, version/sysroot capture and review-output aggregation without changing the documented pipeline-format contract.

No Windows parser/runtime PASS is claimed for this proxy; the semantic self-test still must execute on supported PowerShell/Windows.

### Bounded Git stdout

The preserved Git-output layer resolves the real Git application before installing a temporary `git` function.

All bare Git invocations inside the nested H2 scope are executed through `Diagnostics.Process` with bounded stdout:

- maximum 64 MiB stdout bytes;
- maximum 4,096 decoded stdout records;
- strict UTF-8 decoding;
- nonzero Git exit code preserved through `$LASTEXITCODE` for existing caller semantics;
- oversized byte/record output fails closed;
- the function is removed in `finally`.

This covers `git ls-tree`, `git status --porcelain=v1 --untracked-files=all`, `rev-parse`, `cat-file` and the other bare Git calls visible in the current Windows H2 chain. The self-test forces both record-count and byte-count rejection.

### Bounded PowerShell filesystem enumeration

The next preserved layer installs a module-qualified `Get-ChildItem` proxy.

It supports only the current NXB-153 parameter surface (`-LiteralPath`, `-Force`, `-Recurse`, `-Directory`, `-File` plus common parameters), streams results and rejects any one invocation after 131,072 emitted filesystem objects.

The limit is the combined 65,536-file + 65,536-directory authority ceiling. The self-test verifies normal enumeration and forced low-limit rejection.

### Bounded whole-sysroot copy

The preserved bounded-copy layer exact-object verifies the Python snapshot-copy helper and H2 entry runner, then maps the legacy top-level `Copy-Item` capture flow onto one global bounded whole-sysroot copy.

It rejects unexpected call shape, duplicate invocation, second source roots/destinations and incomplete source-loop consumption. The helper's global file/directory/byte limits therefore apply to the whole Windows sysroot rather than separately to every top-level directory.

### Snapshot consumption authority

After capture, the Windows H2 chain verifies deterministic snapshot identity, enumerates the snapshot through the bounded shell layer, opens native directory/file authority handles, applies current-user write/create/delete denial, proves injection denial and runs H1/workspace/dependency gates through relocated snapshot Rust components.

The deny mask intentionally does not deny `ChangePermissions` or `TakeOwnership`; ACL restoration remains possible while write/create/delete mutation is denied. Restoration, handle disposal and snapshot deletion are part of success.

### Direct .NET capture observations

Three direct `ReadToEndAsync()` paths remain in current source:

- isolated registry-verifier stdout/stderr;
- `git archive` stderr;
- tar-extraction stdout/stderr.

They bypass the `Out-String` proxy, so they remain explicit runtime-review points. Their upstream work is nevertheless source-bounded: Cargo metadata input is capped by the 64 MiB string layer, the registry helper is exact-head code, the Git archive itself is byte-bounded, and the exact-head source manifest is limited to 4,096 tracked files / its documented byte envelope. Real Windows tests must still demonstrate that these process-capture paths do not create an unacceptable availability failure mode.

## Explicit remaining Windows destination-namespace blocker

Current source still does **not** establish continuous native no-delete/no-write authority for every newly created Windows H2 destination child from the instant the Python copier creates it until the later PowerShell directory/file pinning and ACL phase acquires authority.

Post-copy reparse rejection, deterministic identity verification and later file/directory pinning are present, but post-copy equality is not lifetime authority under a strict same-user concurrent pathname attacker model.

Admission requires either:

- copier-created destination handles retained continuously across the Python-to-PowerShell handoff; or
- a strength-equivalent kernel-backed namespace/ACL mechanism that prevents transient child replacement during the handoff.

This remains an explicit #98 blocker.

## Windows runtime boundary

No supported Windows/NTFS PowerShell H2 PASS is claimed from the current execution environment.

Real Windows validation must prove at least:

- parser/function-scope behavior for the `Out-String`, `git`, `Get-ChildItem`, `Copy-Item` and `rustup` interception layers;
- exact formatting equivalence of the bounded `Out-String` proxy for its admitted string/information/error record surface;
- 64 MiB input/output and 4,096-object string-capture rejection;
- 64 MiB / 4,096-record Git-output rejection;
- 131,072-object filesystem-enumeration rejection;
- whole-sysroot file/directory/byte accounting;
- H2 primitive self-tests;
- continuous destination namespace authority or a strength-equivalent mechanism;
- native file-share/directory-handle behavior;
- ACL mutation/injection denial while execution and ACL restoration remain functional;
- Rust 1.97.1 rustc/cargo/rustfmt/Clippy, DLL/sysroot/library loading from the copied snapshot;
- bounded behavior of the remaining direct .NET process captures;
- cleanup/recovery behavior on success and failure.

## Evidence boundary

Source staging does not change schema-v2 host-Rust evidence from:

`version_pinned_object_identity_pending`

A stronger state must be introduced atomically across both platform producers, both semantic reviewers and the dual-platform closure contract. Historical pending evidence must not be reinterpreted as H2 proof.

## Admission acceptance

H2 can be admitted only after the exact same final NXB-153 Git head has real Linux and Windows evidence proving that heavy Rust gates consumed only the verified immutable/pinned and availability-bounded snapshot, the bounded string layer preserves admitted pipeline semantics, Windows destination namespace authority is continuous through creation-to-consumption, direct process-capture behavior is acceptable, final identity/cleanup succeeds and every other #90-#98 gate remains satisfied.
