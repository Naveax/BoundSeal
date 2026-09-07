# NXB-153 Host Rust Toolchain H2 Snapshot Authority

## Status

This document records the current **source-staged, not admitted** H2 host-Rust authority model for NXB-153.

Platform evidence must continue to record:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

until one exact final Git head completes real supported Linux and Windows execution and the producers, reviewers and dual-platform closure are deliberately migrated to a stronger evidence state.

Historical Pass A-D evidence does not validate this current Pass E authority delta.

## Goal

H1 gives a deterministic identity to the installed Rust 1.97.1 tree. H2 prevents that mutable host/rustup tree from remaining heavy-gate authority by copying it into a private verified snapshot and consuming the snapshot instead.

Availability controls are part of authority. File bytes, directory traversal, PowerShell object enumeration, Git stdout and process-output handling must fail closed before attacker-expandable work can accumulate.

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

Linux additionally uses descriptor-relative `O_DIRECTORY` / `O_NOFOLLOW`. The Windows model rejects case-insensitive collisions, Win32 reserved device stems and paths outside the deliberately narrow ASCII component grammar. Windows H2 now adds a long-lived native destination broker around the copy-to-consumption lifetime as described below.

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
           -> nxb-153-windows-immutable-source-h2-broker-entry.ps1
              -> nxb-153-windows-immutable-source-h2-entry-inner.ps1
                 -> nxb-153-windows-immutable-source-h2-inner.ps1
                    -> nxb-153-windows-immutable-source-h1-inner.ps1
                       -> nxb-153-windows-immutable-source-inner.ps1
```

Current outer availability/object layers:

- canonical bounded string-capture guard: `scripts/nxb-153-windows-immutable-source.ps1` -> `f768e3b8a7899b7f63555f380e5a96ae3c8c6ac2`;
- current bounded H2 Git-output guard: `scripts/nxb-153-windows-immutable-source-git-output-inner.ps1` -> `c92a612c2e7921191beb64d1c60a0798fe3fb7ae`;
- preserved PowerShell enumeration guard: `scripts/nxb-153-windows-immutable-source-enumeration-inner.ps1` -> `b586f5c8557f8a08f56f9616c9580b983be0d16f`;
- current bounded-copy/broker supervisor: `scripts/nxb-153-windows-immutable-source-bounded-inner.ps1` -> `6d103dd7711d52e679a675cac9cf2b9d4f52e5fe`;
- H2 broker-entry wrapper: `scripts/nxb-153-windows-immutable-source-h2-broker-entry.ps1` -> `1afaeb0656201fae952a7d877cbc01d5ce7d1fee`;
- native destination broker: `scripts/nxb-153-windows-h2-destination-broker.py` -> `c8520395f24d3fe3f29149b152892fac6cd7872c`;
- bounded dependency direct-child authority: `scripts/nxb-153-windows-dependency-source.ps1` -> `76734e3f5ab9adbf2c9e509ff4be08427da57aa3`;
- bounded immutable-source archive/tar authority: `scripts/nxb-153-windows-immutable-source-inner.ps1` -> `664930b3b62f54b57345ff387fabce7a8171f45f`.

The earlier `7ffbaadb69ecffec8fcc9961c585fcb3644df422` H2 Git-output blob is historical and is not current authority.

Each outer layer pins the `scripts` namespace, exact-Git-object verifies the next admitted implementation object, delegates through a deliberately narrow proxy/supervision surface and re-verifies pinned implementation authority before success. Cleanup failures fail closed.

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

The H2 Git-output layer resolves the real Git application before installing a temporary `git` function.

All bare Git invocations inside the nested H2 scope are executed through `Diagnostics.Process` with bounded stdout:

- maximum 64 MiB stdout bytes;
- maximum 4,096 decoded stdout records;
- strict UTF-8 decoding;
- each stdout read must make progress within **300,000 ms / 5 minutes**;
- after stdout closes, Git must exit within **30,000 ms / 30 seconds**;
- timeout/limit failure attempts recursive termination and bounded reap;
- nonzero Git exit code is preserved through `$LASTEXITCODE` for existing caller semantics;
- oversized byte/record output fails closed;
- the function is removed in `finally`.

This covers `git ls-tree`, `git status --porcelain=v1 --untracked-files=all`, `rev-parse`, `cat-file` and the other bare Git calls visible in the current Windows H2 chain. The self-test forces both record-count and byte-count rejection.

### Bounded PowerShell filesystem enumeration

The next preserved layer installs a module-qualified `Get-ChildItem` proxy.

It supports only the current NXB-153 parameter surface (`-LiteralPath`, `-Force`, `-Recurse`, `-Directory`, `-File` plus common parameters), streams results and rejects any one invocation after 131,072 emitted filesystem objects.

The limit is the combined 65,536-file + 65,536-directory authority ceiling. The self-test verifies normal enumeration and forced low-limit rejection.

### Bounded whole-sysroot copy and destination lifetime

The current bounded layer exact-object verifies the H2 broker-entry wrapper and native destination broker, retains the whole-sysroot global 65,536-file / 65,536-directory / 512 MiB-per-file / 4 GiB-total budget and intercepts only the expected top-level capture flow.

The broker-entry defers creation of the exact H2 snapshot root. The long-lived native broker then creates the snapshot root and descendants using relative `NtCreateFile` create-new semantics from retained parent handles. Destination directory handles are retained from creation. File creator handles withhold write/delete sharing while bytes are populated.

Before writer handles are relaxed, the broker arms a recursive `ReadDirectoryChangesW` watcher. Each file then transitions from creator write authority to a read guard while identity continuity is checked and any watcher-visible mutation is fatal.

The broker remains alive across:

1. destination creation and copy;
2. writer-to-read-guard transition;
3. deterministic snapshot verification;
4. PowerShell file/directory handle acquisition;
5. write/create/delete deny ACL staging and injection probes;
6. relocated Rust heavy gates;
7. post-gate identity checks and ACL restoration;
8. the beginning of final snapshot cleanup.

At the first required `snapshotRoot\bin\rustc.exe` probe, the broker-entry requires a healthy broker `CHECK` after the existing H2 PowerShell object/ACL authority has already been staged. At final snapshot removal it requires another healthy observation, a controlled `STOP`, healthy stopped record and zero broker exit status before deletion proceeds.

This closes the previously identified **source-level** pathname-only Python-to-PowerShell handoff gap. Supported Windows execution is still mandatory before the lifetime mechanism is admitted.

### Snapshot consumption authority

After capture, the Windows H2 chain verifies deterministic snapshot identity, enumerates the snapshot through the bounded shell layer, opens native directory/file authority handles, applies current-user write/create/delete denial, proves injection denial and runs H1/workspace/dependency gates through relocated snapshot Rust components.

The deny mask intentionally does not deny `ChangePermissions` or `TakeOwnership`; ACL restoration remains possible while write/create/delete mutation is denied. Restoration, handle disposal and snapshot deletion are part of success.

### Direct process-output and child-lifecycle hardening

The three previously identified direct `.NET ReadToEndAsync()` capture paths remain removed, and the known child pipe/exit lifecycle gap is now source-bounded.

Current exact blobs:

- `scripts/nxb-153-windows-dependency-source.ps1` -> `76734e3f5ab9adbf2c9e509ff4be08427da57aa3`;
- `scripts/nxb-153-windows-immutable-source-inner.ps1` -> `664930b3b62f54b57345ff387fabce7a8171f45f`.

Current source-staged behavior is:

- isolated registry metadata verification redirects stdin only; stdout/stderr inherit the validation host; stdin uses bounded `WriteAsync` and `FlushAsync`; child exit is bounded;
- `git archive` redirects only binary stdout, reads it with bounded `ReadAsync`, preserves the existing 1 GiB archive cap, inherits stderr and bounds post-stdout exit;
- tar extraction redirects only stdin from the bounded pinned archive, delivers archive chunks with bounded `WriteAsync` / `FlushAsync`, inherits stdout/stderr and bounds post-stdin exit;
- each child-pipe operation uses **300,000 ms / 5 minutes** inactivity authority;
- post-I/O exit uses **30,000 ms / 30 seconds**;
- timeout/failure cleanup attempts recursive `Kill(true)` and bounded reap before process disposal.

The registry helper itself admits at most 32 MiB of Cargo metadata and emits only its bounded validation summary on the successful metadata path. The parent retains no verifier stdout/stderr string.

Static exact-head review confirms the former synchronous `StandardInput.Write(...)`, child-pipe `CopyTo(...)` and parameterless `WaitForExit()` forms are absent from the targeted source-hardened paths.

This closes the known direct-child **source-level** availability finding. Real Windows tests must still demonstrate correct timeout, inherited-output, nonzero-exit, cancellation, process-tree termination and cleanup behavior.

## Explicit remaining Windows runtime blockers

The source-level destination handoff, direct retention and known direct-child lifecycle findings are now hardened, but no supported Windows/NTFS PowerShell H2 PASS is claimed from the current execution environment.

Real Windows validation must prove at least:

- parser/function-scope behavior for the `Out-String`, `git`, `Get-ChildItem`, `Copy-Item`, broker-entry and `rustup` interception/supervision layers;
- exact formatting equivalence of the bounded `Out-String` proxy for its admitted string/information/error record surface;
- 64 MiB input/output and 4,096-object string-capture rejection;
- 64 MiB / 4,096-record Git-output rejection;
- Git read-inactivity and post-stdout exit timeout behavior;
- 131,072-object filesystem-enumeration rejection;
- whole-sysroot file/directory/byte accounting;
- registry-verifier stalled-stdin, nonzero-exit, inherited-output and cleanup behavior;
- exact-head Git-archive stalled-stdout, byte-limit, nonzero-exit and cleanup behavior;
- tar-extraction stalled-stdin, nonzero-exit, inherited-output and cleanup behavior;
- Python `ctypes` and relative `NtCreateFile` destination creation;
- create-new collision and reparse rejection;
- directory/file share-mode behavior and writer-to-read-guard identity continuity;
- recursive watcher create/delete/rename/content/attribute mutation detection, transient restore detection and overflow/failure fail-closed behavior;
- successful creator-broker to PowerShell handle/ACL overlap;
- ACL mutation/injection denial while execution and ACL restoration remain functional;
- Rust 1.97.1 rustc/cargo/rustfmt/Clippy, DLL/sysroot/library loading from the copied snapshot while broker guards remain live;
- deliberate mutation during heavy gates causing final failure;
- broker CHECK/STOP and cleanup/recovery behavior on success and failure.

## Evidence boundary

Source staging does not change schema-v2 host-Rust evidence from:

`version_pinned_object_identity_pending`

A stronger state must be introduced atomically across both platform producers, both semantic reviewers and the dual-platform closure contract. Historical pending evidence must not be reinterpreted as H2 proof.

## Admission acceptance

H2 can be admitted only after the exact same final NXB-153 Git head has real Linux and Windows evidence proving that heavy Rust gates consumed only the verified immutable/pinned and availability-bounded snapshot, the bounded string/Git/direct-child layers behave correctly, Windows destination lifetime authority survives creation-to-consumption, final identity/cleanup succeeds and every other #90-#98 gate remains satisfied.
