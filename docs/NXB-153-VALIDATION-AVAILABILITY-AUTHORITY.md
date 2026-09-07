# NXB-153 Validation Availability Authority

## Status

This document records the current **source-staged, not admitted** availability contract for NXB-153 validation.

Availability is part of validation authority: an exact-head gate is not allowed to consume attacker-expandable stdout, filesystem enumeration, source manifests or toolchain trees without a fail-closed envelope. The limits below constrain resource consumption; they do not replace exact-object, namespace, checksum, immutability or platform-runtime proof.

Historical Pass A-D evidence does not validate this current Pass E availability delta.

## Common admission boundary

The final NXB-153 head still requires real supported Linux and Windows execution. Source-level self-tests and local primitives in this document are not platform admission.

Current schema-v2 evidence therefore remains:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 remains draft/not admitted and issues #90-#98 remain open.

## Linux Git-status capture authority

Three Linux shell entry surfaces previously used direct command substitution around:

`git status --porcelain=v1 --untracked-files=all`

The current source stages bounded outer guards for:

- `scripts/prepare-and-validate-nxb-153-linux.sh`;
- `scripts/validate-nxb-153-linux.sh`;
- `scripts/review-nxb-153-evidence-linux.sh`.

The historical/full implementations are retained byte-for-byte at explicit inner paths where applicable:

- `scripts/prepare-and-validate-nxb-153-linux-inner.sh`;
- `scripts/validate-nxb-153-linux-inner.sh`;
- `scripts/review-nxb-153-evidence-linux-inner.sh`.

Each outer guard exact-head resolves the inner Git blob and admits only the current cleanliness-call shape. The Git status stream is consumed incrementally instead of being retained in full.

Limits per cleanliness capture:

- maximum stdout bytes: **64 MiB**;
- maximum decoded record count: **4,096**;
- clean output becomes an empty stream;
- any non-empty admitted status becomes one bounded dirty sentinel;
- Git/filter failure or limit failure becomes a non-empty invalid sentinel so the pre-existing clean-tree test fails closed.

The guards self-test clean, dirty, forced byte-limit and forced record-limit behavior. The validator and evidence-review guards additionally re-resolve their exact-head inner authority after successful delegation.

The Linux semantic evidence reviewer independently bounds Git process capture rather than relying only on shell guards. `scripts/review-nxb-153-evidence-linux.py` uses bounded temporary output objects with a 64 MiB stdout/stderr envelope, a 4,096-line stdout limit, strict UTF-8 decoding and child file-size limiting where supported.

A narrow local primitive created 4,100 untracked paths and demonstrated fail-closed rejection at the 4,096-record boundary. That primitive is not admission evidence.

## Linux exact-head source-envelope authority

Canonical helper:

`scripts/nxb-153-linux-source-envelope.py`

Current helper policy:

`nxb-153-linux-source-envelope-v1`

The canonical immutable-source outer runner exact-head resolves this helper before the H2/H1/immutable-source chain. The helper source itself is bounded by the outer exact-object implementation envelope and is loaded from the resolved Git blob. The current outer preserves its trailing source bytes while staging the helper text for isolated Python execution.

Before any heavy Rust/Cargo gate, the outer performs two exact-head preflights against the repository descriptor authority.

### Tree/manifest envelope

Input:

`git ls-tree -r -t -l -z --full-tree <exact-head>`

The helper streams NUL-delimited records and fails closed above:

- **64 MiB** total tree-manifest bytes;
- **8,192** total tree records;
- **4,096** tracked regular files;
- **4,096** tracked directories;
- **512 MiB** total tracked regular-file bytes;
- **512 MiB** for any one tracked regular file;
- **4 KiB** for any one Git pathname;
- **8 KiB** for any one encoded `ls-tree` record.

Only `100644` / `100755` blobs and ordinary `040000` tree records are admitted. Object IDs must be canonical lowercase 40-hex SHA-1. Empty, absolute or ambiguous `.` / `..` path components, duplicate full paths and controlled runtime-root collisions fail closed.

Reserved source roots include:

- `target`;
- `.nxb-153-tmp`;
- `.nxb-153-fetch-home`;
- `.nxb-153-vendor`;
- `.nxb-153-cargo-home`;
- `.nxb-153-config`.

This preflight provides an upstream hard bound for the two inner immutable-source Python manifest readers that deliberately consume their complete exact-head `ls-tree` inputs in memory. Those inner manifests are derived from the same exact head and are no larger in authority scope than the preflighted tree.

### Archive envelope

Input:

`git archive --format=tar <exact-head>`

The helper streams the tar output without retaining it and fails closed unless:

- the archive is non-empty;
- total archive bytes are at most **1 GiB**;
- total bytes are aligned to a 512-byte tar block.

The actual immutable-source runner later regenerates the archive from the same exact Git head and still performs namespace plus per-file Git-object verification after extraction. The archive-size preflight is therefore an availability boundary, not a replacement for source-byte authority.

### Narrow primitive verification

The helper has passed local Python compilation and its source self-test. A real temporary Git repository also passed both:

- real `git ls-tree -r -t -l -z --full-tree HEAD` -> helper `validate-tree`;
- real `git archive --format=tar HEAD` -> helper `validate-archive`.

The outer Bash script passed `bash -n`. A separate synthetic Git-object probe confirmed the helper text captured by the exact-source loader hashes back to the same Git blob, including trailing newline bytes.

These are implementation primitives only and do not claim current-head Rust 1.97.1 Linux H2 admission.

## Linux remaining bounded-capture observations

Repo-wide review of the NXB-153 delta leaves two raw `sys.stdin.buffer.read()` calls in the immutable-source inner runner. Both consume exact-head `ls-tree` manifests only after the new source-envelope preflight, so their upstream source volume is now explicitly bounded.

Other relevant readers already have direct caps, including Cargo metadata in `nxb-153-registry-source.py`.

Remaining `subprocess.PIPE` uses visible in the NXB-153 Linux delta are restricted to sealed-tool version/self-test output and a fixed marker primitive. They are not current high-volume attacker-controlled capture surfaces.

The evidence-review shell also buffers the descriptor-guard self-test/review success output, but the semantic reviewer emits only a fixed small closure summary and bounded path material; dependency vendor summary output is a fixed four-field JSON record. No new high-volume capture blocker was identified there.

## Windows H2 availability authority

The Windows H2 chain remains independently bounded and source-staged.

Canonical outer sequence:

```text
scripts/nxb-153-windows-immutable-source.ps1
  -> nxb-153-windows-immutable-source-git-output-inner.ps1
     -> nxb-153-windows-immutable-source-enumeration-inner.ps1
        -> nxb-153-windows-immutable-source-bounded-inner.ps1
           -> H2 destination broker / H1 / immutable-source inner chain
```

Current availability boundaries include:

- `Out-String`: at most **4,096 pipeline objects**, **64 MiB** strict UTF-8 input probe bytes and **64 MiB** final formatted output;
- bare Git stdout: **64 MiB / 4,096 decoded records**;
- `Get-ChildItem`: **131,072 emitted filesystem objects** per admitted invocation;
- host Rust tree / snapshot copy: **65,536 files / 65,536 directories / 512 MiB per file / 4 GiB total**;
- exact-head Git archive streamed to a pinned create-new file: at most **1 GiB**.

The `Out-String` proxy admits only the currently reviewed `String`, `InformationRecord` and `ErrorRecord` surface and applies module-qualified real `Out-String` once to the complete admitted sequence so pipeline-format semantics are preserved.

The source-staged destination lifetime authority is implemented by:

- `scripts/nxb-153-windows-h2-destination-broker.py`;
- `scripts/nxb-153-windows-immutable-source-h2-broker-entry.ps1`;
- the bounded H2 outer entrypoint that exact-object verifies and supervises them.

The broker creates destination children through retained native relative-handle authority, transitions file writers under a recursive change watcher, overlaps with the existing PowerShell file/directory/ACL authority and remains active through the relocated Rust heavy-gate lifetime. This closes the previously identified **source-level** pathname-only handoff gap; it does not create a Windows runtime PASS by documentation.

No supported Windows/NTFS PowerShell runtime PASS is claimed.

## Windows process-output capture hardening

The three previously identified direct `.NET ReadToEndAsync()` capture paths are no longer present in current source.

Current source-staged behavior is:

- isolated registry metadata verification redirects **stdin only**; verifier stdout/stderr inherit the validation host and the parent retains no child output string;
- `git archive` redirects only its binary stdout, which is streamed incrementally into the pinned create-new archive and rejected above **1 GiB**; stderr inherits the validation host;
- tar extraction redirects only stdin from the already bounded pinned archive; stdout/stderr inherit the validation host and are not retained by the parent process.

The parent now uses child exit status for these three paths instead of retaining arbitrarily large stdout/stderr strings. This removes the source-level unbounded `ReadToEndAsync()` memory-capture surface and its associated redirected-pipe retention risk.

Real supported Windows execution is still required to prove the exact process-launch, inherited-output, pipe, cancellation and cleanup behavior under the documented environment. Source staging is not admission.

## Explicit remaining Windows admission blockers

### Destination lifetime runtime proof

The destination lifetime broker is source-staged but still requires supported Windows/NTFS execution proving native relative creation, create-new collision behavior, reparse rejection, handle/share-mode semantics, watcher mutation detection and overflow/failure handling, PowerShell interception/delegation, overlap with ACL authority, relocated Rust/DLL/sysroot loading and cleanup/recovery.

### Process-output runtime proof

The direct in-memory captures are source-removed, but supported Windows execution must still verify that inherited stdout/stderr behavior is compatible with the validation host and that failure/cancellation paths terminate and clean up without hanging or weakening exact-head authority.

## Final admission requirements

The final same exact Git head must still demonstrate:

- full Linux Rust 1.97.1 H2 execution under exact-head immutable workspace/dependency/toolchain authority;
- full supported Windows NTFS/PowerShell H2 execution;
- bounded-capture and source-envelope primitive behavior on the real platform runs;
- destination-broker lifetime and mutation/adversarial behavior on supported Windows;
- process-output inheritance, failure and cleanup behavior on supported Windows;
- lock contention and mutation/injection probes;
- create-only schema-v2 evidence publication;
- object-anchored evidence review;
- same-head dual-platform guarded closure;
- final #90-#98 blocker review.

No availability source staging in this document should be interpreted as admission by itself.
