# NXB-153 Validation Evidence Integrity

## Status

This document records the source-staged integrity contract for NXB-153 exact-head validation evidence. It does **not** claim that the current feature head has passed Rust, Linux or Windows validation.

The purpose is to prevent a rerun, concurrent reviewer or stale preparation step from silently rewriting evidence that was already associated with an exact Git head, while also making the evidence publication boundary explicit about mutation ordering, repository-authority drift and durability.

## Exact-head artifact classes

NXB-153 validation uses three persistent evidence classes under `target/nxb-validation`:

1. **Tooling receipt** — records the exact head, Rust toolchain, cargo-audit/cargo-deny versions and binary SHA-256 values produced by fresh tool preparation.
2. **Platform validation evidence** — records a successful Linux or Windows validation result for one exact head and links it to the immutable tooling receipt.
3. **Dual-platform closure** — accepts Linux and Windows evidence only for the same exact head and canonical Cargo.lock, and emits `admission=blocker_review_required` rather than automatically admitting NXB-153.

All three classes are intended to be create-only for their canonical exact-head pathname.

## Tool preparation serialization

The validation tools live under a shared `target/nxb-tools` directory. Therefore an immutable receipt is insufficient if a later preparation can mutate those tool binaries before noticing that the exact-head receipt already exists.

Both preparation scripts now enforce this ordering:

1. resolve and verify the exact clean Git head;
2. compute the exact-head tooling-receipt pathname;
3. if that receipt already exists, fail **before** `rustup toolchain install` or any `cargo install --force` tool mutation;
4. claim an exact-head preparation lock with create-new semantics;
5. recheck the receipt after the lock is owned, closing the check/claim race;
6. only then install/refresh the pinned Rust components and cargo-audit/cargo-deny binaries;
7. publish the immutable receipt;
8. release the preparation lock before entering the validator.

A stale or racing preparation lock is never silently replaced. It requires explicit recovery.

Linux uses an atomic `mkdir` exact-head lock directory and synchronizes the evidence directory after lock claim/release. Windows uses `.NET FileMode.CreateNew` for the exact-head lock file and `Flush(true)` for the lock bytes. These source contracts still require real platform validation before durability is considered admitted.

## Linux publication contract

### Tooling receipt

`prepare-and-validate-nxb-153-linux.sh` writes the receipt into a unique private temporary file inside the validation directory and claims the canonical exact-head receipt name with a same-directory hard link.

- the canonical receipt is never opened with shell truncation;
- an existing exact-head receipt is checked before tool mutation and is not overwritten;
- exact-head preparations are serialized by the preparation lock;
- a losing publication removes only its own unclaimed temporary path;
- the temporary receipt bytes are `fsync`'d before the hard-link namespace claim;
- creation of the validation directory is followed by a sync of its `target` parent;
- after namespace claim and temporary-link cleanup, the validation directory is `fsync`'d before success is reported;
- temporary-link cleanup failure does not skip the directory-sync attempt; the cleanup outcome is reported after the durability attempt;
- rerunning preparation against an existing receipt fails explicitly and tells the operator to validate against the existing receipt or review/remove it intentionally.

### Platform validation evidence

`validate-nxb-153-linux.sh` uses the same temporary-file plus hard-link create-only pattern for the canonical Linux evidence pathname.

Immediately after exact-head and clean-worktree checks, the validator checks whether canonical Linux evidence already exists. If it does, the validator fails before resolving Rust/tool versions or re-running fmt/check/Clippy/tests/RustSec/cargo-deny. The existing evidence must be reviewed or explicitly recovered instead of manufacturing a second expensive result for the same exact-head pathname.

When no evidence exists, the validator proves the pinned Rust/tooling receipt/tool bytes, canonical Cargo.lock and all validation gates. Only after those gates succeed does it attempt the create-only evidence claim.

Before the hard-link claim the temporary evidence file is `fsync`'d. After claim/cleanup, the validation directory is `fsync`'d before the validator reports success. A temporary-link cleanup failure is retained as an error but does not prevent the directory durability attempt from running first.

### Dual-platform closure

The canonical Linux entrypoint is `review-nxb-153-evidence-linux.sh`; it invokes the stdlib-only `review-nxb-153-evidence-linux.py` implementation.

The Python reviewer:

- strictly validates evidence and tooling-receipt schemas, types, timestamps and SHA-256 values;
- rejects symbolic-link/reparse-point path components where the platform exposes them;
- requires Linux and Windows evidence for the same exact head, Rust/Cargo/tool versions and Cargo.lock;
- publishes the final closure directly with `O_CREAT | O_EXCL`;
- file-syncs the newly created closure before reporting success;
- syncs the containing evidence directory on non-Windows platforms;
- if another process wins the closure-name race, accepts the existing closure only when its parsed deterministic value is exactly equal;
- never uses overwrite-capable `os.replace()` for the canonical closure pathname;
- never performs path-based deletion of a partially visible closure after a write failure.

The shell entrypoint adds a repository-authority guard around that implementation. It captures the clean exact Git head and canonical Cargo.lock SHA-256 before review, runs the reviewer, then requires the final head, clean worktree and Cargo.lock bytes to remain exactly unchanged. If another agent moves the branch or mutates the worktree/lockfile during review, the guarded command fails and any newly visible closure is explicitly treated as requiring recovery/review rather than as a successful current-authority admission artifact.

The current Linux guarded wrapper passes a local `bash -n` syntax check. That is script syntax evidence only, not Rust/platform validation.

## Windows publication contract

### Tooling receipt

`prepare-and-validate-nxb-153-windows.ps1` checks the canonical exact-head receipt before tool mutation, serializes preparation with an exact-head `FileMode.CreateNew` lock file, rechecks the receipt after lock claim, then publishes the final tooling receipt using `.NET FileMode.CreateNew`, `FileAccess.Write` and `FileShare.None` with `Flush(true)`.

An existing exact-head receipt is not overwritten and the shared tool binaries are not refreshed before that condition is detected. A racing/stale preparation lock requires explicit recovery rather than being replaced.

### Platform validation evidence

`validate-nxb-153-windows.ps1` performs the same early existing-evidence preflight immediately after exact-head and clean-worktree verification. Existing canonical Windows evidence prevents the heavy validation gates from being rerun for the same exact head.

When validation is genuinely needed, final exact-head Windows evidence is published with `FileMode.CreateNew` and `Flush(true)`. `WriteAllText` overwrite semantics are not used for the canonical evidence pathname.

### Dual-platform closure

The canonical Windows entrypoint is `review-nxb-153-evidence-windows.ps1`. It captures the initial clean exact head and Cargo.lock SHA-256, invokes `review-nxb-153-evidence.ps1` as the closure implementation, then rechecks the final head, worktree and lock bytes.

The implementation creates a unique pending closure with `FileMode.CreateNew` and moves it to the canonical closure pathname without `-Force`. An existing canonical closure therefore remains a no-overwrite condition; a racing or stale pending file requires explicit recovery rather than silent replacement.

If repository authority changes while the implementation is running, the guarded Windows entrypoint fails after the implementation returns and explicitly marks any newly published closure as requiring recovery/review. The current execution environment has no PowerShell parser/runtime, so this guarded entrypoint is source-staged only and has **no claimed PowerShell PASS**.

Windows directory-entry durability remains a platform-validation concern rather than a source-only claim; the real Windows Rust/PowerShell validation pass must verify the supported filesystem behavior before admission.

## Immutability, authority and reruns

The exact-head artifact name is part of the evidence identity. Re-running a preparation, validator or closure operation must not silently mutate an existing canonical artifact merely to obtain a fresh timestamp or replace earlier bytes.

If a canonical receipt/evidence/closure already exists:

- preparation checks the receipt before shared tool mutation;
- validators stop before repeating expensive gates when platform evidence already exists;
- normal reviewers verify or reject existing evidence according to their contract;
- guarded closure entrypoints additionally require repository head/worktree/Cargo.lock authority to remain unchanged across the whole review command;
- preparation/validation does not overwrite canonical artifacts;
- conflicting, stale-lock, repository-drift or partial state requires explicit inspection/recovery;
- no GitHub Actions rerun is used as a substitute for evidence recovery.

This keeps historical validation evidence attributable to the exact bytes that first claimed its exact-head path instead of turning that path into a mutable status file, and it prevents repeated tool/test work from being used as an accidental polling mechanism.

## Current validation boundary

The Linux shell scripts have source-level shell syntax checks available, and the Python reviewer is stdlib-only. These checks are not substitutes for the required repository validation gates.

The exact final NXB-153 head still requires real Rust 1.97.1 validation on Linux and Windows, including fmt, check, Clippy, unit/focused/full-workspace tests, RustSec, cargo-deny, filesystem behavior, guarded same-head evidence closure and blocker review. PR #89 must remain draft/not admitted until those gates complete.
