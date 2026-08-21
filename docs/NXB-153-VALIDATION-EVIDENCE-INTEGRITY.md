# NXB-153 Validation Evidence Integrity

## Status

This document records the source-staged integrity contract for NXB-153 exact-head validation evidence. It does **not** claim that the current feature head has passed Rust, Linux or Windows validation.

The purpose is to prevent a rerun, concurrent reviewer or stale preparation step from silently rewriting evidence that was already associated with an exact Git head, while also making the Linux evidence publication boundary explicit about file and directory durability.

## Exact-head artifact classes

NXB-153 validation uses three persistent evidence classes under `target/nxb-validation`:

1. **Tooling receipt** — records the exact head, Rust toolchain, cargo-audit/cargo-deny versions and binary SHA-256 values produced by fresh tool preparation.
2. **Platform validation evidence** — records a successful Linux or Windows validation result for one exact head and links it to the immutable tooling receipt.
3. **Dual-platform closure** — accepts Linux and Windows evidence only for the same exact head and canonical Cargo.lock, and emits `admission=blocker_review_required` rather than automatically admitting NXB-153.

All three classes are intended to be create-only for their canonical exact-head pathname.

## Linux publication contract

### Tooling receipt

`prepare-and-validate-nxb-153-linux.sh` writes the receipt into a unique private temporary file inside the validation directory and claims the canonical exact-head receipt name with a same-directory hard link.

- the canonical receipt is never opened with shell truncation;
- an existing exact-head receipt is not overwritten;
- a losing preparation removes only its own unclaimed temporary path;
- the temporary receipt bytes are `fsync`'d before the hard-link namespace claim;
- creation of the validation directory is followed by a sync of its `target` parent;
- after namespace claim and temporary-link cleanup, the validation directory is `fsync`'d before success is reported;
- temporary-link cleanup failure does not skip the directory-sync attempt; the cleanup outcome is reported after the durability attempt;
- rerunning preparation against an existing receipt fails explicitly and tells the operator to validate against the existing receipt or review/remove it intentionally.

### Platform validation evidence

`validate-nxb-153-linux.sh` uses the same temporary-file plus hard-link create-only pattern for the canonical Linux evidence pathname.

The validator first proves the exact head, clean worktree, pinned Cargo.lock, pinned tooling receipt/tool bytes and all validation gates. Only after those gates succeed does it attempt the create-only evidence claim. Existing exact-head evidence is preserved and causes an explicit failure rather than being rewritten with a new timestamp.

Before the hard-link claim the temporary evidence file is `fsync`'d. After claim/cleanup, the validation directory is `fsync`'d before the validator reports success. A temporary-link cleanup failure is retained as an error but does not prevent the directory durability attempt from running first.

### Dual-platform closure

`review-nxb-153-evidence-linux.sh` is a thin wrapper over `review-nxb-153-evidence-linux.py`.

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

## Windows publication contract

### Tooling receipt

`prepare-and-validate-nxb-153-windows.ps1` publishes the exact-head tooling receipt using `.NET FileMode.CreateNew`, `FileAccess.Write` and `FileShare.None`, then calls `Flush(true)` on the stream.

An existing exact-head receipt is not overwritten. Preparation fails explicitly and directs the operator to use the existing receipt for validation or review/remove it intentionally.

### Platform validation evidence

`validate-nxb-153-windows.ps1` publishes the final exact-head Windows validation evidence with the same `FileMode.CreateNew` contract and `Flush(true)`. `WriteAllText` overwrite semantics are not used for the canonical evidence pathname.

### Dual-platform closure

`review-nxb-153-evidence.ps1` creates a unique pending closure with `FileMode.CreateNew` and moves it to the canonical closure pathname without `-Force`. An existing canonical closure therefore remains a no-overwrite condition; a racing or stale pending file requires explicit recovery rather than silent replacement.

Windows directory-entry durability remains a platform-validation concern rather than a source-only claim; the real Windows Rust/PowerShell validation pass must verify the supported filesystem behavior before admission.

## Immutability and reruns

The exact-head artifact name is part of the evidence identity. Re-running a preparation, validator or closure operation must not silently mutate an existing canonical artifact merely to obtain a fresh timestamp or replace earlier bytes.

If a canonical receipt/evidence/closure already exists:

- normal validators/reviewers verify or reject it according to their contract;
- preparation/validation does not overwrite it;
- conflicting or partial state requires explicit inspection/recovery;
- no GitHub Actions rerun is used as a substitute for evidence recovery.

This keeps historical validation evidence attributable to the exact bytes that first claimed its exact-head path instead of turning that path into a mutable status file.

## Current validation boundary

The Linux shell scripts have source-level shell syntax checks available, and the Python reviewer is stdlib-only. These checks are not substitutes for the required repository validation gates.

The exact final NXB-153 head still requires real Rust 1.97.1 validation on Linux and Windows, including fmt, check, Clippy, unit/focused/full-workspace tests, RustSec, cargo-deny, filesystem behavior and same-head evidence closure. PR #89 must remain draft/not admitted until those gates and blocker review complete.
