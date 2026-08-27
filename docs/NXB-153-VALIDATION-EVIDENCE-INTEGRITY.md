# NXB-153 Validation Evidence Integrity

## Status

This document records the source-staged integrity contract for NXB-153 exact-head validation evidence. It does **not** claim that the current feature head has passed Rust, Linux or Windows validation.

The evidence chain must remain attributable to one exact Git head without silent overwrite, duplicate expensive validation, cross-head tool mutation, repository-authority drift, pathname substitution or misleading premature success output.

## Exact-head artifact classes

NXB-153 uses three persistent artifact classes under `target/nxb-validation`:

1. **Tooling receipt** — exact head, platform, pinned Rust toolchain, exact-head tool root, cargo-audit/cargo-deny versions and tool binary SHA-256 values.
2. **Platform validation evidence** — successful Linux or Windows gates for one exact head, cryptographically linked to its tooling receipt.
3. **Dual-platform closure** — accepts Linux + Windows evidence only for the same exact head and Cargo.lock and emits `admission=blocker_review_required` rather than automatically admitting NXB-153.

Canonical exact-head artifact names are create-only.

## Exact-head validation tool roots

Validation binaries are not shared across source heads. The canonical roots are:

- Linux: `target/nxb-tools/linux/<exact-head>`;
- Windows: `target/nxb-tools/windows/<exact-head>`.

The tooling receipt must contain that exact platform/head-relative root in `tools_root`. Both validators and both semantic evidence reviewers reject a receipt whose root does not exactly match `target/nxb-tools/<platform>/<head>`.

This removes a cross-head mutation class that existed when different source heads could independently acquire exact-head preparation locks yet still run `cargo install --force` into one shared `target/nxb-tools` binary directory. Under the current contract, preparing head B cannot overwrite the cargo-audit/cargo-deny binaries used by head A because the physical roots are disjoint.

If an exact-head tool root already exists but its canonical tooling receipt does not, preparation fails closed and requires explicit recovery. It is not silently reused or overwritten.

## Tool preparation serialization

Both platform preparation scripts enforce:

1. resolve a clean exact Git head;
2. derive the exact-head tooling-receipt pathname and platform/head-specific tool root;
3. fail before `rustup` / `cargo install --force` mutation if the canonical receipt already exists;
4. claim an exact-head preparation lock with create-new semantics;
5. recheck the receipt after lock ownership;
6. reject a pre-existing exact-head tool root without an admitted receipt;
7. prepare the pinned Rust components and cargo-audit/cargo-deny into the exact-head tool root;
8. publish the immutable receipt create-only, binding the exact tool root and binary SHA-256 values;
9. release the preparation lock before entering validation.

Linux uses an atomic `mkdir` preparation lock plus evidence-directory sync around lock claim/release. Windows uses a create-new exclusive `FileStream` with `FileShare.None` and `FileOptions.DeleteOnClose`; the same lock handle remains open for the entire tool-preparation and receipt-publication lifecycle. Windows lock bytes are flushed and read back from that same handle before preparation proceeds.

Windows tooling-receipt publication also uses a create-new read/write handle, `Flush(true)`, bounded size and exact same-handle read-back with no trailing bytes. Once a canonical receipt path becomes visible, a later write/finalization failure is explicit recovery state rather than permission to path-delete or overwrite it.

Linux tooling-receipt publication uses a private same-directory temporary file, bounded size, file `fsync`, hard-link create-only namespace claim and evidence-directory `fsync`.

## Duplicate validation suppression

A simple "evidence does not exist yet" preflight is not sufficient to suppress duplicate expensive work: two validators can pass the same absence check before either publishes evidence. NXB-153 therefore serializes the heavy validation phase per platform and exact Git head.

Both validators enforce this order:

1. resolve the exact clean head and canonical platform-evidence path;
2. fail immediately if exact-head platform evidence already exists;
3. claim a platform + exact-head validation lock **before** resolving the Rust/tool versions or starting Cargo gates;
4. after lock ownership, recheck the evidence path before any expensive validation begins;
5. require the platform/head-specific tool root and require the receipt to bind that exact root;
6. keep the lock for the complete fmt/check/Clippy/test/RustSec/cargo-deny and evidence-publication lifecycle;
7. publish the canonical evidence create-only;
8. release the validation lock only after evidence finalization.

Windows uses a create-new `FileStream` with `FileShare.None` and `FileOptions.DeleteOnClose`, retained for the complete validation lifetime. The lock bytes are flushed and exact-read back from the same handle. A competing same-head Windows validator therefore fails before Cargo execution.

Linux uses an atomic same-directory `mkdir` lock for the platform + exact head, synchronizes the evidence directory after lock claim, retains the directory for the heavy validation lifetime and removes it only after create-only evidence publication. A competing same-head Linux validator fails before Cargo execution. Failed runs use the exit trap for bounded empty-directory cleanup; an unreleasable lock becomes explicit recovery state rather than permission to start another validation.

The locks are platform-specific by design: one Linux and one Windows validator for the same head may proceed independently because both platform evidence artifacts are required, while duplicate validators for the same platform/head are suppressed.

Existing canonical evidence remains authoritative for duplicate suppression. Validation is never repeated merely to refresh timestamps or as a polling mechanism.

## Linux publication contract

### Tooling receipt and platform evidence

Linux receipt/evidence publication uses a unique private temporary file plus same-directory hard-link create-only namespace claim.

- receipt and evidence bytes are bounded by 65,536 bytes;
- temporary bytes are `fsync`'d before claim;
- an existing canonical destination is never overwritten;
- losing publication cleans only its own unclaimed temp;
- the evidence directory is synchronized after claim/cleanup before success;
- a cleanup error does not skip the durability attempt.

### Descriptor-anchored evidence review — #98

The canonical Linux closure entrypoint is:

`scripts/review-nxb-153-evidence-linux.sh`

It routes review through:

`scripts/review-nxb-153-evidence-linux-secure.py`

which loads the semantic closure implementation while replacing the filesystem trust primitives used for exact-head evidence review.

The secure Linux launcher:

- requires Linux `O_DIRECTORY` and `O_NOFOLLOW`; unsupported environments fail closed;
- opens the repository root and evidence directory component-by-component from `/` with descriptor-relative `os.open(..., dir_fd=...)` traversal;
- rejects symlink traversal for every opened directory/file component;
- keeps the evidence-directory descriptor pinned across receipt/evidence reads and closure publication;
- opens final evidence/receipt/Cargo.lock objects relative to a pinned directory descriptor;
- validates regular-file type and bounded size using `fstat()` on the opened descriptor;
- reads bytes from that same descriptor rather than reopening a checked pathname;
- requires device/inode/size/mtime/ctime metadata to remain stable across the bounded read;
- computes receipt/evidence/Cargo.lock hashes from those opened bytes;
- requires each tooling receipt to bind `target/nxb-tools/<platform>/<exact-head>`;
- publishes the closure with descriptor-relative `O_CREAT | O_EXCL | O_NOFOLLOW` under the pinned evidence-directory object;
- `fsync`'s the created closure and the pinned evidence-directory descriptor;
- reopens the published closure relative to the same pinned directory descriptor and requires exact canonical bytes;
- never deletes a partially visible create-new closure by pathname after a write/finalization failure.

The launcher contains a networkless `--self-test` that stages ordinary anchored regular-file read, final symlink rejection, and parent-directory rename + replacement resistance.

Historical source/primitive checks for this launcher were:

- Python `py_compile`: PASS;
- descriptor self-test: PASS;
- canonical Linux shell wrapper `bash -n`: PASS.

Those historical checks do not validate the current exact-head tool-root delta. Fresh exact-head execution is still required.

### Guarded repository authority

The shell entrypoint captures the initial clean Git head and Cargo.lock SHA-256, buffers the secure reviewer output, and requires final head/worktree/Cargo.lock equality before printing any review PASS output.

If repository authority changes during review, the command fails and any newly visible closure requires explicit recovery/review.

## Windows publication contract

### Tooling receipt and platform evidence

Windows tooling receipt and validation evidence use `.NET FileMode.CreateNew`, `Flush(true)`, a 65,536-byte maximum and exact read-back from the same open handle before success. The read-back must contain the deterministic bytes and no trailing data.

Existing canonical evidence prevents the heavy validation gates from being repeated for the same exact head; the exact-head validation lock additionally closes the concurrent-start race before heavy gates begin.

Both preparation and validation resolve tools only from `target/nxb-tools/windows/<exact-head>`, and the tooling receipt must bind that same logical root.

### Handle-pinned evidence review — #98

The canonical Windows closure entrypoint is:

`scripts/review-nxb-153-evidence-windows.ps1`

Before invoking the semantic closure implementation, the wrapper uses native Win32 handles through `CreateFileW` and `GetFinalPathNameByHandleW`.

It pins and retains handles for:

- repository root;
- Cargo.lock;
- the semantic evidence-reviewer script;
- evidence directory;
- exact-head Windows platform evidence;
- exact-head Linux platform evidence;
- exact-head Windows tooling receipt;
- exact-head Linux tooling receipt;
- any pre-existing canonical closure, or the newly published canonical closure immediately after the inner review returns.

The source-staged Windows contract is:

- repository/evidence directories are opened with `FILE_FLAG_BACKUP_SEMANTICS`;
- directory handles allow read/write sharing but intentionally omit delete sharing so rename/delete requests remain blocked while review is active;
- evidence/receipt/Cargo.lock/reviewer/closure file handles allow read sharing only, withholding write/delete sharing while review is active;
- `GetFinalPathNameByHandleW` retrieves the normalized path of the object actually opened;
- the resolved handle path must equal the expected absolute path case-insensitively, so a pre-existing junction/symlink/reparse redirection is rejected rather than silently trusted;
- tooling receipts must bind the exact platform/head-specific tool root;
- pinned input handles stay alive for the complete semantic review and final repository-authority recheck;
- after the first semantic review publishes or accepts the closure, the wrapper pins the canonical closure object and runs the semantic review again while that exact object is locked;
- if a pathname substitution occurred between inner publication and the outer closure open, the second review validates the exact substituted object rather than trusting the earlier pathname result;
- the canonical closure handle remains pinned through the final HEAD/worktree/Cargo.lock checks;
- inner reviewer output remains buffered until final authority equality succeeds.

These Win32 share-mode and handle semantics **must still be exercised on real supported Windows before admission**. The current execution environment has no PowerShell runtime, so no Windows syntax/runtime PASS is claimed for the current source head.

### Closure publication

The Windows semantic reviewer publishes directly to the canonical closure pathname with `.NET FileMode.CreateNew`; it does not close a pending file and then perform a pathname-based move.

- the canonical destination is claimed create-only, so a pre-existing or racing destination is never overwritten;
- one `FileStream` remains open with `FileShare.None` while deterministic bytes are written and `Flush(true)` completes;
- the same open handle is rewound and read back completely before success;
- read-back bytes must exactly equal the deterministic canonical closure representation and must contain no trailing bytes;
- closure bytes are bounded by the shared 65,536-byte evidence envelope;
- once create-new succeeds, any write/flush/read-back failure leaves the visible canonical path for explicit recovery rather than deleting it by pathname;
- after the inner publisher closes its stream, the outer wrapper reopens the canonical closure with write/delete sharing withheld, re-runs semantic review against that pinned object and retains the handle until final authority checks finish.

## Immutability and recovery

If a canonical receipt/evidence/closure already exists:

- preparation does not mutate that head's tools before detecting the existing receipt;
- different source heads use disjoint platform/head-specific cargo-audit/cargo-deny roots;
- an orphan exact-head tool root without a receipt requires explicit recovery;
- validation does not repeat expensive gates merely to refresh evidence;
- same-platform same-head validation attempts are serialized before the expensive gate sequence;
- reviewers verify or reject existing canonical content and exact tool-root identity;
- exact-head artifact bytes are not overwritten to obtain a new timestamp;
- stale preparation/validation locks, conflicting evidence, repository drift, pathname/object mismatch or partial publication state require explicit recovery;
- no GitHub Actions rerun is used as polling or evidence recovery.

## Current admission boundary

Issues #90–#98 remain open until their source-staged filesystem/evidence contracts receive the required exact-head platform execution.

The exact final NXB-153 head still requires real Rust 1.97.1 Linux + Windows validation covering fmt, check, Clippy, unit/focused/full-workspace tests, RustSec, cargo-deny, exact-head tool-root isolation, preparation/validation lock concurrency behavior, receipt/evidence publication read-back, filesystem publication behavior, Linux descriptor anchoring, Windows handle pinning, guarded same-head dual-platform closure and final blocker review.

PR #89 remains draft/not admitted and NXB-154 must not use this branch as an implementation base until those gates complete.
