# NXB-153 Validation Evidence Integrity

## Status

This document records the source-staged integrity contract for NXB-153 exact-head validation evidence. It does **not** claim that the current feature head has passed Rust, Linux or Windows validation.

The evidence chain must remain attributable to one exact Git head without silent overwrite, duplicate expensive validation, repository-authority drift, pathname substitution or misleading premature success output.

## Exact-head artifact classes

NXB-153 uses three persistent artifact classes under `target/nxb-validation`:

1. **Tooling receipt** — exact head, pinned Rust toolchain, cargo-audit/cargo-deny versions and tool binary SHA-256 values.
2. **Platform validation evidence** — successful Linux or Windows gates for one exact head, cryptographically linked to its tooling receipt.
3. **Dual-platform closure** — accepts Linux + Windows evidence only for the same exact head and Cargo.lock and emits `admission=blocker_review_required` rather than automatically admitting NXB-153.

Canonical exact-head artifact names are create-only.

## Tool preparation serialization

Validation tools live in the shared `target/nxb-tools` directory. Both platform preparation scripts therefore enforce:

1. resolve a clean exact Git head;
2. derive the exact-head tooling-receipt pathname;
3. fail before `rustup` / `cargo install --force` mutation if that receipt already exists;
4. claim an exact-head preparation lock with create-new semantics;
5. recheck the receipt after lock ownership;
6. prepare the pinned Rust components and audit/deny tools;
7. publish the immutable receipt create-only;
8. release the lock before entering validation.

A stale or racing preparation lock requires explicit recovery. It is never silently replaced.

Linux uses an atomic `mkdir` lock directory plus evidence-directory sync around lock claim/release. Windows uses `.NET FileMode.CreateNew` for the lock file and `Flush(true)` for its bytes. These remain source contracts until real platform validation executes them.

## Duplicate validation suppression

Both platform validators resolve the exact clean head and then check whether canonical platform evidence for that head already exists.

If it exists, validation fails **before** Rust/tool version resolution, fmt, check, Clippy, tests, RustSec or cargo-deny are rerun. Existing evidence must be reviewed or explicitly recovered instead of turning validation into a polling loop.

## Linux publication contract

### Tooling receipt and platform evidence

Linux receipt/evidence publication uses a unique private temporary file plus same-directory hard-link create-only namespace claim.

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

which loads the existing schema/semantic closure implementation while replacing the filesystem trust primitives used for exact-head evidence review.

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
- publishes the closure with descriptor-relative `O_CREAT | O_EXCL | O_NOFOLLOW` under the pinned evidence-directory object;
- `fsync`'s the created closure and the pinned evidence-directory descriptor;
- reopens the published closure relative to the same pinned directory descriptor and requires exact canonical bytes;
- never deletes a partially visible create-new closure by pathname after a write/finalization failure.

The launcher contains a networkless `--self-test` that stages:

- ordinary anchored regular-file read;
- final symlink rejection;
- parent-directory rename + replacement by a symlink to different bytes while proving the already pinned directory descriptor still reads the original object.

Current local source checks for this launcher are:

- Python `py_compile`: PASS;
- descriptor self-test: PASS;
- canonical Linux shell wrapper `bash -n`: PASS.

These are source/primitive checks, not Rust or Linux admission evidence.

### Guarded repository authority

The shell entrypoint additionally captures the initial clean Git head and Cargo.lock SHA-256, buffers the secure reviewer output, and requires final head/worktree/Cargo.lock equality before printing any review PASS output.

If repository authority changes during review, the command fails and any newly visible closure requires explicit recovery/review.

## Windows publication contract

### Tooling receipt and platform evidence

Windows tooling receipt and validation evidence use `.NET FileMode.CreateNew` and `Flush(true)`. Existing canonical evidence prevents the heavy validation gates from being repeated for the same exact head.

### Handle-pinned evidence review — #98

The canonical Windows closure entrypoint is:

`scripts/review-nxb-153-evidence-windows.ps1`

Before invoking the existing semantic closure implementation, the wrapper now uses native Win32 handles through `CreateFileW` and `GetFinalPathNameByHandleW`.

It pins and retains handles for:

- repository root;
- Cargo.lock;
- evidence directory;
- exact-head Windows platform evidence;
- exact-head Linux platform evidence;
- exact-head Windows tooling receipt;
- exact-head Linux tooling receipt.

The source-staged Windows contract is:

- repository/evidence directories are opened with `FILE_FLAG_BACKUP_SEMANTICS`;
- directory handles allow read/write sharing but intentionally omit delete sharing so rename/delete requests remain blocked while review is active;
- evidence/receipt/Cargo.lock handles allow read sharing only, withholding write/delete sharing while the inner reviewer consumes them;
- `GetFinalPathNameByHandleW` retrieves the normalized path of the object actually opened;
- the resolved handle path must equal the expected absolute path case-insensitively, so a pre-existing junction/symlink/reparse redirection is rejected rather than silently trusted;
- pinned handles stay alive for the complete semantic review and final repository-authority recheck;
- inner reviewer output remains buffered until final HEAD/worktree/Cargo.lock equality succeeds.

Microsoft's CreateFile contract defines share modes as lasting for the lifetime of the handle, and omitting `FILE_SHARE_DELETE` prevents subsequent opens requesting delete access; Windows delete access includes rename. `FILE_FLAG_BACKUP_SEMANTICS` is the required CreateFile mode for obtaining a directory handle. `GetFinalPathNameByHandleW` returns the final normalized path for the opened file/directory handle. These semantics are relied on by the source staging but **must still be exercised on real supported Windows before admission**.

The current execution environment has no PowerShell runtime/parser, so no PowerShell syntax/runtime PASS is claimed for this handle-pinning implementation.

### Closure publication

The Windows semantic reviewer now publishes directly to the canonical closure pathname with `.NET FileMode.CreateNew`; it no longer closes a pending file and then performs a pathname-based move.

- the canonical destination is claimed create-only, so a pre-existing or racing destination is never overwritten;
- one `FileStream` remains open with `FileShare.None` while deterministic bytes are written and `Flush(true)` completes;
- the same open handle is rewound and read back completely before success;
- read-back bytes must exactly equal the deterministic canonical closure representation and must contain no trailing bytes;
- closure bytes are bounded by the shared 65,536-byte evidence envelope;
- once create-new succeeds, any write/flush/read-back failure leaves the visible canonical path for explicit recovery rather than deleting it by pathname.

This removes the earlier close-pending-then-`Move-Item` object-substitution window. Windows directory-entry durability remains a real-platform validation concern.

## Immutability and recovery

If a canonical receipt/evidence/closure already exists:

- preparation does not mutate shared tools before detecting the existing receipt;
- validation does not repeat expensive gates merely to refresh evidence;
- reviewers verify or reject existing canonical content;
- exact-head artifact bytes are not overwritten to obtain a new timestamp;
- stale preparation locks, conflicting evidence, repository drift, pathname/object mismatch or partial closure state require explicit recovery;
- no GitHub Actions rerun is used as polling or evidence recovery.

## Current admission boundary

Issues #90–#98 remain open until their source-staged filesystem/evidence contracts receive the required exact-head platform execution.

The exact final NXB-153 head still requires real Rust 1.97.1 Linux + Windows validation covering fmt, check, Clippy, unit/focused/full-workspace tests, RustSec, cargo-deny, filesystem publication behavior, Linux descriptor anchoring, Windows handle pinning, guarded same-head dual-platform closure and final blocker review.

PR #89 remains draft/not admitted and NXB-154 must not use this branch as an implementation base until those gates complete.
