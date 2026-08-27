# NXB-153 Validation Tool Object Integrity

## Status

This document records the source-staged object-identity and implementation-authority contract for the NXB-153 validation security tools. It does **not** claim current-head Linux or Windows admission.

The relevant tools are the exact pinned versions of `cargo-audit` and `cargo-deny` installed for one platform and one exact Git head.

## Threat

Exact-head directory isolation prevents head A and head B from intentionally installing into the same tool root, but directory isolation alone does not close check/use races.

A weaker validator could:

1. hash `target/nxb-tools/<platform>/<head>/bin/cargo-audit`;
2. run hours of Cargo gates;
3. execute `cargo-audit` again by pathname;
4. hash the pathname again before evidence publication.

A concurrent rename/substitution could replace the pathname only for step 3 and restore the original object before step 4. A plain Linux read descriptor also does not prevent in-place writes to the same inode, so even descriptor-pinned execution can observe mutable executable bytes unless the execution image itself becomes immutable.

A second-order Linux problem exists if the helper that performs the sealing is itself reopened by repository pathname. A correct immutable-executable primitive is not an authority boundary if an attacker can redirect `scripts/nxb-153-sealed-tool.py` to different Python bytes immediately before one invocation.

Windows has additional namespace/object-lifetime cases: pinning only `cargo-audit.exe` does not prove that a later pathname execution cannot be redirected if an ancestor such as `bin`, the exact-head root, or another tool-root directory is renamed/replaced. Likewise, semantically parsing a tooling receipt and later hashing it through a second pathname open can bind evidence to bytes different from those that passed semantic review. Initial/final `Cargo.lock` hashes alone also do not prove the bytes consumed by locked Cargo operations in the middle were unchanged.

NXB-153 therefore separates **tool pathname identity**, **tool object bytes**, **tool namespace authority**, **validation-helper implementation authority**, **receipt object authority** and **lockfile object authority**.

## Exact-head roots

Canonical roots remain:

- Linux: `target/nxb-tools/linux/<exact-head>`;
- Windows: `target/nxb-tools/windows/<exact-head>`.

Tooling receipts bind that exact logical root plus the security-tool versions and SHA-256 values.

## Linux committed implementation authority

Linux preparation and validation no longer execute `scripts/nxb-153-sealed-tool.py` by reopening its working-tree pathname after the validation head is fixed.

The source-staged chain is:

1. perform one initial `chdir` to the requested repository root;
2. resolve the exact 40-hex Git `HEAD` from that inherited repository CWD object;
3. require a clean working tree;
4. resolve `scripts/nxb-153-sealed-tool.py` as a Git blob from that **exact head**;
5. require the resolved Git object to be a non-empty blob inside a bounded 1 MiB implementation envelope;
6. stream the exact committed blob with `git cat-file blob <object>` directly into `python3 - ...` for every helper invocation;
7. never reopen the helper through `$repo_root/scripts/...` after the authority head is fixed.

Preparation additionally resolves `scripts/validate-nxb-153-linux.sh` from the same exact-head Git object graph. If preparation proceeds directly into validation, it streams that exact validator blob into `bash -s -- '.'`. Passing `.` keeps the child on the inherited repository CWD object instead of reopening the configured repository pathname.

The tool-installation working directory is also isolated in a subshell. The parent preparation shell therefore never leaves the initially opened repository CWD object and no longer performs a pathname-based `cd "$repo_root"` after installation.

This closes the source-level helper-path substitution window and the preparation-to-validation script-handoff window.

A networkless primitive test exercised the same model:

- a trusted Git repository was opened as the current CWD;
- the repository directory was renamed;
- a replacement tree containing a substituted helper was created at the old pathname;
- the original committed helper blob was streamed through `git cat-file` from the still-open CWD object;
- trusted helper execution remained authoritative;
- the committed validator blob also executed correctly from the same object graph.

This is a narrow Git/CWD/blob primitive PASS, not exact-head NXB-153 platform admission evidence.

## Linux sealed-tool primitive

The canonical committed Linux helper is:

`scripts/nxb-153-sealed-tool.py`

It fails closed unless Linux provides `memfd_create`, `MFD_ALLOW_SEALING`, `/proc/self/fd`, `O_NOFOLLOW` and the four required file seals.

For one executable it:

1. opens the canonical path with `O_RDONLY | O_NOFOLLOW`;
2. requires a regular executable file inside a bounded 1..512 MiB envelope;
3. reads that exact opened object once while checking device/inode/size/mtime/ctime stability;
4. requires ELF magic;
5. computes SHA-256 from those stable bytes;
6. copies those bytes into a new `memfd` created with `MFD_ALLOW_SEALING`;
7. marks the snapshot executable;
8. applies `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL` and verifies that all required seals are active;
9. performs the version probe through `/proc/self/fd/<snapshot>` and requires exact whitespace-token version equality;
10. when running a validation gate, requires the freshly read bytes to match the receipt-admitted SHA-256 before the gate can execute from the sealed snapshot.

The helper's networkless self-test copies `/bin/echo` into a sealed memfd, verifies all four seals, verifies an attempted `pwrite()` is rejected with permission failure and executes the immutable snapshot successfully.

An independent primitive check in the available Linux environment also produced:

- sealed ELF execution: PASS;
- required seal mask: all four seals present;
- post-seal write: rejected with `EPERM`.

These are narrow primitive results only, not exact-head NXB-153 platform admission evidence.

## Linux preparation

After the pinned `cargo install --locked --force --version ... --root <exact-head-root>` operations complete, Linux preparation:

1. retains the initial repository CWD object while cargo installation runs only inside a temporary-directory subshell;
2. executes the sealed-tool implementation from the exact-head committed Git blob;
3. requires `cargo-audit` and `cargo-deny` to be regular non-symlink files;
4. invokes the committed sealed-tool helper separately for each freshly installed executable;
5. derives both the exact version string and SHA-256 from the **same immutable sealed snapshot**;
6. therefore cannot combine a version probe from one transient same-inode byte state with a hash from another state;
7. separately hashes the canonical tool pathnames and requires equality with the sealed-snapshot hashes before receipt publication;
8. publishes the bounded tooling receipt create-only with file and directory durability checks;
9. when validation is requested immediately, streams the exact-head committed validator blob to Bash rather than reopening the validator pathname.

The version test uses exact whitespace-token equality. A token such as `0x22y2` cannot satisfy expected version `0.22.2` merely because `.` would otherwise be a regular-expression wildcard.

Linux preparation now requires both the committed-helper authority chain and the sealed-tool primitive; unsupported Git object state, kernels or Python environments fail closed before receipt admission.

## Linux validation

Before expensive validation starts, the Linux validator:

1. fixes the exact initial Git head from the repository CWD object and requires a clean worktree;
2. resolves the sealed-tool implementation from that exact head and executes all helper operations from the committed blob bytes;
3. requires the exact-head security-tool files to be regular and non-symlink;
4. performs a stable sealed inspection of each canonical executable;
5. derives initial version and SHA-256 from one immutable byte image per tool;
6. requires those values to match one stable tooling-receipt object snapshot;
7. runs fmt/check/Clippy/tests;
8. immediately before RustSec, reopens canonical `cargo-audit` with `O_NOFOLLOW`, stable-reads it, requires the receipt-admitted SHA-256, seals those exact bytes and executes `audit` from that immutable snapshot;
9. immediately before cargo-deny, performs the same receipt-hash check + sealed snapshot and executes `check` from that immutable snapshot;
10. finally re-hashes the canonical paths and requires them still to name the admitted bytes before evidence publication.

The gate execution image is therefore immutable after its admitted SHA-256 is checked. A pathname swap to different bytes fails the receipt-hash check; an in-place write to the source inode after snapshot creation cannot alter the already sealed execution image. A repository/scripts pathname substitution cannot redirect the helper implementation after the exact Git blob authority has been resolved.

This is stronger than the earlier persistent-read-descriptor model, which defeated pathname replacement but could not prohibit same-inode write mutation, and stronger than the first sealed-helper model, which still reopened the helper implementation by repository pathname.

## Linux tooling-receipt object verification

Linux validation no longer performs receipt hashing and semantic parsing through separate pathname opens.

The current source:

1. opens the canonical exact-head tooling receipt once with `O_RDONLY | O_NOFOLLOW`;
2. requires a regular file within the 1..65,536-byte envelope;
3. reads that exact opened object while checking device/inode/size/mtime/ctime stability;
4. strictly decodes and parses those exact bytes as JSON;
5. validates the complete exact field set, platform/head/tool versions/tool hashes/tool root/network contract and canonical `prepared_at` rules;
6. computes the evidence `tooling_receipt_sha256` from the **same exact bytes that passed semantic verification**;
7. finally requires the canonical receipt pathname to hash to those admitted bytes before evidence publication.

A transient path substitution can therefore no longer make the validator semantically verify one receipt object while embedding the SHA-256 of another object into platform evidence.

## Windows namespace and file-object pinning

Windows cannot use the Linux sealed-memfd execution model. Source therefore combines file-object share-mode pinning with native directory namespace handles.

Both Windows preparation and validation use `CreateFileW` / `GetFinalPathNameByHandleW` directory handles that:

- open directories with `FILE_FLAG_BACKUP_SEMANTICS`;
- allow read/write sharing but intentionally omit delete sharing;
- retain the handle across the relevant receipt/validation lifetime;
- normalize the path returned for the opened object;
- require that resolved handle path to equal the expected absolute path case-insensitively, rejecting pre-existing reparse/junction redirection.

The source-staged namespace chain retains handles for the relevant authority components, including:

- repository root;
- `target`;
- `target/nxb-validation`;
- `target/nxb-tools`;
- `target/nxb-tools/windows`;
- `target/nxb-tools/windows/<exact-head>`;
- `target/nxb-tools/windows/<exact-head>/bin`.

The tool files themselves are then opened read-only with `FileShare.Read`, withholding write/delete sharing.

This closes the source-level hole where a child executable handle could remain pinned but canonical pathname execution might be redirected by renaming/replacing an ancestor tool directory.

## Windows preparation

After fresh `cargo install` completes, Windows preparation:

1. retains repository/target/evidence namespace handles;
2. pins the complete tool-root directory chain before tool inspection;
3. rejects a missing tool or a tool file item marked as a reparse point;
4. opens each exact tool with `FileMode.Open`, `FileAccess.Read`, `FileShare.Read`;
5. intentionally withholds write/delete sharing for the lifetime of the pinned stream;
6. runs the exact version check while the file and ancestor namespace handles remain open;
7. computes receipt SHA-256 from the pinned stream with `Get-FileHash -InputStream`;
8. separately hashes the canonical pathname and requires equality with the pinned-stream hash;
9. keeps the namespace handles and both security-tool streams alive through create-new tooling-receipt publication and same-handle receipt read-back.

## Windows validation

The Windows validator now retains file-object authority not only for security-tool executables but also for the tooling receipt and `Cargo.lock` across the complete heavy-validation/evidence lifecycle:

1. pin repository/target/evidence directory authority;
2. acquire the exact-head validation lock;
3. pin `nxb-tools -> windows -> <head> -> bin` directory authority with native handles that omit delete sharing;
4. pin both tool files with read-only `FileStream` objects whose sharing mode is `FileShare.Read`;
5. obtain evidence SHA-256 values from those file streams and require tooling-receipt equality;
6. **before semantic tooling-receipt parsing**, open the exact receipt read-only with `FileShare.Read`, withholding write/delete sharing until evidence publication completes;
7. derive `tooling_receipt_sha256` from that pinned receipt stream rather than a later pathname hash;
8. **before any locked Cargo operation**, open `Cargo.lock` read-only with `FileShare.Read` and derive the admitted lock SHA from that pinned stream;
9. require the pinned `Cargo.lock` SHA to equal the canonical expected SHA before metadata/check/Clippy/tests/security gates start;
10. execute the security tools by canonical path while the complete ancestor namespace chain and tool/receipt/lockfile objects remain pinned;
11. re-hash the pinned tool streams, pinned receipt stream and pinned `Cargo.lock` stream after the heavy gates and require unchanged bytes;
12. re-hash the canonical tool, receipt and `Cargo.lock` pathnames and require that they still name the admitted pinned bytes;
13. retain all relevant handles until create-new Windows validation evidence has been flushed and exact-read back.

Opening the tooling receipt before semantic parsing means later read-only parser reopenings cannot race a write/delete/rebind operation: the pinned stream already withholds those sharing modes. The SHA embedded in platform evidence is taken from that same pinned object.

Pinning `Cargo.lock` closes the source-level window where initial and final lockfile hashes could agree even though a concurrent process temporarily substituted or modified the lockfile only while Cargo was resolving locked dependencies.

The earlier nested-array iteration used to stage the directory-handle list has been replaced with explicit individual handle opens, avoiding PowerShell enumeration/flattening ambiguity in the security-critical namespace chain.

## Windows runtime acceptance

Source staging is not Windows platform proof. Real supported Windows/NTFS execution must specifically demonstrate:

- normal `cargo-audit.exe` and `cargo-deny.exe` version/gate execution while all pin handles are open;
- normal tooling-receipt read access while its pinned stream withholds write/delete sharing;
- normal Cargo metadata/check/Clippy/test operation while the pinned `Cargo.lock` stream is open;
- attempted executable overwrite is rejected;
- attempted executable rename/delete is rejected;
- attempted tooling-receipt overwrite/rename/delete is rejected while validation remains active;
- attempted `Cargo.lock` overwrite/rename/delete is rejected while locked Cargo gates remain active;
- attempted `bin`, exact-head tool-root, `windows`, `nxb-tools`, `target` and relevant repository/validation-directory rename/delete or replacement behaves fail-closed as intended;
- pre-existing junction/symlink/reparse redirection is rejected by final-handle-path comparison;
- final pinned-stream and canonical-path hash equality for tools, tooling receipt and `Cargo.lock`;
- cleanup behavior after a failed gate.

If supported Windows semantics prevent normal Cargo/tool execution under the source-staged sharing modes, or permit pathname execution/object authority to escape the pinned chain, admission remains blocked and the Windows validator must be hardened again before #98 can close.

## Relationship to validation evidence

The tooling receipt answers **which exact tool bytes were prepared**. Platform validation evidence answers **which admitted bytes were used under the platform's immutable/pinned execution model**. On Linux, the receipt SHA stored in platform evidence is derived from the exact stable receipt bytes that passed semantic verification. On Windows, the receipt SHA and lockfile SHA are derived from pinned streams held through evidence publication. The dual-platform reviewer verifies the receipt/evidence cryptographic linkage and exact platform/head tool root.

None of these files is self-authenticating against a malicious host administrator. The contract is instead designed to remove avoidable local pathname races, helper-implementation redirection, same-inode gate mutation, transient receipt/lockfile substitution, accidental cross-head mutation, duplicate validation and ambiguous recovery states inside the supported validation workflow.

## Admission boundary

Current source hardening is insufficient by itself to close #90 or #98.

The exact final NXB-153 head still requires real Rust 1.97.1 Linux + Windows execution proving:

- Linux committed-helper Git-object authority and repository-CWD behavior;
- Linux sealed-tool primitive availability and self-test;
- preparation tool-byte binding;
- exact token version checks;
- stable tooling-receipt object verification;
- validator tool-byte binding;
- Linux security-tool execution from receipt-hash-checked sealed snapshots;
- Windows security-tool execution under pinned file + ancestor namespace authority;
- Windows tooling-receipt and `Cargo.lock` pinned-object behavior under normal readers and adversarial write/delete/rename attempts;
- canonical-path consistency at finalization;
- Windows share-mode and directory-handle behavior;
- exact-head receipt and platform-evidence publication;
- guarded dual-platform closure.

PR #89 remains draft/not admitted until those platform checks and the rest of #90–#98 complete.
