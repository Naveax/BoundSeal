# NXB-153 Validation Tool Object Integrity

## Status

This document records the source-staged object-identity contract for the NXB-153 validation security tools. It does **not** claim current-head Linux or Windows admission.

The relevant tools are the exact pinned versions of `cargo-audit` and `cargo-deny` installed for one platform and one exact Git head.

## Threat

Exact-head directory isolation prevents head A and head B from intentionally installing into the same tool root, but directory isolation alone does not close check/use races.

A weaker validator could:

1. hash `target/nxb-tools/<platform>/<head>/bin/cargo-audit`;
2. run hours of Cargo gates;
3. execute `cargo-audit` again by pathname;
4. hash the pathname again before evidence publication.

A concurrent rename/substitution could replace the pathname only for step 3 and restore the original object before step 4. A plain Linux read descriptor also does not prevent in-place writes to the same inode, so even descriptor-pinned execution can observe mutable executable bytes unless the execution image itself becomes immutable.

Windows has an additional namespace case: pinning only `cargo-audit.exe` does not prove that a later pathname execution cannot be redirected if an ancestor such as `bin`, the exact-head root, or another tool-root directory is renamed/replaced.

NXB-153 therefore separates **tool pathname identity**, **tool object bytes** and **tool namespace authority**.

## Exact-head roots

Canonical roots remain:

- Linux: `target/nxb-tools/linux/<exact-head>`;
- Windows: `target/nxb-tools/windows/<exact-head>`.

Tooling receipts bind that exact logical root plus the security-tool versions and SHA-256 values.

## Linux sealed-tool primitive

The canonical Linux helper is:

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

1. requires `cargo-audit` and `cargo-deny` to be regular non-symlink files;
2. invokes the sealed-tool helper separately for each freshly installed executable;
3. derives both the exact version string and SHA-256 from the **same immutable sealed snapshot**;
4. therefore cannot combine a version probe from one transient same-inode byte state with a hash from another state;
5. separately hashes the canonical tool pathnames and requires equality with the sealed-snapshot hashes before receipt publication;
6. publishes the bounded tooling receipt create-only with file and directory durability checks.

The version test uses exact whitespace-token equality. A token such as `0x22y2` cannot satisfy expected version `0.22.2` merely because `.` would otherwise be a regular-expression wildcard.

Linux preparation now requires the sealed-tool primitive; unsupported kernels/Python environments fail closed before tool preparation proceeds.

## Linux validation

Before expensive validation starts, the Linux validator:

1. requires the exact-head security-tool files to be regular and non-symlink;
2. performs a stable sealed inspection of each canonical executable;
3. derives initial version and SHA-256 from one immutable byte image per tool;
4. requires those values to match the exact-head tooling receipt;
5. runs fmt/check/Clippy/tests;
6. immediately before RustSec, reopens canonical `cargo-audit` with `O_NOFOLLOW`, stable-reads it, requires the receipt-admitted SHA-256, seals those exact bytes and executes `audit` from that immutable snapshot;
7. immediately before cargo-deny, performs the same receipt-hash check + sealed snapshot and executes `check` from that immutable snapshot;
8. finally re-hashes the canonical paths and requires them still to name the admitted bytes before evidence publication.

The gate execution image is therefore immutable after its admitted SHA-256 is checked. A pathname swap to different bytes fails the receipt-hash check; an in-place write to the source inode after snapshot creation cannot alter the already sealed execution image.

This is stronger than the earlier persistent-read-descriptor model, which defeated pathname replacement but could not prohibit same-inode write mutation.

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

The Windows validator uses the same model for the complete heavy-validation/evidence lifecycle:

1. pin repository/target/evidence directory authority;
2. acquire the exact-head validation lock;
3. pin `nxb-tools -> windows -> <head> -> bin` directory authority with native handles that omit delete sharing;
4. pin both tool files with read-only `FileStream` objects whose sharing mode is `FileShare.Read`;
5. obtain evidence SHA-256 values from those file streams and require tooling-receipt equality;
6. execute the security tools by canonical path while the complete ancestor namespace chain and file objects remain pinned;
7. re-hash pinned streams after security-tool execution and require unchanged bytes;
8. re-hash canonical pathnames and require they still name the admitted bytes;
9. retain all relevant handles until create-new Windows validation evidence has been flushed and exact-read back.

The earlier nested-array iteration used to stage the directory-handle list has been replaced with explicit individual handle opens, avoiding PowerShell enumeration/flattening ambiguity in the security-critical namespace chain.

## Windows runtime acceptance

Source staging is not Windows platform proof. Real supported Windows/NTFS execution must specifically demonstrate:

- normal `cargo-audit.exe` and `cargo-deny.exe` version/gate execution while all pin handles are open;
- attempted executable overwrite is rejected;
- attempted executable rename/delete is rejected;
- attempted `bin`, exact-head tool-root, `windows`, `nxb-tools`, `target` and relevant repository/validation-directory rename/delete or replacement behaves fail-closed as intended;
- pre-existing junction/symlink/reparse redirection is rejected by final-handle-path comparison;
- final stream hash and canonical-path hash equality;
- cleanup behavior after a failed gate.

If any supported filesystem permits pathname execution to escape this source-staged namespace/file handle chain, admission remains blocked and the Windows validator must be hardened again before #98 can close.

## Relationship to validation evidence

The tooling receipt answers **which exact tool bytes were prepared**. Platform validation evidence answers **which admitted bytes were used under the platform's immutable/pinned execution model**. The dual-platform reviewer verifies the receipt/evidence cryptographic linkage and exact platform/head tool root.

None of these files is self-authenticating against a malicious host administrator. The contract is instead designed to remove avoidable local pathname races, same-inode gate mutation, accidental cross-head mutation, duplicate validation and ambiguous recovery states inside the supported validation workflow.

## Admission boundary

Current source hardening is insufficient by itself to close #90 or #98.

The exact final NXB-153 head still requires real Rust 1.97.1 Linux + Windows execution proving:

- Linux sealed-tool primitive availability and self-test;
- preparation tool-byte binding;
- exact token version checks;
- validator tool-byte binding;
- Linux security-tool execution from receipt-hash-checked sealed snapshots;
- Windows security-tool execution under pinned file + ancestor namespace authority;
- canonical-path consistency at finalization;
- Windows share-mode and directory-handle behavior;
- exact-head receipt and platform-evidence publication;
- guarded dual-platform closure.

PR #89 remains draft/not admitted until those platform checks and the rest of #90–#98 complete.
