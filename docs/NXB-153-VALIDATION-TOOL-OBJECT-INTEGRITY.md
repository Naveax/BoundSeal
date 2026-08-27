# NXB-153 Validation Tool Object Integrity

## Status

This document records the source-staged object-identity contract for the NXB-153 validation security tools. It does **not** claim current-head Linux or Windows admission.

The relevant tools are the exact pinned versions of `cargo-audit` and `cargo-deny` installed for one platform and one exact Git head.

## Threat

Exact-head directory isolation prevents head A and head B from intentionally installing into the same tool root, but directory isolation alone does not close a check/use pathname race.

A weaker validator could:

1. hash `target/nxb-tools/<platform>/<head>/bin/cargo-audit`;
2. run hours of Cargo gates;
3. execute `cargo-audit` again by pathname;
4. hash the pathname again before evidence publication.

A concurrent rename/substitution could replace the pathname only for step 3 and restore the original object before step 4. Initial and final hashes would agree even though the security gate ran a different executable object.

NXB-153 therefore separates **tool pathname identity** from **tool object identity** and keeps the admitted object pinned across the relevant lifecycle.

## Exact-head roots

Canonical roots remain:

- Linux: `target/nxb-tools/linux/<exact-head>`;
- Windows: `target/nxb-tools/windows/<exact-head>`.

Tooling receipts bind that exact logical root plus the security-tool versions and SHA-256 values.

## Linux preparation

After the pinned `cargo install --locked --force --version ... --root <exact-head-root>` operations complete, Linux preparation:

1. requires `cargo-audit` and `cargo-deny` to be regular non-symlink files;
2. opens the installed tool files on persistent shell file descriptors 8 and 9;
3. uses `/proc/self/fd/8` and `/proc/self/fd/9` as the pinned object names;
4. validates the exact version token through those pinned objects;
5. obtains the receipt SHA-256 values through those pinned objects;
6. separately hashes the canonical tool pathnames and requires equality with the pinned-object hashes before receipt publication;
7. keeps the object descriptors open until the create-only tooling receipt is written, synchronized and finalized;
8. closes the descriptors only after the canonical receipt is successfully published.

The version test uses whitespace-token equality rather than interpolating the expected version into an unescaped regular expression. A token such as `0x22y2` therefore cannot satisfy expected version `0.22.2` merely because `.` is a regular-expression wildcard.

Linux preparation requires `/proc/self/fd`; environments without that object-preserving execution/read surface fail closed.

## Linux validation

Before expensive validation starts, the Linux validator:

1. requires the exact-head security-tool files to be regular and non-symlink;
2. opens `cargo-audit` and `cargo-deny` on persistent descriptors 8 and 9;
3. resolves version and initial SHA-256 from `/proc/self/fd/8` and `/proc/self/fd/9`;
4. requires those values to match the exact-head tooling receipt;
5. keeps both descriptors open throughout fmt/check/Clippy/tests and security gates;
6. executes RustSec through `/proc/self/fd/8 audit`;
7. executes cargo-deny through `/proc/self/fd/9 check`;
8. re-hashes the still-open pinned objects after the gates and requires byte equality with the initial hashes;
9. separately re-hashes the canonical pathnames and requires them to name the same admitted bytes before evidence publication.

A later pathname rename/substitution can therefore cause the canonical-path consistency check to fail, but it cannot change which already-open executable object is used for the two security gates.

### Linux primitive check

A networkless local primitive test opened one trusted executable on a persistent descriptor, replaced its pathname with a different executable, then executed both forms.

Observed behavior:

- `/proc/self/fd/<pinned>` executed the trusted object;
- the replaced pathname executed the substituted object;
- the pinned-object SHA-256 remained the trusted SHA-256;
- the canonical-path SHA-256 differed and therefore exposed the persistent substitution.

This is a narrow Linux file-descriptor primitive PASS only. It is not exact-head NXB-153 validation evidence.

## Windows preparation

Windows cannot use the Linux `/proc/self/fd` execution model. Instead, preparation pins each freshly installed security-tool file using a read-only `FileStream` opened with `FileShare.Read`.

The source-staged contract is:

1. reject a missing tool or a tool whose file item is a reparse point;
2. open the exact file with `FileMode.Open`, `FileAccess.Read`, `FileShare.Read`;
3. intentionally withhold write/delete sharing for the lifetime of the pinned stream;
4. run the exact version check while that handle remains open;
5. compute the tooling-receipt SHA-256 from the pinned stream with `Get-FileHash -InputStream` rather than reopening the pathname;
6. separately hash the canonical pathname and require equality with the pinned-stream hash;
7. keep both security-tool streams open through create-new tooling-receipt publication and same-handle receipt read-back;
8. dispose the pinned tool streams only after receipt publication succeeds or during failure cleanup.

Whether supported Windows permits normal executable loading while those read handles are open, while simultaneously rejecting write/delete/rename substitution as intended, is an explicit real-Windows acceptance requirement. Source shape is not platform proof.

## Windows validation

The Windows validator uses the same pinned-stream model before version/hash resolution and retains both tool streams through the complete heavy validation and evidence-publication lifecycle.

The staged contract is:

1. reject security-tool reparse points;
2. pin both files with read-only `FileStream` objects whose sharing mode is `FileShare.Read`;
3. obtain evidence SHA-256 values from those streams;
4. require tooling receipt equality;
5. execute the security tools by their canonical pathnames while the pinned streams withhold write/delete sharing;
6. re-hash the pinned streams after security-tool execution and require unchanged bytes;
7. re-hash the canonical pathnames and require they still name the admitted bytes;
8. retain the streams until create-new Windows validation evidence has been flushed and exact-read back.

The Windows runtime acceptance must specifically exercise:

- normal `cargo-audit.exe` and `cargo-deny.exe` execution while the pin handles are open;
- attempted file overwrite while the handle is open;
- attempted file rename/delete while the handle is open;
- attempted tool-directory or parent-directory replacement while the child tool handles are open;
- final stream hash and canonical-path hash equality;
- cleanup behavior after a failed gate.

If parent-directory substitution is not blocked by the source-staged share-mode arrangement on a supported Windows filesystem, admission remains blocked and the validator must pin the relevant directory authority with native handles before #98 can close.

## Relationship to validation evidence

The tooling receipt answers **which exact tool object bytes were prepared**. Platform validation evidence answers **which admitted tool object bytes were used and remained stable across validation**. The dual-platform reviewer verifies the receipt/evidence cryptographic linkage and exact platform/head tool root.

None of these files is self-authenticating against a malicious host administrator. The contract is instead designed to remove avoidable local pathname races, accidental cross-head mutation, duplicate validation and ambiguous recovery states inside the supported validation workflow.

## Admission boundary

Current source hardening is insufficient by itself to close #90 or #98.

The exact final NXB-153 head still requires real Rust 1.97.1 Linux + Windows execution proving:

- preparation tool-object binding;
- exact token version checks;
- validator tool-object binding;
- security-tool execution from/under the pinned object model;
- canonical-path consistency at finalization;
- Windows share-mode behavior;
- exact-head receipt and platform-evidence publication;
- guarded dual-platform closure.

PR #89 remains draft/not admitted until those platform checks and the rest of #90–#98 complete.