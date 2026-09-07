# NXB-153 Windows Admission Review Authority

## Status

This document records the current **source-staged, not admitted** canonical Windows admission-review contract for NXB-153.

It supersedes earlier documentation that named `scripts/review-nxb-153-evidence-windows.ps1` as the complete canonical Windows closure entrypoint. That script remains a required subordinate schema-v2/closure reviewer, but direct invocation of it alone is **not sufficient for current NXB-153 Windows admission**.

No supported Windows/NTFS/PowerShell runtime PASS is claimed by this document.

## Canonical entrypoint

The complete current Windows admission-review entrypoint is:

`scripts/review-nxb-153-windows-admission.ps1`

The wrapper requires, on the same exact Git head:

1. successful review of create-only Windows process-lifecycle evidence;
2. successful canonical Windows schema-v2 / dual-platform evidence review;
3. exact-head reviewer-object continuity before, between and after both review phases;
4. unchanged Git HEAD through the complete admission-review sequence;
5. fail-closed cleanup of pinned reviewer handles.

The former direct entrypoint:

`scripts/review-nxb-153-evidence-windows.ps1`

is therefore **subordinate / non-canonical when invoked by itself** for final NXB-153 admission.

## Review chain

Current source-staged order is:

```text
scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1
  -> scripts/nxb-153-windows-process-lifecycle-probe.ps1
  -> create-only target/nxb-validation/nxb-153-windows-process-lifecycle-<head>.json

scripts/review-nxb-153-windows-admission.ps1
  -> scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1
  -> scripts/review-nxb-153-evidence-windows.ps1
     -> scripts/review-nxb-153-evidence-windows-inner.ps1
        -> scripts/review-nxb-153-evidence.ps1
```

The process-lifecycle evidence review must complete before the schema-v2 closure review begins.

## Process-lifecycle evidence authority

Canonical process-lifecycle evidence policy:

`nxb-153-windows-process-lifecycle-evidence-v1`

The evidence writer:

- exact-head verifies its own source, the process probe and the production dependency/archive/tar implementations;
- runs the process probe with canonical **1,000 ms I/O / 1,500 ms exit** probe-only deadlines;
- requires production **300,000 ms I/O / 30,000 ms exit** authority to remain unchanged;
- validates the exact probe field set and exact ordered test set;
- bounds probe JSON and published evidence to **65,536 bytes**;
- publishes the canonical evidence path with `.NET FileMode.CreateNew`;
- performs durable `Flush(true)` and exact same-handle read-back;
- refuses to overwrite an existing exact-head evidence object.

The evidence reviewer:

- requires the canonical exact-head evidence pathname;
- rejects evidence reparse points and evidence outside the bounded envelope;
- opens the evidence object read-only while withholding write/delete sharing;
- uses `GetFinalPathNameByHandleW` to require the opened object to resolve to the expected canonical pathname;
- strict-decodes the pinned bytes and requires the exact evidence schema;
- verifies exact-head Git objects for the probe, writer, reviewer and production child-lifecycle scripts;
- requires canonical production/probe timeout values and exact ordered test results;
- constrains `recorded_at` to the admitted interval after `probed_at`;
- rechecks Git HEAD and all source-object identities before releasing the pinned evidence handle.

A terminal-only probe PASS is supporting diagnostic output and is not sufficient admission evidence.

## Admission-wrapper source authority

`scripts/review-nxb-153-windows-admission.ps1` exact-head verifies and pins read-only handles for:

- itself;
- `scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`.

Write/delete sharing is withheld while those reviewer handles remain open.

After process-evidence review and again after the schema-v2 Windows reviewer, the wrapper:

- recomputes each pinned reviewer's working-tree Git object and requires exact equality with the initial exact-head object;
- requires Git HEAD to remain the initial exact head;
- fails closed if reviewer-handle cleanup reports an error.

The subordinate Windows schema-v2 reviewer retains its existing native handle-pinning, semantic-review rerun, closure-object pinning and final repository/Cargo.lock/worktree authority contract.

## Canonical supported-Windows sequence

From one exact clean final NXB-153 checkout, canonical source-staged ordering is:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\record-nxb-153-windows-process-lifecycle-evidence.ps1
pwsh -NoLogo -NoProfile -File .\scripts\review-nxb-153-windows-admission.ps1
```

The first command dynamically runs the process probe and publishes its create-only exact-head evidence. The second command requires that evidence to pass native-pinned semantic review before it permits the existing Windows schema-v2 / dual-platform closure reviewer to run.

This sequence does not replace the required full Windows validator. The canonical full Windows validation/evidence artifacts must already exist for the same exact head before the admission wrapper can complete its subordinate schema-v2 closure review.

## Compatibility and precedence

Where older NXB-153 documentation says:

`review-nxb-153-evidence-windows.ps1` is the canonical Windows closure entrypoint

interpret that statement as describing the **schema-v2 closure sublayer** only.

For the current source head, the complete admission authority is `review-nxb-153-windows-admission.ps1`, and this document takes precedence for Windows admission-review ordering.

This avoids weakening the older reviewer's native handle and Git-output protections while preventing operators from accidentally bypassing the newly required process-lifecycle evidence gate.

## Remaining runtime proof

Source staging still does not prove supported Windows behavior. Same-head admission still requires real Windows/NTFS/PowerShell Core execution proving at least:

- process-lifecycle evidence creation and review;
- registry-verifier stalled stdin, inherited output, nonzero exit and cleanup behavior;
- Git-archive stalled stdout, archive limit, nonzero exit and cleanup behavior;
- tar stalled stdin, inherited output, nonzero exit and cleanup behavior;
- recursive child-tree termination;
- canonical entry/H2 Git proxy timeout, limit, nesting and restoration behavior;
- H2 destination broker native relative-create/share/watcher/identity behavior;
- relocated Rust 1.97.1 DLL/sysroot behavior while broker authority remains live;
- full Rust/security gates and create-only schema-v2 platform evidence;
- Linux exact-head H2 validation;
- guarded dual-platform closure and final #90-#98 review.

Current evidence remains intentionally:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 remains draft/not admitted. NXB-154 must not use NXB-153 as an admitted implementation base until the same exact final head completes all required runtime/evidence closure gates.
