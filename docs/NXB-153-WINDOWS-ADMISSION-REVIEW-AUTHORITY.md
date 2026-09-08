# NXB-153 Windows Admission Review Authority

## Status

This document records the current **source-staged, not admitted** Windows admission-review contract for NXB-153.

`scripts/review-nxb-153-evidence-windows.ps1` remains a required subordinate schema-v2/closure reviewer, but direct invocation alone is **not sufficient** for current NXB-153 Windows admission. The subordinate three-phase admission wrapper itself is also not sufficient for **complete** Windows admission; it runs beneath `scripts/review-nxb-153-windows-admission-complete.ps1`.

No supported Windows/NTFS/PowerShell runtime PASS is claimed by this document.

## Current authority

Subordinate three-phase admission:

`scripts/review-nxb-153-windows-admission.ps1` -> `6b0e4ddc47ad440ab113ff073d3ae5275a95b949`

Complete admission:

`scripts/review-nxb-153-windows-admission-complete.ps1` -> `b2b5cdec1a24b92e34d2397c9567e2cc4c2e3a98`

Related exact source authority:

- shared canonical Windows outer entry -> `9f1852241f62d6a1357688713dd32595464682b6`;
- H2 outer/direct `-SelfTest` -> `58cfcfa709404f7dae467a4591af755bad52209c`;
- process-evidence writer -> `1ebca56bc704dcacb4864ace03ba16640b4b1e0d`;
- tool-version output probe -> `381529e260f2a9c9b0f20bff3f29a8b2c6ef6e84`;
- host-Git lifetime probe -> `5b12134f18cb6a71efde0d06b0622ec170269401`.

The subordinate wrapper requires on one exact Git head:

1. successful exact-head tool-version output regression probe against pinned production tool-preparation source;
2. successful review of create-only Windows process-lifecycle evidence;
3. successful canonical Windows schema-v2 / dual-platform evidence review;
4. exact-head authority-object continuity before, between and after all phases;
5. unchanged Git HEAD through complete review;
6. fail-closed cleanup of pinned authority, namespace and host-tool handles plus PATH restoration;
7. no subordinate PASS output released before the wrapper succeeds.

Complete Windows admission additionally requires the host-Git lifetime regression probe before this subordinate chain and final complete-wrapper authority/cleanup after it.

## Pre-Git ambient Git authority

Pinning the correct `git.exe` does not by itself determine the repository/object/config authority Git will consume. Canonical Windows authority therefore rejects every environment-variable name beginning with `GIT_`, case-insensitively, **before the first exact-head Git operation**.

This source-staged boundary is present on:

- the three byte-identical canonical outer entrypoints;
- H2 outer/direct `-SelfTest` authority;
- process-evidence writer;
- subordinate admission wrapper;
- complete admission wrapper;
- mandatory host-Git lifetime probe.

Only variable names may be reported; values are never emitted. The exact-head cross-platform environment helper later repeats the `GIT_*` rejection before deeper validation work.

Direct diagnostic probes/reviewers remain parent-bounded when invoked outside the canonical chain and are not promoted to standalone admission authority merely because they can execute independently.

## Review chain

Current source-staged order is:

```text
canonical Windows preparation / validation
  -> pre-Git ambient-authority rejection
  -> pinned host Git + pinned repo/scripts + pinned preserved inner
  -> existing target/nxb-validation directory
  -> record-nxb-153-windows-process-lifecycle-evidence.ps1
     -> pinned host Git + pinned evidence namespaces/sources
     -> nxb-153-windows-process-lifecycle-probe.ps1
     -> create-only process-lifecycle-<head>.json

review-nxb-153-windows-admission-complete.ps1
  -> pre-Git ambient-authority rejection
  -> host-Git lifetime regression probe
  -> review-nxb-153-windows-admission.ps1
     -> pre-Git ambient-authority rejection
     -> tool-version output probe
     -> process-lifecycle evidence review
     -> Windows schema-v2 / dual-platform closure review
  -> final complete-wrapper HEAD/object/PATH/source/namespace/host-Git cleanup
  -> complete PASS only after cleanup
```

## Supported-host Git lifetime authority

The selected installed Git application remains a **supported-host trust boundary**. NXB-153 does not claim independent cryptographic identity for the Git installation itself.

Canonical outer entrypoints, process-evidence recording and admission layers source-stage the following lifetime controls:

- select Git with `Get-Command git -CommandType Application`;
- require a regular non-reparse executable;
- open it read-only with write/delete sharing withheld;
- require native final-path equality for the file handle;
- native-pin the executable directory with delete sharing withheld and final-path equality;
- prepend the pinned directory to PATH;
- require nested Git application resolution to return the same pinned executable;
- keep Git file/directory handles live for the complete parent operation;
- treat PATH restoration and Git-handle cleanup failure as fatal before PASS.

This prevents one canonical run from selecting one supported-host Git for its first authority check and later silently resolving a replacement path.

## Canonical Windows outer entry authority

The three canonical outer entrypoints remain byte-identical:

- `scripts/prepare-and-validate-nxb-153-windows.ps1`;
- `scripts/validate-nxb-153-windows.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`.

Current shared exact blob:

`9f1852241f62d6a1357688713dd32595464682b6`

The shared wrapper rejects ambient `GIT_*` before first Git, pins selected host Git executable + directory, rebinds PATH, native-pins repository root and canonical `scripts`, pins the selected preserved inner source, requires native final-path equality, retains the bounded Git control/data planes and restores proxy/PATH/handles before success.

## H2 outer authority

`scripts/nxb-153-windows-immutable-source.ps1` -> `58cfcfa709404f7dae467a4591af755bad52209c`

The H2 outer can run through its own `-SelfTest` surface. It therefore independently rejects ambient `GIT_*` before resolving the exact-head Git-output inner and does not rely solely on earlier parent sanitization.

The nested Git-output inner remains governed by the existing 64 MiB / 4,096-record / 5-minute read-inactivity / 30-second post-output exit contract.

## Tool-version output probe authority

Canonical tool-version probe:

`scripts/nxb-153-windows-tool-version-output-probe.ps1` -> `381529e260f2a9c9b0f20bff3f29a8b2c6ef6e84`

Production tool-preparation source remains exact-head pinned by the admission wrapper. The probe requires production fixed-output constants **4,096 bytes / 30,000 ms read inactivity / 30,000 ms post-output exit**, strict UTF-8, <=256-character semantic output, recursive cleanup, no reintroduced `Out-String`/unbounded read/wait paths and runtime normal/oversize/invalid-UTF8/nonzero/stall/post-stdout/descendant-cleanup primitives.

The probe is a required subordinate runtime gate, not a replacement for full Windows validation or schema-v2 evidence.

## Process-lifecycle evidence authority

Canonical evidence writer:

`scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1` -> `1ebca56bc704dcacb4864ace03ba16640b4b1e0d`

The writer rejects ambient `GIT_*` before exact-head Git authority, requires canonical validation namespaces to already exist, pins repository/scripts/target/validation directories, pins exact-head inspected sources, pins host Git + directory, rebinds PATH, runs the canonical process probe, publishes create-only evidence with `FileMode.CreateNew`/`FileShare.None`, performs durable flush and same-handle readback, refuses overwrite and rechecks HEAD/source authority before success.

Canonical process-lifecycle evidence remains bounded to **65,536 bytes** and exact ordered **16-record** runtime proof.

## Admission-wrapper source authority

The subordinate admission wrapper exact-head verifies and pins read-only handles for itself, process-evidence reviewer, schema-v2 Windows reviewer, tool-version probe and production tool-preparation source. It native-pins repository root and `scripts`, retains host-Git/source/namespace handles through all phases and requires HEAD/object continuity after every subordinate layer.

Its pre-Git `GIT_*` gate executes before initial exact-head Git lookup. Cleanup or PATH restoration failure remains fatal before PASS.

## Guarded subordinate output

Tool-version and reviewer success output is buffered privately. Each subordinate phase is limited to:

- maximum **65,536 UTF-8 bytes**;
- maximum **4,096 records**.

Tool-version output remains withheld through later process/schema phases. Process-review output remains withheld through schema closure. Schema output remains withheld through final authority, HEAD, PATH and cleanup gates. Later failure discards buffered PASS output.

## Canonical supported-Windows sequence

From one exact clean final NXB-153 checkout:

1. run canonical Windows preparation/full validation for the exact head;
2. independently produce required exact-head Linux validation evidence;
3. record Windows process-lifecycle evidence;
4. run **complete** Windows admission:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\review-nxb-153-windows-admission-complete.ps1
```

Separate manual invocation of subordinate probes/reviewers remains diagnostic and does not replace canonical parent execution.

## Remaining runtime proof

Source staging still does not prove supported Windows behavior. Same-head admission requires real Windows/NTFS/PowerShell Core execution proving at least:

- hostile `GIT_DIR`, `GIT_WORK_TREE`, object-directory/alternate-object and `GIT_CONFIG_*` rejection before first Git on canonical outer/H2/process/admission authority surfaces;
- clean exact HEAD/object resolution after the pre-Git gate;
- host-Git executable/directory no-write/delete lifetime and nested PATH resolution under replacement/rename attempts;
- PATH restoration on success and deliberate late failure;
- canonical outer repo/scripts/preserved-inner final-path rejection under pathname/reparse substitution;
- tool-version fixed-output success/failure/timeout/cleanup behavior;
- process-evidence namespace/source/host-Git pinning and create-only publication/recovery;
- admission-wrapper bounded output withholding/release under success and late-failure cases;
- registry/Git-archive/tar stalled-I/O, nonzero and cleanup behavior;
- recursive child-tree termination;
- canonical entry/H2 Git proxy timeout, limit, nesting and restoration;
- H2 destination broker native relative-create/share/watcher/identity behavior;
- relocated Rust 1.97.1 DLL/sysroot behavior while broker authority remains live;
- full Rust/security gates and create-only schema-v2 platform evidence;
- Linux exact-head H2 validation;
- guarded dual-platform closure and final #90-#98 review.

Current evidence remains intentionally:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 remains draft/not admitted. NXB-154 must not use NXB-153 as an admitted implementation base until same-head closure succeeds.
