# NXB-153 Windows Admission Review Authority

## Status

This document records the current **source-staged, not admitted** canonical Windows admission-review contract for NXB-153.

It supersedes earlier documentation that named `scripts/review-nxb-153-evidence-windows.ps1` as the complete canonical Windows closure entrypoint. That script remains a required subordinate schema-v2/closure reviewer, but direct invocation of it alone is **not sufficient for current NXB-153 Windows admission**.

No supported Windows/NTFS/PowerShell runtime PASS is claimed by this document.

## Canonical entrypoint

The complete current Windows admission-review entrypoint is:

`scripts/review-nxb-153-windows-admission.ps1`

Current exact Git blob:

`c0ea7d3e251e4139bc9c02b75c83a1e4078b74cc`

Commit `93acff2adcf6794f5c0130e6728118d1c15af966` made the exact-head tool-version output regression probe a mandatory canonical admission layer.

The wrapper requires, on the same exact Git head:

1. successful execution of the exact-head Windows tool-version output regression probe against the pinned production tool-preparation source;
2. successful review of create-only Windows process-lifecycle evidence;
3. successful canonical Windows schema-v2 / dual-platform evidence review;
4. exact-head authority-object continuity before, between and after all three phases;
5. unchanged Git HEAD through the complete admission-review sequence;
6. fail-closed cleanup of pinned authority handles;
7. no subordinate PASS output is released before the complete admission-review sequence succeeds.

The former direct entrypoint:

`scripts/review-nxb-153-evidence-windows.ps1`

is therefore **subordinate / non-canonical when invoked by itself** for final NXB-153 admission.

## Review chain

Current source-staged order is:

```text
canonical Windows preparation / validation namespace
  -> existing target/nxb-validation directory
  -> scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1
     -> scripts/nxb-153-windows-process-lifecycle-probe.ps1
     -> create-only target/nxb-validation/nxb-153-windows-process-lifecycle-<head>.json

scripts/review-nxb-153-windows-admission.ps1
  -> scripts/nxb-153-windows-tool-version-output-probe.ps1
     -> exact-head scripts/prepare-and-validate-nxb-153-windows-inner.ps1
     -> AST-loaded Invoke-NxbBoundedFixedOutput production helper
  -> scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1
  -> scripts/review-nxb-153-evidence-windows.ps1
     -> scripts/review-nxb-153-evidence-windows-inner.ps1
        -> scripts/review-nxb-153-evidence.ps1
```

The tool-version output probe must complete before the process-lifecycle evidence review begins. The process-lifecycle evidence review must then complete before the schema-v2 closure review begins.

## Tool-version output probe authority

Canonical tool-version probe:

`scripts/nxb-153-windows-tool-version-output-probe.ps1`

Current exact Git blob:

`fc21d291203bce8d0e53de8f2dbf8992043c1fef`

Production tool-preparation source:

`scripts/prepare-and-validate-nxb-153-windows-inner.ps1`

Current exact Git blob:

`98aa023626e2410dce6800bd799a6d3230355b86`

The admission wrapper pins read-only handles for both files with write/delete sharing withheld before running the probe and retains those handles through the complete admission review.

The probe independently:

- exact-head verifies its own working-tree bytes and the production tool-preparation source through Git object equality;
- parses the production source with the PowerShell AST;
- extracts exactly one `Invoke-NxbBoundedFixedOutput` production helper;
- requires the production fixed-output constants **4,096 bytes / 30,000 ms read inactivity / 30,000 ms post-output exit**;
- requires strict UTF-8, <=256-character semantic output and recursive `Kill(true)` cleanup patterns;
- rejects reintroduced `Out-String`, `ReadToEndAsync`, `ReadLineAsync` and parameterless `WaitForExit()` in the reviewed fixed-output paths;
- requires `Get-ToolVersion` and the tooling-receipt `rustc --version` call to route through that helper;
- dynamically loads the exact production helper body and stages normal, oversize, invalid-UTF8, nonzero-exit, stalled-output, output-then-stall and recursive descendant-cleanup primitives with shorter probe-only deadlines.

The probe is a required runtime gate inside canonical admission, not a replacement for the full Windows validator or for process/schema-v2 evidence.

## Process-lifecycle evidence authority

Canonical process-lifecycle evidence policy:

`nxb-153-windows-process-lifecycle-evidence-v1`

### Namespace and source lifetime

The evidence writer no longer creates `target/nxb-validation` with a pathname-only `New-Item -Force` operation. It requires the canonical validation namespace to already exist through the normal NXB-153 preparation/validation path.

Before the probe runs, the writer opens and retains native directory handles for:

- repository root;
- `scripts`;
- `target`;
- `target/nxb-validation`.

Each directory:

- must already exist as a normal non-reparse directory;
- is opened with native `CreateFileW` directory semantics;
- withholds delete sharing while the writer remains active;
- is resolved through `GetFinalPathNameByHandleW` and must match the expected canonical absolute path.

The writer also opens and retains read-only file handles, with write/delete sharing withheld, for:

- `scripts/nxb-153-windows-process-lifecycle-probe.ps1`;
- `scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1`;
- `scripts/nxb-153-windows-dependency-source.ps1`;
- `scripts/nxb-153-windows-immutable-source-inner.ps1`.

Only after those handles are open does it compare each pathname's Git object to the exact-head committed object. The handles remain live through probe execution, evidence publication and final HEAD/object continuity checks, preventing those source pathnames from being rewritten or deleted during the evidence run.

### Evidence publication

The evidence writer:

- runs the process probe with canonical **1,000 ms I/O / 1,500 ms exit** probe-only deadlines;
- requires production **300,000 ms I/O / 30,000 ms exit** authority to remain unchanged;
- validates the exact probe field set and exact ordered test set;
- bounds probe JSON and published evidence to **65,536 bytes**;
- publishes the canonical evidence path with `.NET FileMode.CreateNew` and `FileShare.None`;
- performs durable `Flush(true)` and exact same-handle read-back;
- refuses to overwrite an existing exact-head evidence object;
- rechecks exact Git HEAD and every pinned source object's Git identity after publication.

Source-file and namespace-handle cleanup is part of successful evidence publication. Disposal failures are accumulated and fail closed. The writer does not print its evidence-recorded PASS summary until source and namespace handles have been released successfully.

If evidence bytes were already published and a later authority or cleanup check fails, the run remains failed and the create-only evidence requires explicit recovery rather than being silently treated as admitted.

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
- `scripts/review-nxb-153-evidence-windows.ps1`;
- `scripts/nxb-153-windows-tool-version-output-probe.ps1`;
- `scripts/prepare-and-validate-nxb-153-windows-inner.ps1`.

Write/delete sharing is withheld while those authority handles remain open.

After the tool-version probe, after process-evidence review, and again after the schema-v2 Windows reviewer, the wrapper:

- recomputes every pinned authority file's working-tree Git object and requires exact equality with the initial exact-head object;
- requires Git HEAD to remain the initial exact head;
- fails closed if authority-handle cleanup reports an error.

This closes the former gap where the tool-version probe was documented as required but was not itself on the canonical admission execution path.

### Guarded subordinate output

Tool-version probe and subordinate reviewer success output is not emitted directly to the operator.

The admission wrapper streams each subordinate phase's information/success output into a private in-memory record list while applying both:

- maximum **65,536 UTF-8 bytes** per phase;
- maximum **4,096 output records** per phase.

The tool-version probe output remains withheld while its authority/HEAD continuity is checked and while both later review phases execute. The process-evidence reviewer output remains withheld while reviewer-object and HEAD continuity are checked and while the schema-v2 closure reviewer executes. The schema-v2 reviewer output is likewise withheld through the final authority-object, HEAD and handle-cleanup checks.

If any later gate or cleanup step fails, buffered subordinate PASS output is discarded rather than printed. Only after the complete wrapper succeeds are the bounded tool-version, process-evidence and schema-v2 summaries released, followed by the canonical Windows admission-review PASS line.

This prevents a tool-version, process-evidence or schema-v2 PASS message from becoming misleading evidence when a later authority check fails.

The subordinate Windows schema-v2 reviewer retains its existing native handle-pinning, semantic-review rerun, closure-object pinning and final repository/Cargo.lock/worktree authority contract.

## Fixed-output Git control-plane calls

The process-evidence/admission helpers use small `Get-NxbGitValue` helpers only for exact control-plane values:

- `git rev-parse HEAD`;
- `git rev-parse <head>:<path>`;
- `git hash-object -- <path>`.

All current call sites require one non-empty result no longer than 256 characters and then require the relevant object/head result to be canonical 40-hex Git identity where applicable. These are not repository-volume commands such as `status`, `ls-tree` or `log`; no attacker-expandable repository listing is consumed through these helpers.

The existing bounded Git-output authority remains mandatory for the broader Windows entry/H2 command surfaces.

## Canonical supported-Windows sequence

The process evidence writer requires the existing canonical `target/nxb-validation` namespace. Therefore the Windows preparation/validation path must establish that namespace before process evidence is recorded.

From one exact clean final NXB-153 checkout, the relevant source-staged ordering is:

1. run the canonical Windows preparation/full validation path for the exact head so its normal validation namespace and platform artifacts exist;
2. independently produce the required exact-head Linux validation evidence;
3. record Windows process-lifecycle evidence:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\record-nxb-153-windows-process-lifecycle-evidence.ps1
```

4. after all required same-head platform artifacts exist, run the complete Windows admission review:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\review-nxb-153-windows-admission.ps1
```

The admission wrapper itself executes the exact-head tool-version output regression probe first. The process writer separately runs its process-lifecycle probe and publishes create-only exact-head evidence; the admission wrapper then requires that evidence to pass native-pinned semantic review before it permits the existing Windows schema-v2 / dual-platform closure reviewer to run.

A separate manual invocation of the tool-version probe can be useful diagnostically, but it does not replace canonical wrapper execution and is not required as a separate operator step once the wrapper includes it.

This sequence does not replace the required full Windows validator or Linux H2 validation.

## Compatibility and precedence

Where older NXB-153 documentation says:

`review-nxb-153-evidence-windows.ps1` is the canonical Windows closure entrypoint

interpret that statement as describing the **schema-v2 closure sublayer** only.

For the current source head, the complete admission authority is `review-nxb-153-windows-admission.ps1`, and this document takes precedence for Windows admission-review ordering.

This avoids weakening the older reviewer's native handle and Git-output protections while preventing operators from accidentally bypassing the required tool-version and process-lifecycle gates.

## Remaining runtime proof

Source staging still does not prove supported Windows behavior. Same-head admission still requires real Windows/NTFS/PowerShell Core execution proving at least:

- exact-head tool-version output probe success as part of canonical admission;
- tool-version fixed-output normal, oversize, invalid-UTF8, nonzero-exit, stall and recursive-cleanup behavior;
- native process-evidence writer namespace/source handle pinning and no-delete-share behavior;
- process-evidence create-only publication and cleanup-failure handling;
- process-lifecycle evidence creation and review;
- admission-wrapper bounded output withholding/release behavior under success and late-failure cases across all three phases;
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
