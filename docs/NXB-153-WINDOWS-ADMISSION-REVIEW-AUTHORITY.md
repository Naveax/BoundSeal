# NXB-153 Windows Admission Review Authority

## Status

This document records the current **source-staged, not admitted** canonical Windows admission-review contract for NXB-153.

It supersedes earlier documentation that named `scripts/review-nxb-153-evidence-windows.ps1` as the complete canonical Windows closure entrypoint. That script remains a required subordinate schema-v2/closure reviewer, but direct invocation alone is **not sufficient for current NXB-153 Windows admission**.

No supported Windows/NTFS/PowerShell runtime PASS is claimed by this document.

## Canonical entrypoint

The complete current Windows admission-review entrypoint is:

`scripts/review-nxb-153-windows-admission.ps1`

Current exact Git blob:

`aa90917a629d57fa9319ead2ffe9d9e0b77f4a35`

The wrapper requires on one exact Git head:

1. successful execution of the exact-head Windows tool-version output regression probe against pinned production tool-preparation source;
2. successful review of create-only Windows process-lifecycle evidence;
3. successful canonical Windows schema-v2 / dual-platform evidence review;
4. exact-head authority-object continuity before, between and after all three phases;
5. unchanged Git HEAD through complete review;
6. fail-closed cleanup of pinned authority, namespace and host-tool handles plus PATH restoration;
7. no subordinate PASS output released before complete review succeeds.

The former direct entrypoint:

`scripts/review-nxb-153-evidence-windows.ps1`

is therefore **subordinate / non-canonical when invoked by itself** for final NXB-153 admission.

## Review chain

Current source-staged order is:

```text
canonical Windows preparation / validation
  -> pinned host Git + pinned repo/scripts + pinned preserved inner
  -> existing target/nxb-validation directory
  -> scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1
     -> pinned host Git + pinned evidence namespaces/sources
     -> scripts/nxb-153-windows-process-lifecycle-probe.ps1
     -> create-only target/nxb-validation/nxb-153-windows-process-lifecycle-<head>.json

scripts/review-nxb-153-windows-admission.ps1
  -> pinned host Git + PATH rebinding
  -> scripts/nxb-153-windows-tool-version-output-probe.ps1
     -> exact-head scripts/prepare-and-validate-nxb-153-windows-inner.ps1
     -> AST-loaded Invoke-NxbBoundedFixedOutput production helper
  -> scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1
  -> scripts/review-nxb-153-evidence-windows.ps1
     -> scripts/review-nxb-153-evidence-windows-inner.ps1
        -> scripts/review-nxb-153-evidence.ps1
```

The tool-version output probe must complete before process-lifecycle evidence review begins. Process-lifecycle evidence review must complete before schema-v2 closure review begins.

## Supported-host Git lifetime authority

The selected installed Git application remains a **supported-host trust boundary**. NXB-153 does not claim an independent cryptographic identity for the Git installation itself.

The current source does bind the lifetime of the selected executable during canonical Windows operations.

For canonical Windows preparation/validation/evidence-review outer entrypoints, process-evidence recording and canonical admission:

- initial Git is selected with `Get-Command git -CommandType Application`;
- the selected executable must be a regular non-reparse file;
- it is opened read-only with write/delete sharing withheld;
- `GetFinalPathNameByHandleW` must resolve the actual file handle to the canonical expected executable path;
- the executable's immediate directory is native-opened with delete sharing withheld and final-path equality;
- the pinned directory is temporarily prepended to PATH;
- nested `Get-Command git -CommandType Application` resolution must return the same pinned executable;
- the Git file and directory handles remain live for the complete parent operation;
- PATH restoration and Git-handle cleanup are part of successful completion and fail closed before PASS.

This prevents a canonical run from selecting one supported-host Git application for its first authority check and later resolving or executing a replacement Git path during the same operation.

Direct diagnostic probes/reviewers outside their canonical parent chain do not by themselves carry the parent host-Git lifetime authority and are not final admission evidence.

## Canonical Windows outer entry authority

The three canonical Windows outer entrypoints remain byte-identical:

- `scripts/prepare-and-validate-nxb-153-windows.ps1`;
- `scripts/validate-nxb-153-windows.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`.

Current shared exact blob:

`18d638dde788abe363322685b04b4a04e87f6394`

The shared wrapper now:

- pins selected host Git executable + directory and rebinds PATH as described above;
- native-pins repository root and canonical `scripts` directory with delete sharing withheld and final-path equality;
- opens the selected preserved inner implementation read-only with write/delete sharing withheld;
- requires the actual inner file handle final path to equal the canonical expected path before Git-object authority is accepted;
- retains the existing bounded 4 KiB fixed-output control-plane Git calls;
- retains the existing 64 MiB / 4,096-record bounded delegated Git proxy with 5-minute read inactivity and 30-second post-stdout exit;
- restores the global Git proxy, PATH and all handles before successful completion.

This closes the previously remaining pathname interval between `Get-Item` and `File.Open` for the outer preserved implementation as well as host-Git lifetime drift during canonical preparation/validation.

## Tool-version output probe authority

Canonical tool-version probe:

`scripts/nxb-153-windows-tool-version-output-probe.ps1`

Current exact Git blob:

`381529e260f2a9c9b0f20bff3f29a8b2c6ef6e84`

Production tool-preparation source:

`scripts/prepare-and-validate-nxb-153-windows-inner.ps1`

Current exact Git blob:

`98aa023626e2410dce6800bd799a6d3230355b86`

The admission wrapper pins read-only handles for both files with write/delete sharing withheld before running the probe and retains those handles through complete admission review.

The probe independently:

- exact-head verifies its own working-tree bytes and production tool-preparation source through Git object equality;
- parses production source with the PowerShell AST;
- extracts exactly one `Invoke-NxbBoundedFixedOutput` production helper;
- requires production fixed-output constants **4,096 bytes / 30,000 ms read inactivity / 30,000 ms post-output exit**;
- requires strict UTF-8, <=256-character semantic output and recursive `Kill(true)` cleanup patterns;
- rejects reintroduced `Out-String`, `ReadToEndAsync`, `ReadLineAsync` and parameterless `WaitForExit()` in reviewed fixed-output paths;
- requires `Get-ToolVersion` and tooling-receipt `rustc --version` to route through that helper;
- dynamically loads the exact production helper body and stages normal, oversize, invalid-UTF8, nonzero-exit, stalled-output, output-then-stall read-inactivity, explicit stdout-close/post-stdout exit timeout and recursive descendant-cleanup primitives with shorter probe-only deadlines.

The distinct post-stdout fixture explicitly closes redirected Windows stdout and remains alive, so the production helper must exit its read loop on EOF and exercise its separate bounded `WaitForExit` path.

The probe is a required runtime gate inside canonical admission, not a replacement for full Windows validation or process/schema-v2 evidence.

## Process-lifecycle evidence authority

Canonical evidence writer:

`scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1`

Current exact blob:

`1313a6af73d0884d9db9f4939a073e2aa00f1109`

Canonical process-lifecycle evidence policy:

`nxb-153-windows-process-lifecycle-evidence-v1`

### Namespace, source and host-Git lifetime

The writer requires the canonical validation namespace to already exist through normal NXB-153 preparation/validation.

Before the probe runs, the writer opens and retains native directory handles for:

- repository root;
- `scripts`;
- `target`;
- `target/nxb-validation`.

Each namespace must be a normal non-reparse directory, is opened with delete sharing withheld, and must resolve through native final-path authority to its expected canonical path.

The writer also opens read-only source handles with write/delete sharing withheld for the probe, writer and inspected production sources, requiring actual file-handle final-path equality before exact-head Git authority is accepted.

The writer additionally pins the selected host Git executable and its directory, prepends the pinned directory to PATH, verifies nested Git application resolution, and retains the Git handles through probe execution, evidence publication and final HEAD/source checks.

Source, namespace and host-Git handle cleanup plus PATH restoration are part of successful publication and fail closed before writer PASS output.

### Evidence publication

The writer:

- runs process probe with canonical **1,000 ms I/O / 1,500 ms exit** probe-only deadlines;
- requires production **300,000 ms I/O / 30,000 ms exit** authority to remain unchanged;
- validates exact probe field set and exact ordered **16-record** test set;
- bounds probe JSON and published evidence to **65,536 bytes**;
- publishes canonical evidence with `.NET FileMode.CreateNew` and `FileShare.None`;
- performs durable `Flush(true)` and exact same-handle read-back;
- refuses overwrite of existing exact-head evidence;
- rechecks exact Git HEAD and pinned source identities after publication.

If evidence bytes were already published and a later authority or cleanup check fails, the run remains failed and create-only evidence requires explicit recovery rather than being silently treated as admitted.

The process-evidence reviewer requires canonical exact-head evidence path, native final-path equality, bounded strict-UTF8 evidence, exact schema/values/16-record sequence, canonical timestamps and final HEAD/source rechecks.

Direct process reviewer invocation is diagnostic/subordinate for final admission. Under canonical admission it resolves Git while the parent admission wrapper's host Git file/directory and PATH binding remain live.

## Admission-wrapper source authority

`scripts/review-nxb-153-windows-admission.ps1` exact-head verifies and pins read-only handles for:

- itself;
- `scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`;
- `scripts/nxb-153-windows-tool-version-output-probe.ps1`;
- `scripts/prepare-and-validate-nxb-153-windows-inner.ps1`.

Write/delete sharing is withheld for those authority handles.

Before any exact-head Git authority lookup, the wrapper pins the selected host Git executable + directory and rebinds PATH to force nested application resolution to that same file.

It also native-pins repository root and canonical `scripts` directory. Each directory handle and each authority-file handle must resolve through `GetFinalPathNameByHandleW` to its expected canonical path.

After tool-version probe, after process-evidence review and again after schema-v2 review, the wrapper:

- recomputes every pinned authority file's working-tree Git object and requires exact equality with initial exact-head object;
- requires Git HEAD to remain the initial exact head;
- keeps host Git/file/namespace handles live through all phases;
- fails closed if PATH restoration or any authority/namespace/host-Git cleanup reports an error.

## Guarded subordinate output

Tool-version probe and subordinate reviewer success output is not emitted directly to the operator.

The admission wrapper streams each subordinate phase's information/success output into a private in-memory record list while applying both:

- maximum **65,536 UTF-8 bytes** per phase;
- maximum **4,096 output records** per phase.

Tool-version probe output remains withheld while its authority/HEAD continuity is checked and while both later phases execute. Process-evidence reviewer output remains withheld through schema-v2 closure. Schema-v2 output remains withheld through final authority, HEAD, PATH restoration and all handle-cleanup checks.

If any later gate or cleanup step fails, buffered subordinate PASS output is discarded. Only after complete wrapper success are bounded summaries released, followed by canonical Windows admission PASS.

## Fixed-output Git control plane

The process-evidence/admission helpers use bounded Git control values only for exact control-plane operations such as:

- `git rev-parse HEAD`;
- `git rev-parse <head>:<path>`;
- `git hash-object -- <path>`;
- selected exact-object type checks.

Current standalone control envelope is **4 KiB raw stdout / 30 s read inactivity / 30 s post-output exit / strict UTF-8 / <=256-character semantic value**, with inherited stderr and recursive cleanup on failure.

The broader canonical outer/H2 Git data plane remains under its separate **64 MiB / 4,096-record / 5-minute read / 30-second exit** authority.

## Canonical supported-Windows sequence

From one exact clean final NXB-153 checkout:

1. run canonical Windows preparation/full validation for the exact head so normal validation namespace and platform artifacts exist;
2. independently produce required exact-head Linux validation evidence;
3. record Windows process-lifecycle evidence:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\record-nxb-153-windows-process-lifecycle-evidence.ps1
```

4. after all required same-head platform artifacts exist, run complete Windows admission review:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\review-nxb-153-windows-admission.ps1
```

The admission wrapper executes exact-head tool-version output probe first, native process-evidence review second and schema-v2/dual-platform closure third.

Separate manual invocation of subordinate probes/reviewers can be useful diagnostically but does not replace canonical parent execution.

## Compatibility and precedence

Where older NXB-153 documentation says:

`review-nxb-153-evidence-windows.ps1` is the canonical Windows closure entrypoint

interpret that as describing the **schema-v2 closure sublayer** only.

Where older Windows entry documentation lists `ab8383...` or `3267f592...` as the current shared outer entry blob, current authority is `18d638dde788abe363322685b04b4a04e87f6394`.

For current source head, complete admission authority is `review-nxb-153-windows-admission.ps1`, and this document takes precedence for Windows admission ordering and host-Git/source/namespace lifetime.

## Remaining runtime proof

Source staging still does not prove supported Windows behavior. Same-head admission still requires real Windows/NTFS/PowerShell Core execution proving at least:

- host Git executable/directory no-write/delete lifetime and nested PATH resolution under replacement/rename attempts;
- PATH restoration on success and deliberate late failure;
- canonical outer repo/scripts/preserved-inner final-path rejection under pathname/reparse substitution;
- exact-head tool-version output probe success inside canonical admission;
- tool-version fixed-output normal, oversize, invalid-UTF8, nonzero-exit, read-inactivity, post-stdout exit and recursive-cleanup behavior;
- native process-evidence writer namespace/source/host-Git pinning and no-delete-share behavior;
- process-evidence create-only publication and cleanup-failure handling;
- process-lifecycle evidence creation and review;
- admission-wrapper bounded output withholding/release under success and late-failure cases;
- registry-verifier stalled stdin, inherited output, nonzero exit and cleanup;
- Git-archive stalled stdout, archive limit, nonzero exit and cleanup;
- tar stalled stdin, inherited output, nonzero exit and cleanup;
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
