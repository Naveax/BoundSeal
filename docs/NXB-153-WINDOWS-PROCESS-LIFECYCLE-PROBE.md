# NXB-153 Windows Process Lifecycle Probe and Evidence

## Status

This document records the current **source-staged, not admitted** Windows process-lifecycle runtime gate for NXB-153.

The gate does not replace the canonical Windows validator, H2 destination-broker tests, main schema-v2 validation evidence or guarded Linux + Windows closure. It proves one narrower property: the exact-head direct-child and broker-control hardening is still present in source and the supported Windows PowerShell/.NET host honors the async pipe, bounded framing, timed-exit and recursive process-tree termination primitives on which that hardening depends.

A terminal-only probe PASS is not admission evidence. Canonical admission uses a four-stage chain:

1. exact-head process primitive probe;
2. create-only exact-head process-lifecycle evidence publication;
3. native-pinned process-lifecycle semantic evidence review;
4. canonical Windows admission wrapper, which requires the process review before the existing Windows schema-v2 / dual-platform closure reviewer.

Policies:

- probe: `nxb-153-windows-process-lifecycle-probe-v1`;
- evidence: `nxb-153-windows-process-lifecycle-evidence-v1`.

Canonical scripts:

- `scripts/nxb-153-windows-process-lifecycle-probe.ps1`;
- `scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1`;
- `scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1`;
- `scripts/review-nxb-153-windows-admission.ps1`.

Canonical complete admission-review authority is defined by:

`docs/NXB-153-WINDOWS-ADMISSION-REVIEW-AUTHORITY.md`.

Where older NXB-153 material calls `scripts/review-nxb-153-evidence-windows.ps1` the canonical Windows closure entrypoint, that statement now describes the schema-v2 closure **sublayer only**. Direct invocation of that script alone is not sufficient for current NXB-153 Windows admission.

## Production source contract checked by the probe

Before starting any adversarial child, the probe resolves exact Git HEAD and requires the working-tree bytes of the inspected files to hash to their exact-head Git objects.

It parses the production PowerShell sources with the PowerShell AST and requires the current direct-child implementations to retain the reviewed contract:

- `scripts/nxb-153-windows-dependency-source.ps1`
  - `Invoke-NxbRegistryVerifierWithInput` uses `WriteAsync` and `FlushAsync`;
  - post-input exit uses `WaitForExit($childExitTimeoutMilliseconds)`;
  - timeout/failure cleanup contains recursive `Kill(true)`;
  - synchronous `StandardInput.Write(...)` and parameterless `WaitForExit()` are absent.
- `scripts/nxb-153-windows-immutable-source-inner.ps1`
  - `New-NxbPinnedGitArchive` uses `ReadAsync`, bounded post-output exit and recursive termination cleanup;
  - synchronous child stdout `BaseStream.Read(...)` and parameterless `WaitForExit()` are absent;
  - `Expand-NxbPinnedTarArchive` uses chunked `WriteAsync`, `FlushAsync`, bounded post-input exit and recursive termination cleanup;
  - child-pipe `CopyTo(...)` and parameterless `WaitForExit()` are absent.
- `scripts/nxb-153-windows-immutable-source-bounded-inner.ps1`
  - `Read-NxbH2BrokerLine` reads the broker control channel from `StandardOutput.BaseStream` with incremental `ReadAsync` rather than `ReadLineAsync`;
  - retained control payload is bounded before decode to **64 KiB**, with at most one trailing CR admitted before the required LF terminator;
  - strict UTF-8 decode occurs only after the byte ceiling succeeds;
  - timeout, malformed framing, oversized framing and invalid UTF-8 attempt recursive broker termination plus bounded reap;
  - `ReadLineAsync` and `ReadToEndAsync` are forbidden in the broker-control reader.

The dependency and immutable-source child paths must retain:

- child I/O inactivity timeout: **300,000 ms / 5 minutes**;
- post-I/O exit timeout: **30,000 ms / 30 seconds**.

The immutable source must retain the exact-head Git archive ceiling of **1 GiB**. The broker-control reader must retain its explicit pre-decode **64 KiB** framing ceiling. A reintroduced direct `ReadToEndAsync()` retention path or post-hoc `ReadLineAsync()` broker limit fails before dynamic execution.

## Dynamic Windows primitives

The probe creates only a private temporary helper script and temporary PID record outside the repository. It launches the currently executing PowerShell Core binary with `UseShellExecute = false` and deliberately exercises the same .NET process primitives used by production source.

For broker-control tests, the probe does **not** use a copied reader implementation. It AST-extracts the exact-head production `Read-NxbH2BrokerLine` function from `scripts/nxb-153-windows-immutable-source-bounded-inner.ps1`, installs only the narrow failure shim it requires, and executes that exact function against synthetic child stdout.

The dynamic suite covers:

1. registry-style text stdin success through `StandardInput.WriteAsync` / `FlushAsync`;
2. registry-style child that never reads stdin, requiring I/O timeout and recursive cleanup;
3. registry-style child that consumes stdin but refuses to exit, requiring post-I/O exit timeout;
4. tar-style binary stdin success through chunked `BaseStream.WriteAsync` / `FlushAsync`;
5. tar-style child that never reads stdin, requiring I/O timeout and recursive cleanup;
6. tar-style child that consumes stdin but refuses to exit, requiring post-I/O exit timeout;
7. Git-archive-style stdout success through `BaseStream.ReadAsync`;
8. Git-archive-style child that never emits stdout, requiring read-inactivity timeout;
9. Git-archive-style nonzero child exit propagation;
10. production broker-control reader accepting one strict-UTF-8 JSON payload terminated by CRLF without retaining the terminator;
11. production broker-control reader rejecting EOF before LF termination;
12. production broker-control reader rejecting invalid UTF-8 before JSON parsing;
13. production broker-control reader timing out and cleaning up a child that stalls without output;
14. direct timed `WaitForExit(...)` behavior against a sleeping child;
15. recursive `Process.Kill(true)` behavior against a child that has spawned a live descendant.

The exact evidence `tests` array contains **16 records** because `exact-head source/AST contract` is itself the first required record before those 15 dynamic primitives.

The stall helpers sleep for 30 seconds. A correct probe does not wait for those sleeps to finish; the parent must fail, kill and reap inside the bounded probe envelope.

The current dynamic suite deliberately leaves the full 64 KiB + terminator boundary as an exact source/AST invariant instead of spending tens of thousands of one-byte asynchronous reads in every admission probe. Supported Windows H2 runtime acceptance still has to exercise the real broker protocol and boundary behavior.

## Probe-only invocation

For debugging the primitive directly:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\nxb-153-windows-process-lifecycle-probe.ps1 `
  -ProbeIoTimeoutMilliseconds 1000 `
  -ProbeExitTimeoutMilliseconds 1500 `
  -Json
```

The 1,000 ms I/O and 1,500 ms exit values are **probe-only** deadlines. They do not alter production 300,000 ms / 30,000 ms authority or the broker-control framing ceiling.

A direct JSON PASS is useful diagnostics but is not the canonical persistent admission artifact.

## Canonical create-only evidence publication

Admission uses the evidence writer instead of manually redirecting probe output:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\record-nxb-153-windows-process-lifecycle-evidence.ps1
```

The writer:

- requires Windows PowerShell Core;
- requires the canonical **1,000 ms I/O / 1,500 ms exit** probe deadlines and rejects custom admission deadlines before the probe starts;
- exact-head verifies the probe, writer, dependency-source, immutable-source and bounded H2 source bytes;
- invokes the exact-head probe in JSON mode;
- limits captured probe JSON to **64 KiB**;
- requires the exact probe field set, policies, same `head_sha`, production source object IDs, timeout values, PASS status and exact ordered test list;
- requires canonical UTC probe time;
- publishes one deterministic record at:

```text
target/nxb-validation/nxb-153-windows-process-lifecycle-<HEAD>.json
```

Publication uses `FileMode.CreateNew`, `FileShare.None`, durable `Flush(true)` and byte-for-byte read-back. Existing exact-head evidence is never overwritten.

The evidence record binds:

- schema/policy/milestone/platform;
- exact Git head;
- probe policy and probe script object;
- evidence-writer object;
- dependency, immutable-source and bounded-H2-source objects;
- production and probe timeout values;
- PowerShell version;
- exact ordered **16-record** test list;
- PASS status;
- probe and evidence timestamps.

## Native-pinned process evidence review

The process-evidence reviewer is:

`scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1`.

It may be invoked directly for narrow diagnostics, but final Windows admission must route through `scripts/review-nxb-153-windows-admission.ps1` so this review cannot be bypassed before the schema-v2 closure sublayer.

The process-evidence reviewer:

- exact-head verifies the probe, evidence writer, reviewer and all three inspected production sources;
- requires the canonical exact-head evidence pathname;
- rejects reparse evidence;
- opens the evidence with read-only access while withholding write/delete sharing;
- resolves the native final path from the file handle and requires it to equal the canonical pathname, rejecting redirected parent authority;
- bounds the pinned evidence object to **64 KiB** and requires strict UTF-8;
- requires the exact field set and exact values for head, script objects, policies, timeouts, platform and PASS status;
- requires the exact ordered **16-record** test result list;
- requires canonical UTC times with `recorded_at` no earlier than `probed_at` and no more than five minutes later;
- computes the pinned evidence SHA-256;
- re-verifies Git HEAD and all exact-head authority objects, including the bounded H2 source, before success.

The reviewer emits only a fixed small success summary containing HEAD, evidence SHA-256 and reviewer object ID. It does not rewrite the evidence.

## Canonical complete Windows admission review

After the process evidence has been recorded and the normal exact-head Linux + Windows platform validation evidence required by the existing closure layer exists, final Windows-side review must use:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\review-nxb-153-windows-admission.ps1
```

The admission wrapper exact-head verifies and pins read-only handles for:

- itself;
- `scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`.

It then:

1. runs the process-lifecycle evidence review first;
2. rechecks all pinned reviewer Git objects and exact Git HEAD;
3. only then runs the existing Windows schema-v2 / dual-platform closure reviewer;
4. rechecks all pinned reviewer Git objects and exact Git HEAD again;
5. fails closed if pinned-reviewer handle cleanup fails.

This makes `scripts/review-nxb-153-evidence-windows.ps1` a required subordinate closure layer rather than a bypassable complete admission entrypoint.

## Failure behavior

Any of the following is fatal:

- inspected source bytes do not match exact-head Git authority;
- production timeout constants, 1 GiB archive ceiling or 64 KiB broker framing ceiling drift;
- required async/timed/recursive-kill patterns disappear;
- forbidden synchronous/unbounded source patterns reappear;
- `ReadLineAsync` or `ReadToEndAsync` reappears in the broker-control reader;
- PowerShell AST parsing fails;
- broker control closes before LF, contains invalid UTF-8 or stalls beyond the admitted probe timeout;
- a stalled input/output operation does not time out;
- a sleeping child does not trigger timed exit failure;
- nonzero child exit is not surfaced;
- recursive `Kill(true)` leaves the spawned descendant alive;
- a probe child cannot be reaped inside the bounded cleanup envelope;
- probe JSON exceeds its bounded envelope or differs from the canonical schema;
- evidence already exists at the exact-head pathname;
- evidence path resolves through redirected/reparse authority;
- evidence fields/object IDs/test sequence/timestamps differ;
- Git HEAD or authority objects drift during review;
- process evidence review fails before schema-v2 review;
- any pinned admission reviewer object changes between review phases;
- admission-wrapper handle cleanup fails.

## What this does not prove

A reviewed PASS from this process-lifecycle chain is supporting platform evidence only. It does **not** prove:

- the real registry helper's complete metadata-validation semantics;
- real `git archive` behavior against the repository or the actual 1 GiB rejection boundary;
- real tar extraction into the immutable source snapshot;
- the real broker's complete 64 KiB response-boundary behavior under adversarial or corrupted output;
- inherited stdout/stderr compatibility across every production child;
- canonical entry/H2 Git proxy nesting/restoration;
- H2 destination-broker native handle/share/watcher semantics;
- relocated Rust 1.97.1 DLL/sysroot behavior;
- mutation/injection/lock-contention behavior;
- full workspace/security gates;
- main schema-v2 validation evidence publication/review;
- same-head Linux + Windows admission.

Those remain mandatory through the canonical full validation/evidence path.

## Admission boundary

For the exact final NXB-153 head, supported Windows admission requires:

1. create-only process-lifecycle evidence publication, which dynamically executes the probe;
2. native-pinned process-lifecycle evidence review;
3. canonical Windows admission wrapper completion, including the existing schema-v2 / dual-platform closure reviewer;
4. complete full Windows NXB-153 validation evidence on the same exact Git head.

Linux H2 validation, object-anchored main evidence review and guarded dual-platform closure remain independently required.

Until all gates close, schema-v2 evidence remains:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 remains draft/not admitted and NXB-154 must not use NXB-153 as an admitted implementation base.