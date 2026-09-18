# NXB-153 Windows Process Lifecycle Probe and Evidence

## Status

This document records the current **source-staged, not admitted** Windows process-lifecycle runtime gate for NXB-153.

The gate does not replace the canonical Windows validator, H2 destination-broker tests, main schema-v2 validation evidence or guarded Linux + Windows closure. A terminal-only probe PASS is not admission evidence.

Policies:

- probe: `nxb-153-windows-process-lifecycle-probe-v1`;
- evidence: `nxb-153-windows-process-lifecycle-evidence-v1`.

Canonical scripts:

- `scripts/nxb-153-windows-process-lifecycle-probe.ps1` -> `1d2ed9a23db922b9c3131784aec4932bf6518766`;
- `scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1` -> `1ebca56bc704dcacb4864ace03ba16640b4b1e0d`;
- `scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1` -> `314a04af4497c67b3761d4cd2f9ba470896d57e6`;
- subordinate `scripts/review-nxb-153-windows-admission.ps1` -> `6b0e4ddc47ad440ab113ff073d3ae5275a95b949`;
- complete `scripts/review-nxb-153-windows-admission-complete.ps1` -> `b2b5cdec1a24b92e34d2397c9567e2cc4c2e3a98`.

Complete Windows admission-review authority is defined by:

- `docs/NXB-153-WINDOWS-ADMISSION-REVIEW-AUTHORITY.md`;
- `docs/NXB-153-WINDOWS-COMPLETE-ADMISSION-AUTHORITY.md`.

## Pre-Git authority boundary

The process-evidence writer is a canonical persistent-evidence authority surface. It rejects every ambient environment variable whose name begins with `GIT_`, case-insensitively, **before its first exact-head Git operation**.

This prevents `GIT_DIR`, `GIT_WORK_TREE`, object-directory/alternate-object settings, `GIT_CONFIG_*`, `GIT_EXEC_PATH` or another `GIT_*` control from redirecting repository/object/config authority before the writer has established exact HEAD and exact source objects. Values are never printed.

The direct process-lifecycle probe remains diagnostic when invoked by itself. During canonical evidence recording it executes beneath the writer's pre-Git gate and pinned host-Git/PATH authority. It is not treated as standalone persistent admission evidence.

## Production source contract checked by the probe

Before adversarial child tests, the probe resolves exact Git HEAD and requires inspected working-tree bytes to hash to exact-head objects. It parses production PowerShell with the AST and requires reviewed direct-child behavior:

- `scripts/nxb-153-windows-dependency-source.ps1`
  - registry verifier uses `WriteAsync` / `FlushAsync`;
  - post-input exit is bounded;
  - timeout/failure cleanup uses recursive `Kill(true)`;
  - synchronous `StandardInput.Write(...)` and parameterless `WaitForExit()` are absent.
- `scripts/nxb-153-windows-immutable-source-inner.ps1`
  - Git archive uses `ReadAsync`, bounded post-output exit and recursive cleanup;
  - tar extraction uses chunked `WriteAsync` / `FlushAsync`, bounded exit and recursive cleanup;
  - direct synchronous child-pipe retention paths remain forbidden.
- `scripts/nxb-153-windows-immutable-source-bounded-inner.ps1`
  - broker control is incrementally read from `StandardOutput.BaseStream`;
  - retained control payload is bounded before decode to **64 KiB**;
  - strict UTF-8 decode follows the byte ceiling;
  - malformed framing/timeout/oversize/invalid UTF-8 attempts recursive broker termination plus bounded reap;
  - `ReadLineAsync` and `ReadToEndAsync` remain forbidden in the broker-control reader.

Production direct-child authority remains:

- I/O inactivity timeout: **300,000 ms / 5 minutes**;
- post-I/O exit timeout: **30,000 ms / 30 seconds**;
- exact-head Git archive ceiling: **1 GiB**;
- broker control pre-decode ceiling: **64 KiB**.

## Dynamic Windows primitives

The probe creates only private temporary helper/PID fixtures and launches the current PowerShell Core binary with `UseShellExecute = false`.

The exact evidence `tests` array contains **16 records**: one exact-head source/AST contract record plus 15 dynamic primitives covering registry-style stdin success/stall/post-input-exit, tar-style binary stdin success/stall/post-input-exit, Git-archive stdout success/stall/nonzero, broker CRLF success/missing-LF/invalid-UTF8/stall, timed post-I/O exit and recursive descendant termination.

Probe-only deadlines remain **1,000 ms I/O / 1,500 ms exit**. They do not modify production limits.

The full broker 64 KiB + terminator boundary remains an exact source invariant here; real supported-Windows H2 runtime acceptance must exercise the production protocol and boundary behavior.

## Probe-only invocation

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\nxb-153-windows-process-lifecycle-probe.ps1 `
  -ProbeIoTimeoutMilliseconds 1000 `
  -ProbeExitTimeoutMilliseconds 1500 `
  -Json
```

A direct JSON PASS is diagnostic only.

## Canonical create-only evidence publication

Admission uses:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\record-nxb-153-windows-process-lifecycle-evidence.ps1
```

Current writer exact blob:

`1ebca56bc704dcacb4864ace03ba16640b4b1e0d`

The writer:

- requires Windows PowerShell Core and canonical probe deadlines;
- rejects ambient `GIT_*` before first exact-head Git authority;
- resolves/pins the supported-host Git executable and directory with final-path equality and write/delete lifetime protection;
- prepends the pinned Git directory to PATH and verifies nested Git resolution;
- keeps Git lifetime pinned through probe execution, evidence publication and final HEAD/source checks;
- native-pins repository root, `scripts`, `target` and `target/nxb-validation` namespaces;
- exact-head pins the probe, writer and inspected production sources;
- invokes the exact-head probe in JSON mode;
- bounds probe JSON and published evidence to **65,536 bytes**;
- requires exact schema/policies/head/object IDs/timeout values/PASS status and exact ordered 16-record test list;
- publishes deterministic evidence at `target/nxb-validation/nxb-153-windows-process-lifecycle-<HEAD>.json` with `FileMode.CreateNew`, `FileShare.None`, durable `Flush(true)` and same-handle byte-for-byte readback;
- refuses overwrite;
- rechecks exact HEAD and source identity after publication;
- treats PATH/source/namespace/host-Git cleanup failure as fatal before writer PASS output.

If bytes were already published and a later authority/cleanup check fails, the run remains failed and recovery must be explicit; published bytes are not silently promoted to admitted evidence.

## Native-pinned process evidence review

`scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1` remains subordinate for final admission. Under canonical admission, its Git resolution executes while the parent admission wrapper's host-Git/PATH authority remains live.

The reviewer exact-head verifies source authority, requires canonical exact-head evidence pathname, rejects reparse evidence, opens evidence while withholding write/delete sharing, requires native final-path equality, bounds evidence to 64 KiB strict UTF-8, validates exact schema/values/16-record order/timestamps, computes pinned evidence SHA-256 and re-verifies HEAD/source objects before a fixed small success summary.

## Canonical complete Windows admission

Final Windows-side admission must use:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\review-nxb-153-windows-admission-complete.ps1
```

Complete wrapper: `b2b5cdec1a24b92e34d2397c9567e2cc4c2e3a98`.

Mandatory order:

1. host-Git lifetime regression probe `5b12134f18cb6a71efde0d06b0622ec170269401`;
2. subordinate admission `6b0e4ddc47ad440ab113ff073d3ae5275a95b949`:
   1. tool-version output regression probe;
   2. process-lifecycle evidence review;
   3. schema-v2 / dual-platform closure review;
3. final complete-wrapper HEAD/object/source/namespace/PATH/host-Git cleanup;
4. complete PASS only after cleanup.

Subordinate output remains bounded and withheld through later authority gates.

## Failure behavior

Fatal conditions include source/object drift, host-Git/path authority failure, pre-Git ambient Git authority, PATH restoration failure, production constant drift, forbidden synchronous/unbounded source patterns, broker framing/UTF-8/timeout failure, stalled I/O that does not time out, nonzero exit not surfaced, descendant survival after recursive kill, unbounded/malformed probe JSON, existing exact-head evidence, evidence path redirection, schema/object/timestamp mismatch, phase authority drift and cleanup failure.

## What this does not prove

This process-lifecycle chain alone does not prove the initial host Git installation, full registry metadata semantics, real repository `git archive`/1 GiB boundary, real tar extraction, complete production broker boundary behavior, destination-broker native lifetime/share/watcher semantics, relocated Rust 1.97.1 DLL/sysroot behavior, full workspace/security gates, main schema-v2 publication/review or same-head Linux + Windows admission.

## Admission boundary

For the exact final NXB-153 head, supported Windows admission still requires canonical Windows preparation/full validation, create-only process-lifecycle evidence, complete Windows admission wrapper completion and full same-head platform evidence.

Linux H2 validation, object-anchored main evidence review and guarded dual-platform closure remain independently required.

Until all gates close:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 remains draft/not admitted and NXB-154 must not use NXB-153 as an admitted implementation base.
