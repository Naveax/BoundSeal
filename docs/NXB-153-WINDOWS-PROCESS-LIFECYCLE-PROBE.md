# NXB-153 Windows Process Lifecycle Probe

## Status

This document records a **source-staged, not admitted** Windows runtime primitive for NXB-153.

The probe does not replace the canonical Windows validator, H2 destination-broker tests, schema-v2 evidence production or guarded Linux + Windows closure. Its purpose is narrower: prove that the exact-head direct-child hardening is still present in source and that the supported Windows PowerShell/.NET host actually honors the async pipe, timed-exit and recursive process-tree termination primitives on which that hardening depends.

Policy:

`nxb-153-windows-process-lifecycle-probe-v1`

Canonical probe:

`scripts/nxb-153-windows-process-lifecycle-probe.ps1`

## Production source contract checked by the probe

Before starting any adversarial child, the probe resolves exact Git HEAD and requires the working-tree bytes of all inspected files to hash to their exact-head Git objects.

It then parses the production PowerShell sources with the PowerShell AST and requires the current direct-child implementations to retain the reviewed contract:

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

Both production sources must retain:

- child I/O inactivity timeout: **300,000 ms / 5 minutes**;
- post-I/O exit timeout: **30,000 ms / 30 seconds**.

The immutable source must additionally retain the exact-head Git archive ceiling of **1 GiB**.

A reintroduced direct `ReadToEndAsync()` retention path fails the probe before dynamic execution.

## Dynamic Windows primitives

The probe creates only a private temporary helper script and temporary PID record outside the repository. It launches the currently executing PowerShell Core binary with `UseShellExecute = false` and deliberately exercises the same .NET process primitives used by the production source.

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
10. direct timed `WaitForExit(...)` behavior against a sleeping child;
11. recursive `Process.Kill(true)` behavior against a child that has spawned a live descendant.

The stall helpers sleep for 30 seconds. A correct probe does not wait for those sleeps to finish; the parent must fail/kill/reap inside the probe timeout envelope.

## Canonical supported-Windows invocation

Run from an exact clean NXB-153 checkout using PowerShell Core:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\nxb-153-windows-process-lifecycle-probe.ps1 `
  -ProbeIoTimeoutMilliseconds 1000 `
  -ProbeExitTimeoutMilliseconds 1500 `
  -Json
```

The explicit 1,000 ms I/O and 1,500 ms exit values are **probe-only** deadlines. They deliberately do not alter the production 300,000 ms / 30,000 ms authority. They are long enough to avoid making admission depend on ordinary PowerShell child startup jitter while remaining short enough to detect a broken timeout path quickly.

A successful JSON record has:

- `schema_version = 1`;
- `policy = nxb-153-windows-process-lifecycle-probe-v1`;
- `milestone = NXB-153`;
- `platform = windows`;
- exact `head_sha`;
- exact Git object IDs for the dependency and immutable-source implementations inspected;
- production and probe timeout values;
- PowerShell version;
- the completed test-name list;
- `status = passed`.

## Failure behavior

Any of the following is fatal:

- inspected source bytes do not match exact-head Git authority;
- production timeout constants drift;
- the 1 GiB archive ceiling drifts;
- a required async/timed/recursive-kill source pattern disappears;
- a forbidden synchronous/unbounded source pattern reappears;
- PowerShell AST parsing fails;
- a stalled input/output operation does not time out;
- a sleeping child does not trigger timed exit failure;
- a nonzero child exit is not surfaced;
- `Kill(true)` does not remove the spawned descendant tree;
- a probe child cannot be reaped within the bounded cleanup envelope.

The probe removes its temporary directory in `finally`. Cleanup failure from the production validation chain remains a separate full-validator concern.

## What this does not prove

A PASS from this probe is supporting platform evidence only. It does **not** prove:

- the real registry helper's full metadata-validation behavior;
- real `git archive` behavior against the exact repository or the actual 1 GiB rejection boundary;
- real tar extraction into the immutable source snapshot;
- inherited stdout/stderr compatibility across every production child;
- canonical entry/H2 Git proxy nesting/restoration;
- H2 destination-broker native handle/share/watcher semantics;
- relocated Rust 1.97.1 DLL/sysroot behavior;
- mutation/injection/lock-contention behavior;
- full workspace/security gates;
- schema-v2 evidence publication or semantic review;
- same-head Linux + Windows admission.

Those remain mandatory through the canonical validation/evidence path.

## Admission boundary

For the exact final NXB-153 head, supported Windows admission now requires both:

1. this process-lifecycle probe to PASS on the supported PowerShell Core/.NET host; and
2. the canonical full Windows NXB-153 validation/evidence chain to PASS on the **same exact Git head**.

Linux H2 validation, object-anchored evidence review and guarded dual-platform closure remain independently required.

Until all of those gates close, schema-v2 evidence remains:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 remains draft/not admitted and NXB-154 must not use NXB-153 as an admitted implementation base.