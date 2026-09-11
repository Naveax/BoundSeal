# NXB-153 Windows Entry Git-Output Authority

## Status

This document records the current **source-staged, not admitted** Windows Git-output, ambient Git-environment and host-Git lifetime contract for NXB-153.

No supported Windows/NTFS/PowerShell runtime PASS is claimed by source staging.

## Canonical Windows entry authority

The three canonical Windows entry surfaces are byte-identical:

- `scripts/prepare-and-validate-nxb-153-windows.ps1`;
- `scripts/validate-nxb-153-windows.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`.

Current shared exact Git blob:

`9f1852241f62d6a1357688713dd32595464682b6`

This supersedes prior current-entry blobs including `18d638dde788abe363322685b04b4a04e87f6394`, `3267f592f074d12326bd518f8b74555f033beba5` and `ab8383d4281ebc147dfe8305a926dd862699cef4`.

The initially resolved installed Git application remains a **supported-host trust boundary**. Current hardening binds the lifetime of that selected host tool rather than claiming an independent cryptographic identity for the Git installation.

The shared wrapper now:

- rejects every ambient environment variable whose name begins with `GIT_`, case-insensitively, before the first exact-head Git operation;
- resolves the host Git application before proxy installation;
- requires the selected Git executable to be a regular non-reparse file;
- opens it read-only with write/delete sharing withheld;
- requires the actual Git file handle final path to equal the canonical expected executable path;
- native-pins the Git executable's immediate directory with delete sharing withheld and final-path equality;
- temporarily prepends the pinned Git directory to PATH;
- requires nested `Get-Command git -CommandType Application` resolution to return the same pinned executable;
- native-pins repository root and canonical `scripts` with delete sharing withheld and final-path equality;
- opens the selected preserved inner implementation read-only with write/delete sharing withheld and requires its actual opened handle final path to equal the expected canonical path;
- exact-head verifies the pinned inner implementation;
- installs the bounded global Git proxy, delegates, and re-verifies HEAD plus pinned inner Git object;
- restores the prior global Git function and PATH and releases all namespace/source/host-Git handles before successful completion;
- treats cleanup/restoration failure as fatal before PASS.

Nested canonical entrypoints therefore resolve the same PATH-pinned host Git while preserving/restoring the outer bounded-proxy authority chain.

## Pre-Git ambient authority boundary

Pinning the correct `git.exe` does not by itself prove which repository, object database or Git configuration that executable will consume. Git honors environment authority including `GIT_DIR`, `GIT_WORK_TREE`, `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_CONFIG_*`, `GIT_EXEC_PATH` and related `GIT_*` controls.

A guard that runs only after `rev-parse HEAD` is therefore too late. The selected Git executable could already have resolved a different repository/object/config authority.

Current source-staged Windows surfaces reject the complete `GIT_*` name family, case-insensitively, before their first exact-head Git operation:

- the three byte-identical canonical outer entrypoints, shared blob `9f1852241f62d6a1357688713dd32595464682b6`;
- `scripts/nxb-153-windows-immutable-source.ps1` -> `58cfcfa709404f7dae467a4591af755bad52209c`;
- `scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1` -> `1ebca56bc704dcacb4864ace03ba16640b4b1e0d`;
- `scripts/review-nxb-153-windows-admission.ps1` -> `6b0e4ddc47ad440ab113ff073d3ae5275a95b949`;
- `scripts/review-nxb-153-windows-admission-complete.ps1` -> `b2b5cdec1a24b92e34d2397c9567e2cc4c2e3a98`;
- `scripts/nxb-153-windows-host-git-lifetime-probe.ps1` -> `5b12134f18cb6a71efde0d06b0622ec170269401`.

Only variable names are reported on rejection. Values are never emitted, avoiding accidental disclosure of credentials or other process secrets carried in Git-related environment variables.

The shared cross-platform environment helper independently rejects the same `GIT_*` family later in the validation lifecycle. The early PowerShell guards exist because a post-Git Python audit cannot retroactively make an earlier Git lookup trustworthy.

## Bounded entry Git process contract

For Git invocations passing through the canonical outer wrapper:

- maximum stdout bytes: **64 MiB**;
- maximum decoded stdout records: **4,096**;
- strict UTF-8 decoding;
- inherited stderr;
- per-read inactivity timeout: **300,000 ms / 5 minutes**;
- post-stdout exit timeout: **30,000 ms / 30 seconds**;
- byte/record/timeout failure attempts recursive process termination and fails closed;
- child exit status is propagated to `$LASTEXITCODE`.

The small raw control-plane calls used before proxy installation and after delegation remain separately bounded to **4 KiB raw stdout / 30 s read inactivity / 30 s post-output exit / strict UTF-8 / <=256-character semantic value**.

The wrapper self-test retains normal Git-version delegation plus deliberate one-record and four-byte rejection checks.

## H2 Git-output layer

Current Windows H2 outer string/Git-output authority wrapper:

`scripts/nxb-153-windows-immutable-source.ps1` -> `58cfcfa709404f7dae467a4591af755bad52209c`

It now independently rejects ambient `GIT_*` before resolving the exact-head Git-output inner object. This makes direct `-SelfTest` invocation fail closed rather than depending on an earlier canonical outer process to have sanitized Git repository/object/config authority.

The nested Git-output inner remains:

`scripts/nxb-153-windows-immutable-source-git-output-inner.ps1` -> `c92a612c2e7921191beb64d1c60a0798fe3fb7ae`

The H2 layer retains the **64 MiB / 4,096-record**, **5-minute read-inactivity**, **30-second post-stdout exit** authority. The nested inner resolves the real Git application while the canonical PATH binding is active; the H2 outer now also enforces its own pre-Git ambient-authority boundary before that delegation.

## Direct-child pipe / exit authority

Current direct-child source blobs remain:

- `scripts/nxb-153-windows-dependency-source.ps1` -> `76734e3f5ab9adbf2c9e509ff4be08427da57aa3`;
- `scripts/nxb-153-windows-immutable-source-inner.ps1` -> `664930b3b62f54b57345ff387fabce7a8171f45f`.

Registry verifier uses bounded async stdin and bounded post-input exit. Git archive uses bounded async stdout under the existing **1 GiB** archive ceiling. Tar extraction uses bounded async stdin. Production child I/O inactivity remains **300,000 ms** and post-I/O exit **30,000 ms**, with recursive termination attempt plus bounded reap on failure/timeout.

## Canonical process-evidence and admission host Git lifetime

Current authority blobs are:

- process-evidence writer `1ebca56bc704dcacb4864ace03ba16640b4b1e0d`;
- subordinate three-phase admission `6b0e4ddc47ad440ab113ff073d3ae5275a95b949`;
- host-Git lifetime probe `5b12134f18cb6a71efde0d06b0622ec170269401`;
- complete canonical admission `b2b5cdec1a24b92e34d2397c9567e2cc4c2e3a98`.

These surfaces reject ambient `GIT_*` before exact-head Git lookup. The process-evidence and admission layers then select the supported-host Git application, pin its file and parent-directory lifetime, prepend the pinned directory to PATH for nested Git resolution, retain that authority through their complete operation and fail closed if PATH restoration or Git-handle cleanup fails.

Direct standalone probes/reviewers remain diagnostic when invoked outside the complete canonical admission chain unless their caller is explicitly part of that chain.

## Runtime proof still required

Real exact-head Windows execution must still demonstrate at least:

- representative `GIT_DIR`, `GIT_WORK_TREE`, `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES` and `GIT_CONFIG_*` injection is rejected before the first exact-head Git operation on every canonical Windows authority surface above, including direct H2 outer `-SelfTest` entry;
- clean environments still resolve the intended exact HEAD and object database after the pre-Git gate;
- host Git executable/directory cannot be replaced or renamed while pinned;
- deliberate alternate PATH/Git injection does not change nested Git resolution;
- original PATH is restored on success and failure;
- repository root, `scripts`, preserved-inner and admission authority handle final-path rejection under deliberate pathname/reparse/namespace substitution;
- outer global Git proxy installation/restoration across prepare -> validate nesting;
- local H2 proxy shadowing/cleanup;
- 64 MiB and 4,096-record fail-closed behavior;
- read-inactivity and post-stdout exit timeouts;
- inherited stderr and `$LASTEXITCODE` behavior;
- recursive child termination;
- registry-verifier, Git-archive and tar real stalled-I/O/nonzero/cleanup behavior;
- process-evidence and admission lifetime behavior under the same exact final head.

## Admission boundary

Current schema-v2 evidence intentionally remains:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 remains draft/not admitted. Issues #90-#98 remain open until the exact final head completes real supported Linux + Windows execution, schema-v2 evidence review and guarded dual-platform closure. NXB-154 must not use NXB-153 as an admitted implementation base before that closure.
