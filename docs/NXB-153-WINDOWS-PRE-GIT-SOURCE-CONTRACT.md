# NXB-153 Windows Pre-Git Source Contract

## Status

This document records the **source-staged, not admitted** regression contract that keeps the NXB-153 canonical Windows authority surfaces from consuming ambient Git repository/object/config authority before their first host-Git resolution.

It does not claim supported Windows/NTFS/PowerShell runtime PASS. Exact-final-head Linux + Windows execution, schema-v2 evidence and guarded closure remain mandatory.

## Regression test authority

Canonical cross-platform source regression test:

`crates/nxb-core/tests/windows_pre_git_authority_source_contract.rs`

Exact Git blob at introduction:

`5fb3eddc5cca5f61990541d038497ffab9f1e3c7`

Introduced by commit:

`6ce21027b44769968543b4ac9323db858f77a444`

The test is intentionally implemented with Rust `std` only and does not invoke PowerShell. It is therefore eligible to execute as part of normal Rust test gates on both Linux and Windows hosts while inspecting the committed PowerShell source tree.

## Canonical surfaces covered

The source-order contract covers:

- `scripts/prepare-and-validate-nxb-153-windows.ps1`;
- `scripts/validate-nxb-153-windows.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`;
- `scripts/nxb-153-windows-immutable-source.ps1`;
- `scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1`;
- `scripts/review-nxb-153-windows-admission.ps1`;
- `scripts/review-nxb-153-windows-admission-complete.ps1`;
- `scripts/nxb-153-windows-host-git-lifetime-probe.ps1`.

Direct diagnostic child probes remain parent-bounded and are not promoted to standalone admission authority by this test.

## Required pre-Git guard shape

For every covered canonical surface, the regression test requires one occurrence of each source marker that establishes the current fail-closed ambient Git authority gate:

- creation of `$ambientGitAuthority` as a `List[string]`;
- enumeration of `[Environment]::GetEnvironmentVariables().Keys`;
- case-insensitive `StartsWith('GIT_', ...)` matching;
- collection of matching variable names;
- failure when the collected set is non-empty;
- deterministic case-normalized ordering of reported names;
- the fixed failure text stating that ambient Git authority is not admitted before exact-head resolution.

Only variable names are part of the rejection path. Values remain excluded from source-staged diagnostics to avoid leaking Git-related credentials or other process secrets.

## Source ordering invariant

Presence alone is insufficient. A guard restored below the first Git lookup would be security theater with nicer indentation.

The regression test therefore requires every guard marker to occur before the surface's canonical host-Git resolution statement.

Current host-Git resolution anchors are:

- shared outer entries and H2 outer: `$gitCommand = Get-Command git -CommandType Application -ErrorAction Stop`;
- process-evidence writer, subordinate admission, complete admission and host-Git lifetime probe: `$git = Get-Command git -CommandType Application -ErrorAction Stop`.

If a guard marker disappears, is duplicated ambiguously, or moves after that host-Git resolution anchor, the Rust integration test fails closed.

## Shared outer byte-identity invariant

The same test also requires the three canonical outer Windows entrypoints to remain byte-identical:

- `prepare-and-validate-nxb-153-windows.ps1`;
- `validate-nxb-153-windows.ps1`;
- `review-nxb-153-evidence-windows.ps1`.

Current shared blob remains:

`9f1852241f62d6a1357688713dd32595464682b6`

This prevents one canonical entry from silently drifting to a weaker pre-Git contract while documentation still describes the wrappers as one shared authority surface.

## Current source authority

At introduction of this regression gate, the covered Windows authority blobs are:

- shared canonical outer entry `9f1852241f62d6a1357688713dd32595464682b6`;
- H2 outer/direct `-SelfTest` `58cfcfa709404f7dae467a4591af755bad52209c`;
- process-evidence writer `1ebca56bc704dcacb4864ace03ba16640b4b1e0d`;
- subordinate admission `6b0e4ddc47ad440ab113ff073d3ae5275a95b949`;
- host-Git lifetime probe `5b12134f18cb6a71efde0d06b0622ec170269401`;
- complete admission `b2b5cdec1a24b92e34d2397c9567e2cc4c2e3a98`.

The test binds the required source structure rather than hardcoding those blob IDs, so legitimate future hardening can change a covered script object without forcing the test to accept stale object identifiers. Exact-head validation and evidence layers remain responsible for binding the actual final objects.

## Admission integration

The regression test is a normal `nxb-core` integration test. Consequently, any final validation path that executes the complete `nxb-core`/workspace Rust test suite also exercises this source-order contract.

This adds a platform-independent regression signal, but it does not replace the supported-Windows adversarial runtime controls. Final Windows proof still has to demonstrate representative `GIT_DIR`, `GIT_WORK_TREE`, `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES` and `GIT_CONFIG_*` injection rejection before initial Git authority on the real PowerShell surfaces.

## Remaining runtime proof

Exact-final-head admission still requires at least:

- execution of this Rust integration test under the pinned Rust 1.97.1 validation gates;
- supported Windows execution of representative pre-Git `GIT_*` injection controls on every canonical authority surface;
- clean-environment resolution of the intended Git repository/object database;
- host-Git file/directory lifetime and PATH rebinding proof;
- repo/scripts/source pathname, reparse and namespace substitution rejection;
- process-evidence create-only publication/review and late-failure output withholding;
- Windows H2, broker, fixed-output and recursive-cleanup runtime behavior;
- create-only schema-v2 platform evidence and guarded same-head Linux + Windows closure.

Current evidence intentionally remains:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 and issues #90-#98 remain open/not admitted. NXB-154 must not use NXB-153 as an admitted implementation base until complete same-head closure succeeds.
