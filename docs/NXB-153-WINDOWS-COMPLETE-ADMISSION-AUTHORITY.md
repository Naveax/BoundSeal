# NXB-153 Windows Complete Admission Authority

## Status

This document defines the current **source-staged, not admitted** complete Windows admission entry for NXB-153.

It supersedes older NXB-153 statements that call `scripts/review-nxb-153-windows-admission.ps1` the complete canonical Windows admission entrypoint. That script remains mandatory, but is the subordinate three-phase admission chain beneath the complete wrapper defined here.

No supported Windows/NTFS/PowerShell runtime PASS is claimed by this source staging.

## Complete canonical entrypoint

The complete Windows admission command is:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\review-nxb-153-windows-admission-complete.ps1
```

Current exact source authority:

- `scripts/review-nxb-153-windows-admission-complete.ps1` -> `b2b5cdec1a24b92e34d2397c9567e2cc4c2e3a98`;
- `scripts/nxb-153-windows-host-git-lifetime-probe.ps1` -> `5b12134f18cb6a71efde0d06b0622ec170269401`;
- subordinate `scripts/review-nxb-153-windows-admission.ps1` -> `6b0e4ddc47ad440ab113ff073d3ae5275a95b949`;
- shared canonical outer entry -> `9f1852241f62d6a1357688713dd32595464682b6`;
- H2 outer/direct `-SelfTest` authority -> `58cfcfa709404f7dae467a4591af755bad52209c`;
- process-evidence writer -> `1ebca56bc704dcacb4864ace03ba16640b4b1e0d`.

## Pre-Git ambient authority

Pinning the selected `git.exe` is not sufficient if Git inherits repository/object/config authority from the process environment. Canonical Windows authority surfaces therefore reject every environment-variable name beginning with `GIT_`, case-insensitively, **before their first exact-head Git operation**.

This applies to the complete wrapper, subordinate admission, host-Git lifetime probe, process-evidence writer, three shared outer entrypoints and H2 outer/direct `-SelfTest` authority. Only variable names may be reported; values are never emitted.

The shared cross-platform environment helper later repeats the complete `GIT_*` rejection. The early PowerShell boundary exists because a post-Git audit cannot retroactively make an earlier `rev-parse`, object lookup or working-tree hash trustworthy.

## Complete wrapper authority

Before any subordinate runtime phase, the complete wrapper:

- requires supported Windows and PowerShell Core;
- rejects ambient `GIT_*` before exact-head Git authority is consulted;
- resolves the installed Git application as a supported-host trust boundary;
- opens that selected Git executable read-only with write/delete sharing withheld;
- requires native handle final-path equality for the Git executable;
- native-pins the Git executable directory with delete sharing withheld and final-path equality;
- prepends the pinned Git directory to `PATH` and requires nested `Get-Command git -CommandType Application` resolution to return the same executable;
- resolves exact Git `HEAD` through the bounded 4 KiB / 30 s / 30 s strict-UTF-8 Git control plane;
- native-pins repository root and canonical `scripts` namespace with delete sharing withheld and final-path equality;
- exact-head opens and pins itself, the host-Git lifetime probe and subordinate admission wrapper with write/delete sharing withheld and native final-path equality.

Those authorities remain live through both subordinate phases and all final HEAD/object checks.

## Mandatory ordering

The complete wrapper requires:

1. exact-head Windows host-Git lifetime regression probe;
2. subordinate `review-nxb-153-windows-admission.ps1` chain:
   1. tool-version fixed-output regression probe;
   2. process-lifecycle evidence review;
   3. Windows schema-v2 / dual-platform closure review;
3. final complete-wrapper exact-head/source authority checks;
4. source, namespace, PATH and host-Git cleanup;
5. only then complete canonical PASS output.

Direct invocation of the subordinate admission script remains useful diagnostically but is not sufficient for complete NXB-153 Windows admission.

## Host-Git lifetime regression probe

The mandatory probe exact-head binds itself and the subordinate admission source, extracts the production pathname/host-tool pinning functions and tests them only against private temporary fixtures. It does **not** rename, replace, modify or delete the user's installed Git.

The dynamic suite requires temporary host-tool baseline writability, final-path identity, write/delete/file-rename/parent-directory-rename denial while pinned, hostile-PATH control before canonical rebinding, pinned-Git resolution after rebinding, byte-exact PATH restoration on success and deliberate failure, restored rename ability after cleanup, and unchanged exact HEAD/source object authority through the probe.

The probe itself now rejects ambient `GIT_*` before its first exact-head Git operation. Its temporary cleanup remains fail-closed and probe PASS is withheld until cleanup succeeds.

## H2 direct authority

`scripts/nxb-153-windows-immutable-source.ps1` -> `58cfcfa709404f7dae467a4591af755bad52209c`

The H2 outer can be invoked through its own `-SelfTest` surface. It therefore independently rejects ambient `GIT_*` before resolving the exact-head H2 Git-output inner rather than assuming a previous outer process sanitized Git authority.

This direct H2 entry remains source-staged; real supported-Windows execution is still required.

## Output withholding

The complete wrapper buffers each subordinate phase independently with:

- maximum **65,536 UTF-8 bytes**;
- maximum **4,096 records**.

Host-Git probe output is not printed before subordinate admission succeeds. Subordinate admission output is not printed before final complete-wrapper authority checks, PATH restoration and all handle cleanup succeed. An early subordinate PASS therefore cannot leak as a complete-admission PASS if a later gate fails.

## Supported-host trust boundary

This hardening does not claim independent cryptographic identity for the installed Git application. The initially selected Git executable remains part of the supported-host trust boundary.

The source-staged contract proves a narrower intended property: once host Git is selected for a complete admission run, Windows file/directory sharing, final-path checks, PATH binding and fail-closed cleanup must prevent that selected executable authority from being silently displaced during the run.

## Remaining runtime proof

Source staging is not runtime admission. Exact-final-head supported Windows execution must still prove:

- representative `GIT_DIR`, `GIT_WORK_TREE`, `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES` and `GIT_CONFIG_*` injection is rejected before the first Git operation on complete/subordinate/process/outer/H2 authority surfaces;
- clean execution still resolves the intended exact HEAD/object database;
- complete wrapper executes successfully;
- host-Git file write/delete/rename and parent-directory rename denial while pinned;
- hostile PATH displacement before rebinding and pinned-Git resolution after rebinding;
- PATH restoration on success and deliberate failure;
- handle cleanup restoring rename ability;
- deliberate late failure after host-Git probe does not print an early complete PASS;
- deliberate late failure after subordinate admission does not print buffered PASS as complete admission;
- bounded subordinate-output rejection;
- existing canonical entry/H2 Git proxy, direct-child, broker, destination, tool-version, Rust 1.97.1 and schema-v2 gates.

Linux exact-head H2 validation and guarded same-head Linux + Windows closure remain independently mandatory.

## Admission boundary

Current schema-v2 evidence remains intentionally:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 remains draft/not admitted. Issues #90-#98 remain open. NXB-154 must not use NXB-153 as an admitted implementation base until the complete wrapper and every required same-head Linux + Windows gate pass on the exact final head.
