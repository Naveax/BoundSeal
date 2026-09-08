# NXB-153 Windows Complete Admission Authority

## Status

This document defines the current **source-staged, not admitted** complete Windows admission entry for NXB-153.

It supersedes older NXB-153 statements that call `scripts/review-nxb-153-windows-admission.ps1` the complete canonical Windows admission entrypoint. That script remains mandatory, but is now the subordinate three-phase admission chain beneath the complete wrapper defined here.

No supported Windows/NTFS/PowerShell runtime PASS is claimed by this source staging.

## Complete canonical entrypoint

The complete Windows admission command is:

```powershell
pwsh -NoLogo -NoProfile -File .\scripts\review-nxb-153-windows-admission-complete.ps1
```

Exact source blobs at introduction:

- `scripts/review-nxb-153-windows-admission-complete.ps1` -> `8b6665e3f44a9722c7c02aa6bc71f8f6ff26bb2e`;
- `scripts/nxb-153-windows-host-git-lifetime-probe.ps1` -> `95e51a33cb50e7aab549f3d50629c9863c6ec7da`;
- subordinate `scripts/review-nxb-153-windows-admission.ps1` -> `aa90917a629d57fa9319ead2ffe9d9e0b77f4a35`.

## Complete wrapper authority

Before any subordinate runtime phase, the complete wrapper:

- requires supported Windows and PowerShell Core;
- resolves the installed Git application as a supported-host trust boundary;
- opens that selected Git executable read-only with write/delete sharing withheld;
- requires native handle final-path equality for the Git executable;
- native-pins the Git executable directory with delete sharing withheld and final-path equality;
- prepends the pinned Git directory to `PATH` and requires nested `Get-Command git -CommandType Application` resolution to return the same executable;
- resolves exact Git `HEAD` through the bounded 4 KiB / 30 s / 30 s strict-UTF-8 Git control plane;
- native-pins repository root and canonical `scripts` namespace with delete sharing withheld and final-path equality;
- exact-head opens and pins itself, the host-Git lifetime probe and the subordinate admission wrapper with write/delete sharing withheld and native final-path equality.

Those authorities remain live through both subordinate phases and all final HEAD/object checks.

## Mandatory ordering

The complete wrapper requires the following order:

1. exact-head Windows host-Git lifetime regression probe;
2. subordinate `review-nxb-153-windows-admission.ps1` chain, which itself requires:
   1. tool-version fixed-output regression probe;
   2. process-lifecycle evidence review;
   3. Windows schema-v2 / dual-platform closure review;
3. final complete-wrapper exact-head/source authority checks;
4. source, namespace, PATH and host-Git cleanup;
5. only then complete canonical PASS output.

Direct invocation of the subordinate admission script is useful for its narrower three-phase diagnostics, but is no longer sufficient for complete NXB-153 Windows admission.

## Host-Git lifetime regression probe

The host-Git lifetime probe exact-head binds itself and the subordinate admission source. It AST-extracts the production:

- `ConvertFrom-NxbFinalPath`;
- `Open-NxbPinnedDirectory`;
- `Open-NxbPinnedHostTool`.

Dynamic tests run only in a private temporary directory. The probe copies the current PowerShell executable to temporary trusted and hostile `git.exe` fixtures. It does **not** rename, replace, modify or delete the user's installed Git.

The dynamic suite requires:

- the temporary host-tool copy is writable before pinning;
- production host-tool pinning returns the expected native final path;
- write access is rejected while the host-tool file is pinned;
- deletion is rejected while pinned;
- file rename is rejected while pinned;
- parent-directory rename is rejected while the directory handle withholds delete sharing;
- a hostile PATH candidate controls resolution before canonical rebinding;
- prepending the pinned trusted directory makes nested `Get-Command git -CommandType Application` resolve the pinned executable;
- PATH restores byte-for-byte after the successful rebinding primitive;
- PATH restores byte-for-byte after a deliberate failure primitive;
- after file/directory handle cleanup, file rename succeeds again;
- after cleanup, parent-directory rename succeeds again;
- exact Git HEAD, subordinate admission object and probe object remain unchanged through the probe.

Probe temporary-fixture cleanup is fail-closed. A primary test failure plus cleanup failure is reported as a combined failure. Probe PASS is withheld until temporary cleanup succeeds.

## Output withholding

The complete wrapper buffers each subordinate phase independently with:

- maximum **65,536 UTF-8 bytes**;
- maximum **4,096 records**.

Host-Git probe output is not printed before the subordinate admission succeeds. The subordinate admission output is not printed before final complete-wrapper authority checks, PATH restoration and all handle cleanup succeed.

Therefore an early subordinate PASS cannot leak as a complete-admission PASS if any later gate fails.

## Supported-host trust boundary

This hardening does not claim an independent cryptographic identity for the installed Git application. The initially selected Git executable is still part of the supported-host trust boundary.

The new contract proves a narrower property at runtime: once that host Git has been selected for a complete admission run, the Windows file/directory sharing model and canonical PATH binding must prevent the selected executable authority from being replaced, renamed or silently displaced during the run.

## Remaining runtime proof

Source staging is not runtime admission. Exact-final-head supported Windows execution must still prove:

- the complete wrapper itself executes successfully;
- host-Git file write/delete/rename denial while pinned;
- host-Git parent-directory rename denial while pinned;
- hostile PATH displacement before rebinding and pinned-Git resolution after rebinding;
- PATH restoration on success and deliberate failure;
- handle cleanup restoring rename ability;
- deliberate late failure after the host-Git probe does not print an early complete PASS;
- deliberate late failure after the subordinate admission does not print its buffered PASS as complete admission;
- bounded subordinate-output rejection;
- existing canonical entry/H2 Git proxy, direct-child, broker, destination, tool-version, Rust 1.97.1 and schema-v2 gates.

Linux exact-head H2 validation and guarded same-head Linux + Windows closure remain independently mandatory.

## Admission boundary

Current schema-v2 evidence remains intentionally:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 remains draft/not admitted. Issues #90-#98 remain open. NXB-154 must not use NXB-153 as an admitted implementation base until the complete wrapper and every required same-head Linux + Windows gate pass on the exact final head.
