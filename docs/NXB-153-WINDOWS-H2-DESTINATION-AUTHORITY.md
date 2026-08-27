# NXB-153 Windows H2 Destination Lifetime Authority

## Status

This document records the current **source-staged, not admitted** Windows H2 Rust-toolchain destination authority model.

It does not claim a supported Windows/NTFS/PowerShell runtime PASS. The exact final NXB-153 head still requires real Windows execution, adversarial mutation tests and same-head Linux + Windows evidence closure before any blocker or PR admission.

The purpose of this authority layer is precise: remove the gap in which a copied H2 Rust snapshot existed only by pathname after the copier had closed its creator handles but before the PowerShell validation layer had acquired its own file/directory/ACL authority.

## Threat boundary

The supported threat model includes a concurrent process running as the same ordinary Windows identity attempting to:

- replace a newly created snapshot child between copy and later validation;
- rename/delete a destination file or directory during handoff;
- modify a destination file during or after creator-handle transition;
- inject a transient file or directory after the initial copy and remove it before final tree verification;
- alter the source-tree DACL after the PowerShell deny rule is staged and use the resulting interval for transient namespace mutation;
- race the snapshot-root pathname while validation is preparing the copied Rust toolchain.

As elsewhere in NXB-153, this contract does not attempt to survive kernel compromise, a malicious administrator with privileges outside the ordinary validation identity, hostile filesystem drivers or simultaneous replacement of trusted operating-system primitives.

## Canonical implementation

Destination broker:

`scripts/nxb-153-windows-h2-destination-broker.py`

Current source-staged broker Git blob:

`c8520395f24d3fe3f29149b152892fac6cd7872c`

Policy:

`nxb-153-windows-h2-destination-authority-v1`

PowerShell lifetime/handoff wrapper:

`scripts/nxb-153-windows-immutable-source-h2-broker-entry.ps1`

Current source-staged wrapper Git blob:

`1afaeb0656201fae952a7d877cbc01d5ce7d1fee`

Windows bounded H2 outer entrypoint:

`scripts/nxb-153-windows-immutable-source-bounded-inner.ps1`

Current source-staged bounded entrypoint Git blob:

`6d103dd7711d52e679a675cac9cf2b9d4f52e5fe`

The outer entrypoint pins the scripts namespace and exact-Git-object verifies both the broker wrapper and broker implementation before use and again before success.

## Snapshot-root creation

The existing H2 inner source historically created the snapshot root with ordinary `New-Item` and the synchronous Python copy helper later filled it.

The broker-entry wrapper now intercepts only the exact H2 snapshot-root creation shape:

`.nxb-153-rust-h2-windows-<exact-head>-<pid>-<32-hex-guid>`

The path must be an immediate child of the canonical validation directory. The wrapper verifies the path is absent and deliberately defers filesystem creation.

Every unrelated `New-Item` call is delegated to module-qualified `Microsoft.PowerShell.Management\New-Item`; the nested immutable-source runtime-directory calls therefore retain their original behavior.

When the existing H2 top-level `Copy-Item` capture loop reaches its first source entry, the bounded outer entrypoint starts the destination broker. The broker, rather than PowerShell, claims the deferred snapshot root.

## Native relative creation

The broker opens the validation directory and creates the snapshot root and every descendant through native relative-handle authority.

Child directories and files are created with `NtCreateFile` relative to the already-open parent directory handle using create-new semantics. The broker rejects reparse-point results and retains the returned destination handle instead of closing it after pathname publication.

Directory handles are retained without delete sharing. File creator handles are created with read/write access but only `FILE_SHARE_READ`, withholding concurrent destination write/delete sharing while the file is populated.

The copy budget remains fail-closed at:

- 65,536 regular files;
- 65,536 directories including root;
- 512 MiB per regular file;
- 4 GiB total regular-file bytes.

Windows path components continue to use the conservative ASCII/case-insensitive/reserved-device-name model used by the existing H2 source authority.

## Creator-write to read-guard transition

After all source bytes are copied and flushed, the broker does **not** simply close the creator handles and return.

Before the first creator write handle is released, it opens a separate snapshot-root directory watcher and arms recursive `ReadDirectoryChangesW` notification for:

- file-name changes;
- directory-name changes;
- attribute changes;
- size changes;
- last-write changes.

Security-descriptor changes are deliberately excluded because the trusted H2 parent applies and later restores its own ACL during validation. The watcher is intended to detect source/object/namespace mutation, not reject the validation harness's expected ACL lifecycle.

Each destination writer is then transitioned to a read guard:

1. record the creator-held file identity;
2. close the creator write handle;
3. immediately reopen the pathname read-only while withholding delete sharing;
4. compare volume serial, file index, file size and last-write identity with the creator record;
5. fail if the recursive watcher reports any mutation during the transition.

The reopened guard permits ordinary reads and does not itself need to remain the sole write barrier because every mutation after the watcher is armed is a validation-fatal event.

This transition exists because Windows sharing modes cannot be strengthened or relaxed on one already-open handle. The recursive kernel watcher converts the unavoidable close/reopen transition into a fail-closed observed interval rather than an unobserved pathname interval.

## Broker lifetime

The broker is long-lived. It remains alive after the copy completes and continues holding:

- the validation-directory authority handle;
- every destination directory handle created from the point of creation;
- read guards for all copied destination files;
- the recursive snapshot-root change watcher.

A bounded stdin/stdout protocol exposes only `CHECK` and `STOP`. Commands are ASCII and bounded; responses are one bounded strict-UTF-8 JSON line. The PowerShell parent requires the exact policy name, exact snapshot root and bounded file/directory/byte summary.

An unexpected broker exit, protocol close, malformed response, mutation notification or watcher failure is fatal.

## Overlap with existing PowerShell authority

The broker-entry wrapper does not stop the broker immediately after the copied snapshot first verifies successfully.

The existing H2 inner continues and:

1. rejects reparse points;
2. verifies the copied tree identity;
3. enumerates every snapshot directory/file through the already bounded enumeration layer;
4. opens its native no-delete-share directory handles;
5. opens every file with read authority and write/delete sharing withheld;
6. stages the current-user write/create/delete deny ACL;
7. proves file/directory injection denial;
8. re-verifies the snapshot tree identity.

The first required `snapshotRoot\bin\rustc.exe` `Test-Path` occurs only after that PowerShell file/directory/ACL authority has been staged. At that point the broker-entry wrapper performs a `CHECK` and requires the broker to still report a clean snapshot, recording that creator authority and PowerShell authority overlapped successfully.

Crucially, the broker is **not stopped at this handoff**.

## Heavy-gate lifetime monitoring

The broker remains active across the complete relocated Rust heavy-gate lifetime.

This is stronger than stopping at the initial PowerShell handoff. The existing H2 ACL intentionally preserves the ability to restore permissions and therefore is not treated, by itself, as proof against a same-user actor that attempts to alter the DACL and then perform a transient file/DLL injection.

Because the recursive broker watcher remains armed, any ordinary file/directory name, size, last-write or attribute mutation during heavy gates becomes a final validation failure even if the actor restores the pathname/bytes before the normal post-gate deterministic tree check.

The existing PowerShell file/directory handles, ACL controls and post-gate deterministic identity checks remain defense-in-depth; none is removed by the broker layer.

## Cleanup boundary

The existing H2 parent restores its ACL backups and disposes its own snapshot file/directory handles during `finally`.

Only when the parent reaches the exact snapshot-root recursive `Remove-Item` does the broker-entry wrapper:

1. perform a final broker `CHECK` if the normal PowerShell handoff was established;
2. require a healthy result;
3. send `STOP`;
4. require a healthy `stopped` record and zero broker exit status;
5. release broker-held creator-derived guards/watcher;
6. delegate the original snapshot deletion to module-qualified `Remove-Item`.

If the nested H2 sequence fails before normal cleanup, the wrapper and bounded outer finally blocks still attempt controlled broker shutdown. Cleanup errors are aggregated and fail closed.

Therefore the broker lifetime covers destination creation, creator-handle transition, PowerShell authority acquisition, heavy Rust execution, post-gate verification, ACL restoration and the beginning of final snapshot cleanup.

## Broker primitive self-test

The broker has a Windows-only self-test that source-stages the expected native behavior:

- create a tiny source tree;
- broker-copy it into a fresh destination;
- verify trusted copied bytes;
- prove a retained destination guard denies file deletion;
- inject a new file into the snapshot tree;
- require the recursive watcher to observe that mutation;
- release all authority and allow temporary-root cleanup.

The bounded Windows H2 entrypoint executes this self-test before real broker use.

The current non-Windows development environment cannot execute the native self-test. The Python source has passed local compilation, but that is not a substitute for the required NTFS/Win32 behavior proof.

## PowerShell support boundary

The repository's documented Windows validation entrypoint uses `pwsh`. The current NXB-153 scripts already use modern `ProcessStartInfo.ArgumentList`; the broker transport follows that established PowerShell 7/.NET model rather than introducing a Windows PowerShell 5.1 compatibility promise.

The broker-entry `Test-Path` proxy uses the canonical `Microsoft.PowerShell.Commands.TestPathType` enum and delegates unrelated operations to module-qualified management cmdlets.

Real supported PowerShell execution remains mandatory because static source inspection cannot prove function-scope interception, native API marshalling, process-pipe behavior or NTFS sharing semantics.

## Remaining runtime acceptance

Destination lifetime authority is now **source-staged**, but #98 must remain open until the exact final head proves on supported Windows/NTFS at least:

- Python `ctypes` signatures and native `NtCreateFile` relative creation behavior;
- create-new collision rejection for root/children;
- reparse-point rejection;
- directory no-delete-share behavior;
- file creator-handle write/delete exclusion;
- writer-to-read-guard identity continuity;
- recursive `ReadDirectoryChangesW` mutation detection, including create/delete/rename/content mutation and transient restore attempts;
- watcher overflow/failure fail-closed behavior;
- cancellation and broker-process cleanup;
- PowerShell `New-Item`, `Test-Path`, `Remove-Item` interception/delegation semantics;
- successful overlap with existing H2 file/directory/ACL authority;
- ordinary relocated rustc/cargo/rustfmt/Clippy/DLL/sysroot loading while broker guards are held;
- no false mutation signal from normal H2 reads and expected ACL lifecycle;
- deliberate mutation during heavy gates causing final validation failure;
- final broker health/STOP before snapshot deletion;
- cleanup/recovery on failures at each handoff phase.

No Windows runtime PASS is claimed until those tests execute.

## Separate remaining availability work

This destination lifetime contract does not automatically close the separate direct process-capture review. Current Windows source still contains direct `.NET ReadToEndAsync()` capture paths for Git-archive stderr, tar-extraction stdout/stderr and the isolated registry verifier. Those paths remain availability-hardening/runtime-review work and must not be silently treated as solved by the destination broker.

## Admission boundary

The exact final NXB-153 head still requires real Rust 1.97.1 Linux and Windows validation, all #90-#98 acceptance conditions, create-only schema-v2 evidence, object-anchored semantic review and guarded same-head dual-platform closure.

PR #89 remains draft/not admitted. NXB-154 must not use the NXB-153 feature branch as an admitted implementation base until that closure completes.
