# NXB-153 Windows H2 Destination Lifetime Authority

## Status

This document records the current **source-staged, not admitted** Windows H2 Rust-toolchain destination authority model.

It does not claim a supported Windows/NTFS/PowerShell runtime PASS. The exact final NXB-153 head still requires real Windows execution, adversarial mutation tests and same-head Linux + Windows evidence closure before any blocker or PR admission.

The purpose of this authority layer is precise: remove the gap in which a copied H2 Rust snapshot existed only by pathname after the copier had closed its creator handles but before the PowerShell validation layer had acquired its own file/directory/ACL authority, without misclassifying NTFS creator-handle close-time metadata settlement as hostile mutation.

## Threat boundary

The supported threat model includes a concurrent process running as the same ordinary Windows identity attempting to:

- replace a newly created snapshot child between copy and later validation;
- rename/delete a destination file or directory during handoff;
- modify a destination file during or after creator-handle transition;
- inject a transient file or directory after the initial copy and remove it before final tree verification;
- alter the source-tree DACL after the PowerShell deny rule is staged and use the resulting interval for transient namespace mutation;
- race the snapshot-root pathname while validation is preparing the copied Rust toolchain;
- force the broker-control transport to retain an oversized or unterminated response before the parent can apply its protocol limit.

As elsewhere in NXB-153, this contract does not attempt to survive kernel compromise, a malicious administrator with privileges outside the ordinary validation identity, hostile filesystem drivers or simultaneous replacement of trusted operating-system primitives.

## Canonical implementation

Destination broker launcher:

`scripts/nxb-153-windows-h2-destination-broker.py`

Current source-staged launcher Git blob:

`d0b6c7c1076c47f01aeba8961c4832866537ff80`

Immutable broker core:

`scripts/nxb-153-windows-h2-destination-broker-core.py`

Pinned core Git blob:

`2cd3f9bd6ee36892a0adeb9cb40d940c8e3a73f6`

The launcher reads the core bytes before import, computes the exact Git blob object identity (`blob <length>\0<bytes>`) and requires the SHA-1 above before executing the core. The run-29 settlement patch is therefore a small source-visible layer over the exact run-28 broker implementation rather than an unreviewed wholesale broker rewrite.

Policy:

`nxb-153-windows-h2-destination-authority-v1`

PowerShell lifetime/handoff wrapper:

`scripts/nxb-153-windows-immutable-source-h2-broker-entry.ps1`

Windows bounded H2 outer entrypoint:

`scripts/nxb-153-windows-immutable-source-bounded-inner.ps1`

The outer entrypoint pins the scripts namespace and exact-Git-object verifies the broker wrapper before use and again before success. The broker launcher independently pins the exact core Git object before import.

## Snapshot-root creation

The broker-entry wrapper intercepts only the exact H2 snapshot-root creation shape:

`.nxb-153-rust-h2-windows-<exact-head>-<pid>-<32-hex-guid>`

The path must be an immediate child of the canonical validation directory. The wrapper verifies the path is absent and deliberately defers filesystem creation.

Every unrelated `New-Item` call is delegated to module-qualified `Microsoft.PowerShell.Management\New-Item`; nested immutable-source runtime-directory calls therefore retain their original behavior.

When the existing H2 top-level `Copy-Item` capture loop reaches its first source entry, the bounded outer entrypoint starts the destination broker. The broker, rather than PowerShell, claims the deferred snapshot root.

## Native relative creation

The broker opens the validation directory and creates the snapshot root and every descendant through native relative-handle authority.

Child directories and files are created with `NtCreateFile` relative to the already-open parent directory handle using create-new semantics. The broker rejects reparse-point results and retains the returned destination handle instead of closing it after pathname publication.

Directory handles are retained without delete sharing. File creator handles are created with read/write access but only `FILE_SHARE_READ`, withholding concurrent destination write/delete sharing while each file is populated. Creator file handles call `SetFileTime` with the preserve/suppress sentinel before they escape `create_relative`, preventing ordinary creator-close access/write-time finalization from becoming an avoidable full-watch false positive.

The copy path computes the expected SHA-256 while streaming each bounded source file into its retained destination writer and flushes the destination before the file enters transition authority.

The copy budget remains fail-closed at:

- 65,536 regular files;
- 65,536 directories including root;
- 512 MiB per regular file;
- 4 GiB total regular-file bytes.

Windows path components continue to use the conservative ASCII/case-insensitive/reserved-device-name model used by the existing H2 source authority.

## Settled writer-to-read-guard transition

Windows sharing modes cannot be strengthened or relaxed on one already-open file handle. A writer therefore must close before a final read-only guard that withholds write/delete sharing can open. NTFS may settle size/last-write metadata around creator-handle close, so arming the full size/last-write watcher before that close can report the broker's own settlement as hostile mutation.

The current source separates **transition authority** from **post-freeze mutation authority**.

Before the first creator writer is released, the broker arms a synchronous recursive `FindFirstChangeNotificationW` transition sentinel with only:

- `FILE_NOTIFY_CHANGE_FILE_NAME`;
- `FILE_NOTIFY_CHANGE_DIR_NAME`.

This namespace-only sentinel makes file/directory replacement, rename, delete and injection during the close/reopen interval fatal while deliberately excluding size/last-write metadata that may be generated by the broker's own NTFS settlement.

Each destination writer is then transitioned to a retained read guard:

1. retain the creator-held expected object identity, attributes and SHA-256;
2. close the creator writer;
3. immediately reopen the same pathname read-only with only `FILE_SHARE_READ`;
4. retain the read guard before validation proceeds;
5. compare volume serial, file index, file size and last-write identity with the creator record;
6. require the exact retained file attributes;
7. hash the complete reopened file through the guard and require the exact expected SHA-256 and expected size;
8. poll the namespace-only transition sentinel and fail closed on any namespace signal.

The writer handle itself prevents a later external write open before it closes. The reopened read guard prevents write/delete sharing after it opens. Exact object identity, exact attributes and exact byte hashing cover the unavoidable close/reopen interval, while the namespace-only sentinel covers namespace races in that interval.

## Bounded full-watch settlement and namespace overlap

Only after every creator writer has become a validated retained read guard does the broker establish the full post-freeze observation layer. The namespace-only transition sentinel remains active throughout this handoff.

The run-29 authority does not treat the first full change signal after writer close as automatically hostile. Hosted Windows proved that an already-completed NTFS creator-close notification can be delivered after the read guards are valid. Instead, the launcher requires a bounded clean full-watch generation while independently proving exact state.

For at most **8 generations**, each generation:

1. requires that no previous full-change sentinel is retained;
2. arms a new recursive `FindFirstChangeNotificationW` sentinel with the complete watch filter;
3. reopens every guarded file read-only and requires exact object identity, attributes, size and SHA-256;
4. recursively verifies the exact destination namespace;
5. polls the still-live namespace-only transition sentinel and fails on any namespace mutation;
6. waits at most **250 ms** on the new full-change sentinel;
7. repeats exact guard-record verification, exact namespace verification and transition-sentinel polling after the wait;
8. accepts the generation only if the timed wait did not signal and an immediate zero-time recheck is also clean;
9. otherwise closes that full-change sentinel, clears it and begins the next bounded generation.

If no clean generation is reached within the bound, readiness fails closed.

A clean generation's `FindFirstChangeNotificationW` handle is retained. The broker then opens the snapshot directory and starts the recursive `ReadDirectoryChangesW` worker for:

- file-name changes;
- directory-name changes;
- attribute changes;
- size changes;
- last-write changes.

Security-descriptor changes remain deliberately excluded because the trusted H2 parent applies and later restores its own ACL during validation.

After the worker starts, the broker again verifies every guard record and the exact namespace, then polls both the transition sentinel and the retained full-change sentinel. Only after that overlap verifies clean does the core retire the namespace-only transition sentinel. It immediately rechecks the full watcher before readiness can be emitted.

This ordering is canonical:

1. retained creator writers and copied bytes;
2. namespace-only transition sentinel;
3. writer close/read-guard reopen with exact identity + attributes + SHA-256 verification;
4. bounded full-sentinel clean-generation settlement while guard bytes/identity and namespace are revalidated;
5. retain the clean full sentinel and start the recursive `ReadDirectoryChangesW` worker;
6. exact guard + namespace verification while transition and full authorities overlap;
7. clean transition-sentinel retirement;
8. full sentinel + recursive watcher retained through the remaining H2 lifetime.

The full watcher is therefore never relied upon to distinguish the broker's own writer-close settlement from hostile activity. A bounded settlement phase drains only generations whose exact filesystem state is independently proven unchanged, while the transition sentinel and retained read guards prevent an unobserved authority gap.

## Broker lifetime and bounded control protocol

The broker is long-lived. After readiness it continues holding:

- the validation-directory authority handle;
- every destination directory handle created from the point of creation;
- read guards for all copied destination files;
- exact identity/attributes/SHA-256 guard records for settlement revalidation;
- the settled full recursive snapshot-root change sentinel;
- the recursive `ReadDirectoryChangesW` worker/handle.

The transition-only namespace sentinel is retired before readiness only after a clean full-watch generation, recursive watcher startup and exact-state overlap verification succeed.

A bounded stdin/stdout protocol exposes only `CHECK` and `STOP`. Commands are ASCII and bounded. Broker responses are strict single-line JSON followed by LF; the Python emitter rejects embedded CR/LF and flushes every record.

`Read-NxbH2BrokerLine` reads `StandardOutput.BaseStream` incrementally, retains at most **65,537 raw bytes** so a 64 KiB payload may optionally carry one CR before LF, requires LF termination, strips only that optional terminator CR, and rejects payload length above **65,536 bytes** before strict UTF-8 decode. It then requires the exact policy name, exact snapshot root and bounded file/directory/byte summary.

Timeout, EOF before newline, oversized framing and invalid UTF-8 attempt recursive broker-process termination and bounded reap before failing. `ReadLineAsync` and `ReadToEndAsync` are forbidden in this control reader.

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

The first required `snapshotRoot\bin\rustc.exe` `Test-Path` occurs only after that PowerShell file/directory/ACL authority has been staged. At that point the broker-entry wrapper performs a `CHECK` and requires the broker to still report a clean snapshot, recording that broker authority and PowerShell authority overlapped successfully.

The broker is **not stopped at this handoff**.

## Heavy-gate lifetime monitoring

The broker remains active across the complete relocated Rust heavy-gate lifetime.

The existing H2 ACL intentionally preserves the ability to restore permissions and therefore is not treated, by itself, as proof against a same-user actor that attempts to alter the DACL and then perform a transient file/DLL injection.

Because the full recursive broker watcher remains armed, any ordinary file/directory name, size, last-write or attribute mutation during heavy gates becomes a final validation failure even if the actor restores the pathname/bytes before the normal post-gate deterministic tree check.

The existing PowerShell file/directory handles, ACL controls and post-gate deterministic identity checks remain defense-in-depth; none is removed by the broker layer.

## Cleanup boundary

`Authority.close()` is fail-closed and non-short-circuit. One cleanup error collector is established before retained authority is released. Cleanup attempts:

1. set the watcher stopping signal;
2. `CancelIoEx` on the watcher handle, tolerating only documented `ERROR_NOT_FOUND` when no pending request exists;
3. close the watcher handle;
4. join the watcher thread with a bounded timeout and record a still-live worker as cleanup failure;
5. close the full change-notification handle;
6. close the transition notification too if an earlier failure left it active;
7. close every remaining writer, file guard and directory handle;
8. close the validation-directory handle;
9. fail with the aggregated cleanup errors after all release attempts have run.

Watcher/sentinel close failures are not swallowed. A cleanup failure therefore prevents a healthy `stopped` record and zero broker exit status on the controlled STOP path.

The existing H2 parent restores its ACL backups and disposes its own snapshot file/directory handles during `finally`.

Only when the parent reaches the exact snapshot-root recursive `Remove-Item` does the broker-entry wrapper:

1. perform a final broker `CHECK` if normal PowerShell handoff was established;
2. require a healthy result;
3. send `STOP`;
4. require a healthy `stopped` record and zero broker exit status;
5. require broker authority cleanup to have succeeded;
6. delegate the original snapshot deletion to module-qualified `Remove-Item`.

If the nested H2 sequence fails before normal cleanup, the wrapper and bounded outer finally blocks still attempt controlled broker shutdown. Cleanup errors are aggregated and fail closed.

Therefore the broker lifetime covers destination creation, settled writer transition, PowerShell authority acquisition, heavy Rust execution, post-gate verification, ACL restoration and the beginning of final snapshot cleanup.

## Broker and control-reader primitive probes

The broker has a Windows-only self-test that stages the expected native behavior:

- create a tiny source tree;
- broker-copy it into a fresh destination;
- complete the settled writer-to-read-guard transition;
- establish a bounded clean full-watch generation;
- verify trusted copied bytes;
- prove retained destination guards deny post-freeze file writes and deletion;
- inject a new file into the snapshot tree;
- require the recursive watcher to observe that mutation;
- release all authority and allow temporary-root cleanup.

The bounded Windows H2 entrypoint executes this self-test before real broker use.

The separate exact-head Windows process-lifecycle probe also AST-extracts the production `Read-NxbH2BrokerLine` implementation and executes that exact function against synthetic child output. The staged dynamic controls require:

- strict-UTF-8 JSON terminated by CRLF to round-trip without the terminator;
- EOF before newline to fail closed;
- invalid UTF-8 to fail closed;
- stalled output to time out and trigger cleanup.

Its source/AST contract separately requires the 64 KiB pre-decode ceiling and forbids `ReadLineAsync`/`ReadToEndAsync` regression.

Source staging and static review are not substitutes for the required NTFS/Win32 behavior proof.

## PowerShell support boundary

The repository's documented Windows validation entrypoint uses `pwsh`. The NXB-153 scripts use modern `ProcessStartInfo.ArgumentList`; the broker transport follows that established PowerShell 7/.NET model rather than introducing a Windows PowerShell 5.1 compatibility promise.

The broker-entry `Test-Path` proxy uses the canonical `Microsoft.PowerShell.Commands.TestPathType` enum and delegates unrelated operations to module-qualified management cmdlets.

Real supported PowerShell execution remains mandatory because static source inspection cannot prove function-scope interception, native API marshalling, process-pipe behavior or NTFS sharing semantics.

## Remaining runtime acceptance

Destination lifetime authority is **source-staged**, but #98 and the H2 admission boundary remain open until the exact final head proves on supported Windows/NTFS at least:

- Python `ctypes` signatures and native `NtCreateFile` relative creation behavior;
- create-new collision rejection for root/children;
- reparse-point rejection;
- directory no-delete-share behavior;
- file creator-handle write/delete exclusion;
- namespace-only transition sentinel behavior during creator close/read-guard reopen;
- writer-to-read-guard object identity, attribute and exact SHA-256 continuity;
- no false hostile signal from ordinary NTFS creator-handle metadata settlement;
- bounded full-sentinel clean-generation settlement after writer transition;
- full recursive change notification after settled guards, including create/delete/rename/content mutation and transient restore attempts;
- exact guard-record and destination-namespace verification during transition/full-watch overlap;
- watcher overflow/failure fail-closed behavior;
- cancellation, bounded watcher-thread shutdown and broker cleanup arbitration;
- real broker-control 64 KiB framing boundary, newline/CRLF handling, malformed UTF-8, protocol EOF and stalled-output cleanup;
- PowerShell `New-Item`, `Test-Path`, `Remove-Item` interception/delegation semantics;
- successful overlap with existing H2 file/directory/ACL authority;
- ordinary relocated rustc/cargo/rustfmt/Clippy/DLL/sysroot loading while broker guards are held;
- deliberate mutation during heavy gates causing final validation failure;
- final broker health/STOP before snapshot deletion;
- cleanup/recovery on failures at each handoff phase.

No Windows runtime PASS is claimed until those tests execute.

## Admission boundary

The exact final NXB-153 head still requires real Rust 1.97.1 Linux and Windows validation, all #90-#98 and #103-#112 acceptance conditions, create-only schema-v2 evidence, object-anchored semantic review and guarded same-head dual-platform closure.

PR #89 remains draft/not admitted. NXB-154 must not use the NXB-153 feature branch as an admitted implementation base until that closure completes.
