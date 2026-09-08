# NXB-153 Windows Fixed-Output Capture Authority

## Status

This document supersedes older NXB-153 notes that still describe post-hoc `Out-String` capture, historical canonical Windows entry blobs, or pathname-only host Git lifetime as current.

This is **source-staged authority only**. No supported Windows/NTFS/PowerShell runtime PASS is claimed by these changes, and NXB-153 remains draft/not admitted.

## Host Git lifetime authority

The current Windows source contract continues to treat the initially resolved installed Git application as a **supported-host trust boundary**. These changes do not claim an independent cryptographic identity for the host Git installation.

What is now source-hardened is the lifetime of that selected host tool.

For canonical Windows entry, process-evidence recording and canonical Windows admission:

- `Get-Command git -CommandType Application` selects the initial host Git application;
- the selected executable must be a regular non-reparse file;
- the executable is opened read-only with write/delete sharing withheld;
- its actual opened handle must resolve through `GetFinalPathNameByHandleW` to the canonical expected executable path;
- its immediate executable directory is opened as a native directory handle with delete sharing withheld and must resolve to the expected canonical path;
- the pinned Git directory is temporarily prepended to `PATH` so nested `Get-Command git -CommandType Application` calls resolve to the same pinned executable;
- nested resolution is checked before authority work proceeds;
- the Git file and directory handles remain live through the relevant validation/evidence/admission sequence;
- `PATH` restoration and host-Git handle cleanup are part of successful completion and fail closed before PASS.

This closes the previously remaining interval where source/evidence authority could begin with one supported-host Git executable and later resolve or execute a different file at the same or another `PATH` location during the same canonical run.

Direct diagnostic probes/reviewers remain non-canonical when invoked outside their documented parent chain. Their admission use is protected by the canonical parent Git lifetime binding described above.

## Canonical Windows entry control-plane Git authority

The three canonical Windows entrypoints continue to share one byte-identical outer implementation:

- `scripts/prepare-and-validate-nxb-153-windows.ps1`;
- `scripts/validate-nxb-153-windows.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`.

Their current shared exact Git blob is:

`18d638dde788abe363322685b04b4a04e87f6394`

This supersedes `3267f592f074d12326bd518f8b74555f033beba5` and the older `ab8383d4281ebc147dfe8305a926dd862699cef4` as the current canonical entry blob.

In addition to the host-Git lifetime binding above, the outer wrapper now native-pins both repository root and canonical `scripts` namespace with no delete sharing and final-path equality. The preserved inner implementation is opened read-only with write/delete sharing withheld and the actual opened file handle must resolve to the expected canonical path before exact-head Git-object authority is accepted.

The small fixed-output Git control plane requires:

- stdout redirected from the pinned host Git application only;
- stderr inherited;
- incremental `StandardOutput.BaseStream.ReadAsync(...)`;
- maximum raw stdout: **4,096 bytes**;
- read-inactivity timeout: **30,000 ms**;
- post-stdout exit timeout: **30,000 ms**;
- strict UTF-8 decoding only after the byte ceiling succeeds;
- non-empty semantic value no longer than **256 characters**;
- nonzero child exit is fatal;
- failure/timeout cleanup attempts recursive `Kill(true)` and bounded reap.

This fixed-output path is used for initial/final `rev-parse`, exact-head inner-object resolution and `cat-file -t`. It is intentionally separate from the existing large bounded Git data-plane proxy used by delegated validation logic.

The delegated Git data plane retains:

- **64 MiB** raw stdout ceiling;
- **4,096 decoded records** ceiling;
- **300,000 ms / 5 minute** read-inactivity timeout;
- **30,000 ms / 30 second** post-stdout exit timeout;
- strict UTF-8 decoding;
- inherited stderr;
- recursive termination on timeout/limit failure;
- `$LASTEXITCODE` propagation.

Nested canonical Windows entrypoints resolve the same PATH-pinned host Git before installing their own bounded proxy. Global proxy restoration, PATH restoration, namespace/file handle cleanup and host-Git handle cleanup are all part of successful outer completion.

## Process-lifecycle probe Git control authority

`scripts/nxb-153-windows-process-lifecycle-probe.ps1` exact blob:

`1d2ed9a23db922b9c3131784aec4932bf6518766`

Commit `ee47458b1defba4371228f462a0f66a377148542` replaced `Get-NxbSmallCommandOutput` post-hoc `Out-String` capture with the bounded fixed-output process shape:

- **4 KiB** raw stdout;
- **30 second** read inactivity;
- **30 second** post-output exit;
- strict UTF-8;
- maximum **256-character** semantic value;
- inherited stderr;
- recursive process-tree termination plus bounded reap on failure.

The direct probe is diagnostic by itself. During canonical process-evidence recording it inherits PATH from the writer after the writer has pinned and rebound the selected host Git, so its own `Get-Command git` resolves the same protected executable.

The existing 16-record runtime evidence test sequence is unchanged.

## Process-evidence writer subprocess authority

`scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1` current exact blob:

`1313a6af73d0884d9db9f4939a073e2aa00f1109`

The writer retains the existing fixed-output and create-only evidence contract and now additionally pins the selected host Git executable and its directory for the full evidence run. The writer temporarily prepends that pinned directory to PATH before launching the process probe, verifies nested Git resolution, and restores PATH only during fail-closed cleanup.

### Git control values

Writer Git authority values use:

- **4 KiB** raw stdout;
- **30 second** read inactivity;
- **30 second** post-output exit;
- strict UTF-8;
- maximum **256-character** semantic value.

### Exact process-probe JSON

The writer launches the exact pinned process probe through the currently executing PowerShell Core binary instead of collecting an in-runspace pipeline through `Out-String`.

Probe JSON stdout is bounded while read:

- maximum raw stdout: **65,536 bytes**;
- read-inactivity timeout: **300,000 ms / 5 minutes**;
- post-output exit timeout: **30,000 ms**;
- strict UTF-8 before JSON parsing;
- inherited stderr;
- nonzero exit is fatal;
- failure/timeout cleanup attempts recursive `Kill(true)` plus bounded reap.

The writer still requires the exact process-probe schema, exact ordered 16-record test sequence, exact-head source objects, create-only evidence publication and final HEAD/source rechecks.

## Process-evidence reviewer Git control authority

`scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1` exact blob:

`314a04af4497c67b3761d4cd2f9ba470896d57e6`

The reviewer uses the **4 KiB / 30 s / 30 s / strict UTF-8 / 256-character** fixed-output Git control contract and recursive cleanup.

When used for admission, this reviewer executes inside the canonical admission wrapper after that wrapper has pinned the host Git and rebound PATH. Direct invocation remains subordinate/non-canonical for final NXB-153 admission.

Evidence-size, native evidence handle-pinning, exact schema and final object/HEAD authority remain unchanged.

## Canonical Windows admission Git control authority

`scripts/review-nxb-153-windows-admission.ps1` current exact blob:

`aa90917a629d57fa9319ead2ffe9d9e0b77f4a35`

The admission wrapper uses the same **4 KiB / 30 s / 30 s / strict UTF-8 / 256-character** fixed-output Git control contract and recursive cleanup.

Before resolving exact HEAD or opening admission source authorities, it now pins the selected host Git executable and its directory, prepends the pinned directory to PATH, and verifies nested application resolution. The host Git handles remain live through:

1. tool-version output regression probe;
2. process-lifecycle evidence review;
3. Windows schema-v2 / dual-platform closure review.

Repository root, canonical `scripts`, and every admission source-authority file remain native/file-handle pinned as separately documented. Subordinate success output remains bounded and withheld until later authority checks, PATH restoration and all source/namespace/host-Git cleanup succeed.

## Windows semantic-review output authority

`scripts/review-nxb-153-evidence-windows-inner.ps1` exact blob:

`4a295b77323b3b4c43075c39c50800e50577dbc9`

`Invoke-NxbBoundedSemanticReview` applies bounds while pipeline records arrive:

- maximum retained/observed semantic output: **65,536 UTF-8 bytes**;
- maximum records: **4,096**;
- the first semantic pass may retain only admitted records for deferred display;
- the second pinned semantic rerun validates/counts output without retaining it;
- closure pinning, final HEAD, clean-worktree and Cargo.lock authority checks remain after those passes.

The canonical outer Windows evidence-review entry supplies the separate bounded Git proxy and is itself executed under pinned host-Git lifetime when reached through canonical preparation/validation or admission.

## Source-review result

Current source hardens the identified standalone output and tool-lifetime surfaces:

- canonical entry host-Git executable/directory lifetime and nested PATH resolution;
- canonical entry repo/scripts and preserved-inner final-path authority;
- process-probe Git fixed values;
- process-evidence writer host-Git lifetime;
- process-evidence writer Git fixed values;
- process-evidence writer process-probe JSON;
- process-evidence reviewer Git fixed values under canonical admission parent authority;
- canonical Windows admission host-Git lifetime and Git fixed values;
- canonical Windows entry raw authority Git fixed values;
- Windows semantic reviewer first and second pass output.

The remaining `Out-String` occurrences reviewed in the Windows H1/H2 chain execute under existing bounded outer/native Git proxy or bounded entry authority and are not treated by this document as new standalone attacker-expandable capture surfaces.

This source review does **not** replace supported Windows execution.

## Runtime admission still required

Real exact-head Windows/NTFS/PowerShell evidence must still prove at least:

- host Git file/directory no-write/delete lifetime under attempted replacement/rename;
- PATH rebinding forces nested application resolution to the pinned Git and restores the original PATH on success/failure;
- canonical entry repo/scripts/preserved-inner final-path rejection under deliberate pathname/reparse substitution;
- canonical entry 4 KiB control-plane timeout/limit/nonzero-exit cleanup;
- canonical delegated Git 64 MiB / 4,096-record timeout/limit behavior;
- nested proxy installation/restoration;
- process-probe Git control behavior under writer-pinned Git lifetime;
- process-evidence writer 64 KiB JSON ceiling and stalled-output cleanup;
- process-evidence reviewer/admission fixed-output Git behavior;
- semantic-review 64 KiB / 4,096-record behavior on both passes;
- registry verifier, Git archive and tar stalled-I/O/nonzero/cancellation cleanup;
- broker-control framing/UTF-8/timeout behavior;
- destination-broker and filesystem mutation/adversarial tests;
- complete Rust 1.97.1 H2 execution;
- create-only schema-v2 evidence publication and object-anchored review.

Current schema-v2 identity remains intentionally:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 and issues #90-#98 remain open/not admitted. NXB-154 must not use NXB-153 as an admitted base until same-head Linux + Windows closure succeeds.
