# NXB-153 Windows Fixed-Output Capture Authority

## Status

This document supersedes older NXB-153 notes that still describe post-hoc `Out-String` capture or the historical canonical Windows entry blob as current.

This is **source-staged authority only**. No supported Windows/NTFS/PowerShell runtime PASS is claimed by these changes, and NXB-153 remains draft/not admitted.

## Canonical Windows entry control-plane Git authority

The three canonical Windows entrypoints continue to share one byte-identical outer implementation:

- `scripts/prepare-and-validate-nxb-153-windows.ps1`;
- `scripts/validate-nxb-153-windows.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`.

Their current shared exact Git blob is:

`3267f592f074d12326bd518f8b74555f033beba5`

This supersedes `ab8383d4281ebc147dfe8305a926dd862699cef4` as the current canonical entry blob.

Commit `7e405f19746e65a07062dcbb8f65719f8ee64952` replaced raw pre-proxy and post-delegation Git authority captures with `Get-NxbWindowsEntryGitControlValue`.

The small fixed-output Git control plane now requires:

- stdout redirected from the real Git application only;
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

The delegated Git data plane retains its existing:

- **64 MiB** raw stdout ceiling;
- **4,096 decoded records** ceiling;
- **300,000 ms / 5 minute** read-inactivity timeout;
- **30,000 ms / 30 second** post-stdout exit timeout;
- strict UTF-8 decoding;
- inherited stderr;
- recursive termination on timeout/limit failure;
- `$LASTEXITCODE` propagation.

## Process-lifecycle probe Git control authority

`scripts/nxb-153-windows-process-lifecycle-probe.ps1` exact blob:

`1d2ed9a23db922b9c3131784aec4932bf6518766`

Commit `ee47458b1defba4371228f462a0f66a377148542` replaced `Get-NxbSmallCommandOutput` post-hoc `Out-String` capture with the same bounded fixed-output process shape:

- **4 KiB** raw stdout;
- **30 second** read inactivity;
- **30 second** post-output exit;
- strict UTF-8;
- maximum **256-character** semantic value;
- inherited stderr;
- recursive process-tree termination plus bounded reap on failure.

The existing 16-record runtime evidence test sequence is unchanged.

## Process-evidence writer subprocess authority

`scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1` exact blob:

`fd574227afbec17cbaf01c3f0be01409f1b1cf3b`

Commit `5eda9d02391a45835fce66dba8b756ef9bb2466e` introduced `Invoke-NxbBoundedProcessOutput` and removed two post-hoc retention paths.

### Git control values

Writer Git authority values use:

- **4 KiB** raw stdout;
- **30 second** read inactivity;
- **30 second** post-output exit;
- strict UTF-8;
- maximum **256-character** semantic value.

### Exact process-probe JSON

The writer now launches the exact pinned process probe through the currently executing PowerShell Core binary instead of collecting an in-runspace pipeline through `Out-String`.

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

Commit `945c5c90aafc06fb870593df851ec394bb5b1364` replaced reviewer `Get-NxbGitValue` post-hoc capture with the same **4 KiB / 30 s / 30 s / strict UTF-8 / 256-character** fixed-output Git control contract and recursive cleanup.

Evidence-size, native handle-pinning, exact schema and final object/HEAD authority remain unchanged.

## Canonical Windows admission Git control authority

`scripts/review-nxb-153-windows-admission.ps1` exact blob:

`8937cd567158343d108d3a258932d745775518d7`

Commit `274a783ad4c3d82f325c731b5023b6aa27ed62c1` replaced admission `Get-NxbGitValue` post-hoc capture with the same **4 KiB / 30 s / 30 s / strict UTF-8 / 256-character** fixed-output Git control contract and recursive cleanup.

The admission wrapper still requires process-lifecycle evidence review before the schema-v2 Windows closure reviewer and withholds success until later HEAD/object/cleanup checks succeed.

## Windows semantic-review output authority

`scripts/review-nxb-153-evidence-windows-inner.ps1` exact blob:

`4a295b77323b3b4c43075c39c50800e50577dbc9`

Commit `5edc6eb3c6bdf5acca09bc2152cea38ab2c9ba52` removed both `6>&1 | Out-String` semantic-review retention paths.

`Invoke-NxbBoundedSemanticReview` now applies bounds while pipeline records arrive:

- maximum retained/observed semantic output: **65,536 UTF-8 bytes**;
- maximum records: **4,096**;
- the first semantic pass may retain only admitted records for deferred display;
- the second pinned semantic rerun validates/counts output without retaining it;
- closure pinning, final HEAD, clean-worktree and Cargo.lock authority checks remain after those passes.

The existing canonical outer Windows evidence-review entry still supplies the separate bounded Git proxy for native `git` calls inside this preserved inner implementation.

## Source-review result

After these changes, the newly identified standalone post-hoc output surfaces are source-hardened:

- process-probe Git fixed values;
- process-evidence writer Git fixed values;
- process-evidence writer process-probe JSON;
- process-evidence reviewer Git fixed values;
- canonical Windows admission Git fixed values;
- canonical Windows entry raw authority Git fixed values;
- Windows semantic reviewer first and second pass output.

The remaining `Out-String` occurrences reviewed in the Windows H1/H2 chain execute under existing bounded outer/native Git proxy or bounded entry authority and are not treated by this document as new standalone attacker-expandable capture surfaces.

This source review does **not** replace supported Windows execution.

## Runtime admission still required

Real exact-head Windows/NTFS/PowerShell evidence must still prove at least:

- canonical entry 4 KiB control-plane timeout/limit/nonzero-exit cleanup;
- canonical delegated Git 64 MiB / 4,096-record timeout/limit behavior;
- nested proxy installation/restoration;
- process-probe Git control behavior;
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