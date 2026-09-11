# NXB-153 Windows Fixed-Output Capture Authority

## Status

This document records the current **source-staged, not admitted** Windows fixed-output, Git-control and selected host-Git lifetime authority for NXB-153.

No supported Windows/NTFS/PowerShell runtime PASS is claimed. Historical blobs are not current authority unless explicitly labelled as superseded.

## Current authority set

- shared canonical Windows outer entry -> `9f1852241f62d6a1357688713dd32595464682b6`;
- H2 outer/direct `-SelfTest` -> `58cfcfa709404f7dae467a4591af755bad52209c`;
- process-lifecycle probe -> `1d2ed9a23db922b9c3131784aec4932bf6518766`;
- process-evidence writer -> `1ebca56bc704dcacb4864ace03ba16640b4b1e0d`;
- process-evidence reviewer -> `314a04af4497c67b3761d4cd2f9ba470896d57e6`;
- subordinate Windows admission -> `6b0e4ddc47ad440ab113ff073d3ae5275a95b949`;
- tool-version probe -> `381529e260f2a9c9b0f20bff3f29a8b2c6ef6e84`;
- host-Git lifetime probe -> `5b12134f18cb6a71efde0d06b0622ec170269401`;
- complete Windows admission -> `b2b5cdec1a24b92e34d2397c9567e2cc4c2e3a98`;
- Windows validator inner -> `d32246838e9a7445fa87aafec85c32ebd6416d8a`;
- Windows validator fixed-output source contract -> `93bb0bf9e131fd30bfb7fbc700589f36c99b006c`;
- Windows semantic-review inner -> `4a295b77323b3b4c43075c39c50800e50577dbc9`.

## Pre-Git ambient authority

The selected `git.exe` can still consume repository/object/config authority from environment variables. Canonical Windows authority surfaces therefore reject every environment-variable name beginning with `GIT_`, case-insensitively, **before their first exact-head Git operation**.

This applies to the three shared outer entrypoints, H2 outer/direct `-SelfTest`, process-evidence writer, subordinate admission, complete admission and host-Git lifetime probe. Values are never printed.

Direct process/tool diagnostic probes remain parent-bounded when used for admission and are not promoted to standalone persistent authority.

## Host Git lifetime authority

The initially resolved installed Git application remains a **supported-host trust boundary**; NXB-153 does not claim independent cryptographic identity for that installation.

For canonical Windows outer entry, process-evidence recording and admission layers, source staging requires:

- select Git with `Get-Command git -CommandType Application`;
- require a regular non-reparse executable;
- open it read-only with write/delete sharing withheld;
- require native final-path equality for the opened file handle;
- native-pin the immediate executable directory with delete sharing withheld and final-path equality;
- prepend that directory to PATH;
- require nested Git resolution to return the same pinned executable;
- retain Git file/directory handles through the parent authority operation;
- restore PATH and release handles only through fail-closed cleanup before PASS.

## Canonical Windows entry control plane

The three byte-identical outer entrypoints are:

- `scripts/prepare-and-validate-nxb-153-windows.ps1`;
- `scripts/validate-nxb-153-windows.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`.

Current shared exact blob:

`9f1852241f62d6a1357688713dd32595464682b6`

The small Git control plane requires:

- pinned host Git stdout only;
- inherited stderr;
- incremental `StandardOutput.BaseStream.ReadAsync(...)`;
- maximum raw stdout **4,096 bytes**;
- read-inactivity timeout **30,000 ms**;
- post-stdout exit timeout **30,000 ms**;
- strict UTF-8 only after byte bound succeeds;
- non-empty semantic value <= **256 characters**;
- nonzero exit fatal;
- recursive `Kill(true)` plus bounded reap on timeout/failure.

The delegated Git data plane remains separately bounded to **64 MiB / 4,096 records / 300,000 ms read inactivity / 30,000 ms post-output exit**, strict UTF-8, inherited stderr and recursive cleanup.

## H2 outer authority

`scripts/nxb-153-windows-immutable-source.ps1` -> `58cfcfa709404f7dae467a4591af755bad52209c`

The H2 outer independently rejects ambient `GIT_*` before resolving its exact-head Git-output inner so direct `-SelfTest` does not rely on earlier parent sanitization. The H2 Git-output layer retains its separate large bounded data-plane contract.

## Process-lifecycle probe Git control authority

`scripts/nxb-153-windows-process-lifecycle-probe.ps1` -> `1d2ed9a23db922b9c3131784aec4932bf6518766`

Its diagnostic small-command path retains the **4 KiB / 30 s / 30 s / strict UTF-8 / <=256-character** fixed-output shape with inherited stderr and recursive cleanup.

Direct invocation is diagnostic. During canonical evidence recording it executes under the process writer after the writer's pre-Git gate and pinned host-Git/PATH authority are established.

## Process-evidence writer authority

`scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1` -> `1ebca56bc704dcacb4864ace03ba16640b4b1e0d`

The writer:

- rejects ambient `GIT_*` before exact-head Git lookup;
- pins host Git + directory and rebinds PATH;
- uses the 4 KiB / 30 s / 30 s strict-UTF8 control plane for Git values;
- launches the exact pinned process probe through the current PowerShell Core executable;
- bounds probe JSON to **65,536 bytes** with **300,000 ms** read inactivity and **30,000 ms** post-output exit;
- preserves exact 16-record runtime evidence semantics;
- publishes create-only evidence and rechecks HEAD/source authority;
- fails closed on PATH/source/namespace/host-Git cleanup.

## Process-evidence reviewer authority

`scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1` -> `314a04af4497c67b3761d4cd2f9ba470896d57e6`

The reviewer uses the **4 KiB / 30 s / 30 s / strict UTF-8 / <=256-character** Git-control contract. Under admission it runs beneath the parent admission wrapper's host-Git/PATH lifetime authority. Direct invocation remains subordinate/diagnostic.

## Windows admission Git control authority

`scripts/review-nxb-153-windows-admission.ps1` -> `6b0e4ddc47ad440ab113ff073d3ae5275a95b949`

Before exact HEAD/source lookup, the admission wrapper rejects ambient `GIT_*`, pins host Git + directory, rebinds PATH and verifies nested application resolution. Host-Git and source/namespace handles remain live through:

1. tool-version fixed-output probe;
2. process-lifecycle evidence review;
3. Windows schema-v2 / dual-platform closure review.

Subordinate output remains bounded and withheld until later authority checks, PATH restoration and cleanup succeed.

Complete admission is `scripts/review-nxb-153-windows-admission-complete.ps1` -> `b2b5cdec1a24b92e34d2397c9567e2cc4c2e3a98`; it adds the mandatory host-Git lifetime probe before the subordinate chain and final complete-wrapper cleanup afterward.

## Tool-version output authority

`scripts/nxb-153-windows-tool-version-output-probe.ps1` -> `381529e260f2a9c9b0f20bff3f29a8b2c6ef6e84`

The probe exact-head binds production tool-preparation source and requires the preparation helper to retain the **4,096-byte / 30,000-ms read / 30,000-ms exit** fixed-output contract, strict UTF-8, <=256-character semantic output and recursive cleanup. It dynamically exercises normal, oversize, invalid UTF-8, nonzero exit, stalled output, output-then-stall/post-output exit and descendant cleanup behavior with shorter probe-only deadlines.

Preparation authority remains documented in `docs/NXB-153-WINDOWS-TOOL-VERSION-OUTPUT-AUTHORITY.md`.

## Windows validator pre-H2 fixed-output authority

`scripts/validate-nxb-153-windows-inner.ps1` -> `d32246838e9a7445fa87aafec85c32ebd6416d8a`

A source audit found that the validator performed four small version inspections before its first H2 delegation while the H2 bounded `Out-String` proxy was not yet active. The validator now independently applies the same native-process fixed-output discipline to:

- `cargo-audit.exe --version`;
- `cargo-deny.exe --version`;
- `rustup run 1.97.1 rustc --version`;
- `rustup run 1.97.1 cargo --version`.

The validator contract requires:

- `UseShellExecute = false`;
- redirected stdout and inherited stderr;
- incremental `StandardOutput.BaseStream.ReadAsync(...)`;
- **4,096-byte** raw stdout ceiling;
- **30,000 ms** read-inactivity timeout;
- **30,000 ms** post-stdout exit timeout;
- nonzero exit rejection;
- strict UTF-8 after the byte ceiling;
- semantic output <= **256 characters**;
- recursive `Kill(true)` plus bounded reap on failure/timeout.

The validator resolves `rustup` with `Get-Command rustup -CommandType Application` and passes the resolved application path to the bounded helper. The validator source no longer contains `Out-String`.

Cross-platform source regression authority:

`crates/nxb-core/tests/windows_validator_fixed_output_source_contract.rs` -> `93bb0bf9e131fd30bfb7fbc700589f36c99b006c`

The first `std`-only Rust integration test verifies the production constants/helper shape, rejects `Out-String`/`ReadToEndAsync`/`ReadLineAsync`/parameterless `WaitForExit()`, requires bounded tool/rustc/cargo call paths and asserts that bounded version setup precedes the first H2 delegation.

The second test reads both the validator and preparation PowerShell sources, extracts each complete `Invoke-NxbBoundedFixedOutput` source region and requires those regions to be source-identical while both retain the same **4096 / 30000 / 30000** constants.

This closes a regression-evidence gap without duplicating a second dynamic probe: the exact-head Windows tool-version probe dynamically executes the preparation helper, while the Rust workspace test refuses any validator helper that drifts from that dynamically exercised source primitive. Canonical Linux immutable validation and Windows dependency validation both run the workspace test suite, so this equivalence gate participates in both full Rust paths.

This remains source-level inheritance evidence only. Supported-Windows dynamic validator execution is mandatory because executable/path identity, PowerShell/.NET semantics, surrounding pin lifetimes and actual timeout/cleanup behavior remain runtime properties.

## Windows semantic-review output authority

`scripts/review-nxb-153-evidence-windows-inner.ps1` -> `4a295b77323b3b4c43075c39c50800e50577dbc9`

`Invoke-NxbBoundedSemanticReview` bounds semantic output while records arrive:

- maximum **65,536 UTF-8 bytes**;
- maximum **4,096 records**;
- first pass may retain only admitted records for deferred display;
- second pinned semantic rerun validates/counts without retaining output;
- closure pinning, final HEAD, clean-worktree and Cargo.lock authority checks remain after both passes.

## Source-review result

Current source hardens:

- pre-Git repository/object/config environment authority on canonical Windows surfaces;
- selected host-Git executable/directory lifetime and nested PATH resolution;
- canonical entry repo/scripts/preserved-inner final-path authority;
- fixed-output Git control values;
- bounded process-probe JSON;
- process-evidence and admission Git-control authority;
- preparation tool-version fixed-output behavior;
- validator pre-H2 rustc/cargo/security-tool version capture plus helper equivalence to the dynamically probed primitive;
- semantic reviewer output retention.

This source review does **not** replace supported Windows execution.

## Runtime admission still required

Exact-head Windows/NTFS/PowerShell evidence must still prove:

- hostile `GIT_DIR`, `GIT_WORK_TREE`, object-directory/alternate-object and `GIT_CONFIG_*` rejection before first Git on canonical outer/H2/process/admission authority surfaces;
- clean exact HEAD/object resolution after pre-Git rejection;
- host Git file/directory no-write/delete/rename lifetime and PATH rebinding/restoration;
- canonical entry repo/scripts/preserved-inner final-path rejection under pathname/reparse substitution;
- 4 KiB control-plane timeout/limit/nonzero cleanup;
- 64 MiB / 4,096-record delegated Git timeout/limit behavior and nesting/restoration;
- preparation and validator fixed-output normal/oversize/invalid-UTF8/nonzero/stall/post-output-exit/recursive-cleanup behavior;
- both validator source-regression tests under pinned Rust 1.97.1;
- process writer 64 KiB JSON ceiling and stalled-output cleanup;
- process reviewer/admission fixed-output Git behavior;
- semantic-review 64 KiB / 4,096-record behavior on both passes;
- registry/Git-archive/tar stalled-I/O/nonzero/cancellation cleanup;
- broker framing/UTF-8/timeout behavior;
- destination-broker filesystem/adversarial tests;
- complete Rust 1.97.1 H2 execution;
- create-only schema-v2 evidence and object-anchored review.

Current schema-v2 identity remains intentionally:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 and issues #90-#98 remain open/not admitted. NXB-154 must not use NXB-153 as an admitted base until same-head Linux + Windows closure succeeds.
