# NXB-153 Windows Tool-Version Output Authority

## Status

This document records a source-staged NXB-153 availability hardening found after the broader fixed-output capture review.

It does **not** claim supported Windows/NTFS/PowerShell runtime PASS. NXB-153 remains draft/not admitted and the host Rust schema-v2 identity remains pending.

## Finding

The preserved Windows preparation implementation already pinned every namespace component and both freshly installed security-tool files before version/hash inspection. That protected executable pathname identity, but the small `--version` outputs were still collected through post-hoc `Out-String` retention.

The same preparation path also inserted `rustup run 1.97.1 rustc --version` into the tooling receipt through a direct post-hoc `Out-String` capture.

A pinned executable path is an identity control, not an output-memory bound. Those fixed-output calls therefore required the same incremental process discipline used elsewhere in the Windows admission chain.

## Current source authority

Current prepared-tool implementation:

`scripts/prepare-and-validate-nxb-153-windows-inner.ps1`

Exact Git blob:

`98aa023626e2410dce6800bd799a6d3230355b86`

Source hardening commits:

- `43e97db07a0f9241dd382a4ff865f0d32c412ad2` — introduced bounded fixed-output version capture;
- `638126fcf7fc13621d5aa57f5e6e105c5259add2` — restored the pre-existing `RUSTC_WRAPPER` ambient-authority rejection that was accidentally omitted during the complete-file replacement and restored the trailing newline.

The net change from the previous source-stage head preserves the ambient compiler/Cargo/Python authority deny-list.

## Fixed-output process contract

`Invoke-NxbBoundedFixedOutput` is used for:

- freshly installed pinned `cargo-audit.exe --version`;
- freshly installed pinned `cargo-deny.exe --version`;
- `rustup run 1.97.1 rustc --version` used in the create-only tooling receipt.

The helper requires:

- `UseShellExecute = false`;
- child stdout redirected;
- child stderr inherited;
- incremental `StandardOutput.BaseStream.ReadAsync(...)`;
- maximum raw stdout: **4,096 bytes**;
- read-inactivity timeout: **30,000 ms**;
- post-stdout exit timeout: **30,000 ms**;
- nonzero child exit is fatal;
- strict UTF-8 decoding only after the raw-byte ceiling succeeds;
- non-empty semantic result no longer than **256 characters**;
- failure/timeout cleanup attempts recursive `Kill(true)` followed by bounded reap;
- process and buffer disposal in `finally`.

`Get-ToolVersion` retains its exact-version-token check after bounded capture.

## Exact-head regression probe authority

The fixed-output helper has a dedicated supported-Windows regression probe:

`scripts/nxb-153-windows-tool-version-output-probe.ps1`

Current exact Git blob:

`381529e260f2a9c9b0f20bff3f29a8b2c6ef6e84`

Probe source commits:

- `a54d2754a552514c8b4390f0f3c45cf738025973` — introduced the exact-head production-helper probe;
- `90b24664b8728afa31a74cb59f7c0febf5229b0b` — fixed the StrictMode literal source-pattern check and widened the probe-only nested-process timeout defaults to reduce false negatives;
- `5f83a9d9ef6957b4d560a3fa1784341632dfc6c5` — added a distinct post-stdout-exit timeout primitive by explicitly closing the redirected Windows stdout handle while the fixture process remains alive.

The probe does not reimplement the production helper. It:

1. resolves exact `HEAD` through bounded Git stdout;
2. verifies the working-tree bytes of both the tool-preparation inner and the probe itself against their exact-head Git objects;
3. parses the tool-preparation inner with the PowerShell AST;
4. requires the production `4096 / 30000 / 30000` constants, `RUSTC_WRAPPER` rejection and the absence of `Out-String` in that preparation source;
5. extracts exactly one `Invoke-NxbBoundedFixedOutput` function body from the exact-head AST;
6. requires incremental `ReadAsync`, raw-byte ceiling, strict UTF-8, bounded exit, <=256-character semantic result and recursive `Kill(true)` cleanup patterns, while rejecting `ReadToEndAsync`, `ReadLineAsync` and parameterless `WaitForExit()`;
7. requires both `Get-ToolVersion` and the tooling-receipt Rust version call to route through the bounded helper;
8. loads only that exact production helper body for dynamic primitive testing.

Dynamic probe-only timeout constants are intentionally shorter than production timing. Static source assertions separately require the production 30-second values. The dynamic tests exercise:

- normal bounded fixed-output success;
- output above 4 KiB rejection;
- invalid UTF-8 rejection;
- nonzero exit propagation;
- stalled stdout read-inactivity timeout;
- output-then-stall read-inactivity timeout after some valid output;
- **post-stdout exit timeout after the child explicitly closes its redirected stdout handle but remains alive**;
- recursive descendant-process cleanup after timeout.

The post-stdout fixture uses the redirected `STD_OUTPUT_HANDLE` obtained through the Windows standard-handle API and closes that process handle before sleeping. This distinguishes EOF-followed-by-live-process behavior from ordinary no-progress reads.

A successful probe can emit bounded JSON containing the exact head, tool-preparation object, probe object, production/probe limits, PowerShell version and ordered test results. That output is evidence of these primitives only; canonical admission still requires the complete Windows admission wrapper and the rest of the NXB-153 evidence chain.

## Existing identity and receipt controls retained

This change does not relax the existing preparation authority:

- repository and target/validation namespaces remain pinned;
- exact-head create-new preparation lock remains required;
- exact-head tool root must not pre-exist without an admitted receipt;
- cargo-audit and cargo-deny are installed into the exact-head tool root;
- every namespace component used to resolve the installed executables is pinned without delete sharing;
- both tool executable files are pinned before version/hash inspection;
- pinned-stream SHA-256 is compared with pathname SHA-256 before receipt publication;
- Git HEAD and clean-worktree authority are rechecked before publication;
- tooling receipt remains create-only, bounded and read back byte-for-byte;
- tool handles remain held through receipt publication;
- `RUSTC_WRAPPER` remains rejected by the ambient-authority guard together with the other compiler/Cargo/Python override variables.

## Relationship to the H1/H2 Out-String guard

Other `Out-String` occurrences in the Windows H1/H2 validation chain were reviewed separately. Those captures execute beneath the existing bounded H2 `Out-String` proxy, which applies byte/object limits before delegating admitted bounded objects to the module-qualified real formatter and self-tests formatting equivalence.

The preparation-tool version calls documented here occur outside that H2 string-guard boundary, which is why they require an independent native-process fixed-output helper and the dedicated exact-head probe above.

## Canonical admission integration

`scripts/review-nxb-153-windows-admission.ps1` now executes the exact-head tool-version probe as its first mandatory runtime phase before process-lifecycle evidence review and schema-v2 closure review.

The admission wrapper pins both the probe and production tool-preparation source with write/delete sharing withheld for the complete admission review, rechecks their Git objects and HEAD after the probe, and withholds probe output through all later authority/cleanup checks.

A direct standalone probe run remains useful diagnostically but is not a substitute for the canonical admission wrapper.

## Remaining runtime proof

Supported exact-head Windows execution must still demonstrate at least:

- successful execution of the tool-version probe as part of `scripts/review-nxb-153-windows-admission.ps1` against the exact final head;
- normal cargo-audit/cargo-deny/rustc version capture;
- stalled stdout timeout;
- output above 4 KiB rejection before unbounded retention;
- invalid UTF-8 rejection;
- nonzero exit propagation;
- actual post-stdout exit timeout behavior of the close-handle fixture;
- recursive process-tree cleanup on failure;
- preservation of tool-path pinning while the version child executes;
- correct create-only tooling receipt publication and later exact-object validation.

This is in addition to the existing NXB-153 Windows H2, broker, direct-child, schema-v2 and same-head dual-platform admission requirements.

Current schema-v2 evidence remains intentionally:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 and issues #90-#98 remain open/not admitted. NXB-154 must not use this branch as an admitted implementation base until real same-head Linux + Windows closure succeeds.
