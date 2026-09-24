# NXB-153 Windows Tool-Version Output Authority

## Status

This document records source-staged NXB-153 availability hardening for fixed-output tool/version capture outside the bounded H2 formatting boundary.

It does **not** claim supported Windows/NTFS/PowerShell runtime PASS. NXB-153 remains draft/not admitted and the host Rust schema-v2 identity remains pending.

## Finding

The preserved Windows preparation implementation already pinned every namespace component and both freshly installed security-tool files before version/hash inspection. That protected executable pathname identity, but the small `--version` outputs were originally collected through post-hoc `Out-String` retention.

The same preparation path also inserted `rustup run 1.97.1 rustc --version` into the tooling receipt through a direct post-hoc `Out-String` capture.

A later source audit found the same availability gap in `scripts/validate-nxb-153-windows-inner.ps1`: before delegating to the immutable H2 runner, the validator captured `rustc`, `cargo`, `cargo-audit` and `cargo-deny` version output through direct `Out-String` paths. Those calls occur before the H2 bounded `Out-String` proxy is active, so the H2 guard could not bound them.

A pinned executable path is an identity control, not an output-memory bound. All of these pre-H2 fixed-output calls therefore require native incremental process discipline.

A further review found an evidence-quality gap after the validator helper was added: the supported-Windows dynamic tool-version probe executes the preparation helper, while the validator helper was protected only by static source markers. Source equivalence is now part of the canonical regression contract so the validator helper cannot drift away from the dynamically exercised preparation primitive without failing the Rust workspace tests.

## Current source authority

Prepared-tool implementation:

`scripts/prepare-and-validate-nxb-153-windows-inner.ps1`

Exact Git blob:

`98aa023626e2410dce6800bd799a6d3230355b86`

Validator implementation:

`scripts/validate-nxb-153-windows-inner.ps1`

Current exact Git blob:

`d32246838e9a7445fa87aafec85c32ebd6416d8a`

Cross-platform validator source regression test:

`crates/nxb-core/tests/windows_validator_fixed_output_source_contract.rs`

Current exact Git blob:

`93bb0bf9e131fd30bfb7fbc700589f36c99b006c`

Source hardening commits:

- `43e97db07a0f9241dd382a4ff865f0d32c412ad2` — introduced bounded fixed-output version capture in Windows tool preparation;
- `638126fcf7fc13621d5aa57f5e6e105c5259add2` — restored the pre-existing `RUSTC_WRAPPER` ambient-authority rejection accidentally omitted during that complete-file replacement and restored the trailing newline;
- `a401c760e3b553ca1ead62c3212df47cdca7f72b` — routed Windows validator `rustc`, `cargo`, `cargo-audit` and `cargo-deny` version capture through the same bounded native-process discipline;
- `411ee3d7ce743cfb31c74625040f630f2ea23e79` — introduced the platform-independent validator fixed-output source regression test;
- `b701d4e8689e3f2bfb62297df7b7cd00fd0f54a7` — normalized that Rust regression test to the workspace formatting contract;
- `3598ff27acffca06980a953a9307e9cd89f08e71` — requires the validator helper source to remain identical to the preparation helper dynamically exercised by the exact-head Windows tool-version probe.

The current source retains the ambient compiler/Cargo/Python authority deny-list and does not relax existing tool/file/path pinning.

## Fixed-output process contract

`Invoke-NxbBoundedFixedOutput` is used in Windows preparation for:

- freshly installed pinned `cargo-audit.exe --version`;
- freshly installed pinned `cargo-deny.exe --version`;
- `rustup run 1.97.1 rustc --version` used in the create-only tooling receipt.

The same contract is independently present in the Windows validator for:

- pinned `cargo-audit.exe --version`;
- pinned `cargo-deny.exe --version`;
- `rustup run 1.97.1 rustc --version` used to validate the receipt and emit schema-v2 evidence;
- `rustup run 1.97.1 cargo --version` used in schema-v2 evidence.

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

`Get-ToolVersion` retains its exact-version-token check after bounded capture. The validator resolves `rustup` as an application and passes that resolved application path to the bounded helper instead of invoking a post-hoc pipeline capture.

## Preparation exact-head regression probe authority

The preparation fixed-output helper has a dedicated supported-Windows regression probe:

`scripts/nxb-153-windows-tool-version-output-probe.ps1`

Current exact Git blob:

`381529e260f2a9c9b0f20bff3f29a8b2c6ef6e84`

Probe source commits:

- `a54d2754a552514c8b4390f0f3c45cf738025973` — introduced the exact-head production-helper probe;
- `90b24664b8728afa31a74cb59f7c0febf5229b0b` — fixed the StrictMode literal source-pattern check and widened the probe-only nested-process timeout defaults to reduce false negatives;
- `5f83a9d9ef6957b4d560a3fa1784341632dfc6c5` — added a distinct post-stdout-exit timeout primitive by explicitly closing the redirected Windows stdout handle while the fixture process remains alive.

The probe does not reimplement the preparation helper. It:

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

## Validator source-regression authority

The validator's pre-H2 fixed-output path is bound by:

`crates/nxb-core/tests/windows_validator_fixed_output_source_contract.rs`

The Rust test uses `std` only and can therefore run in both canonical Linux and Windows workspace test suites while inspecting committed PowerShell source. Its first test requires:

- production `4096 / 30000 / 30000` constants;
- redirected stdout with inherited stderr and no shell execution;
- incremental `ReadAsync` raw-byte accounting;
- bounded post-stdout process exit;
- nonzero exit rejection;
- strict UTF-8 after byte admission;
- <=256-character semantic output;
- recursive `Kill(true)` cleanup;
- application-only `rustup` resolution;
- bounded `cargo-audit`, `cargo-deny`, `rustc` and `cargo` version routes;
- absence of `Out-String`, `ReadToEndAsync`, `ReadLineAsync` and parameterless `WaitForExit()` in the validator source;
- helper/version setup occurring before the first H2 delegation.

The first test expects one bounded-helper definition and exactly three source call sites: the common security-tool path, `rustc`, and `cargo`. The common security-tool path is invoked separately for cargo-audit and cargo-deny at runtime.

The second test reads both exact workspace sources and extracts the complete `Invoke-NxbBoundedFixedOutput` source region from each. It requires:

- validator and preparation helper source regions to be identical;
- both sources to retain the same `4096 / 30000 / 30000` production constants.

This makes dynamic-probe inheritance fail closed: the existing exact-head Windows probe dynamically executes the preparation helper, while the cross-platform Rust contract refuses a validator helper that is not the same source primitive. This is still not a substitute for running the validator itself on supported Windows, because executable identity, PowerShell/.NET/runtime behavior and surrounding call-site lifetime remain runtime properties.

Because canonical Linux immutable validation and Windows dependency validation both execute `cargo test --workspace --all-features --locked`, both source-regression tests are part of both full Rust test paths.

## Existing identity and receipt controls retained

This change does not relax the existing preparation or validation authority:

- repository and target/validation namespaces remain pinned;
- exact-head create-new preparation and validation locks remain required;
- exact-head tool root must not pre-exist without an admitted receipt;
- cargo-audit and cargo-deny remain installed into the exact-head tool root;
- every namespace component used to resolve the installed executables remains pinned without delete sharing;
- both tool executable files are pinned before version/hash inspection;
- pinned-stream SHA-256 is compared with pathname SHA-256 where required;
- Git HEAD and clean-worktree authority are rechecked before publication;
- tooling receipt and validation evidence remain create-only and bounded;
- tool handles remain held through their authority intervals;
- `RUSTC_WRAPPER` remains rejected together with the other compiler/Cargo/Python override variables.

## Relationship to the H1/H2 Out-String guard

`Out-String` occurrences inside the immutable Windows H1/H2 chain are reviewed separately. Those captures execute beneath the existing bounded H2 `Out-String` proxy, which applies byte/object limits before delegating admitted bounded objects to the module-qualified real formatter and self-tests formatting equivalence.

Preparation tool-version calls occur outside that H2 string-guard boundary and therefore use an independent native-process fixed-output helper plus the dedicated Windows regression probe.

The validator version calls also occur **before** its first H2 delegation. They are independently bounded by the validator's native-process helper and guarded against source regression by the cross-platform Rust integration tests. The validator source itself no longer contains `Out-String`.

## Canonical admission integration

`scripts/review-nxb-153-windows-admission.ps1` executes the exact-head preparation tool-version probe as its first mandatory runtime phase before process-lifecycle evidence review and schema-v2 closure review.

The admission wrapper pins both the probe and production tool-preparation source with write/delete sharing withheld for the complete admission review, rechecks their Git objects and HEAD after the probe, and withholds probe output through all later authority/cleanup checks.

The validator bounded-output source contract, including helper equivalence to the dynamically probed preparation primitive, is exercised through the normal Rust workspace suite in both canonical platform validation paths. Supported Windows validator execution remains separately mandatory.

A direct standalone probe run remains useful diagnostically but is not a substitute for the canonical admission wrapper.

## Remaining runtime proof

Supported exact-head Windows execution must still demonstrate at least:

- successful execution of the preparation tool-version probe as part of `scripts/review-nxb-153-windows-admission.ps1` against the exact final head;
- successful execution of both validator source-regression tests under pinned Rust 1.97.1;
- normal preparation and validator cargo-audit/cargo-deny/rustc version capture plus validator cargo version capture;
- stalled stdout timeout;
- output above 4 KiB rejection before unbounded retention;
- invalid UTF-8 rejection;
- nonzero exit propagation;
- actual post-stdout exit timeout behavior;
- recursive process-tree cleanup on failure;
- preservation of tool-path pinning while version children execute;
- correct create-only tooling receipt and validation-evidence publication with later exact-object review.

This is in addition to the existing NXB-153 Windows H2, broker, direct-child, schema-v2 and same-head dual-platform admission requirements.

Current schema-v2 evidence remains intentionally:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 and issues #90-#98 remain open/not admitted. NXB-154 must not use this branch as an admitted implementation base until real same-head Linux + Windows closure succeeds.
