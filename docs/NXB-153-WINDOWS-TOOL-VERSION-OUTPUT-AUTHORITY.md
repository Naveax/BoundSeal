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

The net change from the previous admitted source-stage head preserves the ambient compiler/Cargo/Python authority deny-list.

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

The preparation-tool version calls documented here occur outside that H2 string-guard boundary, which is why they required an independent native-process fixed-output helper.

## Remaining runtime proof

Supported exact-head Windows execution must still demonstrate at least:

- normal cargo-audit/cargo-deny/rustc version capture;
- stalled stdout timeout;
- output above 4 KiB rejection before unbounded retention;
- invalid UTF-8 rejection;
- nonzero exit propagation;
- post-stdout exit timeout;
- recursive process-tree cleanup on failure;
- preservation of tool-path pinning while the version child executes;
- correct create-only tooling receipt publication and later exact-object validation.

This is in addition to the existing NXB-153 Windows H2, broker, direct-child, schema-v2 and same-head dual-platform admission requirements.

Current schema-v2 evidence remains intentionally:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 and issues #90-#98 remain open/not admitted. NXB-154 must not use this branch as an admitted implementation base until real same-head Linux + Windows closure succeeds.
