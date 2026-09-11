# NXB-153 Windows Validator Cleanup Authority

## Status

This document records the source-staged fix for NXB-153 blocker #104.

It does **not** claim supported Windows/NTFS/PowerShell runtime PASS. PR #89 remains draft/not admitted and #104 remains open until exact-final-head failure-injection and cleanup/recovery behavior are proven on supported Windows.

## Finding

The Windows validator previously emitted its PASS/HEAD/tool/evidence lines inside the protected validation body, before mandatory cleanup had completed. Its outer `finally` also performed raw sequential `Dispose()` operations followed by `Pop-Location`.

A cleanup exception could therefore:

- occur after success text was already visible;
- skip later stream/validation-lock/namespace cleanup;
- skip caller-location restoration;
- mask an earlier evidence publication failure if the evidence stream disposal also failed.

That ordering was incompatible with fail-closed validation authority. PASS is not authoritative until mandatory cleanup and location restoration succeed.

## Current source authority

Windows validator:

`scripts/validate-nxb-153-windows-inner.ps1`

Current exact Git blob after the #104 source fix:

`49e0bde20ab23e13b96747c1e621054be26f4909`

Source-fix commit:

`8290c495a8f29905561a0c0eba12a9e18f37c280`

Cross-platform cleanup source regression:

`crates/nxb-core/tests/windows_validator_cleanup_source_contract.rs`

Current exact Git blob:

`efb90b97201b903a2311f6cd96689986dd0891d8`

Regression commits:

- `42ca76826c13d36db910ecc6310cbe3601782b4d` — introduced the cleanup/PASS-withholding source contract;
- `f977cc52576e503c558196de71b19be5a8814f1d` — corrected duplicate-marker accounting so the regression itself is fail-closed rather than producing a false failure.

## Cleanup and PASS contract

The current validator:

1. records whether repository location was successfully pushed;
2. captures the primary validation failure instead of allowing cleanup to replace it;
3. attempts every pinned-stream cleanup independently;
4. attempts validation-lock cleanup independently;
5. attempts every namespace-handle cleanup independently in reverse order;
6. attempts `Pop-Location` independently;
7. collects cleanup failures instead of allowing the first cleanup exception to skip later cleanup;
8. if validation failed, returns the primary failure and includes any cleanup failures;
9. if validation succeeded but cleanup failed, fails closed;
10. requires an explicit successful-validation state after cleanup arbitration;
11. emits PASS/HEAD/tool/evidence lines only after all mandatory cleanup and location restoration succeed.

Published create-only evidence is not pathname-deleted merely because later cleanup fails.

## Evidence publication cleanup

The create-only schema-v2 evidence handle has its own primary/cleanup failure arbitration.

If evidence write/flush/read-back fails and `Dispose()` also fails, the publication failure remains the primary failure and the cleanup failure is appended. If publication succeeds but evidence-handle cleanup fails, validation fails before the validator can mark the run successful.

This prevents a disposal failure from masking the more important evidence-integrity failure.

## Cross-platform source regression

The `std`-only Rust integration test checks committed PowerShell source without executing Windows APIs. It requires:

- explicit primary-failure, cleanup-error, location and validation-success state;
- independently guarded cleanup for every pinned stream and the validation lock;
- independently guarded reverse-order namespace cleanup;
- independently guarded `Pop-Location`;
- removal of the legacy raw sequential cleanup shape;
- evidence publication primary/cleanup arbitration before validation success;
- validation success before post-cleanup error arbitration;
- primary-failure arbitration before cleanup-only failure arbitration;
- cleanup-only and explicit-success gates before PASS output.

Canonical Linux immutable validation and Windows dependency validation both execute `cargo test --workspace --all-features --locked`, so this source regression participates in both full Rust test paths.

This remains source-level evidence only.

## Supported-Windows runtime proof still required

Exact-final-head Windows execution must still prove at least:

- an injected early cleanup failure does not prevent later cleanup attempts;
- validation-lock release/recovery behavior after failure;
- location restoration on validation and cleanup failure paths;
- a late cleanup failure emits no PASS output;
- evidence write/read-back failure remains primary if evidence-handle cleanup also fails;
- successful cleanup preserves the existing create-only schema-v2 evidence behavior and PASS output;
- no source/object/path authority is weakened while adding cleanup arbitration.

Until those tests and the rest of NXB-153 same-head Linux + Windows admission succeed, #104 remains open and NXB-154 must not use NXB-153 as an admitted base.
