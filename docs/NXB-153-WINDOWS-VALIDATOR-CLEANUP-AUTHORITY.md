# NXB-153 Windows Validator Cleanup Authority

Status: **source + deterministic fault-harness closure staged / supported Windows exact-head admission pending / not admitted**.

This document records the NXB-153 blocker #104 authority boundary. It does not claim supported Windows/NTFS/PowerShell runtime PASS. PR #89 remains draft until the exact final head passes the canonical Linux + Windows admission workflow.

## Required invariant

A Windows validation PASS is authoritative only after the protected validation body, evidence publication arbitration, every mandatory cleanup action, validation-lock release and caller-location restoration have all succeeded.

A cleanup failure must never:

- appear after PASS has already been emitted;
- short-circuit later mandatory cleanup;
- hide the primary validation/evidence-publication failure;
- leave the validator in an implicit-success state.

## Production cleanup state machine

`scripts/validate-nxb-153-windows-inner.ps1` routes cleanup through one shared `Invoke-NxbValidationCleanup` state machine. It independently attempts cleanup for:

- immutable-source stream;
- Cargo.lock stream;
- tooling-receipt stream;
- cargo-deny stream;
- cargo-audit stream;
- validation lock;
- retained namespace handles in reverse order;
- pushed PowerShell location.

Errors are accumulated rather than allowing the first disposal exception to skip later cleanup.

`Assert-NxbValidationOutcome` then arbitrates the protected-body result:

1. preserve the primary validation failure and append cleanup diagnostics when both exist;
2. fail closed when validation succeeded but any cleanup failed;
3. require an explicit successful-validation state;
4. allow PASS/HEAD/tool/evidence output only after those gates.

Evidence publication uses the same primary-before-cleanup rule through `Assert-NxbEvidencePublicationOutcome`: a publication/write/read-back failure remains primary if evidence-handle disposal also fails.

## Deterministic cleanup fault harness

The validator exposes only the bounded self-test selector `-SelfTest cleanup-faults`. The harness invokes the same production cleanup/arbitration helpers rather than a duplicate model.

It proves that:

- an injected early cleanup failure is retained while later stream/namespace cleanup still runs;
- a real create-new `DeleteOnClose` validation-lock stream is released even after an earlier injected cleanup failure;
- the original PowerShell location is restored;
- an injected late cleanup failure cannot pass outcome arbitration;
- evidence-publication failure remains primary when evidence cleanup also fails;
- the clean arbitration path succeeds.

The fault probes are deterministic local objects and perform no network activity or external mutation.

## Canonical admission wiring

`.github/workflows/nxb-153-admission.yml` executes `Prove Windows validator cleanup fault arbitration` on the exact event head in the supported `windows-2025` job before the normal Windows preparation/validation/review path.

The normal path still performs exact-head checkout, pre-Git authority rejection, hosted Git/Python normalization, sealed-tool preparation, immutable-source validation, process lifecycle evidence and final admission review. The cleanup self-test is additive and does not replace those gates.

## Source regression

`crates/nxb-core/tests/windows_validator_cleanup_source_contract.rs` binds the shared label-driven cleanup state machine, evidence-publication arbitration, deterministic fault harness, post-cleanup PASS ordering and canonical workflow wiring. The regression checks shared cleanup labels plus the single generic cleanup-error formatter rather than duplicating stale per-resource diagnostic strings.

## Admission still pending

Source/harness staging is not supported-platform admission. Blocker #104 remains open until the final canonical NXB-153 head runs the cleanup fault harness on supported Windows and the same head completes the rest of the Windows and Linux schema-v2 admission gates.

No runtime PASS is claimed by this document. NXB-154 must not use NXB-153 as an admitted base before that closure.
