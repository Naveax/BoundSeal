# Changelog

All notable changes to BoundSeal are documented here.

## [Unreleased]

### BSL-150 — pinned process evidence-key provider

- Added the private `bsl-evidence-key-provider-process` workspace crate.
- Adapted the BSL-149 evidence-key lifecycle to the existing BSL-140 shell-free, absolute-path and SHA-256-pinned process transport.
- Bound executable digest, process identity, exact store/key mapping, provider-handle SHA-256, optional provider-version policy, timeout and session expiry into the adapter capability identity.
- Added zeroizing transfer from external provider material into the exact 32-byte evidence-sealing key boundary.
- Added a real process fixture and adversarial coverage for success, identity/digest and request mismatches, short key material, provider-version drift, logical failure, timeout, debug redaction and one-fetch enforcement.
- Added exact-head Linux and Windows validation harnesses, pinned Rust and supply-chain tools, schema-v2 platform evidence and deterministic dual-platform closure review.
- Preserved the repository-wide GitHub Actions shutdown; no workflow was added or re-enabled.

Every final PR head must pass the committed-lockfile package/workspace gates, RustSec, cargo-deny and dual-platform closure before merge.

## [0.1.0-contract-complete] - 2026-08-04

This checkpoint closes the BSL-0 through BSL-147 contract architecture.

### Safety and authorization

- Explicit authorization, scope, destination, DNS, TLS, HTTP and budget contracts.
- Signed unified operator plans and one-use activation certificates.
- Exact account, tenant, role, session, provider and secret-binding identities.
- Fail-closed redirects, query-bearing requests, unsafe methods and unapproved active probes.

### Authenticated live execution

- Vault-backed request injection with zeroized secret material.
- External vault-provider lifecycle and absolute-path/SHA-256-pinned process bridge.
- Checkpoint-bound authenticated request transactions.
- Deterministic resumable GET/HEAD queue with emergency stop and crash reconciliation.
- Signed live-run launch host with ordered external teardown.

### Closure and operator handoff

- Signed terminal run closure and immutable evidence attestation.
- Exact runtime, runner, launch, teardown, report, export and audit-root binding.
- Signed operator-reviewed manual-submission handoff.
- Canonical report and finding validation with exact partial-scope acknowledgement.
- Automatic HackerOne submission remains intentionally disabled.

### Verification and release evidence

- Canonical committed `Cargo.lock`.
- Full workspace format, check, all-target Clippy and tests.
- Deterministic synthetic system demo.
- Ubuntu and Windows contract regression matrices.
- RustSec and cargo-deny policy checks.
- Release binary, deterministic CycloneDX SBOM, source manifest and SHA-256 evidence.

### Known boundaries

- No browser or proxy automation.
- No password-manager or operating-system credential-store adapter.
- No credential discovery.
- No unrestricted autonomous scanning or active exploitation.
- Persistent encrypted evidence storage remains a contract without a production sealer.
