# Changelog

All notable changes to NXBounty are documented here.

## [Unreleased]

No post-contract-complete product changes are currently scheduled.

## [0.1.0-contract-complete] - 2026-08-04

This checkpoint closes the NXB-0 through NXB-147 contract architecture.

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
