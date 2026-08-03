# Changelog

All notable changes to NXBounty are documented here.

## [Unreleased]

### NXB-139

- Added a signed, one-use external vault-provider bootstrap plan.
- Added metadata-only provider begin/fetch/commit-abort requests and zeroizing secret material.
- Added transactional vault/session provisioning with exact origin and account partitioning.
- Added rollback on partial fetch, vault, broker or provider-commit failure.
- Added explicit session and secret teardown receipts.
- Updated repository status documentation through NXB-139.

### Planned

- Concrete external vault provider adapters.
- Unified authenticated operator CLI.
- Encrypted local evidence persistence.

## [0.1.0-contract-complete] - 2026-07-31

### Added

- NXB-0 through NXB-119 deterministic architecture contracts.
- Thirty-four private Rust workspace crates.
- Scope, destination, DNS-pin, transport, stream, TLS and strict HTTP/1 contracts.
- Secret, session, cookie and redirect isolation.
- Content analysis, planning, passive analysis and safe inert validation.
- Evidence, reporting, workflow, replay and release/lifecycle governance.
- Pinned Rust toolchain and committed dependency lockfile.
- Dependency advisory, license and source-policy CI gates.
- Deterministic synthetic system demo and receipt verifier.
- Current architecture, status, security and release documentation.

### Security

- No live network, browser, scanner, shell, process or deployment adapter.
- No credential attacks, destructive testing, persistence or lateral movement.
- No raw secret or HTTP body material in public audit/demo receipts.
