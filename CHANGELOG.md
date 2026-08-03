# Changelog

All notable changes to NXBounty are documented here.

## [Unreleased]

### NXB-141

- Added a signed unified operator plan binding discovery, policy, target origin, session injection, external-vault lifecycle, provider identity/capability, account partition, secret roots and execution budgets.
- Added external Ed25519 activation templates, verification and atomic one-use consumption.
- Added a networkless binder CLI for plan, verification and activation operations.
- Added no-clobber synchronized artifact publication and bounded artifact/key-file reads.
- Added passive-path whitespace rejection and explicit sequential/checkpoint/workspace constraints.
- Kept live unified execution disabled pending checkpoint recovery, workspace accounting, provider startup, request injection and teardown-order validation.

### NXB-140

- Added a concrete process-backed implementation of the NXB-139 external vault-provider contract.
- Bound the provider executable's absolute path and SHA-256 digest to the signed provider instance identity.
- Added shell-free startup with cleared environment, null stderr and anonymous pipe-only protocol transport.
- Added bounded length-prefixed metadata/secret framing and zeroizing secret buffers.
- Added exact handshake identity, sequence, timeout, single-session and clean-exit enforcement.
- Added real child-process integration tests and permanent adversarial workflow coverage.
- Updated repository status documentation through NXB-140.

### NXB-139

- Added a signed, one-use external vault-provider bootstrap plan.
- Added metadata-only provider begin/fetch/commit-abort requests and zeroizing secret material.
- Added transactional vault/session provisioning with exact origin and account partitioning.
- Added rollback on partial fetch, vault, broker or provider-commit failure.
- Added explicit session and secret teardown receipts.
- Updated repository status documentation through NXB-139.

### Planned

- Password-manager, HSM and OS credential-store-specific provider adapters.
- Checkpointed unified authenticated live-execution CLI.
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
