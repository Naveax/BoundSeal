# Repository status

## Completion

- Architecture milestones: NXB-0 through NXB-149 contract block
- Workspace crates: 48
- Current package version: 0.1.0
- Distribution status: private, `publish = false`
- Execution mode: deterministic by default; signed and explicitly gated live HTTPS available
- Submission mode: operator-reviewed manual handoff only; automatic submission disabled
- Release checkpoint: `v0.1.0-contract-complete` merged; tag creation remains an external release operation

## Quality gates

The permanent CI requires:

- pinned Rust toolchain;
- canonical committed `Cargo.lock`;
- `cargo fmt --all --check`;
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`;
- `cargo test --workspace --all-features --locked`;
- Ubuntu and Windows contract regression tests;
- deterministic demo generation and verification;
- RustSec dependency audit;
- cargo-deny advisories, licenses, bans and source checks;
- secret-pattern scanning and immutable release evidence.

NXB-148 additionally requires Ubuntu and Windows package-level checks for canonical lockfile state, formatting, all-target Clippy, authenticated-encryption round trips and adversarial persistent-store recovery.

NXB-149 additionally requires Ubuntu and Windows package-level checks for signed plan activation, exact provider identity, one-fetch acquisition, key-size and lifetime validation, metadata-only receipts, mandatory success/failure teardown and redacted key diagnostics.

## Product readiness

| Area | Status |
|---|---|
| Safety and authorization contracts | Complete |
| Networkless fixture coverage | Complete |
| Synthetic end-to-end smoke demo | Complete |
| Scope-controlled HTTPS/TLS backend | Complete |
| Signed one-request and bounded discovery sessions | Complete |
| Vault-backed authenticated request injection | Complete |
| External vault-provider lifecycle contract | Complete |
| Concrete external vault backend | Complete; absolute-path and SHA-256-pinned process bridge |
| Unified operator artifact/activation contract | Complete; networkless binder and one-use activation |
| Durable authenticated operator state | Complete; canonical checkpoints and recovery journal |
| Unified authenticated live execution | Complete; bounded GET/HEAD runtime, resumable runner and signed host |
| Ordered external teardown | Complete; fail-closed terminal lifecycle binding |
| Signed run closure and evidence attestation | Complete |
| Signed manual-submission handoff | Complete; exact report/export and review binding |
| Encrypted persistent evidence store | Complete; AES-256-GCM, create-only atomic publication and deterministic verification manifest |
| Evidence sealing key-provider lifecycle | Complete; signed plan, exact identity, one fetch, mandatory teardown and metadata-only receipt |
| Automatic HackerOne submission | Intentionally not implemented |
| Password-manager/OS credential-store adapter | Not implemented |
| Cloud KMS or HSM key adapter | Not implemented |
| Browser/proxy automation | Not implemented |

## Release meaning

The repository contains the signed bounded live-execution chain from unified activation through authenticated runtime, resumable execution, terminal teardown, cryptographic closure and operator-reviewed manual-submission handoff. NXB-148 adds persistent authenticated encryption only for evidence records that already passed redaction and content-address validation. NXB-149 adds the provider-neutral signed lifecycle for acquiring the exact 256-bit sealing key without serializing, logging or persisting key bytes. The repository does not claim unrestricted autonomous scanning, browser automation, credential discovery, active exploitation, arbitrary process execution or automatic HackerOne submission.
