# Repository status

## Completion

- Architecture milestones: NXB-0 through NXB-139
- Workspace crates: 38
- Current package version: 0.1.0
- Distribution status: private, `publish = false`
- Execution mode: deterministic by default; signed and explicitly gated live HTTPS available
- Planned checkpoint: `v0.1.0-contract-complete`

## Quality gates

The permanent CI requires:

- pinned Rust toolchain;
- committed `Cargo.lock`;
- `cargo fmt --all --check`;
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`;
- `cargo test --workspace --all-features --locked`;
- deterministic demo generation and verification;
- RustSec dependency audit;
- cargo-deny advisories, licenses, bans and source checks.

## Product readiness

| Area | Status |
|---|---|
| Safety and authorization contracts | Complete |
| Networkless fixture coverage | Complete |
| Synthetic end-to-end smoke demo | Complete |
| Documentation and release metadata | Complete |
| Scope-controlled HTTPS/TLS backend | Complete |
| Signed one-request and bounded discovery sessions | Complete |
| Vault-backed authenticated request injection | Complete |
| External vault-provider lifecycle contract | Complete |
| Concrete external vault backend | Not implemented |
| Unified authenticated operator CLI | Not implemented |
| Browser/proxy automation | Not implemented |
| Encrypted persistent evidence store | Contract only; production sealer not implemented |

## Release meaning

The repository now includes a bounded live execution path. It does not claim unrestricted autonomous scanning, browser automation, credential discovery, active exploitation, or automatic HackerOne submission.
