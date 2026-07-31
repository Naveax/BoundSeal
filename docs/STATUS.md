# Repository status

## Completion

- Architecture milestones: NXB-0 through NXB-119
- Workspace crates: 34
- Current package version: 0.1.0
- Distribution status: private, `publish = false`
- Execution mode: deterministic and networkless
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
| Real resolver/socket/TLS backend | Not implemented |
| Browser/scanner automation | Not implemented |
| Live authorized-target runner | Not implemented |
| Encrypted persistent evidence store | Not implemented |

## Release meaning

`contract-complete` means the safety and governance architecture is implemented and regression-tested. It does not claim that NXBounty can scan a live HackerOne target.
