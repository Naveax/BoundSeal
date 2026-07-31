# NXBounty

NXBounty is a private, deterministic and scope-enforced bug bounty research platform for explicitly authorized targets.

## Current status

The architecture-contract program is complete through **NXB-119**. The repository contains 34 Rust crates covering policy, scope enforcement, destination and DNS pinning, one-use transport permits, bounded streams, strict HTTP/1 framing, secret/session boundaries, redirect isolation, TLS identity contracts, request planning, passive analysis, safe validation, evidence/reporting, workflow certification, replay, release governance, lifecycle governance and post-closure governance.

This does **not** mean the product is a live scanner. The current release is a networkless contract-complete foundation with deterministic fixtures and a synthetic end-to-end smoke demo.

## What works

- policy and authorization validation;
- public-destination guardrails and scope narrowing;
- one-use permit, executor, stream, TLS and HTTP contract layers;
- in-memory secret, session and cookie lifecycle contracts;
- deterministic content analysis, planning, passive findings and validation contracts;
- evidence, reporting, workflow, replay and release/lifecycle certification;
- append-only metadata-only audit chains;
- synthetic system smoke receipt generation and verification;
- workspace-wide formatting, Clippy, tests and dependency policy checks.

## What is intentionally not enabled

- real DNS resolution, sockets or public-network traffic;
- browser, proxy or scanner automation;
- credential discovery, brute force or spraying;
- destructive testing, persistence or lateral movement;
- arbitrary shell, process or plugin execution;
- raw secret, cookie, authorization or request/response-body storage.

## Toolchain

The workspace is pinned by `rust-toolchain.toml`. Build with the committed lockfile:

```bash
cargo build --workspace --locked
cargo test --workspace --all-features --locked
```

## CLI

Validate the example policy and event:

```bash
cargo run -p nxb-core --locked -- validate-policy examples/target.policy.toml
cargo run -p nxb-core --locked -- validate-event examples/event.json
cargo run -p nxb-core --locked -- check-destination 8.8.8.8
```

Inspect repository status:

```bash
cargo run -p nxb-core --locked -- system-status
```

Run and verify the deterministic synthetic architecture demo:

```bash
cargo run -p nxb-core --locked -- demo-run --output target/nxb-demo-receipt.json
cargo run -p nxb-core --locked -- verify-demo target/nxb-demo-receipt.json
```

The demo performs no I/O outside the selected output file. It creates a hash-chained receipt for the policy, gateway, transport, stream, TLS, HTTP, analysis, planning, finding, validation, evidence/reporting and closure stages.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/STATUS.md`](docs/STATUS.md)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- [`docs/RELEASE-CHECKLIST.md`](docs/RELEASE-CHECKLIST.md)
- [`SECURITY.md`](SECURITY.md)
- [`CHANGELOG.md`](CHANGELOG.md)

## Repository status

Private. Every workspace package is marked `publish = false`. The intended first checkpoint is `v0.1.0-contract-complete`.
