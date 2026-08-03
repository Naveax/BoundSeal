# NXBounty

NXBounty is a private, deterministic and scope-enforced bug bounty research platform for explicitly authorized targets.

## Current status

The verified implementation is complete through the **NXB-141 unified operator contract block**. The workspace now contains 40 private Rust crates spanning policy and scope enforcement, pinned live HTTPS transport, signed one-request and bounded discovery sessions, passive analysis/reporting, vault-backed session injection, a signed one-use external vault-provider lifecycle, a pinned process-backed provider bridge, and a networkless unified artifact/activation binder.

This is still not an unrestricted scanner. Live execution remains compile-time gated, explicitly acknowledged, signed, same-origin, HTTPS/443, GET/HEAD-only, sequential and resource bounded. The repository does not yet contain a unified authenticated live-execution command or a password-manager-specific adapter.

## What works

- policy and authorization validation;
- public-destination guardrails and scope narrowing;
- one-use permit, executor, stream, TLS and HTTP contract layers;
- in-memory and external-provider secret/session lifecycle contracts;
- absolute-path and SHA-256-pinned process provider with bounded anonymous-pipe framing;
- signed unified component binding and one-use activation consumption;
- bounded, no-clobber networkless plan and activation-template publication;
- deterministic content analysis, planning, passive findings and validation contracts;
- evidence, reporting, workflow, replay and release/lifecycle certification;
- append-only metadata-only audit chains;
- synthetic system smoke receipt generation and verification;
- workspace-wide formatting, Clippy, tests and dependency policy checks.

## What is intentionally not enabled

- unrestricted resolver, socket or public-network traffic;
- a unified authenticated live-execution loop;
- browser, proxy or unrestricted scanner automation;
- credential discovery, brute force or spraying;
- destructive testing, persistence or lateral movement;
- arbitrary or unpinned shell, process or plugin execution;
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

The `nxb-unified-operator` binary is networkless. It binds verified component artifacts, emits or verifies a unified plan, emits an external-signing template, verifies activation certificates and consumes an activation exactly once. It does not execute a scan.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/STATUS.md`](docs/STATUS.md)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- [`docs/NXB-140-PINNED-PROCESS-VAULT-PROVIDER.md`](docs/NXB-140-PINNED-PROCESS-VAULT-PROVIDER.md)
- [`docs/NXB-141-UNIFIED-OPERATOR-CONTRACT.md`](docs/NXB-141-UNIFIED-OPERATOR-CONTRACT.md)
- [`docs/RELEASE-CHECKLIST.md`](docs/RELEASE-CHECKLIST.md)
- [`SECURITY.md`](SECURITY.md)
- [`CHANGELOG.md`](CHANGELOG.md)

## Repository status

Every workspace package is marked `publish = false`. The repository includes verified live-network and pinned process-provider components plus a networkless unified authorization contract. Live authenticated orchestration still requires a future checkpointed execution block, signed plans, one-use activations and explicit operator acknowledgement.
