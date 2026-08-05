# NXBounty

NXBounty is a private, deterministic and scope-enforced bug bounty research platform for explicitly authorized targets.

## Current status

The implementation is complete through the **NXB-149 signed evidence key-provider lifecycle block**. The workspace contains 48 private Rust crates spanning policy and scope enforcement, pinned live HTTPS transport, signed one-use activation, authenticated operator state, a resumable bounded runner, a signed live-run host, cryptographic run closure, an operator-reviewed manual submission boundary, create-only encrypted evidence persistence and provider-neutral evidence-key acquisition.

This is not an unrestricted scanner. Live execution remains compile-time gated, explicitly acknowledged, signed, same-origin, HTTPS/443, GET/HEAD-only, sequential and resource bounded. NXB-147 remains a networkless manual handoff, NXB-148 persists only previously validated and redacted evidence records, and NXB-149 acquires only the exact plan-bound sealing key through a one-fetch provider lifecycle. None of these blocks calls HackerOne, accesses browser credentials or submits reports automatically.

## What works

- policy, authorization and public-destination validation;
- exact scope narrowing and pinned DNS, socket, TLS, SNI, Host and HTTP identities;
- one-use permits, signed unified plans and one-use activation consumption;
- vault-backed session injection and a SHA-256-pinned external provider process bridge;
- durable authenticated operator checkpoints and recovery journals;
- deterministic, bounded and resumable GET/HEAD execution;
- signed live-run launch, ordered teardown and fail-closed lifecycle handling;
- cryptographically bound terminal run closure and evidence attestation;
- canonical report/export verification and signed manual-submission handoff;
- AES-256-GCM persistent sealing for validated redacted evidence records;
- create-only atomic evidence publication, canonical recovery and deterministic verification manifests;
- signed provider-neutral evidence-key plans and Ed25519 activations;
- exact provider identity, one-fetch key acquisition and mandatory completed/aborted teardown;
- metadata-only content-addressed evidence-key acquisition receipts;
- exact acknowledgement of untested scope for partial closures;
- deterministic content analysis, passive findings, validation, evidence and reporting contracts;
- append-only metadata-only audit chains;
- Linux and Windows adversarial contract validation;
- workspace formatting, Clippy, tests and dependency-policy gates.

## What is intentionally not enabled

- unrestricted resolver, socket or public-network traffic;
- browser, proxy or unrestricted scanner automation;
- credential discovery, brute force or spraying;
- destructive testing, persistence or lateral movement;
- arbitrary or unpinned shell, process or plugin execution;
- raw secret, cookie, authorization or request/response-body storage;
- automatic HackerOne or third-party report submission;
- concrete password-manager, cloud-KMS, HSM or OS credential-store evidence-key adapters.

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

The `nxb-unified-operator` binary is networkless. It binds verified component artifacts, emits or verifies a unified plan, emits an external-signing template, verifies activation certificates and consumes an activation exactly once.

NXB-147 is a library contract for creating and verifying an immutable operator handoff. Manual submission remains a deliberate human action outside the repository. NXB-148 is a library-backed persistent store for encrypting canonical redacted `EvidenceRecord` values with externally supplied key material. NXB-149 defines the signed, provider-neutral lifecycle that obtains that key without serializing or logging key bytes.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/STATUS.md`](docs/STATUS.md)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- [`docs/NXB-140-PINNED-PROCESS-VAULT-PROVIDER.md`](docs/NXB-140-PINNED-PROCESS-VAULT-PROVIDER.md)
- [`docs/NXB-141-UNIFIED-OPERATOR-CONTRACT.md`](docs/NXB-141-UNIFIED-OPERATOR-CONTRACT.md)
- [`docs/NXB-146-SIGNED-RUN-CLOSURE.md`](docs/NXB-146-SIGNED-RUN-CLOSURE.md)
- [`docs/NXB-147-SIGNED-MANUAL-SUBMISSION-HANDOFF.md`](docs/NXB-147-SIGNED-MANUAL-SUBMISSION-HANDOFF.md)
- [`docs/NXB-148-PRODUCTION-EVIDENCE-SEALER.md`](docs/NXB-148-PRODUCTION-EVIDENCE-SEALER.md)
- [`docs/NXB-149-EVIDENCE-KEY-PROVIDER-LIFECYCLE.md`](docs/NXB-149-EVIDENCE-KEY-PROVIDER-LIFECYCLE.md)
- [`docs/RELEASE-CHECKLIST.md`](docs/RELEASE-CHECKLIST.md)
- [`SECURITY.md`](SECURITY.md)
- [`CHANGELOG.md`](CHANGELOG.md)

## Repository status

Every workspace package is marked `publish = false`. The repository now contains the bounded signed live-execution chain through terminal closure and manual-submission handoff, encrypted persistence for validated redacted evidence, and a signed one-fetch key-provider lifecycle. It does not claim unrestricted autonomous scanning, active exploitation, automatic submission, credential discovery or a concrete KMS/password-manager adapter.