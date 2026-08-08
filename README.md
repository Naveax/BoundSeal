# NXBounty

NXBounty is a private, deterministic and scope-enforced bug bounty research platform for explicitly authorized targets.

## Current status

The implementation is complete through the **NXB-150 pinned process evidence-key provider** block. The workspace contains 49 private Rust crates spanning policy and scope enforcement, pinned live HTTPS transport, signed one-use activation, authenticated operator state, a resumable bounded runner, a signed live-run host, cryptographic run closure, an operator-reviewed manual submission boundary, create-only encrypted evidence persistence and concrete pinned-process evidence-key acquisition.

NXB-150 binds the NXB-149 provider-neutral evidence-key lifecycle to the existing NXB-140 absolute-path and SHA-256-pinned process transport. Its merge gate is exact-head Windows and Linux validation with deterministic dual-platform evidence closure; every final PR head must satisfy that gate independently.

This is not an unrestricted scanner. Live execution remains compile-time gated, explicitly acknowledged, signed, same-origin, HTTPS/443, GET/HEAD-only, sequential and resource bounded. NXB-147 remains a networkless manual handoff, NXB-148 persists only previously validated and redacted evidence records, NXB-149 acquires only the exact plan-bound sealing key through a one-fetch provider lifecycle, and NXB-150 does not bundle a provider-specific secret-store helper. None of these blocks calls HackerOne, accesses browser credentials or submits reports automatically.

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
- an NXB-150 adapter that reuses the pinned, shell-free process-provider transport;
- capability binding for executable digest, process identity, store/key mapping, provider-handle digest, version policy, session expiry and exact nanosecond timeout;
- real process-fixture coverage for success, mismatch, short-key, logical-failure, timeout, sub-millisecond capability separation and one-fetch paths;
- exact acknowledgement of untested scope for partial closures;
- deterministic content analysis, passive findings, validation, evidence and reporting contracts;
- append-only metadata-only audit chains;
- exact-head Linux and Windows validation with RustSec, cargo-deny and deterministic closure review.

## What is intentionally not enabled

- unrestricted resolver, socket or public-network traffic;
- browser, proxy or unrestricted scanner automation;
- credential discovery, brute force or spraying;
- destructive testing, persistence or lateral movement;
- arbitrary or unpinned shell, process or plugin execution;
- raw secret, cookie, authorization or request/response-body storage;
- automatic HackerOne or third-party report submission;
- a bundled password-manager, cloud-KMS, HSM, PKCS#11 or OS credential-store helper.

## Toolchain

The workspace is pinned by `rust-toolchain.toml`. Build with the committed lockfile:

```bash
cargo build --workspace --locked
cargo test --workspace --all-features --locked
```

GitHub-hosted Actions are disabled for this repository. NXB-150 validation is exposed through exact-head local harnesses:

Linux:

```bash
bash scripts/validate-nxb-150-linux.sh
```

Windows:

```powershell
pwsh -NoProfile -File .\scripts\validate-nxb-150-windows.ps1
```

Both require Rust `1.97.1`, the fixed canonical `Cargo.lock` SHA-256, package and workspace format/check/Clippy/tests, RustSec and cargo-deny. Successful evidence is written only after all gates complete on one unchanged clean head.

Core commands executed by the harnesses:

```bash
cargo metadata --locked
cargo fmt --all -- --check
cargo check -p nxb-evidence-key-provider-process --all-features --locked
cargo clippy -p nxb-evidence-key-provider-process --all-targets --all-features --locked -- -D warnings
cargo test -p nxb-evidence-key-provider-process --all-features --locked -- --test-threads=1
cargo test -p nxb-vault-provider --locked -- --test-threads=1
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked -- --test-threads=1
cargo audit
cargo deny check
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

NXB-147 is a library contract for creating and verifying an immutable operator handoff. Manual submission remains a deliberate human action outside the repository. NXB-148 is a library-backed persistent store for encrypting canonical redacted `EvidenceRecord` values with externally supplied key material. NXB-149 defines the signed, provider-neutral lifecycle that obtains that key without serializing or logging key bytes. NXB-150 maps that lifecycle to the existing pinned process-provider protocol.

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
- [`docs/NXB-150-PINNED-PROCESS-EVIDENCE-KEY-PROVIDER.md`](docs/NXB-150-PINNED-PROCESS-EVIDENCE-KEY-PROVIDER.md)
- [`docs/RELEASE-CHECKLIST.md`](docs/RELEASE-CHECKLIST.md)
- [`SECURITY.md`](SECURITY.md)
- [`CHANGELOG.md`](CHANGELOG.md)

## Repository status

Every workspace package is marked `publish = false`. The repository contains the bounded signed live-execution chain through terminal closure and manual-submission handoff, encrypted persistence for validated redacted evidence, a signed one-fetch key-provider lifecycle and its pinned-process adapter. It does not claim unrestricted autonomous scanning, active exploitation, automatic submission or credential discovery.
