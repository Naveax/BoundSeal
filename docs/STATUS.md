# Repository status

## Completion

- Fully validated architecture milestones: NXB-0 through NXB-150
- Workspace manifest members: 49 private crates
- Current package version: 0.1.0
- Distribution status: private, `publish = false`
- Execution mode: deterministic by default; signed and explicitly gated live HTTPS available
- Submission mode: operator-reviewed manual handoff only; automatic submission disabled
- Release checkpoint: `v0.1.0-contract-complete` merged; tag creation remains an external release operation

## Quality gates

GitHub-hosted Actions are disabled for this repository. The workflow files were removed from `main`, and NXB-150 does not add or re-enable a workflow.

NXB-150 provides:

- a private `nxb-evidence-key-provider-process` crate;
- reuse of the NXB-140 absolute-path and SHA-256-pinned process transport;
- capability binding for exact executable digest, process identity, store/key mapping, provider-handle SHA-256, optional version policy, timeout and session expiry;
- one NXB-149 acquisition mapped to one process-provider session;
- zeroizing transfer from process secret material into the NXB-149 32-byte key boundary;
- completed/aborted teardown mapping with timeout and fatal failure remaining abortable;
- a real child-process fixture;
- adversarial tests for success, executable mismatch, store/request mismatch, version mismatch, short key, logical failure, timeout, one-fetch enforcement and debug redaction;
- exact-head Windows and Linux validation harnesses;
- pinned Rust `1.97.1`, cargo-audit `0.22.2` and cargo-deny `0.20.2`;
- schema-v2 per-platform evidence and deterministic dual-platform closure.

The mandatory validation command set is:

```text
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

A final PR head is merge-eligible only when both platforms validate that same unchanged head and the deterministic closure reports `ready_for_manual_pr_review`.

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
| Pinned process evidence-key adapter | Complete; exact-head dual-platform validation required for every final PR head |
| Password-manager/OS credential-store helper | Not implemented |
| Cloud KMS, HSM or PKCS#11 helper | Not implemented |
| Automatic HackerOne submission | Intentionally not implemented |
| Browser/proxy automation | Not implemented |

## Release meaning

The repository contains the signed bounded live-execution chain from unified activation through authenticated runtime, resumable execution, terminal teardown, cryptographic closure and operator-reviewed manual-submission handoff. NXB-148 adds persistent authenticated encryption for evidence records that already passed redaction and content-address validation. NXB-149 adds the provider-neutral signed lifecycle for acquiring the exact 256-bit sealing key without serializing, logging or persisting key bytes. NXB-150 connects that lifecycle to the existing pinned process-provider security boundary.

The repository does not claim unrestricted autonomous scanning, browser automation, credential discovery, active exploitation, arbitrary process execution or automatic HackerOne submission.
