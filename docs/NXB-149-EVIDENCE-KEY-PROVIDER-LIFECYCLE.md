# NXB-149 — Signed evidence key-provider lifecycle

## Purpose

NXB-149 defines the provider-neutral boundary used to acquire the 256-bit key consumed by the NXB-148 production evidence sealer. It separates evidence persistence from concrete password-manager, OS credential-store, cloud KMS and HSM implementations.

The lifecycle is networkless by contract. A future adapter may communicate with an external provider, but the adapter must implement this exact plan, activation, fetch and teardown boundary.

## Signed plan

The canonical `EvidenceKeyPlan` binds:

- exact provider identity and capability digest;
- exact evidence key identifier;
- exact evidence store identifier;
- exact policy snapshot SHA-256;
- activation Ed25519 public key;
- bounded issue and expiry times;
- exactly one permitted key fetch.

The plan ID and plan SHA-256 are content addressed. Mutation of any bound field invalidates the plan.

## Activation

An `EvidenceKeyActivation` contains an Ed25519 signature over a domain-separated canonical message containing the exact plan SHA-256. The activation is consumed by value by the acquisition API and cannot authorize a second fetch through the same invocation.

Activation verification occurs before the provider session begins.

## Provider lifecycle

An `EvidenceKeyProvider` implements four operations:

1. report its exact provider identity;
2. begin a session bound to the plan, store and policy snapshot;
3. fetch exactly one key bound to the exact request;
4. finish with either a completed or aborted metadata-only outcome.

Provider identity mismatch fails before `begin`. After a successful `begin`, every fetch, validation or sealer-construction failure produces an aborted outcome and requires `finish`. A teardown failure overrides an otherwise successful acquisition.

## Acquisition sequencing

`acquire_evidence_sealer` applies the lifecycle in a fixed order:

1. validate the canonical plan and active time window;
2. verify the exact Ed25519 activation;
3. compare the provider's reported identity with the plan;
4. begin the provider session;
5. issue one exact key request;
6. validate key ID, size and expiry;
7. build the metadata-only receipt and production sealer;
8. finish with a completed or aborted outcome;
9. return the sealer only after successful teardown.

No provider method is invoked before activation and identity validation. No second fetch path exists inside one acquisition call.

## Key material

`ProviderKeyMaterial` contains:

- key ID;
- provider version ID;
- expiry time;
- exactly 32 key bytes held in a `Zeroizing<Vec<u8>>`.

The key bytes are never serializable and are redacted from `Debug`. Invalid-length input is overwritten before rejection. Valid material must match the plan key ID and remain valid through the complete plan lifetime.

The host copies the exact 32 bytes into `EvidenceSealingKey`, constructs `ProductionEvidenceSealer`, and relies on the NXB-148 source-key zeroization boundary during construction.

## Receipt

A successful acquisition emits a content-addressed `EvidenceKeyAcquisitionReceipt` containing only:

- plan and activation identities;
- provider-identity SHA-256;
- key ID and non-secret provider version ID;
- store and policy identifiers;
- acquisition and key-expiry times;
- receipt SHA-256.

No key bytes, key-derived plaintext, provider credentials or secret-bearing diagnostics are included.

## Fail-closed cases

NXB-149 rejects:

- malformed or expired plans;
- plan digest drift;
- wrong activation signatures;
- provider identity mismatch;
- provider begin, fetch or teardown failure;
- wrong key IDs;
- keys shorter or longer than 32 bytes;
- keys that expire before the plan;
- sealer-construction failure.

## Validation record

GitHub-hosted Actions are disabled for the repository, so NXB-149 does not leave a workflow enabled after merge.

Before the temporary workflow was removed, GitHub Actions run `30991875053` (`NXB-149 evidence key-provider lifecycle`, run number 50) validated the implementation against the updated `main` base. Both Ubuntu and Windows completed successfully with:

- canonical committed `Cargo.lock` verification;
- Rust formatting verification on Ubuntu;
- package check with all features;
- all-target Clippy with warnings denied;
- deterministic, single-threaded adversarial tests.

The fixture verifies successful acquisition, exact provider identity, invalid activation signatures, wrong key IDs, insufficient key lifetime, provider fetch failure, mandatory aborted teardown, teardown failure overriding success, redacted key diagnostics, invalid key sizes and plan-digest tampering.

The crate can be reproduced locally or through an external orchestrator with:

```text
cargo generate-lockfile
git diff --exit-code -- Cargo.lock
cargo fmt --all -- --check
cargo check -p nxb-evidence-key-provider --all-features --locked
cargo clippy -p nxb-evidence-key-provider --all-targets --all-features --locked -- -D warnings
cargo test -p nxb-evidence-key-provider --all-features --locked -- --test-threads=1
```

## Explicit exclusions

NXB-149 does not implement a concrete:

- password-manager adapter;
- Windows Credential Manager or macOS Keychain adapter;
- Linux Secret Service adapter;
- cloud KMS adapter;
- HSM or PKCS#11 adapter;
- password-derived key flow.

It also does not enable automatic submission, browser automation, unrestricted scanning or raw credential persistence.
