# NXB-150 — Pinned process evidence-key provider

## Status

NXB-150 is implemented on draft PR #68 but is not release-complete. Source integration, the real child-process fixture and adversarial tests are committed. Canonical `Cargo.lock` publication and actual pinned-toolchain formatting, check, Clippy and test execution remain mandatory before review or merge.

## Purpose

NXB-150 implements the first concrete adapter for the NXB-149 signed evidence-key provider lifecycle. It reuses the existing NXB-140 process-provider transport instead of introducing a second executable protocol.

The adapter is intended for a small, separately reviewed helper executable that talks to a password manager, OS credential store, cloud KMS, HSM or another secret source. The repository does not bundle any provider-specific helper.

## Security boundary

The adapter preserves the NXB-140 process controls:

- absolute executable path;
- regular-file and symbolic-link checks;
- SHA-256 executable pinning before and after spawn;
- shell-free process creation;
- cleared environment with only the protocol minimum restored;
- null stderr and anonymous-pipe-only protocol transport;
- nonce-bound identity handshake;
- bounded metadata and secret frames;
- zeroizing secret buffers;
- bounded operation timeout;
- fail-closed child termination and clean-exit enforcement.

Adapter construction is side-effect free. `ProcessEvidenceKeyProvider::new` validates configuration and derives the capability identity without opening a process. The NXB-149 host first validates the plan, Ed25519 activation and exact provider identity. Only the subsequent provider `begin` call consumes the stored process configuration, validates the pinned executable and performs the process handshake.

The underlying `ProcessVaultProvider` Drop implementation terminates every child that did not reach `Finished`. Therefore begin failure, caller abandonment and incomplete teardown cannot leave an unmanaged helper process running. Store mismatch is rejected before process creation.

## Capability identity

The NXB-149 `EvidenceKeyProviderIdentity` returned by the adapter uses backend kind `pinned-process`. Its capability SHA-256 binds a canonical descriptor containing:

- adapter protocol version;
- NXB-140 process protocol version;
- exact process provider identity;
- exact executable SHA-256;
- exact evidence store ID;
- exact evidence key ID;
- SHA-256 of the configured provider handle;
- optional required provider-version SHA-256;
- transport session expiry;
- bounded operation timeout in milliseconds.

This prevents a signed NXB-149 plan from being reused with a different executable, provider instance, key mapping, timeout or version policy.

The configured transport session expiry is a capability-bound compatibility envelope for the process protocol. It is not the authorization source for evidence sealing. NXB-149 validates the signed plan time window and independently requires returned key material to remain valid through that plan.

## Lifecycle mapping

The adapter maps one NXB-149 acquisition to one NXB-140 process session:

1. validate adapter configuration and derive the content-bound NXB-149 provider identity without spawning;
2. let NXB-149 validate the exact plan, active time window, Ed25519 activation and provider identity;
3. validate the exact store-bound begin request before process creation;
4. consume the process configuration, validate the executable and complete the nonce-bound process handshake;
5. open one process-provider session;
6. validate the exact plan/store/key-bound fetch request before child fetch;
7. issue one process secret fetch with a 32-byte maximum;
8. validate optional provider-version pinning locally even if the helper ignores the requested pin;
9. transfer the zeroizing process secret into `ProviderKeyMaterial`;
10. map completed or aborted NXB-149 teardown to committed or aborted process teardown;
11. return success only after the process exits cleanly.

The process provider handle is required by the child protocol but is never included in adapter `Debug` output, receipts or capability plaintext. Only its SHA-256 is capability-bound. Invalid-length key material is zeroized by the NXB-149 material constructor before rejection.

## Implemented fixture coverage

The real child-process fixture and integration tests cover:

- successful 32-byte acquisition and clean process teardown;
- invalid activation rejection before process spawn;
- executable digest mismatch during the signed begin phase;
- store mismatch before provider-session begin and process creation;
- exact fetch-request mismatch before child fetch;
- returned key length rejection;
- provider-version mismatch followed by aborted teardown;
- logical child failure followed by aborted teardown;
- process timeout followed by abort completion;
- debug redaction for executable path, provider handle and key bytes;
- capability changes when provider mapping changes;
- second-fetch rejection while preserving abortability.

The test source is present, but these cases are not counted as passed until the pinned Rust toolchain actually compiles and executes them.

## Required terminal validation

GitHub-hosted Actions remain disabled. NXB-150 does not add or re-enable a workflow. Validation must run locally or through an external orchestrator:

```text
cargo generate-lockfile
git diff --exit-code -- Cargo.lock
cargo fmt --all -- --check
cargo check -p nxb-evidence-key-provider-process --all-features --locked
cargo clippy -p nxb-evidence-key-provider-process --all-targets --all-features --locked -- -D warnings
cargo test -p nxb-evidence-key-provider-process --all-features --locked -- --test-threads=1
cargo test -p nxb-vault-provider --locked -- --test-threads=1
```

A lockfile candidate was prepared from the last immutable release-candidate lockfile by adding the new path-package stanza. It is not accepted as canonical evidence until published and reproduced by `cargo generate-lockfile` with no diff.

An external validation attempt through the available Hugging Face Jobs connector failed before execution with `Tool hf_jobs not found`. The local container also lacks both a Rust toolchain and outbound DNS. These infrastructure failures produced no compilation or test result and are not treated as validation.

## Explicit exclusions

NXB-150 does not include:

- a password-manager-specific helper;
- Windows Credential Manager, macOS Keychain or Linux Secret Service integration;
- a cloud KMS SDK;
- HSM or PKCS#11 integration;
- password-derived keys;
- shell execution, inherited credentials or persistent raw key storage.
