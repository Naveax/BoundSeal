# BSL-150 — Pinned process evidence-key provider

## Status

BSL-150 is implemented. Source integration, the real child-process fixture, adversarial tests, the canonical committed lockfile, exact-head Linux and Windows validation harnesses and deterministic dual-platform evidence closure are part of the milestone contract.

A final PR head is merge-eligible only after both platforms validate that same unchanged head and the closure reports `ready_for_manual_pr_review`. Any later commit invalidates the earlier exact-head evidence and requires a fresh platform pair and closure.

## Purpose

BSL-150 implements the first concrete adapter for the BSL-149 signed evidence-key provider lifecycle. It reuses the existing BSL-140 process-provider transport instead of introducing a second executable protocol.

The adapter is intended for a small, separately reviewed helper executable that talks to a password manager, OS credential store, cloud KMS, HSM or another secret source. The repository does not bundle any provider-specific helper.

## Security boundary

The adapter preserves the BSL-140 process controls:

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

Adapter construction is side-effect free. `ProcessEvidenceKeyProvider::new` validates configuration and derives the capability identity without opening a process. The BSL-149 host first validates the plan, Ed25519 activation and exact provider identity. Only the subsequent provider `begin` call consumes the stored process configuration, validates the pinned executable and performs the process handshake.

The underlying `ProcessVaultProvider` Drop implementation terminates every child that did not reach `Finished`. Therefore begin failure, caller abandonment and incomplete teardown cannot leave an unmanaged helper process running. Store mismatch is rejected before process creation.

## Capability identity

The BSL-149 `EvidenceKeyProviderIdentity` returned by the adapter uses backend kind `pinned-process`. Its capability SHA-256 binds a canonical descriptor containing:

- adapter protocol version;
- BSL-140 process protocol version;
- exact process provider identity;
- exact executable SHA-256;
- exact evidence store ID;
- exact evidence key ID;
- SHA-256 of the configured provider handle;
- optional required provider-version SHA-256;
- transport session expiry;
- exact bounded operation timeout in nanoseconds.

The timeout is encoded without unit truncation. Distinct sub-millisecond `Duration` values must produce distinct capability SHA-256 identities. This prevents a signed BSL-149 plan from being reused with a different executable, provider instance, key mapping, timeout or version policy.

The configured transport session expiry is a capability-bound compatibility envelope for the process protocol. It is not the authorization source for evidence sealing. BSL-149 validates the signed plan time window and independently requires returned key material to remain valid through that plan.

## Lifecycle mapping

The adapter maps one BSL-149 acquisition to one BSL-140 process session:

1. validate adapter configuration and derive the content-bound BSL-149 provider identity without spawning;
2. let BSL-149 validate the exact plan, active time window, Ed25519 activation and provider identity;
3. validate the exact store-bound begin request before process creation;
4. consume the process configuration, validate the executable and complete the nonce-bound process handshake;
5. open one process-provider session;
6. validate the exact plan/store/key-bound fetch request before child fetch;
7. issue one process secret fetch with a 32-byte maximum;
8. validate optional provider-version pinning locally even if the helper ignores the requested pin;
9. transfer the zeroizing process secret into `ProviderKeyMaterial`;
10. map completed or aborted BSL-149 teardown to committed or aborted process teardown;
11. return success only after the process exits cleanly.

The process provider handle is required by the child protocol but is never included in adapter `Debug` output, receipts or capability plaintext. Only its SHA-256 is capability-bound. Invalid-length key material is zeroized by the BSL-149 material constructor before rejection.

## Fixture and adversarial coverage

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
- exact sub-millisecond timeout capability separation;
- second-fetch rejection while preserving abortability.

These cases are executed serially by the platform harnesses against the real child-process fixture.

## Exact-head validation harnesses

Linux:

```text
bash scripts/validate-bsl-150-linux.sh
```

Windows:

```text
pwsh -NoProfile -File .\scripts\validate-bsl-150-windows.ps1
```

Both harnesses require:

- a clean, unchanged exact Git head;
- Rust `1.97.1` with rustfmt and Clippy;
- pinned local `cargo-audit 0.22.2` and `cargo-deny 0.20.2` binaries;
- committed `Cargo.lock` SHA-256 `f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff`;
- locked Cargo metadata resolution;
- package format, check, all-target Clippy and serial real-process tests;
- `bsl-vault-provider` regression tests;
- full workspace check, all-target/all-feature Clippy and serial tests;
- RustSec audit;
- cargo-deny advisories, licenses, bans and source checks.

A successful run writes platform-specific schema-v2 JSON under:

```text
target/bsl-validation/
```

Evidence binds the exact head, Rust/Cargo and supply-chain tool versions, security-tool executable hashes, canonical lockfile SHA-256 and each completed gate. It contains no provider handle, secret material, authorization data or private signing key.

The committed lockfile is the resolution authority. The harnesses use `cargo metadata --locked` and locked package/workspace commands; they do not accept a mutable-index `cargo generate-lockfile` rebuild as a reproducibility gate.

The harnesses emit no success document if the expected SHA-256 differs, the working tree moves, the exact head changes or any package, workspace or supply-chain command fails.

## Mandatory command sequence

```text
cargo metadata --locked
cargo fmt --all -- --check
cargo check -p bsl-evidence-key-provider-process --all-features --locked
cargo clippy -p bsl-evidence-key-provider-process --all-targets --all-features --locked -- -D warnings
cargo test -p bsl-evidence-key-provider-process --all-features --locked -- --test-threads=1
cargo test -p bsl-vault-provider --locked -- --test-threads=1
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked -- --test-threads=1
cargo audit
cargo deny check
```

## Dual-platform closure

The Linux and Windows evidence documents must describe the same exact head, canonical lockfile and pinned tool versions. The closure verifier rejects missing fields, unknown fields, wrong JSON types, mixed heads, future timestamps, failed gates, path indirection, symbolic links, tampered prior closure output and orphan pending files.

Successful review creates:

```text
target/bsl-validation/bsl-150-closure-<HEAD>.json
```

with status:

```text
ready_for_manual_pr_review
```

That status authorizes manual PR review only. It is not an automatic merge instruction.

## Explicit exclusions

BSL-150 does not include:

- a password-manager-specific helper;
- Windows Credential Manager, macOS Keychain or Linux Secret Service integration;
- a cloud KMS SDK;
- HSM or PKCS#11 integration;
- password-derived keys;
- shell execution, inherited credentials or persistent raw key storage.
