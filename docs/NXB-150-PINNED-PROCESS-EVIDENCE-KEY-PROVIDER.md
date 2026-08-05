# NXB-150 — Pinned process evidence-key provider

## Purpose

NXB-150 implements the first concrete adapter for the NXB-149 signed evidence-key provider lifecycle. It reuses the existing NXB-140 process-provider transport instead of introducing a second executable protocol.

The adapter is intended for a small, separately reviewed helper executable that talks to a password manager, OS credential store, cloud KMS, HSM or another secret source. The repository does not bundle any provider-specific helper.

## Security boundary

The adapter must preserve all NXB-140 process controls:

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
- transport session expiry.

This prevents a signed NXB-149 plan from being reused with a different executable, provider instance, key mapping or version policy.

## Lifecycle mapping

The adapter maps one NXB-149 acquisition to one NXB-140 process session:

1. connect and complete the pinned process handshake;
2. report the derived NXB-149 identity;
3. validate the exact store-bound begin request;
4. open one process-provider session;
5. validate the exact plan/store/key-bound fetch request;
6. issue one process secret fetch with a 32-byte maximum;
7. validate optional provider-version pinning;
8. convert the zeroizing process secret into `ProviderKeyMaterial`;
9. map completed or aborted NXB-149 teardown to committed or aborted process teardown;
10. return success only after the process exits cleanly.

The process provider handle is never included in `Debug` output or receipts. Only its SHA-256 is bound into the adapter capability identity.

## Validation targets

The implementation must cover:

- successful 32-byte acquisition and clean process teardown;
- executable digest mismatch before spawn;
- handshake identity mismatch;
- store, plan or key request mismatch before fetch;
- returned key length rejection;
- provider-version mismatch;
- logical child failure followed by aborted teardown;
- process timeout followed by abort completion;
- debug redaction for executable path, provider handle and key bytes;
- second-fetch and invalid lifecycle-state rejection.

## Repository policy

GitHub-hosted Actions remain disabled. NXB-150 must not add or re-enable a workflow. Validation commands and exact results will be recorded in this document and `docs/STATUS.md` after implementation.

## Explicit exclusions

NXB-150 does not include:

- a password-manager-specific helper;
- Windows Credential Manager, macOS Keychain or Linux Secret Service integration;
- a cloud KMS SDK;
- HSM or PKCS#11 integration;
- password-derived keys;
- shell execution, inherited credentials or persistent raw key storage.
