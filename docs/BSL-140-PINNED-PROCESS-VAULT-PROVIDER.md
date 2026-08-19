# NXB-140 pinned process vault-provider backend

NXB-140 supplies the first concrete backend for the NXB-139 external vault-provider contract. It launches one explicitly selected provider executable and exchanges bounded provider messages over anonymous standard-input and standard-output pipes.

It is not a shell adapter and it is not a password manager. The child executable remains responsible for reading exact handles from its own OS credential store, HSM, password manager or remote vault.

## Security invariants

- The executable path must be absolute, canonical and refer directly to a regular file.
- Symbolic-link entry paths are rejected.
- The executable is hashed before spawn and after the handshake.
- `ProcessVaultProviderConfig.executable_sha256` must equal the signed plan's `provider_instance_sha256`.
- The child-reported provider ID, instance digest and capability digest must exactly match the pinned identity.
- No shell is involved and no provider arguments are accepted.
- The inherited environment is cleared. On Windows only `SystemRoot` and `WINDIR` are preserved for process startup.
- Secrets are never accepted through command-line arguments, environment variables or plaintext files.
- Child stderr is discarded rather than captured into logs or evidence.
- One backend instance owns one child process and at most one active provider session.
- Every request and response after the handshake is bound to a strictly increasing sequence number.
- Operation timeouts terminate the child. A killed active session remains locally abortable so NXB-139 rollback preserves the original failure.
- Secret payloads are held in `Zeroizing<Vec<u8>>` buffers and are transferred into `SecretInput` without an intermediate secret copy.
- Debug implementations omit the executable path and never include secret payloads.

## Wire protocol

Each frame uses this fixed header:

| Field | Size | Meaning |
|---|---:|---|
| Magic | 4 bytes | ASCII `NXB1` |
| Metadata length | 4 bytes | Big-endian unsigned length |
| Secret length | 4 bytes | Big-endian unsigned length |

The header is followed by UTF-8 JSON metadata and then raw secret bytes. Metadata is limited to 64 KiB. Secret bytes are limited by the existing vault `MAX_SECRET_BYTES` contract.

Metadata and secret payloads are deliberately separated. Begin, finish, hello and failure frames must have a zero-length secret section. A successful fetch frame declares its exact secret byte count and the host rejects count mismatch, empty values, request-budget overrun or global secret-budget overrun.

## Handshake

1. The host generates a fresh 32-byte nonce.
2. The host sends protocol version, nonce, metadata limit and secret limit.
3. The child returns the protocol version, SHA-256 of the nonce text and its provider identity.
4. The host verifies the nonce response, exact identity and executable digest again.

The nonce proves freshness of the pipe peer. Trust still comes from the executable digest and signed provider identity, not from the nonce alone.

## Lifecycle

- `connect` validates and hashes the executable, spawns it and completes the handshake.
- `begin` opens the single provider session.
- `fetch` requests one exact opaque handle and returns zeroizing material.
- `finish(committed)` or `finish(aborted)` closes the session and requires a clean child exit.
- Protocol, framing, I/O and timeout failures terminate the child fail-closed.
- A logical provider fetch denial keeps the channel alive long enough for an explicit abort.
- Dropping an unfinished provider kills and reaps the child.

## Validation coverage

The fixture and integration tests verify:

- exact executable digest enforcement before spawn;
- exact handshake identity and capability enforcement;
- full NXB-139 bootstrap and teardown through the process backend;
- operation timeout, child termination and upstream abort completion;
- logical provider failure followed by explicit abort;
- absence of fixture secret material and executable paths from debug/log output.

The permanent adversarial workflow runs the NXB-140 suite and records a SHA-256 of its sanitized log in the immutable local-lab status artifact.

## Explicit limitations

- NXB-140 does not provide a Bitwarden, 1Password, KeePass, Windows Credential Manager, HSM or cloud-vault implementation.
- It does not sandbox the child with namespaces, seccomp, AppContainer, job objects or a restricted token.
- Pre-spawn and post-handshake hashing narrows executable replacement risk but cannot provide a portable, race-free proof of the exact image loaded by every operating-system loader.
- The provider executable must keep all metadata fields secret-free and must enforce read-only exact-handle access internally.
- Unified authenticated operator CLI wiring is not part of NXB-140.
