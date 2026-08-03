# NXB-139 — External vault-provider lifecycle

NXB-139 adds the production-facing contract that can provision NXBounty's existing in-memory vault and session broker from an external secret provider without placing secret values in command-line arguments, JSON/TOML plans, receipts, debug output, or persistent state.

It intentionally does not implement a concrete HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, 1Password, browser-profile, or operating-system credential-store adapter. Concrete providers implement the bounded `ExternalVaultProvider` trait and remain unable to widen the signed plan.

## Signed bootstrap plan

`ExternalVaultSessionPlan` binds one exact provider bootstrap to:

- the NXB-137 discovery-plan SHA-256;
- the normalized HTTPS origin SHA-256 and exact DNS authority;
- run, worker, account, tenant and role partitions;
- one provider ID, provider-instance digest and capability digest;
- a bounded list of unique provider handles and logical secret IDs;
- exact secret kinds and delivery metadata;
- exact header names and non-secret prefixes or exact secure cookie metadata;
- per-secret byte ceilings and optional provider-version digests;
- a maximum one-hour in-memory session lifetime;
- a maximum fifteen-minute bootstrap-plan window;
- an Ed25519 activation-key digest and canonical plan digest.

The plan contains provider handles and metadata only. It never contains secret values.

## One-use activation

An externally signed `ExternalVaultActivationCertificate` binds the exact plan, provider instance, discovery plan and target origin. `consume_activation_once` verifies the Ed25519 signature and atomically creates a durable `create_new` replay marker containing hashes and timestamps only.

The returned activation proof is non-serializable and non-cloneable. A provider bootstrap cannot start from a certificate without first consuming that proof.

## Provider lifecycle

A provider implementation receives metadata-only session and secret requests through four bounded operations:

1. `identity` returns the provider ID and signed instance/capability digests;
2. `begin` opens an opaque provider session;
3. `fetch` returns one zeroizing secret value, version ID and mandatory expiry for one signed provider handle;
4. `finish` commits or aborts the opaque provider session.

Provider failures are represented by validated machine-readable codes so provider error strings cannot accidentally expose secret material.

## Transactional provisioning

`bootstrap_external_session`:

- verifies the plan and consumed activation;
- verifies the exact provider identity before any fetch;
- fetches only signed handles;
- rejects oversized, stale, short-lived or wrong-version material;
- derives the vault binding and delivery exclusively from the signed plan;
- inserts values into `InMemorySecretVault`;
- creates an exact singleton-authority HTTPS `SessionBroker` session;
- commits the provider session only after all vault and broker operations succeed;
- aborts and revokes every inserted handle on any partial failure;
- revokes the created session and all handles if provider commit fails.

The bootstrap receipt stores provider/version/handle hashes, counts, binding roots and audit tails only.

## Explicit teardown

`deprovision_external_session` consumes the provisioned session object, revokes the broker session, revokes every vault handle, and emits a self-verifying teardown receipt. The provisioned object uses a custom `Debug` implementation that hides actual vault handles.

## Deliberately excluded

NXB-139 does not add:

- plaintext secret files or command-line secret values;
- browser cookie-database extraction;
- a concrete external provider backend;
- provider write/delete/rotation privileges;
- cross-origin or parent-domain secret bindings;
- POST, PUT, PATCH or DELETE requests;
- a unified authenticated scanning CLI;
- persistence of secret values or value hashes.

The unified authenticated operator CLI is the next integration block after this provider lifecycle.
