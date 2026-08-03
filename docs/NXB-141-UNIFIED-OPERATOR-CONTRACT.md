# NXB-141 — Unified authenticated operator contract

## Status

The first NXB-141 block provides:

- a signed unified execution contract;
- a networkless NXB-137/138/139/140 artifact binder CLI;
- one-use external Ed25519 activation consumption.

This block performs no network request and does not start the process vault provider. It is the authorization and artifact-integrity boundary required before a bounded live execution command can be introduced.

## Purpose

The contract binds the verified discovery session, session-injection manifest, external-vault lifecycle and provider identity into one fail-closed operator authorization document.

The binding records:

- exact discovery plan, policy and target-origin SHA-256 values;
- exact injection-manifest, external-vault plan and bootstrap-receipt SHA-256 values;
- discovery, run, worker, account, tenant and role partitions;
- provider identity, capability and secret-binding roots;
- allowed passive path prefixes;
- request, depth, body, total-byte, pacing and concurrency limits;
- the earliest component expiration;
- checkpoint cadence and maximum workspace bytes.

The signed provider-instance digest can refer to the NXB-140 pinned process-provider executable. The binder does not launch or trust a process by path alone.

## Networkless binder CLI

`nxb-unified-operator` provides:

```text
plan
verify-plan
activation-template
verify-activation
consume-activation
```

The `plan` command verifies all source artifacts before emitting a unified plan. It requires:

- the discovery plan to be currently valid;
- the injection manifest to be currently valid;
- the external-vault plan digest and committed bootstrap receipt to verify;
- exact discovery-plan and target-origin hashes across all artifacts;
- exact authority and account/tenant/role partitions;
- the injection session ID to hash to the provisioned external session ID;
- the injection bootstrap-handle hash set to equal the receipt handle set;
- every provider header or cookie delivery to be present in the injection allowlist;
- authenticated paths to remain inside discovery path scope;
- injection lifetime to remain inside the provisioned external session lifetime.

The unified expiration is capped by the earliest discovery, injection or external-session expiration.

## Activation

A separate Ed25519 activation certificate binds the complete unified plan and its component hashes. Activation is consumed with an atomic `create_new` marker. Reusing the same activation fails closed.

Plan and activation-template artifacts are published through a no-clobber temporary-file sequence: create in the destination directory, write, `sync_all`, atomically hard-link into the final name, then remove the temporary name. Existing output files are never overwritten.

## Safety boundary

- HTTPS-origin metadata only; no secret values are accepted.
- Only passive path prefixes are allowed; destructive path tokens are rejected.
- Maximum concurrency is fixed to one.
- Unified validity cannot exceed the earliest bound component expiration.
- Request and response budgets cannot exceed the discovery-session limits.
- Workspace storage is explicitly bounded.
- Empty or non-lowercase hexadecimal key material is rejected.
- The crate and CLI forbid unsafe Rust.
- The binder does not perform DNS, socket, TLS, HTTP, provider execution, secret injection or report submission.

## Validation required

- canonical Cargo lockfile generation;
- Rustfmt;
- workspace check and Clippy with all targets/features and warnings denied;
- full workspace tests;
- unified contract and binder CLI tests;
- NXB-140 process-provider tests on Ubuntu and Windows through the current `main` merge result;
- RustSec, cargo-deny, adversarial lab and release evidence.

## Next NXB-141 block

The next block will attach checkpointed, bounded execution state to this verified contract. The live loop will remain disabled until checkpoint recovery, workspace quota enforcement, exact provider startup, authenticated request injection and teardown ordering are all verified together.
