# NXB-140 — Unified live operator

## Status

Implementation blocks A and B are present:

- signed unified execution contract;
- networkless NXB-137/138/139 artifact binder CLI.

No network request is executed by these blocks.

## Purpose

The contract binds the verified NXB-137 discovery session, NXB-138 session-injection manifest and NXB-139 external-vault lifecycle into one fail-closed operator authorization document.

The binding records:

- exact discovery plan, policy and target-origin SHA-256 values;
- exact injection-manifest, external-vault plan and bootstrap-receipt SHA-256 values;
- discovery, run, worker, account, tenant and role partitions;
- provider identity, capability and secret-binding roots;
- allowed passive path prefixes;
- request, depth, body, total-byte, pacing and concurrency limits;
- the earliest component expiration;
- checkpoint cadence and maximum workspace bytes.

## Networkless binder CLI

`nxb-unified-operator` provides:

```text
plan
verify-plan
activation-template
verify-activation
consume-activation
```

The `plan` command verifies the source artifacts before emitting a unified plan. It requires:

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

## Safety boundary

- HTTPS-origin metadata only; no secret values are accepted.
- Only passive path prefixes are allowed; destructive path tokens are rejected.
- Maximum concurrency is fixed to one.
- Unified validity cannot exceed the earliest bound component expiration.
- Request and response budgets cannot exceed NXB-137 limits.
- Workspace storage is explicitly bounded.
- Empty or non-lowercase hexadecimal key material is rejected.
- The binder does not perform DNS, socket, TLS, HTTP, provider execution, secret injection or report submission.

## Validation completed for blocks A and B

- canonical Cargo lockfile generation;
- Rustfmt;
- unified contract check, Clippy `-D warnings` and tests;
- unified binder binary check, Clippy `-D warnings` and tests;
- optional networkless-fixture feature-matrix hardening.

## Next NXB-140 block

The next block will attach checkpointed, bounded execution state to this verified contract. The live loop will not be enabled until checkpoint recovery, workspace quota enforcement and teardown ordering are verified.
