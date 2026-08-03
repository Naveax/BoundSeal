# NXB-140 — Unified live operator

## Status

Implementation block A introduces the signed unified execution contract. It does not yet execute network requests.

## Purpose

The contract binds the already verified NXB-137 discovery session, NXB-138 session-injection manifest and NXB-139 external-vault lifecycle into one fail-closed operator authorization document.

The binding records:

- exact discovery plan, policy and target-origin SHA-256 values;
- exact injection-manifest, external-vault plan and bootstrap-receipt SHA-256 values;
- discovery, run, worker, account, tenant and role partitions;
- provider identity, capability and secret-binding roots;
- allowed passive path prefixes;
- request, depth, body, total-byte, pacing and concurrency limits;
- the earliest component expiration;
- checkpoint cadence and maximum workspace bytes.

## Activation

A separate Ed25519 activation certificate binds the complete unified plan and its component hashes. Activation is consumed with an atomic `create_new` marker. Reusing the same activation fails closed.

## Safety boundary

- HTTPS-origin metadata only; no secret values are accepted.
- Only passive path prefixes are allowed; destructive path tokens are rejected.
- Maximum concurrency is fixed to one.
- Unified validity cannot exceed the earliest bound component expiration.
- Request and response budgets cannot exceed NXB-137 limits.
- Workspace storage is explicitly bounded.
- The crate does not perform DNS, socket, TLS, HTTP, vault-provider or session-injection operations.

## Next NXB-140 block

The next block will add a networkless component binder and CLI that reads the real NXB-137, NXB-138 and NXB-139 artifacts, verifies their cross-document invariants and emits this unified plan. Only after that binder is verified will the live execution loop be attached.
