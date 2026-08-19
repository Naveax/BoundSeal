# bsl-platform-assurance

Deterministic contracts for BSL-66 through BSL-83.

The crate provides three connected layers:

- P10 binds adapter conformance, reproducibility and platform-release certificates to one policy and an exact integration scenario.
- P11 applies typed operator commands through sequence, nonce, lifetime, target and role-separated approval checks.
- P12 requires mandatory assurance evidence, an immutable freeze manifest and exact milestone closure before issuing the final certificate.

All state transitions and certificates are content-addressed and audit-linked. The crate exposes no external-I/O or operating-system execution surface.
