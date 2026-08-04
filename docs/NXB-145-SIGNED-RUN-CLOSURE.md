# NXB-145 — Signed run closure

NXB-145 converts the terminal outputs of NXB-143 and NXB-144 into one canonical, reviewable and cryptographically attestable closure record.

## Bound inputs

The closure manifest binds:

- the NXB-141 unified operator plan and policy snapshot,
- the terminal NXB-144 runner manifest and checkpoint,
- the terminal NXB-143 runtime checkpoint,
- request, depth, response-byte and evidence counters,
- the knowledge-reporting export manifest root,
- report JSON and Markdown hashes,
- knowledge, session and vault audit tails,
- the external provider teardown receipt,
- additional immutable artifact hashes,
- explicit hashes for untested scope.

## Dispositions

A run is `complete` only when the runner and runtime are both completed, the pending queue is empty and no untested scope remains.

Completed runs with pending or explicitly untested scope are `partial`. Aborted runs are `aborted`. Partial and aborted closure records must list at least one untested-scope SHA-256 value.

## Security properties

- Only bounded counters, identifiers and SHA-256 values are persisted.
- Secret-like metadata, URLs, authorization values, cookies and token material are rejected.
- Runner and runtime terminal states must match.
- Export policy snapshots must match the signed unified plan.
- Report, evidence, audit and teardown roots are tied into one manifest digest.
- The final closure certificate is verified with the Ed25519 public key embedded in the unified plan.
- `unsafe` Rust is forbidden in the closure crate.

NXB-145 does not submit reports automatically. It produces an operator-reviewable closure and evidence attestation suitable for later report packaging and manual submission.
