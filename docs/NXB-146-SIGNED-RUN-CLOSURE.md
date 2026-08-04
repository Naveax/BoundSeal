# NXB-146 — Signed run closure and evidence attestation

NXB-146 converts the terminal outputs of the NXB-145 live-run host into one canonical, reviewable and cryptographically attestable closure record.

## Bound inputs

The closure manifest binds:

- the NXB-141 unified operator plan and policy snapshot,
- the NXB-145 launch bundle and terminal teardown outcome,
- the terminal NXB-144 runner manifest and checkpoint,
- the terminal NXB-143 runtime checkpoint,
- request, depth, response-byte and evidence counters,
- the knowledge-reporting export manifest root,
- report JSON and Markdown hashes,
- knowledge, session and vault audit tails,
- the external provider teardown receipt,
- additional immutable artifact hashes,
- explicit hashes for untested scope.

## Exact terminal-component binding

Closure construction consumes the real runner checkpoint and runtime recovery objects. It recomputes both checkpoint digests, rejects unresolved or continuation-allowed runtime state, and requires counters and terminal statuses to agree.

The NXB-145 teardown outcome must carry the same provider-teardown, runtime-checkpoint and runner-checkpoint hashes used by the closure manifest. A caller-provided synthetic terminal snapshot is not accepted.

## Dispositions

A run is `complete` only when the runner and runtime are both completed, the pending queue is empty and no untested scope remains.

Completed runs with explicit untested scope are `partial`. Aborted runs are `aborted`. Partial and aborted closure records must list at least one untested-scope SHA-256 value.

## Security properties

- Only bounded counters, identifiers and SHA-256 values are persisted.
- Secret-like metadata, URLs, authorization values, cookies and token material are rejected.
- Runner, runtime and live-host teardown states must match.
- Export policy snapshots must match the signed unified plan.
- Report, evidence, audit and teardown roots are tied into one manifest digest.
- Closure IDs are deterministically derived from canonical manifest content.
- The final closure certificate is verified with the Ed25519 key ID bound by the unified plan.
- `unsafe` Rust is forbidden in the closure crate.

NXB-146 does not submit reports automatically. It produces an operator-reviewable closure and evidence attestation suitable for later report packaging and manual submission.
