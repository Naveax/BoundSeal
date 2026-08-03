# NXB-142 — Checkpointed bounded operator state

NXB-142 adds the networkless state and crash-recovery boundary required before the unified authenticated operator may execute live requests.

## Security boundary

The state engine does not perform DNS, TLS, HTTP, provider startup, secret injection or report submission. It records and validates the bounded execution state associated with one verified NXB-141 unified operator plan and one consumed activation certificate.

A state store is bound to:

- the exact operator identifier;
- unified plan and component-binding SHA-256 values;
- the consumed activation-certificate SHA-256;
- the activation expiry and consumed-marker path;
- the request, depth, response-body, total-response and workspace budgets from the unified plan.

Recovery fails closed if the activation marker is missing, the checkpoint chain is incomplete, a digest or identity changes, counters regress, a budget is exceeded, a publication is incomplete or an unexpected entry exists in the dedicated state directory.

## Checkpoint chain

Each checkpoint is published as an immutable `checkpoint-<20 digit sequence>.json` file. A checkpoint contains:

- contiguous sequence number;
- previous-checkpoint SHA-256;
- plan, binding and activation identity;
- run status;
- monotonic execution counters;
- checkpoint timestamp and optional terminal/teardown reason;
- its own calculated SHA-256.

Publication uses a same-directory, create-new temporary file, explicit file synchronization and a no-clobber hard-link publication step. A leftover temporary publication causes recovery to fail instead of guessing whether the checkpoint committed.

## State machine

The state machine uses these statuses:

- `ready` — activation consumed and initial checkpoint committed;
- `running` — bounded execution may continue while plan and activation time limits remain valid;
- `teardown_pending` — execution counters are frozen while cleanup is attempted;
- `completed` — terminal successful cleanup state;
- `aborted` — terminal fail-closed stop state.

Terminal states cannot be advanced. Cleanup and terminal checkpoints cannot change execution counters. Aborting unchanged state remains possible after plan expiry so cleanup and final audit state are not prevented by an expired execution permit.

## Budget accounting

The engine validates:

- completed request count;
- total response bytes;
- last response-body bytes;
- maximum observed discovery depth;
- evidence bytes;
- cumulative checkpoint-file bytes;
- maximum requests between checkpoints.

Evidence bytes plus checkpoint bytes may not exceed the unified plan workspace limit.

## Recovery

`OperatorStateStore::open` and `recover` re-read the complete append-only chain. Continuation is allowed only when the latest state is `ready` or `running`, the unified plan remains within its validity interval and the consumed activation has not expired.

The caller must enter `teardown_pending` or `aborted` before provider/session/vault teardown integration is added by the next execution-runtime block.

## Validation

The permanent NXB-142 state-hardening workflow runs targeted check, all-target/all-feature Clippy and deterministic state tests on Ubuntu, plus state/recovery tests on Windows.

The independent NXB-142 full-verification workflow also verifies the canonical lockfile, full workspace check/Clippy/tests, synthetic demo, RustSec, cargo-deny, release binary, deterministic CycloneDX SBOM, SHA-256 checksums and immutable secret-scanned evidence on Ubuntu-slim. Repository-wide CI and operator release-hardening remain additional independent gates.
