# NXB-144 — Resumable bounded live runner

NXB-144 joins the NXB-137 deterministic passive discovery queue, the NXB-141 unified authenticated-operator binding and the NXB-143 checkpoint-bound request runtime. It remains a bounded defensive operator and does not introduce a generic attack engine.

## Durable execution model

The runner stores a canonical manifest and a hash-linked checkpoint sequence. Each checkpoint binds:

- the exact unified plan and discovery-plan hashes;
- the deterministic pending GET/HEAD queue;
- visited target hashes and rejected-candidate counts;
- the exact number of requests committed by NXB-143;
- the latest runtime request/checkpoint hashes;
- teardown, completion or abort state.

The queue is sequential and sorted by depth, target and method. Candidates must remain inside the signed path and depth scope. Query targets, fragments, cross-origin URLs, destructive paths and non-GET/HEAD methods are rejected before execution.

## Runtime synchronization and recovery

A queue item is removed only after NXB-143 has durably written its `prepared -> outcome -> checkpoint -> commit` transaction. Runner and runtime counters must match exactly.

If the process crashes after the runtime commit but before the runner checkpoint, reopening verifies the committed method, target hash, depth and request index against the queue head. It then advances the queue without issuing the request again. Because the response body is intentionally not persisted, candidates that would have been discovered from that response cannot be reconstructed; the checkpoint increments `recovery_gap_count` and reports the coverage gap.

Prepared-only or otherwise indeterminate NXB-143 requests are never reconciled as successful and cannot be retried automatically. The runner permits only teardown or abort in that state.

## Live authenticated bridge

`execute_next_live_authenticated` delegates the exact queue head to the existing permit-only transport, rustls HTTPS, session-injection, session-broker and vault boundary. The caller supplies the per-request connection attempt and pipeline created from the already authorized gateway/permit path.

The optional passive discovery helper inspects the authenticated response body only in memory, uses the existing operator parser and policy engine, and emits normalized same-origin GET/HEAD candidates. Raw bodies and secret values are not written to runner checkpoints.

## Workspace and ownership

The runner uses a stable-inode operating-system lock, canonical no-clobber publication and bounded checkpoint files. Before a live transaction, it reserves current runner bytes plus future checkpoint/terminal evidence through the NXB-143 runtime workspace accounting. Runtime state, runtime journal and runner evidence remain inside the signed unified workspace budget.

## Emergency stop and teardown

An idempotent `EMERGENCY_STOP` marker is checked before every request. It moves the runner to `teardown_pending` without invoking the network executor.

Runner completion is recorded only after the NXB-143 runtime reaches `completed` following provider/session/vault teardown. Runtime abort is mirrored as runner abort. Request counters must still match at the terminal checkpoint.

## Control plane

The `nxb-resumable-runner` binary provides networkless commands to:

- build and verify a runner manifest;
- inspect the latest durable checkpoint;
- request an emergency stop.

Actual live execution uses the library API so the host application must explicitly supply the verified unified artifacts, consumed activation, session/vault objects and one-request transport attempt.

## Explicit limitations

NXB-144 does not mint program scope, DNS decisions, transport tickets, session secrets or activation signatures. It does not follow redirects, execute JavaScript, persist authenticated bodies, retry indeterminate requests, enable destructive methods, run active probes or submit reports automatically.
