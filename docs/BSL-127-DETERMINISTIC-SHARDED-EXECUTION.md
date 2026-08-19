# BSL-127 — Deterministic Sharded Execution

## Purpose

BSL-127 partitions finite, already-authorized endpoint-rule work into deterministic, origin-isolated shards. The coordinator provides exact ownership, shard-local and global resource accounting, exact-once leases, global emergency stop and deterministic finding merge.

It does not provide a distributed transport or execute network requests.

## Assignment

An origin is assigned from:

```text
SHA-256("bsl-shard-v1", run_partition_sha256, origin_sha256)
```

The first 64-bit digest prefix is reduced modulo the configured shard count. Endpoint identity is not part of the partition key, so every pair belonging to the same normalized origin remains in the same shard.

The assignment receipt binds:

- shard ID;
- origin SHA-256;
- endpoint-rule pair;
- assignment digest.

## Origin isolation

The first accepted item for an origin freezes:

- shard ownership;
- session-partition SHA-256;
- credential-partition SHA-256.

Later work for the same origin must use the exact same session and credential partitions. Conflicting partitions fail before pair ownership or resource reservations are changed.

## Exact pair ownership

Every endpoint-rule pair has one global owner. Duplicate ownership is rejected even when a caller presents another origin or partition identity.

Shard lifetime pair limits include queued, in-flight, completed, failed and expired work, preventing terminal items from being replaced to bypass capacity accounting.

## Resource model

Every work item reserves finite:

- requests;
- mutations;
- accounted memory;
- evidence bytes;
- disk bytes;
- elapsed milliseconds.

Enqueue preflights both:

```text
global_used + global_reserved + new_reservation <= global_budget
shard_used  + shard_reserved  + new_reservation <= shard_budget
```

A failed preflight does not claim pair ownership, create an origin binding or charge resources.

Actual completion usage must remain within the work reservation. Overrun fails closed, releases the reservation and marks the pair failed.

## Lease lifecycle

```text
queued → in_flight → completed
queued → expired
in_flight → failed
in_flight → expired
```

Lease identity binds sequence, shard, origin, pair, authorization and lease times. A consumed lease cannot be completed twice.

Authorization expiry is enforced for both queued and in-flight work. Expiry releases all reservations.

## Finding merge

Shard results contain only exact finding IDs and resource usage. The coordinator merges IDs into a global ordered set:

- the first occurrence is a global unique finding;
- later occurrences are counted as cross-shard duplicates;
- shard-local accepted and duplicate counts remain available;
- no approximate filter may suppress an exact ID.

## Stop behavior

Any terminal BSL-125 run reason blocks new enqueue and lease operations.

Global emergency stop additionally:

- drains every shard queue;
- revokes every in-flight lease;
- releases all outstanding reservations;
- marks affected pairs failed;
- records `emergency_stop` as the terminal reason.

## Receipt

The self-verifying receipt contains:

- shard and origin-binding counts;
- exact owned, queued, in-flight, completed, failed and expired pair counts;
- global reserved and used resources;
- global unique and duplicate finding counts;
- terminal stop reason;
- one deterministic summary and state root per shard;
- global pair-ownership, origin-binding and finding-set roots;
- final receipt SHA-256.

## Regression coverage

Tests verify:

- one shard per origin across multiple endpoint-rule pairs;
- conflicting session or credential partitions fail transactionally;
- duplicate pair ownership rejection;
- shard-budget failure without ownership changes;
- 10,000 exact-owned pairs without a fixed 256 ceiling;
- cross-shard exact finding deduplication;
- exact-once lease behavior and reservation overrun denial;
- global emergency-stop draining;
- queued and leased authorization expiry;
- insertion-order-independent assignments and receipts;
- receipt tamper rejection.

## Next stage

BSL-128 may introduce a scope-controlled live adapter MVP only after this layer remains green. Any live adapter must consume existing policy, destination, DNS pinning, permit, executor, stream, TLS, HTTP, scheduler, sharding and coverage contracts rather than bypassing them.
