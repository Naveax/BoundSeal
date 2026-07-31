# NXB-126 — Adaptive Safe-Rule Scheduler

## Purpose

NXB-126 reorders finite, already-authorized endpoint-rule work so the available request, mutation, time and evidence budgets are spent on rules with the highest observed useful yield.

The scheduler does not authorize targets, create capabilities or execute requests. Every queued item must already carry:

- an admitted endpoint-rule pair;
- a plan SHA-256;
- a capability SHA-256;
- an authorization SHA-256;
- a finite authorization expiry;
- explicit request, mutation and cost reservations.

## Deterministic score

The scheduler uses integer fixed-point arithmetic. It never uses floating-point values.

Useful reward favors:

- validated findings;
- unclassified unique findings awaiting validation;
- inconclusive findings at a lower weight.

Penalty includes:

- rejected findings;
- duplicate findings.

Cost includes:

- the rule minimum cost;
- accumulated observed cost;
- the queued item's estimated cost.

An exploration ratio gives unseen or lightly sampled rules a bounded temporary advantage:

```text
exploration = (completed_checks + 4) / (completed_checks + 1)
```

The fixed score is proportional to:

```text
useful_reward × severity_weight × confidence_weight
× base_priority_weight × item_priority_weight × exploration
────────────────────────────────────────────────────────────
penalty × accounted_cost
```

The result is scaled by `1_000_000_000` and reduced with integer division. Score ties are resolved by the canonical endpoint-rule key and then authorization digest.

## Exact work lifecycle

A work item may be:

```text
queued → leased → completed
queued → expired
leased → failed
leased → expired
```

Pair IDs are exact-once inside one scheduler run. A lease ID is generated from sequence, pair, authorization and lease times. Completing the same lease twice is rejected.

## Safety boundaries

- unknown rules are rejected;
- duplicate pairs are rejected;
- expired authorizations are never leased;
- request and mutation reservations are preflighted transactionally;
- in-flight concurrency is bounded;
- reservations are released on completion, failure or expiry;
- `completed`, `saturated`, resource-stop, cancellation and emergency-stop states block new work and leases;
- scheduling cannot modify scope, capabilities, plans or authorization expiry;
- no exploit payload or network operation exists in this layer.

## Receipt

The scheduler receipt includes:

- registered rules;
- known, queued, in-flight, completed, failed and expired pair counts;
- outstanding request and mutation reservations;
- terminal run reason;
- deterministic profile, metric, queue, in-flight and terminal-pair SHA-256 roots;
- a self-verifying receipt digest.

## Regression coverage

Tests verify:

- validated low-cost rules outranking noisy expensive rules;
- bounded exploration priority for unseen rules;
- saturation blocking new work and leases;
- authorization expiry with reservation release;
- transactional reservation denial;
- 10,000 queued pairs without a 256 ceiling;
- insertion-order-independent ranking and receipts;
- exact-once leases and per-rule metric updates;
- receipt tamper rejection.

## Next stage

NXB-127 will partition authorized work into deterministic origin-isolated shards. Each shard will receive explicit local budgets while a global coordinator preserves exact pair ownership, global emergency stop and deterministic finding merge.
