# BSL-121 — Resource-Derived Finding Capacity

## Decision

The former fixed `256 findings per analyzer` ceiling is removed. Analyzer output is complete for the supplied observation. Run-level accumulation is governed by an explicit resource model rather than an arbitrary count.

## Capacity model

For a run budget:

- `B_mem`: bytes reserved for serialized finding state;
- `B_evidence`: bytes reserved for evidence accounting;
- `E_scope`: maximum distinct endpoints admitted by policy;
- `R_max`: conservative upper bound of enabled rules per endpoint;
- `C_finding`: minimum accounted bytes for one finding;
- `C_evidence`: minimum accounted bytes for one evidence reference.

The theoretical unique-finding capacity is:

```text
N_memory   = floor(B_mem / C_finding)
N_evidence = floor(B_evidence / C_evidence)
N_scope    = E_scope * R_max
N_max      = min(N_memory, N_evidence, N_scope)
```

Actual serialized finding size and declared evidence size are charged during ingestion, so the accumulator may stop before `N_max` when findings are larger than the conservative floor.

## Runtime properties

- No fixed 256-result ceiling.
- Duplicate finding IDs do not consume finding, evidence or endpoint capacity.
- Unique findings are accepted until the first real boundary is reached.
- Stop reasons are explicit: derived capacity, memory budget, evidence budget or endpoint budget.
- All arithmetic is saturating and uses `u64` accounting.
- The accumulator remains networkless and does not widen target authorization.

## Strengthening plan

### Stage A — Streaming persistence

Replace the in-memory `Vec<Finding>` retention path with an append-only finding sink:

- bounded in-memory write buffer;
- content-addressed segments;
- atomic segment commit;
- crash-safe checkpoint;
- per-segment SHA-256 manifest;
- encrypted local storage adapter;
- backpressure instead of process-memory growth.

Expected effect: capacity becomes primarily disk/evidence-policy limited rather than RAM limited.

### Stage B — Hierarchical deduplication

Add three deduplication levels:

1. exact `finding_id` deduplication;
2. rule + endpoint + normalized evidence correlation;
3. root-cause clustering across equivalent endpoints.

Use an exact hot set plus disk-backed sorted runs. Bloom filters may be used only as a negative-cache accelerator; they must never suppress a finding without exact confirmation.

Expected effect: large repetitive applications no longer consume capacity with equivalent findings.

### Stage C — Adaptive rule scheduling

Maintain per-rule measurements:

- requests consumed;
- unique findings produced;
- duplicate ratio;
- evidence bytes;
- validation success rate;
- false-positive rejection rate;
- average execution cost.

Compute a bounded priority score:

```text
score = expected_unique_yield * confidence_weight * severity_weight
        / max(resource_cost, minimum_cost)
```

The score may reorder queued safe checks, but may not bypass scope, capability, rate or mutation budgets.

Expected effect: the run spends finite resources on rules with the highest observed unique-finding yield.

### Stage D — Saturation detection

Track marginal yield over deterministic windows:

```text
marginal_yield = new_unique_findings / completed_checks
```

A run may enter `saturated` state when all conditions hold:

- minimum sample count completed;
- marginal yield remains below policy threshold for several windows;
- no high-priority unexplored endpoints remain;
- validation and cleanup queues are empty;
- resource budgets have not been violated.

Saturation is an optimization stop, not a claim that no vulnerability exists.

### Stage E — Sharded execution

Partition by normalized origin and endpoint hash:

- deterministic shard assignment;
- shard-local exact dedup;
- global merge by finding ID;
- independent byte and request budgets;
- global emergency stop;
- no cross-origin credential sharing.

Expected effect: large authorized scopes can be processed in parallel without weakening origin isolation.

### Stage F — Coverage accounting

Produce a run coverage receipt containing:

- admitted endpoints;
- analyzed endpoints;
- enabled rules;
- executed rule-endpoint pairs;
- skipped pairs and explicit reasons;
- unique and duplicate finding counts;
- validation state counts;
- memory, evidence, disk, request and time consumption;
- stop or saturation reason.

This receipt distinguishes “no finding observed” from “not tested” and “budget exhausted”.

## Required order

1. Merge BSL-121 resource-derived capacity.
2. Add append-only encrypted finding sink.
3. Add exact disk-backed dedup and root-cause correlation.
4. Add coverage receipt and saturation telemetry.
5. Add adaptive scheduling under existing capability budgets.
6. Add deterministic sharding.
7. Only after those layers, connect the future scope-controlled live adapter MVP.

## Non-goals

This change does not add:

- live network access;
- scanning outside explicit authorization;
- unlimited requests;
- unlimited memory or disk use;
- exploit payload generation;
- brute force, credential attacks or destructive testing.
