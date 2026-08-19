# NXB-125 — Coverage and Saturation Receipts

## Purpose

NXB-125 makes run completeness and stopping conditions explicit. A run receipt must distinguish:

- an endpoint-rule pair that executed and produced no finding;
- an explicitly skipped pair and its reason;
- an admitted pair that was never tested;
- a run stopped by a resource boundary;
- a complete run;
- a run stopped because deterministic marginal yield saturated.

## Coverage matrix

The theoretical matrix is:

```text
theoretical_pairs = admitted_endpoints × enabled_rules
```

Every recorded pair has exactly one immutable outcome:

- `executed`, with unique/duplicate finding counts, validation dispositions and resource use;
- `skipped`, with an explicit typed reason.

Duplicate pair outcomes and outcomes for unadmitted endpoints or disabled rules are rejected.

## Resource boundaries

Execution resource deltas are preflighted transactionally against:

- accounted memory bytes;
- evidence bytes;
- disk bytes;
- requests;
- elapsed milliseconds.

The first exceeded budget becomes the terminal stop reason. The pair that would exceed the budget is not recorded and its resource delta is not charged.

## Saturation model

Marginal yield is measured in fixed deterministic windows:

```text
marginal_yield = new_unique_findings / completed_checks
```

Integer cross multiplication is used; floating-point arithmetic is not involved.

A run may enter `saturated` only when all conditions hold:

1. the minimum completed-check count is reached;
2. the required number of consecutive full windows is below the configured yield threshold;
3. no high-priority unexplored pair remains;
4. the validation queue is empty;
5. the cleanup queue is empty;
6. no earlier terminal reason exists.

Saturation is an optimization stop. It is not a claim that no vulnerability exists.

## Receipt contents

The deterministic receipt includes:

- admitted, considered, analyzed and untested endpoint counts;
- enabled rule count;
- theoretical, recorded, executed, skipped and untested pair counts;
- skipped-pair counts grouped by reason;
- unique and duplicate findings;
- validated, rejected and inconclusive finding counts;
- resource consumption;
- queue telemetry;
- closed saturation windows;
- terminal stop reason;
- endpoint-set, rule-set and pair-outcome SHA-256 roots;
- a final self-verifying receipt digest.

Incomplete-window progress is derivable from executed-pair totals minus the closed-window totals, while the exact pair-outcome root preserves all execution metrics.

## Regression coverage

Tests verify:

- tested-with-zero-findings versus skipped versus untested states;
- 10,000 pair accounting without a fixed 256 ceiling;
- three-window low-yield saturation;
- high-priority and validation queues blocking saturation;
- transactional request-budget stop;
- insertion-order-independent receipts;
- complete-matrix and empty-queue requirements;
- receipt tamper rejection.

## Next stage

NXB-126 will add adaptive safe-rule scheduling. Scheduling may reorder already-authorized work using observed unique-yield and cost, but it cannot bypass scope, capability, mutation, rate, request, time or cleanup boundaries.
