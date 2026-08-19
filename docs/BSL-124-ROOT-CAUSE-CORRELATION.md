# BSL-124 — Root-Cause Correlation

## Purpose

BSL-124 groups exact unique findings into deterministic root-cause clusters without suppressing or deleting any original finding membership.

A root cause is identified from:

- rule ID;
- policy snapshot SHA-256;
- normalization version;
- affected component SHA-256;
- normalized evidence SHA-256;
- response-shape SHA-256.

Endpoint identity is intentionally excluded from the root-cause ID so equivalent failures across many endpoints can be represented as one cause with a complete affected-endpoint set.

## Safety and integrity

- every finding ID remains in the cluster membership set;
- every affected endpoint and evidence digest remains addressable;
- the same finding ID with changed content is rejected as an identity conflict;
- exact duplicate observations increment a counter but do not consume membership capacity;
- policy, component, normalized evidence, response shape or rule changes produce distinct roots;
- severity is aggregated using the highest observed value;
- confidence is aggregated using the minimum observed value;
- titles are reduced to the lexicographically smallest title so insertion order cannot change the result;
- all collections use deterministic ordered maps and sets.

## Resource model

Correlation capacity may be derived from explicit memory reservations and the upstream BSL-121 capacities:

```text
maximum_clusters = min(cluster_budget / 1024, source_unique_findings)
maximum_members = min(member_budget / 256, source_unique_findings)
maximum_endpoints_per_cluster = min(endpoint_budget / 96, source_distinct_endpoints)
```

Configured architecture guards remain in place for addressability, but the operational limit is derived from the run resource budget rather than the former 256-finding ceiling.

## Regression coverage

The test suite verifies:

- capacity greater than 256;
- 5,000 endpoint findings collapsing to one root cause while retaining all 5,000 finding, endpoint and evidence memberships;
- multiple findings on one endpoint;
- exact duplicate accounting;
- forged reuse of a finding ID;
- insertion-order-independent cluster and receipt hashes;
- distinct policy/evidence roots;
- endpoint-budget failure without partial mutation.

## Next stage

BSL-125 will add coverage and saturation receipts. Correlation is an organizational layer only; it never claims that untested endpoints are safe and never replaces exact finding persistence or exact disk-backed deduplication.
