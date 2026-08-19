# BSL-123 — Disk-Backed Exact Deduplication

## Decision

Finding suppression requires an exact full `finding_id` match. Probabilistic structures may accelerate negative lookups in later stages, but they may never independently classify a finding as duplicate.

## Storage model

- canonical finding IDs are lowercase 64-character SHA-256 strings;
- each immutable run stores sorted unique identifiers;
- each record is fixed-width: `64 hex bytes + newline`;
- lookups use file seeking and binary search without loading a run into the hot set;
- a bounded in-memory `BTreeSet` absorbs recent IDs;
- the hot set is flushed into append-only run files;
- run metadata is recorded in a hash-chained manifest;
- temporary and orphan run files are fail-closed.

## Exactness

The decision path is:

1. exact hot-set lookup;
2. range check against run first/last IDs;
3. exact fixed-record binary search on each candidate run;
4. duplicate only when all 64 characters match.

Prefixes, truncated hashes and approximate membership never produce duplicate classification.

## Durability

Run commit order:

1. encode a strictly sorted run;
2. write a new temporary file;
3. `fsync` it;
4. atomically rename to the immutable run name;
5. `fsync` the directory;
6. append the run manifest record;
7. `fsync` the manifest.

Opening the index verifies manifest sequence, previous-hash linkage, record hashes, file hashes, fixed record length, canonical IDs, strict sorting, run bounds and absence of orphan files.

## Resource policy

- hot-set size is bounded;
- entries per run are bounded;
- total run count is bounded;
- disk bytes are bounded;
- a failed flush leaves the hot set intact;
- all counters use saturating arithmetic.

## Regression coverage

- 10,000 unique IDs survive flushing and reopening;
- exact duplicates are detected after reopen;
- IDs sharing 63-character prefixes remain distinct;
- tampered runs are rejected;
- disk backpressure preserves pending IDs;
- orphan runs and noncanonical IDs are rejected.

## Integration

BSL-124 will add semantic and root-cause correlation above this exact layer. Exact finding-ID dedup remains the authoritative first stage and cannot be bypassed by correlation heuristics.
