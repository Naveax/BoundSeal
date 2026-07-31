# NXB-122 — Append-Only Encrypted Finding Sink

## Scope

NXB-122 replaces unbounded in-memory retention as the only persistence path with an append-only, segment-oriented encrypted sink contract.

## Commit sequence

Each segment is committed in this order:

1. validate redacted finding metadata;
2. serialize a bounded plaintext segment in memory;
3. compute its SHA-256 identity;
4. pass the segment and associated data to a caller-supplied authenticated-encryption backend;
5. write the sealed segment to a new temporary file;
6. `fsync` the temporary file;
7. atomically rename it to the immutable segment name;
8. `fsync` the directory;
9. append a hash-chained manifest record;
10. `fsync` the manifest.

No existing segment path may be overwritten.

## Encryption boundary

The store does not invent a cipher. Production code must provide a `SegmentSealer` backed by an approved authenticated-encryption implementation and externally managed key material.

The backend must provide:

- a non-plaintext algorithm identifier;
- a SHA-256 key identifier;
- a nonce of at least 12 bytes;
- an authentication tag of at least 16 bytes;
- ciphertext distinct from the plaintext storage representation;
- a declared maximum overhead for preflight disk accounting.

The fixture sealer is compiled only for tests.

## Recovery and integrity

Opening a store verifies:

- manifest sequence monotonicity;
- exact previous-hash linkage from the store genesis;
- manifest record hashes;
- segment presence;
- immutable segment-file hashes;
- ciphertext hashes;
- segment metadata equality;
- absence of orphan or temporary segment files.

A crash after segment rename but before manifest append therefore produces an explicit orphan condition instead of silent adoption or deletion.

## Resource behavior

- segment finding count is bounded;
- segment plaintext bytes are bounded;
- total disk bytes are bounded;
- disk exhaustion applies backpressure without clearing the pending buffer;
- plaintext buffers are explicitly zeroed on clear and drop;
- committed files contain ciphertext plus metadata-only hashes;
- raw cookie, authorization, password, token and body metadata keys are rejected.

## Tests

The regression suite covers:

- 1,000 findings across sixteen encrypted segments;
- absence of finding title, summary and origin in sealed files;
- reopen and append-chain continuation;
- tamper detection;
- disk-budget backpressure;
- secret-bearing metadata rejection;
- fail-closed orphan detection.

## Next stage

NXB-123 will place an exact disk-backed deduplication index in front of this sink. Bloom filters may accelerate negative lookups but can never suppress a finding without exact confirmation.
