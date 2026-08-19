# NXBounty P4-P6 — safe validation, knowledge and deterministic workflow

This batch completes the networkless architecture from bounded active validation through reportable evidence and final run certification.

## P4 — NXB-30 through NXB-35

### NXB-30 — Safe mutation engine

- accepts only `SafeActive` request plans;
- requires an already-consumed probe capability receipt bound to the exact endpoint;
- supports query, header, form and JSON scalar mutation locations;
- emits deterministic inert `nxb_...` markers only;
- excludes callback URLs, scripts, shell commands, traversal strings and exploit payload families;
- public receipts contain hashes and lengths, not mutation values.

### NXB-31 — Ownership ledger

- records only NXB-created objects;
- binds object creation to mutation and response receipts;
- authorizes later writes only while the object is registered, unexpired and owned by the same run;
- requires an explicit bounded cleanup recipe.

### NXB-32 — Cleanup transaction

- exact lifecycle: registered, cleanup pending, cleaned or cleanup failed;
- maximum three cleanup attempts;
- cleanup failure produces a fail-stop audit event;
- cleaned objects cannot be cleaned twice.

### NXB-33 — Differential observations

- stores status, header fingerprint, body hash, bounded body size, semantic tokens, timing, session generation and audit anchor;
- never stores the raw response body;
- binds baseline and mutated observations to the same endpoint and mutation ID;
- enforces hard body-size and timing-delta limits.

### NXB-34 — Repeatability oracle

- requires at least two stable baseline and two paired mutation samples;
- confirms only identical repeatable differential fingerprints with sufficient material changes;
- otherwise rejects or marks the candidate inconclusive.

### NXB-35 — Finding promotion

- promotes only confirmed oracle results;
- binds the validated finding to mutation, endpoint, repeatable delta and evidence hashes;
- extends the append-only validation audit chain.

## P5 — NXB-36 through NXB-41

### NXB-36 — Application knowledge graph

- provenance- and policy-bound nodes for origins, endpoints, parameters, sessions, findings, evidence, owned objects and workflows;
- typed edges for observation, discovery, validation, dependency and report relationships;
- bounded node and edge counts.

### NXB-37 — Evidence store

- content-addressed redacted evidence records;
- deterministic deduplication by serialized safe content hash;
- rejects authorization, cookie, password, token and secret-like material;
- stores summaries and bounded metadata rather than raw request or response bodies.

### NXB-38 — Finding deduplication

- deterministic cluster key from rule, origin and endpoint;
- merges passive and validated observations;
- retains maximum severity and confidence;
- tracks all evidence hashes and member IDs.

### NXB-39 — Finding lifecycle

- candidate, validating, validated, reportable, suppressed and closed states;
- reportable requires validated evidence and cleanup clearance;
- suppression requires a hashed reason;
- invalid transitions fail closed.

### NXB-40 — Report builder

- deterministic Markdown and JSON output;
- includes only reportable validated findings;
- references content-addressed evidence IDs;
- escapes Markdown and rejects secret-like report content;
- enforces report-size limits.

### NXB-41 — Export manifest

- safe relative logical paths only;
- per-entry class, hash and size;
- deterministic root hash;
- manifest verification detects tampering.

## P6 — NXB-42 through NXB-47

### NXB-42 — Capability graph

- typed nodes for capabilities, endpoints, sessions, findings, evidence, owned objects and workflows;
- typed prerequisite, enablement, binding, validation, production and compensation edges;
- policy snapshot is immutable across the graph.

### NXB-43 — Risk-chain synthesis

- bounded breadth-first synthesis with maximum depth eight;
- finding nodes must already be validated, reportable or closed;
- compensation edges are excluded from forward risk chains;
- output is explicitly non-executable and contains hashes and evidence references only.

### NXB-44 — Typed workflow DAG

Closed action vocabulary:

- observe;
- generate inert mutation;
- compare differential;
- evaluate oracle;
- register owned object;
- clean up owned object;
- store evidence;
- build report;
- certify run.

No arbitrary command or network action exists. Dependencies must form a DAG, active steps require capabilities and mutation/write budgets are aggregated with checked arithmetic.

### NXB-45 — Workflow lease engine

- exact-once, expiring step leases;
- deterministic topological scheduling;
- pause, resume, cancellation and emergency stop;
- maximum three attempts per step;
- cleanup compensation is isolated from normal execution;
- replayed or expired leases are denied.

### NXB-46 — Oracle quorum and drift

- bounded unique oracle votes;
- immutable policy snapshot across votes;
- confirmed votes require repeatable delta hashes;
- conflicting confirmed deltas produce drift rather than confirmation.

### NXB-47 — Run certification

A run certificate is issued only when:

- workflow state is completed;
- no cleanup object remains unresolved;
- no step failed;
- all audit chains were verified;
- no policy drift was detected;
- oracle quorum is confirmed or rejected, not inconclusive or drifted;
- the export manifest root and all audit roots are valid SHA-256 values.

## Preserved security boundary

This batch does not add:

- DNS resolution or sockets;
- TLS negotiation or public internet access;
- browser, proxy or scanner adapters;
- exploit payload libraries;
- command execution;
- credential attacks or discovery;
- persistence, lateral movement or autonomous pivoting;
- destructive testing or bulk data access.

All execution-like behavior remains a networkless typed state machine over synthetic observations and hash-bound receipts.
