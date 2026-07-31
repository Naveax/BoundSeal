# NXBounty architecture

## Status

NXBounty's deterministic architecture-contract program is complete through NXB-119. The codebase is organized as a deny-by-default set of typed contracts rather than a monolithic scanner.

The current system is **contract complete and product incomplete**:

- contract complete: authorization, policy, scope, resource, identity, audit, evidence, workflow and lifecycle invariants are implemented and fixture-tested;
- product incomplete: no real resolver, socket, TLS backend, browser or scanner adapter is enabled.

## Runtime contract chain

```text
Authorization + target policy
          │
          ▼
Policy compiler and scope gateway
          │
          ▼
Destination decision and DNS pin contract
          │
          ▼
One-use transport permit
          │
          ▼
Permit-only executor and bounded stream
          │
          ▼
TLS peer-identity grant
          │
          ▼
TLS-gated strict HTTP/1 channel
          │
          ▼
Session, cookie and redirect isolation
          │
          ▼
Content analysis and discovery graph
          │
          ▼
Request planner, scheduler and probe capability
          │
          ▼
Passive finding and safe inert validation
          │
          ▼
Evidence, report and deterministic workflow
          │
          ▼
Replay, release, assurance and lifecycle closure
```

## Crate groups

### Foundation

- `nxb-policy`, `nxb-events`, `nxb-audit`, `nxb-budget`
- `nxb-destination`, `nxb-dns`, `nxb-gateway`

### Transport and protocol contracts

- `nxb-transport`, `nxb-pinned-transport`
- `nxb-executor`, `nxb-local-executor`
- `nxb-stream`, `nxb-stream-fixture`
- `nxb-tls`, `nxb-http1`, `nxb-http1-fixture`
- `nxb-channel-contracts`, `nxb-redirect`

### Identity and state

- `nxb-vault`, `nxb-session`, `nxb-cookie-jar`

### Analysis and planning

- `nxb-content-analysis`, `nxb-planner`
- `nxb-passive-analyzers`, `nxb-active-validation`

### Evidence and orchestration

- `nxb-knowledge-reporting`
- `nxb-workflow-graph`
- `nxb-adapter-boundary`, `nxb-replay-lab`
- `nxb-release-governance`, `nxb-platform-assurance`
- `nxb-lifecycle-governance`, `nxb-post-closure-governance`

### User surface

- `nxb-core`: policy/event/destination utilities plus the deterministic system smoke demo.

## Non-negotiable invariants

1. A child policy may narrow but never broaden its parent.
2. A destination, redirect or session transition must be re-authorized at its own boundary.
3. Credentials are opaque, short-lived and never serialized in public receipts.
4. Every permit, lease and grant is exact-bound, expiring and replay-resistant.
5. Resource ceilings are explicit and terminal on exhaustion.
6. A scanner observation is not reportable until validation and evidence gates close.
7. Write-like tests are limited to NXB-owned objects and require cleanup proof.
8. Audit and evidence records contain metadata, lengths and hashes, not raw secrets or bodies.
9. External-I/O adapters are absent from the contract-complete release.
10. Credential attacks, destructive behavior, persistence and lateral movement are hard-denied.

## Synthetic integration demo

`nxb demo-run` creates a twelve-stage, SHA-256-linked receipt:

1. policy compilation;
2. scope gateway;
3. destination and transport authorization;
4. bounded stream;
5. TLS peer identity;
6. strict HTTP exchange;
7. content analysis;
8. request planning;
9. passive finding;
10. safe validation;
11. evidence and report;
12. assurance and program closure.

This is a deterministic smoke test, not a network execution path.

## Next product phase

A future live MVP must be developed separately and may only add:

- policy-approved resolver adapter;
- pinned-IP TCP connector;
- real TLS backend producing the existing TLS grant;
- TLS-gated HTTP adapter;
- encrypted local evidence storage;
- explicitly authorized passive checks.

No live adapter is part of `v0.1.0-contract-complete`.
