# NXBounty P7-P9 architecture contract

This document freezes the networkless P7-P9 architecture batch. P6 already supplies deterministic workflow, quorum and run certification. P7-P9 add adapter isolation, deterministic replay and release governance without enabling public-network execution.

## Phase map

### P7 — NXB-48 through NXB-53

1. **NXB-48 Adapter manifest** — immutable adapter identity, declared capabilities, resource ceilings and content digest.
2. **NXB-49 Admission authority** — exact run, worker, policy, manifest and fixture-profile binding.
3. **NXB-50 Typed envelope** — a closed action vocabulary with content-addressed inputs and outputs.
4. **NXB-51 Session supervisor** — sequence, quota, cancellation, emergency-stop and terminal-state enforcement.
5. **NXB-52 Fixture registry** — synthetic-only fixture profiles with immutable object hashes.
6. **NXB-53 Conformance certificate** — audit, quota, fixture and terminal-state closure.

### P8 — NXB-54 through NXB-59

1. **NXB-54 Replay bundle** — immutable inputs anchored to an adapter conformance certificate.
2. **NXB-55 Virtual clock and deterministic seed** — no wall-clock dependency.
3. **NXB-56 Bounded fault plan** — delay, fragmentation, backpressure, timeout, reset and truncation only.
4. **NXB-57 Replay engine** — exact sequence, checkpoints and content-addressed observations.
5. **NXB-58 Drift comparator** — deterministic, metadata-only comparison with explicit classifications.
6. **NXB-59 Reproducibility certificate** — quorum over independent replay receipts.

### P9 — NXB-60 through NXB-65

1. **NXB-60 Component inventory** — immutable component and dependency digests.
2. **NXB-61 Compatibility contract** — schema, policy and fixture compatibility matrix.
3. **NXB-62 Release gates** — hard safety boundaries cannot be waived.
4. **NXB-63 Artifact attestation** — deterministic artifact manifest and audit closure.
5. **NXB-64 Rollout and rollback drill** — simulation-only state machine with exact rollback evidence.
6. **NXB-65 Platform release certificate** — adapter, replay, policy, audit, compatibility and rollback closure.

## Non-negotiable exclusions

P7-P9 do not add:

- sockets, resolvers, TLS negotiation or public-network transports;
- browser, scanner or operating-system process adapters;
- arbitrary shell, command, script or plugin execution;
- raw credentials, cookies, authorization values, request bodies or response bodies;
- exploit payload libraries, credential attacks, persistence, lateral movement or destructive behavior;
- autonomous deployment or rollback.

All inputs are synthetic fixture identifiers, hashes, bounded metadata and typed state transitions.

## Authority chain

```text
Policy snapshot + run + worker
              │
              ▼
       Adapter manifest
              │
              ▼
       Admission authority
              │
              ▼
      Synthetic fixture grant
              │
              ▼
       Adapter session audit
              │
              ▼
    Conformance certificate
              │
              ▼
       Immutable replay bundle
              │
              ▼
  Deterministic replay + drift
              │
              ▼
 Reproducibility certificate
              │
              ▼
 Release gates + rollback drill
              │
              ▼
 Platform release certificate
```

## Fail-closed rules

- Policy, run, worker, manifest, fixture or digest mismatch denies admission.
- Grants and session sequence numbers are exact and non-replayable.
- Quota exhaustion, cancellation, emergency stop or audit drift terminates the session.
- Fixtures use `fixture://` identifiers only and cannot contain network destinations or secret-like material.
- Fault plans are bounded and cannot create commands, payloads or external callbacks.
- Replay results become reproducible only when independent receipts agree on the same result digest.
- Hard release gates cannot be waived by risk acceptance.
- A platform release certificate requires a successful rollback drill even when the simulated rollout succeeds.
