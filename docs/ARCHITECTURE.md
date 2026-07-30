# NXBounty architecture contract

## Ownership boundaries

NXBounty Core owns:

- policy compilation;
- scope and destination decisions;
- request budgets and cancellation;
- credential handles;
- canonical application and event models;
- validation, evidence, deduplication and reporting.

External tools own only specialist protocol or detection behavior. They will run through bounded adapters and will not be trusted with unrestricted network access.

## Planned process model

```text
Target profile + policy snapshot + session handles
                       │
                       ▼
                Policy Compiler
                       │
                       ▼
                 Scope Gateway
                       │
       ┌───────────────┼────────────────┐
       ▼               ▼                ▼
 Browser worker   Recon adapters   API adapters
       │               │                │
       └───────────────┼────────────────┘
                       ▼
              Canonical event bus
                       ▼
           Application knowledge graph
                       ▼
        Deterministic rule/workflow engine
                       ▼
          Differential validation oracles
                       ▼
          Capability and attack-chain graph
                       ▼
          Evidence store and report output
```

## Non-negotiable invariants

1. Network-capable adapters use the Scope Gateway as their only egress path.
2. A child policy may narrow but never broaden its parent policy.
3. Credentials are represented by opaque, time-limited handles outside the vault.
4. Every observation includes tool and policy-decision provenance.
5. A scanner finding is not a reportable finding until a validation oracle confirms it.
6. Write tests operate only on NXBounty-created, ownership-ledgered objects and must clean up.
7. Cleanup failure, identity drift or scope drift stops the run.
8. Unattended execution never enables credential attacks, destructive behavior or persistence.

## Initial crates

- `nxb-policy`: policy format, hard denials and request-scope decisions.
- `nxb-events`: canonical event and provenance contract.
- `nxb-core`: command-line validation utilities during NXB-0.

## Next milestone

`NXB-1 — Scope Gateway`

The next milestone adds a local-only proxy skeleton, DNS-resolution decisions, redirect-chain enforcement, token-bucket budgeting and append-only decision logs. It will first be tested against synthetic local fixtures; it will not ship a real-target scanner.
