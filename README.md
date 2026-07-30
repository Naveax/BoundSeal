# NXBounty

NXBounty is a private, deterministic and scope-enforced bug bounty research platform for explicitly authorized targets.

## Current milestone

`NXB-0 — Source Lock and Policy Contract`

The repository currently contains only the safety and data-contract foundation:

- strict target-policy parsing and validation;
- hard denials for credential brute force and destructive testing;
- host, scheme, method, request-budget and authorization-expiry checks;
- public-destination guardrails;
- canonical JSON event envelopes with provenance;
- a small CLI for validating policies, events and destination IPs;
- fixture tests and GitHub Actions CI.

No crawler, scanner, payload runner, authenticated browser worker or real-target workflow is enabled at this stage.

## Build

```bash
cargo build --workspace
cargo test --workspace
```

## Validate the example policy

```bash
cargo run -p nxb-core -- validate-policy examples/target.policy.toml
cargo run -p nxb-core -- validate-event examples/event.json
cargo run -p nxb-core -- check-destination 8.8.8.8
```

## Safety model

All future network-capable adapters must use a single NXBounty Scope Gateway. Adapters will not own credentials, broaden policy, change request budgets or connect directly to arbitrary destinations.

Unattended execution will remain bounded to passive, read-only and inert-marker testing. Destructive actions, credential attacks, persistence, lateral movement and bulk access to third-party data are hard-denied.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Repository status

Private. Packages are marked `publish = false`.