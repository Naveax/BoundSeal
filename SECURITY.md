# Security policy

BoundSeal is a private security-research project. Use is restricted to systems and programs for which the operator has explicit authorization.

## Supported version

Only the current `main` branch and the latest contract-complete checkpoint are supported.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, target data or private evidence.

Report privately to the repository owner through GitHub's private security reporting interface when available. Include:

- affected commit;
- impacted crate and API;
- minimal synthetic reproduction;
- expected and observed security boundary;
- whether any real credential or target data was involved.

Never include live secrets. Replace them with deterministic fixture values.

## Hard safety boundary

The project must not add or enable:

- credential stuffing, brute force, spraying or OTP guessing;
- destructive data mutation or denial of service;
- persistence, reverse shells or lateral movement;
- arbitrary internal-network exploration;
- bulk collection of third-party data;
- unrestricted shell, process or plugin execution.

A real network adapter must pass through the existing policy, gateway, permit, destination, TLS, session and audit contracts.

## Dependency response

Security advisories are checked in CI against the committed `Cargo.lock`. A vulnerable direct dependency should be upgraded or removed. Any temporary advisory exception must document scope, reachability and an expiry date.
