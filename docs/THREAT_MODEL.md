# Threat model

## Protected assets

- authenticated cookies, access tokens and local-storage state;
- program policy and authorization snapshots;
- target and account identities;
- raw requests, responses, traces and evidence;
- scanner source revisions and rule packs;
- BoundSeal decision and audit logs.

## Primary threats

### Scope escape

An adapter follows a redirect, DNS change, alternate IP, embedded third-party resource or malformed URL outside the approved scope.

**Control:** centralized gateway, URL normalization, DNS/IP checks, redirect re-authorization and deny-by-default routing.

### Secret disclosure

A tool writes cookies or tokens to logs, reports, command lines, crash dumps or GitHub artifacts.

**Control:** opaque vault handles, structured redaction, no real sessions in GitHub-hosted CI and encrypted local evidence.

### Tool compromise

A dependency, template or external scanner executes unexpected code or bypasses command restrictions.

**Control:** pinned revisions, SBOM, isolated processes/containers, command allowlists and network access only through the gateway.

### Unsafe automation

A test locks accounts, changes real user data, causes resource exhaustion or persists changes.

**Control:** hard-denied credential/destructive modes, conservative budgets, owned test objects, snapshots, rollback and emergency stop.

### False validation

A reflected input, generic error or transient timing change is reported as a vulnerability.

**Control:** baseline, negative control, repetition, cross-account comparison, state verification and side-effect checks.

### Evidence overcollection

The platform stores unrelated personal or customer data while proving a finding.

**Control:** minimal extraction, field hashing, encrypted raw evidence, sanitized report fixtures and retention limits.

## Trust boundaries

- GitHub-hosted CI is trusted for source build and synthetic fixtures only.
- Self-hosted workers are semi-trusted and must be disposable.
- External scanners are untrusted adapters.
- Target responses are untrusted data.
- Program policy snapshots are required authorization inputs, not advisory metadata.

## Hard-denied capabilities

- credential stuffing or brute force;
- OTP or recovery-code guessing;
- destructive data mutation;
- persistence or reverse shells;
- lateral movement;
- bulk collection of third-party data;
- denial of service or resource exhaustion;
- arbitrary internal-network exploration.
