# NXB-131 through NXB-135 product integration

## Status

This document defines the bounded operator layer that connects the existing NXB policy, transport, content-analysis, finding and reporting contracts. It does not broaden the authorization model and it does not introduce implicit network access.

## NXB-131 — scope-controlled passive discovery

The operator accepts only an already-authorized HTTPS seed URL. Structured response bodies may contribute link, script, resource and form metadata through `nxb-content-analysis`.

Scheduling rules are fail-closed:

- HTTPS only;
- same-origin only;
- GET and HEAD only;
- redirects are observations and require a new authorization decision;
- query-bearing targets remain passive metadata in operator schema v1;
- form actions remain metadata unless a separately authorized method capability exists;
- logout, delete, remove, revoke, shutdown and similar path segments are rejected;
- depth, endpoint, body and request budgets are mandatory;
- queue order and deduplication are deterministic;
- emergency stop and cancellation clear pending work.

## NXB-132 — authorized session and vault references

The session manifest contains metadata and opaque vault handles only. It cannot contain cookie values, bearer tokens, API keys or credentials.

Each reference is bound to:

- exact account and tenant partitions;
- exact DNS host;
- HTTPS only;
- an allowed header name or cookie metadata contract;
- expiry time;
- Secure cookie requirements;
- exact cookie domain and bounded path.

Browser cookie extraction, credential discovery, plaintext secret persistence and session mutation are outside the contract.

## NXB-133 — live probe authorization

Passive analyzers may inspect an already-received response for security headers, cookie flags, CORS, cache policy, redirect safety and TLS metadata without additional requests.

Any probe that emits requests must pass all gates:

1. the operator configuration grants the exact probe capability;
2. the program policy enables active testing;
3. the exact endpoint and method are in scope;
4. the fixed request cost fits the remaining budget;
5. the capability reference is present;
6. account and tenant partitions are explicit for authorization differentials;
7. query-bearing and dangerous paths remain denied in operator schema v1.

## NXB-134 — report and evidence export

The operator produces:

- deterministic JSON;
- Markdown review report;
- HackerOne draft marked for manual review;
- root-cause groups;
- affected endpoint hashes;
- evidence SHA-256 values;
- coverage and saturation state;
- untested areas;
- stop reason;
- confirmed, candidate, inconclusive, false-positive and suppressed dispositions;
- an export manifest with artifact hashes.

Automatic report submission is hard-disabled. Secret-like material is rejected before serialization and again before filesystem export.

## NXB-135 — hardening and release boundary

The hardening test suite covers:

- malformed config and session inputs without panics;
- deterministic scheduler ordering;
- secret-redaction rejection;
- stale temporary-file recovery;
- unwritable output failure;
- safe release paths;
- deterministic checksums;
- Windows long-path behavior when Windows CI is enabled;
- config migration to fail-closed schema v1 defaults.

Release artifacts are represented by an ordered manifest containing per-file SHA-256 values and an SBOM hash. Signing keys are never stored in the repository. Release signing must occur in a separately authorized release job or offline operator environment.

## CLI boundary

The product command is networkless by default:

```powershell
nxb scan `
  --program scope.toml `
  --target https://example.com/ `
  --output-directory .\nxb-output
```

An optional response snapshot can be analyzed without fetching it again:

```powershell
nxb scan `
  --program scope.toml `
  --target https://example.com/ `
  --response-snapshot response-snapshot.json `
  --output-directory .\nxb-output
```

Live traffic remains behind the existing signed plan, one-time Ed25519 activation, exact destination binding, compile-time `live-network` feature and explicit `--enable-live` switch.

## Explicit non-goals

- no browser automation;
- no JavaScript execution;
- no credential guessing;
- no automatic cookie extraction;
- no destructive methods;
- no redirect following;
- no public-target integration tests;
- no automatic HackerOne submission.
