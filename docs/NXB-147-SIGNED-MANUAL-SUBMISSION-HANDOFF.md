# NXB-147 — Signed manual submission handoff

NXB-147 converts a verified NXB-146 run-closure certificate and the exact validated report/export artifacts into one canonical package for operator-reviewed manual submission.

## Bound inputs

The handoff manifest binds:

- the exact NXB-146 closure ID, manifest SHA-256 and signature-byte SHA-256,
- the unified operator plan and policy snapshot,
- the validated report ID, JSON SHA-256 and Markdown SHA-256,
- the evidence export root and source knowledge-audit tail,
- a deterministic digest of the exact report finding set,
- the target platform and program handle,
- the operator review decision and review timestamp,
- explicit acknowledgement of all untested-scope hashes for partial closures,
- optional review-note SHA-256 and bounded secret-safe metadata.

## Safety boundary

- Aborted closures cannot produce a submission-ready handoff.
- Partial closures require exact acknowledgement of the closure's untested-scope hash set.
- A `hold` review decision cannot produce a submission-ready manifest.
- The closure certificate is reverified against the Ed25519 key ID bound by the unified plan.
- Report JSON is parsed and compared with the structured report document.
- Report JSON, Markdown, export-root and audit-tail hashes must match the NXB-146 closure artifacts.
- Secret-like metadata, URLs, authorization values, cookies, bearer tokens and private-key material are rejected.
- The handoff ID and manifest SHA-256 are deterministic.
- `unsafe` Rust is forbidden.

NXB-147 does not call HackerOne or any other external service. It does not read browser credentials, store API tokens or submit reports automatically. The resulting package is an immutable operator handoff for manual review and submission.
