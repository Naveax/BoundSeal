# Vercel Open Source — `vercel/flags`

## Campaign status

- Platform: HackerOne
- Program: Vercel Open Source
- Selected asset: `https://github.com/vercel/flags`
- Research mode: source-code review and local controlled proof-of-concept
- Status: active reconnaissance
- Last policy review: 2026-07-30

## Authorization boundary

This campaign is limited to the asset currently listed by the Vercel Open Source HackerOne program. Source review is permitted. Any dynamic validation must run locally against researcher-controlled data and infrastructure unless the current program policy explicitly authorizes another environment.

Hard denials:

- no testing against Vercel production services;
- no testing against third-party deployments;
- no denial-of-service or resource-exhaustion testing outside a local bounded harness;
- no credential attacks, social engineering, persistence, or bulk data access;
- no report submission without a reproducible security impact.

## Initial attack-surface map

1. `packages/flags/src/lib/crypto.ts`
   - JWE encryption/decryption
   - purpose binding (`overrides`, `values`, `definitions`, `proof`)
   - `FLAGS_SECRET` validation
2. `packages/flags/src/lib/verify-access.ts`
   - Bearer token parsing
   - toolbar access-proof verification
3. `packages/flags/src/next/overrides.ts`
   - encrypted override cookie decryption
   - memoization and malformed-input behavior
4. `packages/flags/src/react/index.tsx`
   - JSON embedding in script elements
   - XSS escaping boundary
5. Framework adapters
   - Next.js request/cookie handling
   - SvelteKit request/cookie handling
   - trust boundaries between request-derived context and flag evaluation

## Completed review notes

### JWE purpose separation

The crypto layer uses direct-key `A256GCM` JWE and verifies the `pur` claim before returning each token type. No cross-purpose token confusion has been demonstrated.

### Access proof

`verifyAccess` removes a leading case-insensitive `Bearer ` prefix and validates the resulting JWE as a `proof` token. No authentication bypass has been demonstrated.

### React JSON embedding

`FlagDefinitions` and `FlagValues` use a helper that JSON-serializes values and replaces `<` with `\u003c` before inserting content through `dangerouslySetInnerHTML`. No script-breakout XSS has been demonstrated.

## Active hypotheses

- malformed override cookies may create a cache/rejection edge case across requests;
- adapter-specific cookie parsing may diverge between Next.js and SvelteKit;
- access-proof or override tokens may have replay/scope properties that produce security impact in realistic deployments;
- untrusted flag definitions or values may reach an unsafe serialization or rendering sink outside the reviewed React component;
- request-derived identifiers may allow cross-user cache contamination or unintended flag evaluation reuse.

Each hypothesis remains unconfirmed until a local test reproduces a concrete confidentiality, integrity, or availability impact.

## Evidence standard

A report candidate must include:

1. affected current commit/version;
2. minimal vulnerable application;
3. exact attacker preconditions;
4. deterministic reproduction steps;
5. security impact beyond a product-quality bug;
6. regression test or bounded PoC;
7. confirmation that the issue is not excluded by the current HackerOne policy.
