# BSL P0–P3 — Networkless Analysis Batch

This batch implements BSL-12 through BSL-29 without enabling DNS resolution, sockets, TLS negotiation, browser automation, proxies, public-network traffic or active exploit execution.

## P0 — Channel, request and response contracts

- **BSL-12 TLS-gated HTTP channel:** exact stream/TLS binding snapshots, `http/1.1` ALPN, one-use channel grants, plain-HTTP separation and sensitive-header denial on cleartext channels.
- **BSL-13 typed request construction:** typed methods, origin-form targets, canonical query encoding, caller-header policy, request fingerprints and metadata-only receipts.
- **BSL-14 bounded body sources:** empty, fixed, chunked, form, JSON and multipart fixture bodies with hard byte/chunk/part limits and body digests.
- **BSL-15 response envelope:** status/header/body accounting, bounded non-serializable body preview, content metadata, redirect/cookie summaries and stream/TLS/HTTP audit anchors.

## P1 — Content and discovery

- **BSL-16 strict content type and charset:** bounded MIME parsing, duplicate-parameter rejection, UTF-8/ASCII validation and sniffing disabled by default.
- **BSL-17 bounded content encoding:** synthetic gzip/deflate/Brotli accounting, layer count, compressed/decompressed bytes and expansion-ratio limits.
- **BSL-18 structured extractors:** bounded lexical HTML/XML, structural JSON and text token extraction. Scripts, DTDs, entities and browser execution remain disabled.
- **BSL-19 discovery graph:** canonical HTTP(S) URL/form metadata, fragment removal, duplicate suppression, same-origin candidates and cross-origin passive-only nodes.

## P2 — Planning and capability control

- **BSL-20 request intent planner:** provenance, risk class, policy snapshot, cost estimates, session requirement and redirect/retry budgets.
- **BSL-21 work queue and scheduler:** bounded priority queue, per-host/global concurrency, deterministic rate spacing, exact-once leases, cancellation and emergency stop.
- **BSL-22 run state machine:** immutable policy binding, validated transitions, pause/resume token hashing, generation and terminal-state enforcement.
- **BSL-23 probe capability system:** module/run/worker binding, endpoint/method allowlists, request/mutation budgets, secret level, body replay, redirect permission, expiry and revocation.

## P3 — Passive analyzers

- **BSL-24 security headers:** HSTS, CSP, MIME sniffing, referrer, permissions, duplicate policy and version-like disclosure checks.
- **BSL-25 cookie security:** Secure, HttpOnly, SameSite and domain-scope analysis without storing cookie values in findings.
- **BSL-26 TLS metadata:** verification, hostname coverage, TLS version, ALPN, expiry, root fingerprint and replay-feature analysis.
- **BSL-27 redirect analysis:** downgrade, cross-origin credentials/body replay, loops, chain depth and session-generation anomalies.
- **BSL-28 CORS analysis:** wildcard/credentials, null origin, duplicate allow-origin and missing `Vary: Origin` checks.
- **BSL-29 cache analysis:** authenticated cacheability, public/private conflicts, cookie-setting public responses and missing variance metadata.

## Data safety

Raw request/response bodies, cookie values, authorization values and discovered query contents are not serialized into receipts or findings. Evidence is represented through bounded metadata and SHA-256 digests. In-memory previews and observed header values are private runtime objects with redacted output contracts.

## Execution boundary

All tests are deterministic fixtures. This batch produces plans, capabilities, envelopes, discovery nodes and passive findings only. It cannot resolve a hostname, open a socket, negotiate TLS, follow a redirect, send a request or mutate a live target.
