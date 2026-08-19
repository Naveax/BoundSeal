# BSL-2 — Audit and Destination Contract

## Status

This milestone remains a networkless decision layer. It does not resolve DNS, open sockets, follow redirects, operate a browser, or execute scanner tools.

## Destination decision contract

Every resolved address supplied by a future gateway transport must be assessed independently. A request is denied if any address in the resolution set is non-public.

The classifier currently denies:

- IPv4 unspecified and `0.0.0.0/8`
- loopback
- RFC1918 private ranges
- RFC6598 shared/CGNAT space
- link-local addresses
- documentation ranges
- benchmarking ranges
- selected protocol-assignment ranges
- multicast
- limited broadcast
- reserved high IPv4 space
- IPv6 unique-local, link-local and deprecated site-local ranges
- IPv6 documentation, benchmarking, ORCHID and discard-only ranges
- selected IPv6 protocol-assignment and transition ranges
- IPv4-mapped IPv6 values when the embedded IPv4 address is non-public

A classification is returned with the deny decision and persisted in the audit event. The transport layer must not replace this classifier with a boolean-only check.

## Redirect contract

The caller must submit each redirect hop as a new `RequestIntent`. Every hop is re-evaluated for:

1. redirect depth,
2. URL scheme, host and method scope,
3. presence of DNS resolution results,
4. classification of every resolved address,
5. total, concurrency and rate budgets.

A previously authorized hop does not authorize its redirect target.

## Audit contract

Every gateway decision, including denials that spend no request budget, is appended to a SHA-256 hash chain before the decision is returned.

Each record commits to:

- sequence number,
- previous record hash,
- decision ID,
- allow/deny outcome,
- reason code and structured details,
- normalized method,
- sanitized URL,
- every resolved destination and classification,
- redirect depth,
- monotonic elapsed milliseconds.

The URL query and fragment are removed before audit persistence because they may contain access tokens or other sensitive values.

Verification rejects:

- sequence changes,
- broken previous-hash links,
- modified event data,
- modified record hashes,
- a tail hash inconsistent with the final record.

## Failure semantics

A gateway decision is not returned if its audit record cannot be serialized and committed. This prevents an unaudited request authorization path.

## Known boundaries

- Audit records are currently retained in memory only.
- The chain proves internal consistency, not external timestamping or independent notarization.
- The current gateway intentionally runs at a narrower `1 request/second` and `1 concurrent request` setting until compiled policy limits can be exposed through a no-broadening API.
- IANA special-purpose registries must be reviewed and pinned before the first real network transport is enabled.
- DNS resolver pinning and rebinding protection belong to the future transport milestone and are not implemented here.
