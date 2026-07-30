# NXB-11 — TLS Peer Identity Contract

## Purpose

NXB-11 freezes the trust and peer-identity boundary that a future TLS backend must satisfy. It does not implement a TLS stack. It validates bounded synthetic observations against the already authorized stream binding.

## Binding order

1. A `TransportPermit` is consumed.
2. The permit-only executor produces a completed execution receipt.
3. `BoundedByteStream` verifies the permit, receipt and executor audit chain.
4. `TlsPeerVerifier` reads the immutable stream grant and current stream-audit tail.
5. Only an HTTPS stream with an exact DNS SNI may enter TLS verification.
6. A successful verification produces a non-serializable `TlsSessionGrant` bound to that stream, ticket, SNI, certificate fingerprints and TLS audit record.

A certificate observation cannot authorize a different stream, ticket, port, SNI or HTTP authority.

## Protocol policy

Only TLS 1.2 and TLS 1.3 are accepted. ALPN must be exactly `http/1.1`. TLS 1.0, TLS 1.1, unknown versions, `h2`, missing ALPN, 0-RTT, renegotiation and session resumption are rejected in this milestone.

Handshake read bytes, write bytes and elapsed time are independently bounded. The verifier never consumes raw handshake bytes.

## Certificate-chain contract

The synthetic chain is ordered leaf first and trust anchor last. The verifier requires:

- bounded chain depth and encoded-byte accounting
- lowercase SHA-256 fingerprints and SPKI identifiers
- valid certificate time windows
- no unsupported critical extension marker
- a non-CA leaf with digital-signature usage and Server Authentication EKU
- issuer-SPKI linkage and successful signature-validation markers
- CA and certificate-sign usage on intermediates and root
- path-length constraints
- a self-issued root whose fingerprint exists in the explicit trust store

The `signature_valid` fields are outputs expected from a future cryptographic backend. NXB-11 does not claim to perform X.509 parsing or signature verification itself.

## DNS identity

Only DNS Subject Alternative Names participate in hostname verification. Common Name is retained only in the synthetic fixture model to prove it is ignored.

Exact SANs must match normalized SNI. Wildcards are accepted only as the complete left-most label and match exactly one label. Broad patterns such as `*.com` and `*.co.uk` are rejected.

IP-address SNI, Unicode input, malformed labels and multi-level wildcard matches are rejected.

## Audit

Every verified or rejected observation is appended to a SHA-256 audit chain before a decision is returned. Records contain:

- verifier, stream, execution and ticket identifiers
- permit binding hash and stream-audit anchor
- SNI, HTTP authority, port and redirect depth
- protocol, ALPN, resource counters and chain depth
- chain, leaf, root and matched-SAN fingerprints or digests
- typed outcome and bounded reason metadata

Certificate bytes, Subject names, Common Name, SAN lists, handshake messages, secrets and HTTP payloads are not recorded.

## Validation boundary

Formatting, Clippy and all workspace tests run on the complete permit-to-stream fixture path. TLS fixtures use synthetic certificate metadata and public IP literals only. They do not resolve hostnames, import a system trust store, open sockets or negotiate a TLS connection.

## Exclusions

NXB-11 adds no socket backend, TLS library binding, X.509 parser, operating-system trust import, revocation network lookup, OCSP, CRL, certificate transparency lookup, public-network traffic, browser integration, proxying or scanner behavior.
