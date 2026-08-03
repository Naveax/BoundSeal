# NXB-130 — Local Adversarial Integration Lab

NXB-130 certifies the NXB-128 live passive transport and HTTP path without contacting a public target.

## Test-only socket mapping

The logical permit remains HTTPS/443 and carries the exact SNI/Host binding. Under `cfg(test)` only, the physical socket may be mapped to an ephemeral loopback listener. This mapping is unavailable in production builds and does not weaken the public-destination guard.

The lab uses the valid logical DNS name `lab.example`; it does not relax production DNS-name validation to permit single-label names.

## Verified TLS-to-HTTP handoff

Rustls/webpki performs the certificate-chain and hostname verification. NXB then binds that verified observation to the exact bounded stream and commits the binding to the TLS audit chain. HTTP/1.1 can only open through `Http1Codec::new_verified_tls` with the resulting `TlsSessionGrant`.

The binding rejects:

- a different stream, ticket, execution or binding hash;
- a different SNI, Host authority or port;
- TLS versions other than 1.2 or 1.3;
- an ALPN other than `http/1.1`;
- early data, renegotiation and resumed sessions;
- malformed certificate or trust-store fingerprints.

## Required scenarios

1. valid trusted TLS 1.2/1.3 plus HTTP/1.1 response;
2. wrong certificate hostname;
3. untrusted certificate;
4. redirect observed but not followed;
5. oversized response header;
6. truncated `Content-Length` body;
7. malformed chunk framing;
8. bounded read timeout;
9. production constructor still rejects loopback.

## Transcript

CI emits an immutable metadata-only artifact containing:

- scenario names;
- expected and observed outcome classes;
- per-scenario SHA-256 evidence;
- transcript and log SHA-256 values;
- source commit and workflow run identifiers.

It contains no certificate bytes, response body, request bytes, socket port, key material or secret. The workflow does not commit generated state back to the branch.

## Merge order

NXB-130 is stacked on NXB-129. NXB-129 is merged first after the combined workspace CI and loopback lab are green. NXB-130 is then retargeted to `main`, rechecked and merged.
