# NXB-130 — Local Adversarial Integration Lab

NXB-130 certifies the NXB-128 live passive transport and HTTP path without contacting a public target.

## Test-only socket mapping

The logical permit remains HTTPS/443 and carries the exact SNI/Host binding. Under `cfg(test)` only, the physical socket may be mapped to an ephemeral loopback listener. This mapping is unavailable in production builds and does not weaken the public-destination guard.

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

CI emits a metadata-only JSON transcript containing scenario names, expected/observed outcome classes and SHA-256 evidence. It contains no certificate bytes, response body, request bytes, socket port, key material or secret.

## Merge order

NXB-130 is stacked on NXB-129. NXB-129 must remain draft until this lab passes. After the lab transcript is committed and independently verified, NXB-129 may be merged first and NXB-130 rebased/merged second.
