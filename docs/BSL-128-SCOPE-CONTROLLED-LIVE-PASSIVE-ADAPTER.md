# BSL-128 — Scope-Controlled Live Passive Adapter

## Objective

BSL-128 introduces the first production network implementation without turning BSL into an unrestricted scanner. It executes one bounded passive HTTPS request only after upstream policy, scope, DNS pinning, ticket and permit controls have already approved an exact endpoint.

## Non-bypassable admission chain

```text
compiled policy
→ scope gateway
→ pinned DNS context
→ connection ticket
→ exact connection attempt
→ consumed one-use permit
→ permit executor
→ live TLS stream
→ bounded stream
→ strict HTTP/1 exchange
```

The live backend does not accept a URL or hostname from a caller. It receives only the `PermitEndpoint` derived from a consumed `TransportPermit`.

## Connection constraints

Production connections require:

- scheme `https`;
- port `443`;
- redirect depth `0`;
- a destination classified as public by `bsl-destination`;
- exact remote IP from the permit;
- exact SNI matching the HTTP authority;
- one TCP connection created with `TcpStream::connect_timeout`;
- no DNS lookup or fallback address selection inside the adapter.

## TLS profile

The production client uses:

- rustls with the ring crypto provider;
- TLS 1.3 and TLS 1.2 only;
- Mozilla trust anchors from `webpki-roots`;
- certificate and server-name verification;
- ALPN limited to `http/1.1`;
- session resumption disabled;
- early data disabled;
- bounded TLS buffering;
- sanitized, closed failure codes rather than raw TLS errors.

The receipt records hashes and metadata, not certificate bytes or raw server names.

## Request profile

Only `GET` and `HEAD` exist in the public request type.

The request target must:

- be an origin-form absolute path beginning with `/`;
- remain below 4 KiB;
- contain no query, fragment, percent escape, backslash, control byte or whitespace;
- contain no denylisted action segment such as logout, delete, destroy, revoke, reset or shutdown.

The caller cannot provide arbitrary headers. The adapter emits only:

- `Host`, derived from the stream grant;
- `Accept: */*`;
- `Accept-Encoding: identity`;
- a fixed BSL passive-research user agent;
- `Content-Length: 0`;
- `Connection: close`.

Cookies, authorization data, request bodies and vault leases are not accepted in BSL-128.

## Response handling

The established TLS stream is wrapped by the existing `BoundedByteStream` and `Http1Codec` implementations. Existing strict framing rules remain authoritative for:

- header count and byte limits;
- body and total wire limits;
- content-length and transfer-encoding conflicts;
- chunk and trailer limits;
- interim response limits;
- truncation and bytes remaining after a framed response;
- read, write, operation and total time limits.

3xx responses are recorded but never followed.

## Budget lifetime

A successful connection-ticket consumption owns one scope-gateway in-flight reservation. The reservation remains active across:

- permit execution;
- TCP connect;
- TLS handshake;
- bounded stream creation;
- HTTP serialization, transfer and parsing;
- final receipt construction.

Every terminal result releases that reservation exactly once.

## Receipts

The final self-verifying receipt binds:

- ticket, policy decision and DNS context;
- executor, stream and HTTP exchange identities;
- request method and hashed target;
- exact remote IP;
- hashed server name;
- TLS protocol, ALPN, cipher suite and leaf-certificate hash;
- response status, framing, header/trailer counts and body hash;
- redirect observation;
- transport, executor, stream and HTTP audit anchors;
- final receipt SHA-256.

## Tests

Mandatory tests cover:

- passive target validation;
- loopback rejection before socket creation in the production backend;
- non-443 rejection before socket creation;
- cancellation before backend invocation;
- cross-layer budget validation;
- receipt tamper rejection.

A local rustls HTTP/1 fixture additionally exercises a real verified TLS handshake and strict exchange when the CI environment can bind loopback port 443. The production constructor cannot enable the loopback test exception.

## Explicit exclusions

BSL-128 does not include:

- target discovery or crawling;
- redirects;
- JavaScript or browser execution;
- authentication or credential handling;
- cookies;
- query mutation;
- active validation probes;
- exploit payloads;
- multiple targets or concurrent network execution;
- public CLI exposure.

Those capabilities require separate policy-bound phases and cannot be inferred from this adapter.
