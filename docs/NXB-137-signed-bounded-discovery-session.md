# NXB-137 — Signed bounded discovery sessions

NXB-137 extends the NXB-136 single-request bridge with a separately signed, strictly bounded passive discovery session. It does not change or broaden the NXB-136 one-request contract.

## Commands

The `nxb-discovery-session` binary provides networkless planning and verification plus a feature-gated live runner:

```text
cargo run -p nxb-core --bin nxb-discovery-session -- plan ...
cargo run -p nxb-core --bin nxb-discovery-session -- activation-template ...
cargo run -p nxb-core --bin nxb-discovery-session -- verify-plan ...
cargo run -p nxb-core --bin nxb-discovery-session -- verify-activation ...
cargo run -p nxb-core --bin nxb-discovery-session --features live-network -- run ... --enable-live
```

## Signed plan boundary

A discovery-session plan binds all of the following into one canonical SHA-256 document:

- exact policy-file digest;
- seed HTTPS/443 URL and seed GET/HEAD method;
- exact origin digest;
- selected public IP and complete signed DNS result set;
- DNS context, resolver identity, and TTL;
- allowed GET/HEAD methods;
- allowed path prefixes with segment-boundary matching;
- maximum request count;
- maximum discovery depth;
- maximum response-body bytes per request;
- maximum total response bytes;
- minimum interval between requests;
- sequential concurrency of exactly one;
- activation signing-key identifier;
- validity window.

The activation certificate repeats the critical policy, origin, request, and total-byte budgets and signs the exact plan digest with Ed25519.

## Runtime behavior

The live runner:

1. verifies the plan, activation, public key, policy digest, policy scope, request rate, and one-use ledger;
2. starts from the signed seed request;
3. authorizes every request independently through the scope gateway and pinned transport;
4. performs verified TLS and bounded HTTP/1 processing through the production live adapter;
5. verifies response length and SHA-256 against the live receipt;
6. keeps raw bodies only in process memory;
7. performs passive header, cookie, and cache analysis;
8. extracts same-origin discovery candidates;
9. rejects candidates outside the signed method, depth, path-prefix, origin, policy, or byte boundaries;
10. writes deterministic operator reports and a chained per-request session receipt.

## Hard denials

NXB-137 does not:

- follow redirects;
- send query-bearing requests;
- use methods other than GET or HEAD;
- execute logout, delete, revoke, reset, unsubscribe, or similar action paths;
- inject cookies, bearer tokens, API keys, CSRF tokens, or browser credentials;
- run reflection, rate-limit, authorization-differential, or other active probes;
- submit reports automatically;
- persist raw response bodies;
- retry a consumed activation after a crash.

Crash recovery is deliberately fail-closed in NXB-137. A crashed run requires a fresh plan and activation. Durable deterministic resume remains a later operator milestone.
