# BSL-3 Policy Narrowing and DNS Pinning Contract

## Scope

BSL-3 remains a networkless decision layer. It does not resolve DNS, open sockets, follow redirects, or contact a target. Callers supply synthetic or externally obtained DNS observations to the gateway.

## Child-policy invariant

A child policy may only reduce authority inherited from a compiled parent policy.

Allowed reductions:

- replace the host allowlist with a non-empty subset of parent-permitted hosts;
- add exclusions;
- reduce schemes and HTTP methods;
- disable subdomain matching, active testing, or out-of-band callbacks;
- lower request rate, concurrency, and total request budgets;
- shorten authorization expiry.

Rejected expansions:

- a host not permitted by the parent;
- enabling subdomains when the parent disables them;
- adding a scheme or method;
- enabling active testing or OOB callbacks;
- increasing any budget;
- extending authorization lifetime.

Credential brute force and destructive testing remain hard-denied and are not child-policy fields.

## Gateway budget invariant

The gateway now uses the compiled policy values directly:

```text
maximum_total_requests
maximum_concurrency
maximum_requests_per_second
```

A fractional rate such as `0.5 req/s` receives one initial token, then refills at the configured rate. It does not permit a burst larger than one request when the configured rate is below one.

## DNS context model

DNS pins are keyed by:

```text
(context_id, normalized_host)
```

A context represents one navigation, request chain, or other bounded caller-defined operation. Within the same context and host:

- the address set must remain exactly equal;
- address order is ignored;
- the resolver identity must remain equal;
- observation time must not move backwards;
- TTL changes are recorded but never weaken an existing pin.

A redirect to another host creates a separate pin under the same context. A new context may establish a different address set, which avoids globally freezing legitimate load-balanced DNS.

## Rebinding decisions

The gateway rejects both:

- public-to-private changes, through destination classification;
- public-to-different-public changes, through exact-set DNS pinning.

DNS failures are evaluated before request budgets, so rejected rebinding observations do not spend request capacity.

## Audit provenance

Every audit event includes:

- DNS context identifier;
- resolver identifier;
- observed TTL;
- pin status: `not_evaluated`, `pinned`, `matched`, or `rejected`;
- resolved destination addresses and destination classes.

These fields are included in the existing SHA-256 audit chain. Modifying DNS provenance after the fact invalidates record verification.

## Explicit non-goals

BSL-3 does not yet provide:

- an operating-system DNS resolver;
- DNSSEC validation;
- resolver transport provenance;
- socket-to-pinned-address enforcement;
- an HTTP proxy;
- browser or scanner adapters;
- real-target execution.

The next transport milestone must consume only gateway-approved, pinned destination addresses and must not re-resolve a hostname independently.
