# nxb-live-adapter

`nxb-live-adapter` is the first scope-controlled live transport implementation in NXB.

It performs one passive HTTPS exchange only after an existing `PinnedTransportCoordinator` has issued and consumed an exact transport permit.

## Production boundary

- HTTPS only
- TCP port 443 only
- exact permit IP only; no resolver call inside the adapter
- exact SNI and HTTP authority binding
- redirect depth must be zero
- GET and HEAD only
- origin-form path only
- no query string, fragment, percent-encoded path, request body, cookie or authorization header
- no redirect following, crawling, mutation, exploit payload or credential operation
- public destinations only
- bounded connection, stream, HTTP wire, header, body, operation and time budgets
- verified TLS 1.2/1.3 using Mozilla roots
- ALPN limited to `http/1.1`
- TLS early data and session resumption disabled

## Pipeline

```text
scope gateway
→ pinned DNS decision
→ connection ticket
→ one-use transport permit
→ permit executor
→ exact-IP TCP + verified TLS
→ bounded byte stream
→ strict HTTP/1 codec
→ self-verifying passive receipt
```

The gateway in-flight reservation covers the entire connection, TLS and HTTP exchange and is released exactly once on every terminal path.

## Status

NXB-128 intentionally exposes no public CLI command. NXB-129 will provide the policy-driven orchestration and explicit operator interface after this adapter is merged and remains green.
