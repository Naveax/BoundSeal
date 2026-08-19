# BSL-4 — Pinned Transport Contract

## Objective

BSL-4 introduces the authorization object that must exist between a successful scope decision and any future socket implementation. It does not open sockets or perform DNS resolution.

## Trust boundary

```text
Request intent + DNS observation
        │
        ▼
ScopeGateway
  scope / destination / DNS pin / budget / audit
        │ allow decision + gateway audit tail
        ▼
PinnedTransportCoordinator
        │ one-use connection ticket
        ▼
Future transport adapter
```

A future transport adapter must accept only a consumed `TransportPermit`. It must not accept a URL, hostname, cookie, scanner request, or raw IP as independent authority.

## Ticket binding

Each ticket is bound to exactly:

- one gateway decision ID;
- one DNS context;
- one normalized DNS hostname;
- one scheme;
- one TCP port;
- one selected IP from the exact pinned address set;
- one TLS SNI value, or no SNI for plain HTTP;
- one HTTP Host authority;
- one redirect depth;
- one issue time and expiry;
- one gateway audit-chain tail hash;
- one deterministic binding hash.

Changing any field requires a new ticket.

## One-use rule

The first consume attempt burns the ticket. This includes:

- a successful exact match;
- an IP mismatch;
- an SNI or Host mismatch;
- a port or scheme mismatch;
- a redirect-depth mismatch;
- an expired ticket;
- a monotonic-clock regression.

A second attempt returns `already_consumed`. This prevents retrying different destinations against the same authorization object.

## Redirect rule

A ticket created at redirect depth `N` cannot be used at depth `N + 1`. Every redirect hop must return to the gateway, repeat scope and DNS checks, and receive a new ticket.

## DNS and TOCTOU rule

The ticket stores the complete pinned DNS address set and one selected IP. The future socket layer receives the selected IP directly and must not resolve the hostname again. TLS SNI and HTTP Host remain the authorized DNS hostname while the socket destination remains the selected pinned IP.

## Audit binding

The gateway decision is committed first. Its audit tail hash becomes `gateway_audit_anchor` in the ticket. Ticket issue and consume events are stored in a separate SHA-256 append-only transport chain containing that anchor.

This preserves a narrow gateway schema while cryptographically linking every ticket to the exact gateway history that authorized it.

## Context release

Releasing a DNS context:

1. revokes every unconsumed ticket for that context;
2. releases the corresponding in-flight reservations;
3. removes the gateway DNS pins.

A revoked ticket cannot be consumed.

## Excluded from BSL-4

- operating-system DNS calls;
- TCP, UDP, TLS, HTTP, QUIC, proxy, or browser networking;
- certificate validation;
- cookie or session handling;
- scanner adapters;
- real-target execution;
- long-lived or reusable bearer tickets.

All BSL-4 tests use synthetic public IP fixtures and no outbound network access.
