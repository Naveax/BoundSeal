# BSL-8 — Secret Vault and Session Boundary

## Purpose

Authenticated testing requires cookies, bearer tokens, API keys and CSRF values, but these values must not become ordinary strings that scanner, audit, error or reporting code can copy freely.

BSL-8 introduces two boundaries:

- `bsl-vault` owns raw secret bytes and issues opaque handles and short-lived leases.
- `bsl-session` binds those handles to one run, worker, account, tenant, role, authority and scheme.

## Secret lifecycle

```text
SecretInput (one-time raw bytes)
    -> InMemorySecretVault
    -> SecretHandle
    -> context-bound SecretLease
    -> session/authority-bound SecretHeaderLease
    -> one-use SecretHeaderBatch
    -> Http1Codec write
    -> zeroize on drop
```

Raw secret values are not serializable and use redacted `Debug` implementations. Audit events contain only handles, counts, binding metadata, outcomes and SHA-256 chain material.

## Binding rules

Every secret is bound to:

- run ID
- worker ID
- account ID
- tenant ID
- role ID
- exact allowed hosts
- exact allowed schemes
- optional expiry

A session may narrow these sets but cannot broaden them. Every exchange rechecks all identity fields and derives authority and scheme from the existing stream grant rather than caller input.

## HTTP injection

The normal HTTP request API rejects common authentication headers including `Authorization`, `Cookie`, `Proxy-Authorization`, `X-API-Key` and `X-CSRF-Token`.

Authenticated headers can enter the HTTP wire only through `SecretHeaderLease`. The lease is single-use, expires quickly and must match the stream authority and scheme. The HTTP audit wire replaces secret values with a length-only redaction marker before hashing.

## Revocation

- Secret revocation removes and zeroizes its stored value and revokes dependent leases.
- Lease revocation prevents materialization.
- Session revocation prevents new leases.
- Emergency purge revokes every session and clears all in-memory secret and lease state.

A header lease already materialized inside an active exchange cannot be recalled from CPU memory; it is therefore single-use, short-lived and consumed immediately by the session broker.

## Explicit exclusions

BSL-8 does not add:

- disk persistence
- environment-variable import
- OS keychain integration
- browser cookie import
- login automation
- credential discovery
- password spraying or brute force
- cross-account fallback
- public-network execution
- report export of secret values
