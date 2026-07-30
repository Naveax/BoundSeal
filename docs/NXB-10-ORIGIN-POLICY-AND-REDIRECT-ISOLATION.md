# NXB-10 — Origin Policy and Redirect Isolation

## Purpose

NXB-10 turns redirects into a sequence of independently authorized requests. A previous HTTP response cannot grant permission for its `Location` destination.

## Hop contract

Every redirect hop performs the following sequence:

1. Require exactly one bounded `Location` field.
2. Resolve it against the current absolute HTTP(S) URL.
3. Remove the fragment and reject user information or unsupported schemes.
4. Apply deterministic 301/302/303/307/308 method and body rules.
5. Reject HTTPS-to-HTTP downgrade.
6. Reject request loops and reused DNS contexts.
7. Validate the exact session identity and declared generation transition.
8. Re-enter `ScopeGateway` with a new redirect depth and DNS observation.
9. Require a new one-use transport ticket bound to the new origin and depth.
10. Append a metadata-only redirect audit record.

A gateway denial is a terminal redirect result and never contains a ticket.

## Method and body rules

- 301/302 convert POST to GET and discard the body.
- 301/302 preserve other methods and bodies.
- 303 converts every method except HEAD to GET and discards the body.
- 303 keeps HEAD but discards any body metadata.
- 307/308 preserve method and body.
- A cross-origin hop that would preserve a non-empty body is rejected.

## Origin and secret isolation

Origins are compared by normalized scheme, host and effective port. Same-origin hops may request a fresh vault lease for all session-bound secrets. Cross-origin hops must discard non-cookie credential capability and may only rematerialize cookies that independently match the new origin, path and scheme.

No raw Authorization, API-key, CSRF or Cookie header batch is carried between codecs. Redirect output states containing full URLs are intentionally not serializable, and their Debug representation contains only origin and SHA-256 target metadata.

## Session isolation

The session ID, run, worker, account, tenant and role must remain identical across the chain. A response that declares session-state mutation must advance generation by exactly one. A response without mutation must retain the current generation. This prevents stale pre-rotation state from being applied to a later hop.

## Audit

Redirect records contain origin metadata, method/body disposition, secret disposition, session identity hash, generation, DNS context, gateway decision hash, gateway audit anchor, ticket identity/binding hash and transport audit anchor.

Raw `Location` values, paths, queries and fragments are excluded. They are represented only by SHA-256 digests.

## Validation boundary

Formatting, Clippy and tests run across the complete workspace. Redirect fixtures use synthetic HTTP responses and public IP literals only; they do not resolve hostnames or open sockets.

## Exclusions

NXB-10 does not add a resolver, socket backend, TLS client, browser, proxy, login automation, scanner adapter or public-network execution. Tests use only synthetic HTTP responses and public-address fixtures.
