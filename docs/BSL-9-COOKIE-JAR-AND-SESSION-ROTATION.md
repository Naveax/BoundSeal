# BSL-9 — Cookie Jar and Session Rotation

## Purpose

BSL-9 processes response `Set-Cookie` fields without allowing cookie values to escape the in-memory secret boundary. It adds deterministic cookie replacement, deletion and session-generation semantics above BSL-8.

## Processing order

1. Keep every `Set-Cookie` field separate. Comma folding is prohibited.
2. Parse and validate every field before changing vault or jar state.
3. Collapse repeated keys in response order; the last field for the same name/domain/path wins.
4. Prevalidate all existing handles that will be replaced or deleted.
5. Insert every new value into `bsl-vault` using zeroizing buffers.
6. Roll back newly inserted handles if staging fails.
7. Revoke replaced/deleted handles.
8. Commit jar metadata atomically.
9. Advance session generation when a session-like cookie appears, any cookie value rotates, or an existing cookie is deleted.
10. Append metadata-only cookie and session audit records.

## Strict parser contract

Supported attributes are Domain, Path, Max-Age, Expires, Secure, HttpOnly and SameSite. Unknown or duplicate attributes are rejected. `Max-Age` takes precedence over `Expires`.

The parser rejects:

- CR/LF and control-byte injection
- comma-folded cookie fields
- invalid name/value octets
- Domain attributes outside the response origin
- public-suffix-like Domain scopes
- Domain attributes on IP origins
- Secure cookies received over HTTP
- SameSite=None without Secure
- invalid `__Secure-` and `__Host-` prefix combinations
- invalid or oversized paths, values and field counts

## Vault and scope rules

Cookie values exist only in a zeroizing parser buffer and `bsl-vault`. The jar stores opaque handles, metadata and value hashes. Host-only cookies receive an exact-host binding. Domain cookies are intersected with the session's already authorized host set; they cannot broaden it.

Cookie leases validate account, tenant, role, run, worker and expiry first. Authority/path filtering occurs during materialization, allowing a multi-host session to hold scoped cookies without causing unrelated requests to fail.

## Session rotation

Each session owns a cookie jar and generation counter. Successful authenticated responses are inspected for `Set-Cookie` fields. A committed rotation updates the session's active opaque handles, generation and cookie-audit anchor. Old cookie handles are revoked before the new state becomes active.

The response-cookie helper receives authority, scheme, request target and monotonic time as one immutable context object, preventing those related binding values from diverging across the transaction.

Logout uses an explicit jar purge that revokes active cookie handles and marks the session revoked.

## Validation boundary

All parser, replacement, deletion, rotation, logout and redaction behavior is exercised only through deterministic in-memory HTTP and vault fixtures. No validation test opens a socket or resolves a hostname.

## Audit and exclusions

Cookie audit records contain counts, origin metadata, key hashes, generation transitions and vault audit anchors. Cookie values and complete `Set-Cookie` fields are excluded.

BSL-9 does not add browser import, public-suffix downloads, disk persistence, login automation, sockets, public-network execution or scanner adapters.
