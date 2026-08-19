# bsl-cookie-jar

Deterministic, in-memory `Set-Cookie` parsing and transactional cookie-vault updates.

Security properties:

- one `Set-Cookie` header is parsed independently; comma folding is never used
- Domain, Path, Max-Age, Expires, Secure, HttpOnly and SameSite are bounded and validated
- `__Host-` and `__Secure-` requirements are enforced
- public-suffix-like Domain scopes and insecure Secure-cookie origins are rejected
- cookie values exist only in zeroizing parser buffers and `bsl-vault`
- replacement/deletion revokes old vault handles before jar state is committed
- audit records contain metadata and hashes, never cookie values
- session generation advances when session-like cookies appear, rotate or are deleted

No browser import, disk persistence, public suffix network service, socket or public-network behavior is included.
