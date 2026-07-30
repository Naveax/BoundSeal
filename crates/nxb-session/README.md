# nxb-session

`nxb-session` binds authenticated HTTP execution to one run, worker, account, tenant, role, host and scheme.

A session contains only opaque `SecretHandle` values. It never owns or exposes raw cookies, bearer tokens, API keys or CSRF values. Each HTTP exchange requests a short-lived vault lease and immediately consumes a one-use secret-header lease through `Http1Codec`.

Session scope may narrow a secret binding but cannot broaden it. Revoked or expired sessions cannot issue new leases. Emergency purge revokes every session and clears the in-memory vault.

The crate intentionally excludes browser import, disk persistence, login automation, credential discovery and cross-account fallback.
