# NXB-138 — Vault-backed session injection

NXB-138 adds a fail-closed authorization boundary between the signed bounded discovery session introduced by NXB-137 and the existing in-memory secret vault, session broker, cookie jar, verified TLS channel, and HTTP/1 codec.

It does not import browser profiles, read browser cookie databases, persist plaintext credentials, broaden the NXB-137 request scope, or enable active probes.

## Signed injection manifest

A `SessionInjectionManifest` is bound to:

- the exact NXB-137 discovery-plan SHA-256;
- the exact normalized HTTPS origin SHA-256;
- one DNS authority and the `https` scheme;
- one session identifier;
- exact run, worker, account, tenant and role identifiers;
- an opaque bootstrap secret-handle set;
- allowed request-path prefixes;
- allowed secret-header names;
- allowed cookie names;
- explicit CSRF cookie/header/token-handle mappings;
- a maximum lease duration of 30 seconds or less;
- a bounded validity window;
- an Ed25519 activation-key identifier;
- the canonical manifest SHA-256.

The manifest contains opaque handles and metadata only. Secret values are retained by `nxb-vault` and are not serialized into the manifest.

## Activation and replay prevention

The manifest requires a separately signed `SessionInjectionActivationCertificate`. Its payload binds the activation to the manifest, discovery plan, target origin and session identifier.

Before use, the certificate is verified with Ed25519. `consume_activation_once` then creates a durable marker with `create_new`, so the same activation cannot be consumed twice. The marker stores hashes and timestamps only.

## Per-request authorization

`BoundSessionInjection::authorize_request` revalidates the complete boundary before every request:

- manifest and activation validity;
- exact discovery-plan and target-origin bindings;
- active session status and expiry;
- exact run, worker, account, tenant and role partition;
- exact HTTPS authority;
- GET or HEAD only;
- passive path validation and signed path-prefix membership;
- non-regressing session generation;
- current vault metadata for every session handle;
- exact secret identity and authority bindings;
- static header secrets remaining inside the bootstrap handle set;
- header and cookie allowlists;
- secure, unexpired and domain-bound cookies;
- explicit CSRF token/header/cookie binding;
- CSRF cookie applicability to the current request path.

The resulting lease duration is the minimum remaining lifetime across the manifest, activation, session and the manifest lease cap. The authorization receipt contains counts and hashes, not secret material.

## Cookie rotation

Static header secrets cannot be added after binding. Allowlisted cookies may rotate through the existing `nxb-session` cookie jar when the replacement cookie remains secure, unexpired, authority-bound, name-allowlisted and path-compatible.

This allows normal authenticated session renewal without turning server-controlled `Set-Cookie` responses into a general secret-injection channel.

## Live adapter integration

`LivePassivePipeline::execute_authenticated` is a separate path. The existing passive `execute` path is unchanged.

The authenticated path:

1. obtains current session metadata;
2. obtains a metadata-only injection authorization;
3. consumes the one-use pinned transport ticket;
4. establishes the existing library-verified TLS stream;
5. creates the TLS-bound HTTP/1 codec;
6. delegates secret leasing and header/cookie materialization to `SessionBroker::exchange`;
7. returns the ordinary live receipt plus the injection-authorization digest, session-audit tail and vault-audit tail.

Secrets are materialized only inside the existing zeroizing vault/header lease types and only after verified TLS binding.

## Deliberately excluded

NXB-138 does not add:

- browser cookie-store extraction;
- plaintext secret files or command-line secret values;
- cross-origin or subdomain widening;
- query-bearing discovery targets;
- redirects;
- POST, PUT, PATCH or DELETE requests;
- active reflection, rate-limit or authorization-differential probes;
- automatic HackerOne submission;
- a unified end-user authenticated scanner CLI.

The unified operator and external vault-provider lifecycle remain later architecture work.
