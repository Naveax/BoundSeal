# NXB-138 — Vault-backed session injection

NXB-138 adds a fail-closed authorization boundary between the signed bounded discovery session introduced by NXB-137 and the existing in-memory secret vault, session broker, cookie jar, verified TLS channel, and HTTP/1 codec.

It does not import browser profiles, read browser cookie databases, persist plaintext credentials, broaden the NXB-137 request scope, or enable active probes.

## Signed injection manifest

A `SessionInjectionManifest` is bound to:

- the exact NXB-137 discovery-plan SHA-256;
- the exact normalized HTTPS origin SHA-256;
- one exact DNS authority and the `https` scheme;
- one session identifier;
- exact run, worker, account, tenant and role identifiers;
- an opaque bootstrap secret-handle set;
- canonical request-path prefixes;
- allowed secret-header names;
- allowed cookie names;
- explicit CSRF cookie/header/token-handle mappings;
- a maximum lease duration of 30 seconds or less;
- a bounded validity window;
- a 32-byte Ed25519 activation key identifier;
- the canonical manifest SHA-256.

The manifest contains opaque handles and metadata only. Secret values remain inside `nxb-vault` and are not serialized into the manifest.

## Mandatory activation consumption

The manifest requires a separately signed `SessionInjectionActivationCertificate`. Its payload binds the activation to the manifest, discovery plan, target origin and session identifier.

`consume_activation_once` verifies the Ed25519 certificate and atomically creates a durable `create_new` replay marker. It returns a non-serializable, non-cloneable `ConsumedSessionInjectionActivation` proof. `BoundSessionInjection::bind` accepts this consumed proof instead of accepting a certificate directly, so a caller cannot construct a usable bound injection while skipping replay consumption.

The replay marker stores hashes, state and timestamps only. The same activation ID cannot produce a second consumed proof in the same state directory.

## Per-request authorization

`BoundSessionInjection::authorize_request` revalidates the complete boundary before every request:

- manifest and consumed activation validity;
- exact discovery-plan and target-origin bindings;
- active session status and expiry;
- exact run, worker, account, tenant and role partition;
- exact singleton HTTPS authority and scheme sets for the session and every secret;
- GET or HEAD only;
- canonical passive paths without query, fragment, percent encoding, dot segments, duplicate separators or destructive path tokens;
- signed path-prefix membership;
- non-regressing session generation;
- current vault metadata and expiry for every session handle;
- static header secrets remaining inside the bootstrap handle set;
- header and cookie allowlists;
- secure, unexpired cookies with an exact authority and a path contained by the signed path scope;
- explicit CSRF token/header/cookie binding;
- CSRF cookie applicability to the current request path.

The resulting lease duration is the minimum remaining lifetime across the manifest, activation, session and the manifest lease cap. The authorization receipt contains counts and SHA-256 bindings, not secret material, and verifies its own canonical digest.

## Cookie rotation

Static header secrets cannot be added after binding. Allowlisted cookies may rotate through the existing `nxb-session` cookie jar only when the replacement cookie remains secure, unexpired, exact-authority-bound, name-allowlisted and contained by a signed request-path prefix.

This permits bounded authenticated session renewal without turning server-controlled `Set-Cookie` responses into a general secret-injection channel.

## Live adapter integration

`LivePassivePipeline::execute_authenticated` is a separate path. The existing passive `execute` path is unchanged.

The authenticated path:

1. obtains current session metadata;
2. obtains a metadata-only injection authorization;
3. consumes the one-use pinned transport ticket;
4. establishes the existing library-verified TLS stream;
5. creates the TLS-bound HTTP/1 codec;
6. delegates short-lived secret leasing and header/cookie materialization to `SessionBroker::exchange`;
7. returns the ordinary live receipt plus the injection-authorization digest, session-audit tail and vault-audit tail.

Secrets are materialized only inside the existing zeroizing vault/header lease types and only after verified TLS binding.

## Deliberately excluded

NXB-138 does not add:

- browser cookie-store extraction;
- plaintext secret files or command-line secret values;
- cross-origin, parent-domain or subdomain widening;
- query-bearing discovery targets;
- redirects;
- POST, PUT, PATCH or DELETE requests;
- active reflection, rate-limit or authorization-differential probes;
- automatic HackerOne submission;
- a unified end-user authenticated scanner CLI;
- an external production vault provider.

The unified operator and external vault-provider lifecycle remain later architecture work.
