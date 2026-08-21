# NXB-153 Guided Target and Authorization Setup

## Status

NXB-153 is the productization slice that turns the existing authorization and policy contracts into a guided, networkless operator workflow. The implementation is staged on `nxb-153-guided-target-setup` and remains draft until real Rust compilation and runtime validation are available.

This document describes the intended contract. It does not expand the product's network, authorization, or request-method boundaries.

## Product goal

An operator must be able to create an authorization-bound target profile without hand-authoring TOML or target-profile JSON while still seeing the exact effective scope and budgets before activation.

The guided path therefore separates setup into two phases:

1. **Preview**: normalize and compile operator input, emit the exact effective boundary, perform no network activity and persist no target profile.
2. **Activation**: rebuild the same normalized preview, require the exact preview SHA-256 plus a second acknowledgement, then create linked continuity metadata and the immutable target profile through bounded create-only publication.

## Supported commands

### Manual guided input

- `nxb target setup`
- `nxb target activate`

Manual guided setup requires at least one explicit `--include-path`. Omission is rejected rather than being silently widened to `/`. An operator may still explicitly choose `--include-path /` when the entire admitted origin is intentionally in scope.

### Bounded scope import

- `nxb target setup-import`
- `nxb target activate-import`

The import format is bounded JSON schema version 1. It exists only as an input convenience. Imported values are normalized through exactly the same guided compiler as manual arguments before a preview or activation can succeed.

Imported scope must contain an explicit, non-empty `include_paths` array. Missing or empty path scope is rejected rather than silently becoming `/`. This keeps a malformed import from widening itself to the entire origin.

## Authorization contract

Guided setup requires all of the following before a preview is accepted:

- a bounded authorization evidence file;
- a non-secret authorization reference;
- a researcher identity string;
- an authorization basis: `program-policy`, `owned-asset`, or `written-permission`;
- a future UTC authorization expiry;
- the exact acknowledgement `I_HAVE_EXPLICIT_AUTHORIZATION`.

The raw authorization evidence bytes and the `--authorization-document` source path are never copied into the target profile or guided activation artifact. Explicit reference fields are operator-provided non-secret persisted metadata and must not be used for secrets.

Activation adds a second independent acknowledgement:

`I_CONFIRM_THIS_EXACT_PREVIEW`

The operator must also supply the exact `preview_sha256` emitted by setup. Activation rebuilds the normalized preview from current input and refuses persistence if the digest differs. The authorization evidence bytes are hashed again immediately before publication and must still match the preview authorization digest.

## Scope and policy compiler

The guided compiler produces the ordinary `TargetPolicy` model and round-trips it through canonical TOML before activation. It does not introduce a parallel policy engine.

The guided boundary is intentionally narrower than the general internal policy schema:

- exact HTTPS origin;
- port 443 only;
- canonical public DNS host, no IP literals;
- no wildcard origin syntax;
- exact-host only while registrable-domain / Public Suffix List validation is unavailable;
- canonical include/exclude path prefixes;
- `GET`, `HEAD`, and `OPTIONS` only;
- active testing disabled;
- out-of-band callbacks disabled;
- credential brute force hard-denied;
- destructive testing hard-denied;
- maximum request rate between 0 and 5 requests/second;
- maximum concurrency between 1 and 8;
- maximum total request budget between 1 and 100,000.

### Raw guided origin grammar

Guided origin admission performs a narrow lexical check **before** WHATWG URL parsing. This prevents operator syntax from being normalized away into a broader or apparently cleaner authority boundary.

Accepted raw guided origins use:

- the literal lowercase `https://` scheme prefix;
- a literal ASCII DNS authority;
- no userinfo delimiter;
- no percent-encoded authority bytes;
- no query or fragment delimiter, including empty `?` or `#` forms;
- no path syntax beyond an optional single literal root `/`;
- either no port or the exact literal `:443` spelling.

Host case normalization remains intentional, so `https://EXAMPLE.ORG:443` canonicalizes to `https://example.org`. Unicode/IDNA input is not silently converted by the guided path; the operator must supply the literal ASCII DNS representation that is actually being authorized.

This lexical gate rejects normalization-equivalent forms such as empty userinfo, dot-path traversal that collapses to `/`, percent-encoded dot or host text, empty ports and zero-padded `:0443` before the URL parser can reinterpret them. The ordinary parsed-component and public-DNS checks still run afterward as a second layer.

### Exact-host-only subdomain contract

`TargetPolicy` schema v1 supports `allow_subdomains`, and its compiled matcher expands a host by DNS suffix when that flag is true. The current guided layer does not have a pinned Public Suffix List / registrable-domain validator. A syntactically valid host can therefore be a public suffix, making suffix expansion much broader than the operator's intended program boundary.

NXB-153 fails closed instead of approximating this with a small hardcoded suffix list:

- guided `allow_subdomains=true` is rejected;
- imported `allow_subdomains: true` is rejected through the same compiler;
- admitted previews and generated policy documents therefore contain `allow_subdomains = false`;
- exact-host operation remains available.

Future subdomain support requires a reproducible PSL-backed registrable-domain check, representative wildcard/exception controls, Cargo.lock evidence and platform validation. Until then, the boolean is visible in the input schema but enabling it is not an admitted guided capability.

### Split scope binding in policy schema v1

`TargetPolicy` schema version 1 models host, scheme, method, subdomain behavior, authorization and automation budgets. It does not currently contain path-prefix fields. NXB-153 therefore does not pretend otherwise.

Path scope is bound through the exact guided preview and immutable target profile:

- `include_paths` and `exclude_paths` are part of the deterministic preview identity;
- changing only path scope changes `preview_sha256`;
- activation rebuilds the preview and rejects a stale SHA before persistence;
- activated path rules are part of `TargetProfile` identity material and therefore change `identity_sha256`;
- the complete confirmed preview is retained in the guided continuity artifact.

The canonical `TargetPolicy` document remains the policy-engine contract for host/scheme/method/subdomain/authorization/budget dimensions. Future execution layers must enforce both the admitted target-profile path boundary and the compiled policy boundary. They must not infer that a policy document lacking path fields grants the whole origin.

This split is explicit so that NXB-153 does not mutate policy schema v1 merely to create an appearance of coverage. A future policy schema revision may move path prefixes into the policy engine only with migration and compatibility work.

## Preview surface

The preview exposes the normalized values that matter to an operator before activation:

- target identity and exact origin;
- include and exclude paths;
- program metadata;
- authorization reference, evidence digest, researcher, basis and expiry;
- allowed methods;
- `allow_subdomains: false` for admitted guided scopes;
- request rate, concurrency and total-request budgets;
- active/OOB/bruteforce/destructive flags;
- policy snapshot and canonical policy document SHA-256 values;
- hard-denied actions;
- deterministic `preview_sha256`;
- `network_activity: none`.

The preview is non-persistent with respect to target state.

## Guided activation continuity artifact

A successful guided activation creates two linked records:

1. a create-only guided continuity record in `state/target-<target-id>.guided-activation.json`;
2. the immutable active target profile in `targets/<target-id>.json`.

The continuity record is intentionally published first. Until the target profile is successfully published, continuity metadata is inert and does not constitute an active target. This ordering prevents an artifact-publication failure from first creating an active profile and then needing unsafe pathname rollback.

The continuity record exists because target profile schema v2 intentionally remains compact and backward-compatible. Some guided setup facts, such as authorization basis, researcher, authorization expiry and `allow_subdomains`, would otherwise be visible only before activation.

The continuity record contains:

- artifact schema version;
- target ID;
- the prospective immutable target-profile identity SHA-256;
- the complete confirmed setup preview;
- the canonical generated policy document;
- a random publication nonce;
- the exact creation time shared with the prospective profile;
- `network_activity: none`.

The activation result returns the relative artifact path and SHA-256 so later product layers can verify the record before using it.

### Persistence-envelope preflight

The workspace writer has a 64 KiB document limit. NXB-153 performs a serialization-based persistence preflight that reconstructs the canonical target-profile representation and the complete guided continuity-artifact representation from the preview, including the exact policy document. Both representations must fit beneath the writer cap with a 4 KiB schema-evolution margin, leaving a 60 KiB guided admission envelope per persisted document.

The preflight uses fixed-width placeholders for the 32-character publication nonce and canonical UTC timestamp, so those runtime fields cannot silently increase the admitted serialized size. JSON escaping overhead is measured by the same canonical serializer used by persistence. Raw authorization evidence bytes and the authorization source path are not part of the representation.

The common guided build invokes this preflight **before a setup/setup-import preview is emitted**. Activation and activate-import rebuild the same guided input and run the preflight again before any target profile or continuity record is written. Therefore an oversized normalized scope is rejected at setup time rather than being presented as an activatable preview and failing late during persistence.

`target_persistence_envelope_cli` stages both sides of this contract: an escaping-heavy imported scope that remains below the import parser's 64 KiB source limit but exceeds the guided persistence envelope is rejected during setup, while a normal admitted preview activates and leaves both persisted records inside the explicit envelope.

## Secret boundary

The continuity artifact may contain non-secret scope and authorization metadata, including researcher identity and the canonical generated policy. It must not contain:

- raw authorization evidence bytes;
- authorization evidence source paths;
- credentials, bearer tokens or browser/session secrets.

The evidence file itself remains operator-controlled input and is represented only by its SHA-256 and safe reference.

## Create-only publication and partial-state semantics

`workspace::create_document()` stages bytes in a unique temporary file, applies private file permissions, writes and synchronizes the file, and validates the private permissions **before** any destination name is claimed.

The create-only namespace claim now uses a same-directory hard link rather than an existence-check followed by `rename`:

1. prepare and sync the private temporary file;
2. atomically call `fs::hard_link(temp, destination)`;
3. if the destination already exists, fail without changing it;
4. if the claim succeeds, remove the temporary link;
5. synchronize the parent directory where the platform supports that durability operation.

The destination and temporary path refer to the same prepared file object after the hard-link claim, so no post-claim permission mutation is required. Concurrent creators cannot both claim the same destination name. There is intentionally **no fallback to overwrite-capable rename** when hard-link creation is unsupported; unsupported filesystems fail closed.

### Explicit published-error state

A failure before the hard-link claim means the destination was not published by that call. A failure after the namespace claim, such as temporary-link cleanup or parent-directory synchronization failure, is represented by a dedicated publication error type. `create_document_error_published()` lets callers distinguish this state from ordinary unpublished failure.

The primitive never deletes the destination after a successful namespace claim merely because finalization later fails. This prevents error cleanup from turning an uncertain durability condition into destructive pathname rollback.

Workspace unit coverage stages:

- a pre-existing destination that remains byte-for-byte unchanged after a second create attempt;
- eight concurrent creators with exactly one successful destination claimant;
- a post-claim injected parent-sync failure that reports `published=true` while leaving the destination intact and readable;
- private-permission validation for the successful concurrent destination;
- workspace initialization preserving a claimed manifest instead of destructively cleaning the workspace after a published-state error.

Migration prepare also consumes the explicit publication state: if the active migration journal became visible but publication finalization failed, the source backup is retained for recovery instead of being deleted as though the journal had never been published.

These tests are part of the existing `cargo test -p nxb-core --lib` validation gate.

### Guided activation commit order and inert recovery

Guided activation no longer publishes a target profile and then tries to delete it when continuity publication fails. It instead:

1. builds and validates the prospective immutable target profile entirely in memory;
2. canonicalizes its bytes and computes the exact content-derived profile identity;
3. publishes and exact-byte verifies the continuity artifact;
4. publishes the target profile last;
5. exact-byte verifies the target profile after successful create-only publication.

No activation failure path performs compare-then-delete rollback of the target profile or continuity artifact. This removes the previous pathname-swap race in activation cleanup.

If continuity publication fails before publication, the target profile is never attempted. If continuity is published but profile publication fails before its destination claim, the continuity record remains inert and the command fails. If either create-only call reports the explicit published-but-finalization-incomplete state, activation fails loudly and does not delete the visible destination.

A later activation may recover an **inert continuity-only** state only when the target profile is still absent and the existing continuity artifact exactly binds the same activation contract. Recovery parses the artifact through an owned, `deny_unknown_fields` mirror of the persisted schema and requires byte-for-byte equality with the canonical serializer before any reuse. It then verifies the schema version, target ID, `network_activity`, complete confirmed preview, canonical policy-document value and digest, 32-character lowercase-hex publication nonce, UTC creation time, and the prospective target-profile identity reconstructed using that stored creation time. On Unix the continuity parent directory is synchronized again before the artifact is reused. A field, byte-layout or semantic mismatch is left untouched and rejected fail-closed.

The existing continuity bytes are never rewritten during this recovery. Successful prior activations remain non-idempotent: if the target profile already exists, repeating activation is still rejected as a duplicate instead of being silently treated as success.

`target_activation_recovery_cli` stages both sides of the recovery contract. It removes only the profile inside an isolated test workspace to simulate continuity-only state, then verifies that exact retry recreates the same profile identity without changing the artifact bytes. A changed path-scope preview is rejected while the artifact remains unchanged and no profile is created. Source-level recovery coverage additionally rejects semantically valid but noncanonical artifact bytes.

The remaining #90 source concern is the **published-but-finalization-incomplete** case itself, especially a temporary-link cleanup failure after the destination claim. The current error type deterministically distinguishes published from unpublished state but does not yet classify which finalization component failed. That postcondition detail plus real Linux/Windows validation remain explicit blockers; no durability-completion claim is made yet.

### Cross-cutting caller audit

The shared create-only primitive is used beyond NXB-153 activation, including workspace initialization/migration, target lifecycle records and release-manifest output. Caller audit found the destructive error-cleanup cases in workspace initialization and migration prepare; both now consume explicit published state instead of deleting claimed records. Ordinary target/release create paths do not delete their destinations after create errors and therefore remain fail-closed.

Issue #90 remains open until the remaining published-finalization semantics and Linux/Windows Rust validation close. The hard-link publication path, explicit publication state, caller fixes, canonical inert recovery and its tests are source hardening, not validation evidence.

Existing migration status remains compatible because migration recovery recognizes only its dedicated `migration-active.json`, `migration-source.json`, and `migration-applied.json` files as transient migration state.

## Scope-import fail-closed rules

The JSON import parser rejects:

- unsupported schema versions;
- unknown fields;
- oversized documents;
- missing or empty `include_paths`;
- wildcard or otherwise invalid origins;
- origin syntax that depends on URL-parser normalization;
- non-HTTPS/443 origins;
- subdomain expansion while no registrable-domain/PSL boundary is available;
- duplicate/noncanonical path rules;
- repeated interior path separators such as `/api//admin`;
- exclusions outside every included prefix;
- exclusions that remove an entire included prefix;
- exclusions that shadow another explicit include prefix;
- normalized scopes whose canonical profile or guided continuity artifact exceeds the guided persistence envelope.

After parsing, import provenance disappears from the effective preview. Equivalent manual and imported input must produce the same normalized preview and preview SHA-256.

## Acceptance coverage staged in source

The NXB-153 branch contains CLI or source-level acceptance tests for:

- deterministic networkless preview;
- exact HTTPS/443 normalization;
- raw origin syntax that WHATWG parsing can normalize away, including empty userinfo, dot/encoded path forms, empty/zero-padded port and percent-encoded authority text;
- documented positive origin canonicalization for host case, literal `:443` and optional root `/`;
- authorization acknowledgement and expiry rejection;
- wildcard/domain/port/path rejection;
- explicit manual guided include scope, with omission rejected and explicit `/` retained as an intentional choice;
- exclude/include contradiction rejection and interior repeated-separator rejection;
- manual and imported subdomain expansion rejection until a PSL-backed registrable boundary exists;
- exact-host generated policy/continuity behavior with `allow_subdomains=false`;
- serialization-based profile/continuity persistence-envelope admission with JSON escaping accounted for;
- oversized persistence representations rejected before preview emission;
- admitted normal scope activating with persisted records below the writer envelope;
- budget limits and digest binding;
- exact-preview activation;
- path-only scope changes invalidating stale preview activation and appearing in target identity;
- stale-preview and duplicate-activation rejection;
- raw authorization non-persistence;
- bounded scope-import equivalence and rejection cases;
- missing/empty imported path scope fail-closed behavior;
- guided continuity artifact content, digest binding and secret boundary;
- prospective profile identity reconstruction before publication;
- hard-link create-only no-clobber behavior for pre-existing and concurrent destinations;
- explicit published-state reporting for post-claim finalization failure;
- artifact-first/profile-last activation with no pathname rollback deletion;
- exact inert-continuity recovery without artifact rewrite;
- changed-preview recovery rejection with artifact bytes preserved;
- noncanonical continuity-byte recovery rejection;
- post-activation `target show` operation with the continuity state record present.

The platform validators run `nxb-core` library tests before the focused CLI suites, so the shared workspace create-only primitive tests run before full workspace regression. The focused Linux and Windows lists include `target_activation_recovery_cli`, `target_scope_failclosed_cli`, `target_subdomain_failclosed_cli`, and `target_persistence_envelope_cli` in addition to the earlier setup/activation/import/path suites.

## Validation state

No compiler or runtime pass is claimed yet for the current branch head.

Repository GitHub Actions remain intentionally disabled and no workflow has been created or dispatched for NXB-153. The available local execution environment does not contain a Rust toolchain. An independent Hugging Face CPU Jobs attempt was made for formatting, workspace checking and focused tests, but the provider rejected job creation with HTTP 402 because the connected account is not on a Jobs-capable paid plan. Direct external toolchain/bootstrap downloads from the execution sandbox are also unavailable because outbound DNS/network access is blocked.

Before the PR can leave draft, the exact final head still requires real Rust validation, including at minimum:

- `cargo fmt --all -- --check`;
- `cargo check --workspace --all-targets`;
- `cargo test -p nxb-core --lib` plus focused `nxb-policy` and NXB-153 CLI tests;
- Clippy with repository warning policy;
- RustSec and cargo-deny through the exact-head tooling receipts;
- same-head Linux and Windows evidence closure;
- relevant broader regressions on the supported platform matrix.

Issue #90 additionally requires its create-only publication/caller-recovery semantics to be validated on Linux and Windows before it can close.

## Roadmap mapping

NXB-153 roadmap acceptance is addressed as follows:

| Roadmap requirement | Implementation |
| --- | --- |
| Import or manually record program scope/rules | `setup` and bounded `setup-import`; both manual and imported path scope must be explicit |
| Explicit authorization evidence, ownership metadata and acknowledgement | evidence digest/reference + researcher + basis + expiry + two acknowledgements |
| Compile imported scope into existing policy contracts | canonical `TargetPolicy` for exact host/scheme/method/authorization/budget plus exact-preview and target-identity binding for path prefixes; guided subdomain broadening disabled pending PSL validation |
| Display inclusions, exclusions, rate limits and prohibited actions | deterministic setup preview |
| Reject ambiguous wildcard/domain/port mappings fail-closed | pre-parser raw origin grammar + parsed public-DNS/HTTPS/443 validation + exact-host-only subdomain contract + path-scope contradiction checks + serialized persistence-envelope admission |
| Create target without hand-editing TOML/JSON | exact-preview `activate` / `activate-import`, artifact-first/profile-last publication, exact inert-continuity recovery, shared create-only no-clobber namespace claim |

NXB-154 must build on the admitted NXB-153 target identity and authorization boundary rather than bypassing it. Any later request/session execution must enforce the path rules from the target profile in addition to the compiled `TargetPolicy` host/method boundary.
