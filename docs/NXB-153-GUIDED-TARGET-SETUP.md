# NXB-153 Guided Target and Authorization Setup

## Status

NXB-153 is the productization slice that turns the existing authorization and policy contracts into a guided, networkless operator workflow. The implementation is staged on `nxb-153-guided-target-setup` and remains draft until real Rust compilation and runtime validation are available.

This document describes the intended contract. It does not expand the product's network, authorization, or request-method boundaries.

## Product goal

An operator must be able to create an authorization-bound target profile without hand-authoring TOML or target-profile JSON while still seeing the exact effective scope and budgets before activation.

The guided path therefore separates setup into two phases:

1. **Preview**: normalize and compile operator input, emit the exact effective boundary, perform no network activity and persist no target profile.
2. **Activation**: rebuild the same normalized preview, require the exact preview SHA-256 plus a second acknowledgement, then create the immutable target profile and its continuity artifact.

## Supported commands

### Manual guided input

- `nxb target setup`
- `nxb target activate`

### Bounded scope import

- `nxb target setup-import`
- `nxb target activate-import`

The import format is bounded JSON schema version 1. It exists only as an input convenience. Imported values are normalized through exactly the same guided compiler as manual arguments before a preview or activation can succeed.

## Authorization contract

Guided setup requires all of the following before a preview is accepted:

- a bounded authorization evidence file;
- a non-secret authorization reference;
- a researcher identity string;
- an authorization basis: `program-policy`, `owned-asset`, or `written-permission`;
- a future UTC authorization expiry;
- the exact acknowledgement `I_HAVE_EXPLICIT_AUTHORIZATION`.

The raw authorization evidence bytes and source path are never copied into the target profile or guided activation artifact. Only the authorization reference and SHA-256 binding are persisted.

Activation adds a second independent acknowledgement:

`I_CONFIRM_THIS_EXACT_PREVIEW`

The operator must also supply the exact `preview_sha256` emitted by setup. Activation rebuilds the normalized preview from current input and refuses persistence if the digest differs.

## Scope and policy compiler

The guided compiler produces the ordinary `TargetPolicy` model and round-trips it through canonical TOML before activation. It does not introduce a parallel policy engine.

The guided boundary is intentionally narrower than the general internal policy schema:

- exact HTTPS origin;
- port 443 only;
- canonical public DNS host, no IP literals;
- no wildcard origin syntax;
- canonical include/exclude path prefixes;
- `GET`, `HEAD`, and `OPTIONS` only;
- active testing disabled;
- out-of-band callbacks disabled;
- credential brute force hard-denied;
- destructive testing hard-denied;
- maximum request rate between 0 and 5 requests/second;
- maximum concurrency between 1 and 8;
- maximum total request budget between 1 and 100,000.

`allow_subdomains` is explicit and is visible in the preview. The generated policy is compiled through the existing `nxb-policy` checks, and activation binds the canonical policy document SHA-256 into the immutable target profile.

## Preview surface

The preview exposes the normalized values that matter to an operator before activation:

- target identity and exact origin;
- include and exclude paths;
- program metadata;
- authorization reference, evidence digest, researcher, basis and expiry;
- allowed methods;
- subdomain behavior;
- request rate, concurrency and total-request budgets;
- active/OOB/bruteforce/destructive flags;
- policy snapshot and canonical policy document SHA-256 values;
- hard-denied actions;
- deterministic `preview_sha256`;
- `network_activity: none`.

The preview is non-persistent with respect to target state.

## Guided activation continuity artifact

A successful guided activation creates two linked records:

1. the existing immutable target profile in `targets/<target-id>.json`;
2. a create-only guided continuity record in `state/target-<target-id>.guided-activation.json`.

The continuity record exists because target profile schema v2 intentionally remains compact and backward-compatible. Some guided setup facts, such as authorization basis, researcher, authorization expiry and `allow_subdomains`, would otherwise be visible only before activation.

The continuity record contains:

- artifact schema version;
- target ID;
- immutable target-profile identity SHA-256;
- the complete confirmed setup preview;
- the canonical generated policy document;
- creation time;
- `network_activity: none`.

The activation result returns the relative artifact path and SHA-256 so later product layers can verify the record before using it.

### Secret boundary

The continuity artifact may contain non-secret scope and authorization metadata, including researcher identity and the canonical generated policy. It must not contain:

- raw authorization evidence bytes;
- authorization evidence source paths;
- credentials, bearer tokens or browser/session secrets.

The evidence file itself remains operator-controlled input and is represented only by its SHA-256 and safe reference.

### Publication and rollback

The target profile is published through the existing create-only private workspace writer. The continuity record is then published through the same bounded create-only primitive.

If continuity publication fails after profile creation, activation attempts to remove any partially published continuity file and the just-created target profile. The command fails closed instead of reporting a successful guided activation with incomplete continuity metadata.

Existing migration status remains compatible because migration recovery recognizes only its dedicated `migration-active.json`, `migration-source.json`, and `migration-applied.json` files as transient migration state.

## Scope-import fail-closed rules

The JSON import parser rejects:

- unsupported schema versions;
- unknown fields;
- oversized documents;
- wildcard or otherwise invalid origins;
- non-HTTPS/443 origins;
- duplicate/noncanonical path rules;
- exclusions outside every included prefix;
- exclusions that remove an entire included prefix.

After parsing, import provenance disappears from the effective preview. Equivalent manual and imported input must produce the same normalized preview and preview SHA-256.

## Acceptance coverage staged in source

The NXB-153 branch contains CLI acceptance tests for:

- deterministic networkless preview;
- exact HTTPS/443 normalization;
- authorization acknowledgement and expiry rejection;
- wildcard/domain/port/path rejection;
- budget limits and digest binding;
- exact-preview activation;
- stale-preview and duplicate-activation rejection;
- raw authorization non-persistence;
- bounded scope-import equivalence and rejection cases;
- guided continuity artifact content, digest binding and secret boundary;
- post-activation `target show` operation with the continuity state record present.

## Validation state

No compiler or runtime pass is claimed yet for the current branch head.

Repository GitHub Actions remain intentionally disabled and no workflow has been created or dispatched for NXB-153. The available local execution environment does not contain a Rust toolchain. An independent Hugging Face CPU Jobs attempt was made for formatting, workspace checking and focused tests, but the provider rejected job creation with HTTP 402 because the connected account is not on a Jobs-capable paid plan.

Before the PR can leave draft, the exact final head still requires real Rust validation, including at minimum:

- `cargo fmt --all -- --check`;
- `cargo check --workspace --all-targets`;
- focused `nxb-policy` and NXB-153 CLI tests;
- Clippy with repository warning policy;
- relevant broader regressions on the supported platform matrix.

## Roadmap mapping

NXB-153 roadmap acceptance is addressed as follows:

| Roadmap requirement | Implementation |
| --- | --- |
| Import or manually record program scope/rules | `setup` and bounded `setup-import` |
| Explicit authorization evidence, ownership metadata and acknowledgement | evidence digest/reference + researcher + basis + expiry + two acknowledgements |
| Compile imported scope into existing policy contracts | generated canonical `TargetPolicy`, compile and deterministic round-trip |
| Display inclusions, exclusions, rate limits and prohibited actions | deterministic setup preview |
| Reject ambiguous wildcard/domain/port mappings fail-closed | guided origin and import validation |
| Create target without hand-editing TOML/JSON | exact-preview `activate` / `activate-import` |

NXB-154 must build on the admitted NXB-153 target identity and authorization boundary rather than bypassing it.
