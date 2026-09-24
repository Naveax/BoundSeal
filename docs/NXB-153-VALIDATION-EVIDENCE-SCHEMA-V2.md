# NXB-153 Validation Evidence Schema v2

## Status

This document defines the source-staged schema-v2 contract for NXB-153 platform validation evidence and dual-platform closure. It does **not** claim that the current feature head has passed the required Linux or Windows admission runs.

Schema v2 exists so evidence cannot report only ordinary fmt/check/test/security-tool success while silently omitting the authority layers that make those results attributable to the exact intended source, dependency and helper objects.

## Platform evidence identity

Canonical platform evidence remains create-only under:

- `target/nxb-validation/nxb-153-linux-<exact-head>.json`
- `target/nxb-validation/nxb-153-windows-<exact-head>.json`

Both semantic reviewers require the complete exact field set. Unknown or missing fields fail closed.

`schema_version` must be integer `2`.

The established identity/tool/result fields remain:

- `milestone = NXB-153`
- `gate = guided_target_authorization_setup`
- `platform`
- `head_sha`
- `rustc`
- `cargo`
- `cargo_audit`
- `cargo_audit_sha256`
- `cargo_deny`
- `cargo_deny_sha256`
- `tooling_receipt`
- `tooling_receipt_sha256`
- `tooling_receipt_verified`
- `cargo_lock_sha256`
- `cargo_lock_expected_sha256`
- `lockfile_pinned_and_unchanged`
- fmt/check/Clippy/unit/focused/workspace gate results
- `rustsec`
- `cargo_deny_checks`
- `test_threads`
- `network_activity`
- `validated_at`

## Authority fields added by schema v2

Every platform evidence object additionally requires exactly these authority fields:

### `validation_environment_policy`

Must equal:

`nxb-153-compiler-cargo-python-authority-v2`

This binds the evidence to the named ambient-environment rejection policy rather than an unspecified environment check.

### `validation_environment_authority`

Must equal `passed`.

The platform validator may emit this only after the canonical environment authority has passed in the real validation flow. Linux additionally performs the outer exact-head committed environment-helper audit before later Python/rustup operations; Windows performs a case-insensitive outer guard before rustup probes and repeats the policy inside dependency validation.

### `python_isolated_helper_authority`

Must equal `passed`.

Python security/authority helpers used by the canonical validation path must execute in isolated mode where the staged contract requires it. Linux outer helper parsing/fsync/sealed-helper execution and evidence-review bootstrap use `python3 -I`; immutable-source/dependency/environment helpers use isolated Python as well. Windows registry/environment Python verifier calls use isolated mode in the canonical dependency path.

This field does not claim that the Python interpreter executable itself is cryptographically pinned against a malicious host. It records the narrower import/startup-isolation contract.

### `workspace_namespace_authority`

Must equal `passed`.

This means the platform's canonical immutable workspace runner completed its exact-head source namespace contract before and after the heavy gates.

### `workspace_git_object_authority`

Must equal `passed`.

This means the canonical immutable workspace flow verified tracked source bytes against exact-head Git blob identity, not merely pathname equality or a clean mutable working tree.

On Linux this includes descriptor-relative `O_NOFOLLOW` tracked-file reads and canonical Git blob reconstruction before and after heavy gates. On Windows it refers to the pinned extracted-file Git blob verification contract.

### `dependency_source_authority`

Must equal `passed`.

This means the checksum-bound canonical crates.io/vendor contract completed in the real validation flow, including rejection of unsupported external sources/workspace Cargo source overrides, vendor verification, controlled Cargo source replacement, offline heavy gates and final dependency-source revalidation.

### `security_tool_object_authority`

Must equal `passed`.

This means cargo-audit/cargo-deny execution used the platform's admitted exact-head object-authority model: receipt-hash-checked sealed executable snapshots on Linux or pinned tool files plus ancestor namespace authority on Windows.

### `host_rust_toolchain_identity`

Current required value:

`version_pinned_object_identity_pending`

This field is intentionally **not** `passed` yet. Rust 1.97.1 version selection is enforced, but the complete host `rustup` / Cargo / rustc / rustfmt / Clippy / sysroot executable-and-tree object identity remains a separate admission blocker.

A reviewer rejects any other value until the host-toolchain authority contract is deliberately revised together with both producers and both reviewers.

## Producer rule

A platform validator must never infer schema-v2 authority fields merely from historical validation, documentation, preparation receipts or another platform's result.

The producer writes an authority field as `passed` only after the corresponding canonical helper/gate has completed successfully in the **same platform validation invocation for the same exact head**.

Platform evidence is still published only after final HEAD/worktree/lock/tool/receipt authority checks and remains create-only. A partial or conflicting visible canonical evidence object requires explicit recovery; validation must not overwrite it.

## Reviewer rule

Both semantic reviewers enforce the exact schema-v2 field set and exact expected values. A schema-v1 platform evidence object cannot participate in a schema-v2 closure.

The migration order is deliberately fail-closed:

1. semantic reviewers were changed to require schema v2;
2. Linux producer was changed to emit schema v2;
3. Windows producer was changed to emit schema v2.

Therefore a partially migrated source state could reject evidence, but could not admit old incomplete evidence as if it satisfied the stronger authority contract.

## Dual-platform closure v2

Canonical closure remains:

`target/nxb-validation/nxb-153-closure-<exact-head>.json`

Closure `schema_version` is `2`.

The closure requires Linux and Windows evidence to agree on at least:

- exact head;
- canonical Cargo.lock;
- Rust/Cargo/security-tool versions;
- `validation_environment_policy`;
- current `host_rust_toolchain_identity` state.

The closure `requirements` map records the new authority classes as `passed` only after both platform evidence objects satisfy their exact contracts:

- validation environment authority;
- isolated Python helper authority;
- workspace namespace authority;
- workspace Git-object authority;
- dependency-source authority;
- security-tool object authority.

Host Rust toolchain identity remains `blocker_pending` in closure v2.

The closure status therefore still uses:

- `status = dual_platform_validation_passed`
- `admission = blocker_review_required`

A valid dual-platform closure is evidence that the required platform validations passed; it is not automatic NXB-153 admission.

## Network statement

Platform evidence retains the bounded validation network statement used by the canonical validation flow. Closure itself records `network_activity = none` because semantic closure review consumes existing local evidence/receipt/repository objects and must not perform validation network acquisition.

## Admission boundary

Schema v2 makes the evidence model more truthful, but does not make source staging equivalent to a platform PASS.

The exact final head still requires real Rust 1.97.1 Linux + Windows execution of the complete canonical flows, supported-host runtime semantics, same-head schema-v2 evidence, guarded dual-platform closure, host Rust toolchain identity resolution and final blocker review.

PR #89 remains draft/not admitted. Issues #90–#98 remain open until their required real-platform evidence and blocker review are complete.