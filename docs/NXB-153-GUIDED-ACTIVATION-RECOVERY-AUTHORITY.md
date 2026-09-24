# NXB-153 Guided Activation Completed-Recovery Authority

## Status

This document records the source-staged fix for NXB-153 blocker #103 and its later #105/#106 hardening.

It does **not** claim exact-final-head platform admission. PR #89 remains draft/not admitted and #103 remains open until the completed-recovery path passes the canonical Rust/security/platform validation set, including supported-platform publication/finalization failure tests.

## Finding

Guided activation publishes the continuity artifact before the immutable target profile. If create-only profile publication makes the destination visible but a later publication-finalization step fails, rollback deletion is intentionally refused.

The original retry path then rejected immediately when `profile_path` existed. It could recover artifact-present/profile-absent inert continuity, but it could not recognize an exact already-visible profile plus its exact guided artifact.

That left an exact state without an idempotent completion path.

## Current source authority

Activation implementation:

`crates/nxb-core/src/target/activation.rs`

Current implementation blob after #105 activation/disable linearization hardening:

`0b225518141800ad9823b8057195a14022478f03`

Historical #103 completed-recovery implementation blob introduced by the original fix:

`05cd07302f3df7c8f7f80fa3fd27c1194e017742`

Original completed-recovery source-fix commit:

`dfe4389c4655175928db7e51c7c520d19a4b62de`

Updated main activation CLI regression:

`crates/nxb-core/tests/target_activation_cli.rs`

Current blob:

`fc34cabd9090a4e39c00afa62ac24067a3ea3676`

Dedicated completed-recovery matrix:

`crates/nxb-core/tests/target_activation_completed_recovery_cli.rs`

Current blob after #106 real-transient enumeration/status integration:

`48780c22fea53ee9ac5c84772150a0f34dcfd71a`

#106 transient-enumeration authority:

`docs/NXB-153-CREATE-DOCUMENT-TRANSIENT-ENUMERATION-AUTHORITY.md`

Existing artifact-present/profile-absent recovery coverage remains in:

`crates/nxb-core/tests/target_activation_recovery_cli.rs`

## Recovery contract

After validating the exact preview confirmation, authorization evidence, policy binding, workspace root and the initial absence of a disable receipt, activation resolves profile/artifact existence.

If the profile already exists, recovery is admitted only when:

1. the guided activation artifact also exists;
2. `recover_inert_continuity()` accepts the artifact as bounded, canonical JSON;
3. artifact version, target id and `network_activity = none` match;
4. the stored preview is exactly equal to the current normalized confirmed preview;
5. the stored policy document is exactly equal to the current policy document;
6. the policy document digest matches the preview policy binding;
7. publication nonce and timestamp remain valid;
8. the prospective profile reconstructed from the artifact timestamp and current preview has the exact identity SHA-256 recorded by the artifact;
9. prospective profile policy SHA-256 matches the confirmed policy;
10. canonical prospective profile bytes are byte-for-byte equal to the already-persisted profile bytes;
11. recovery durability completes where the platform supplies that durability operation;
12. the #105 final disable-receipt gate remains clear immediately before returning the recovered active result.

Only after all checks pass does recovery return `activation_value(...)` with the same preview, policy, artifact and profile identity bindings.

The completed-recovery branch does **not** call `create_document` for the profile or artifact and does not delete/replace either publication.

## Fail-closed states

Recovery remains rejected when:

- a disable receipt is visible at the initial or #105 final result gate;
- profile exists but guided artifact is missing;
- artifact is malformed/noncanonical or does not match exact preview/policy;
- artifact profile-identity binding does not reconstruct to the prospective profile;
- profile bytes differ from canonical prospective profile bytes;
- confirmed normalized preview differs;
- policy/hash bindings differ;
- any workspace pathname/indirection/private-document check fails.

No mismatch is repaired by overwrite or rollback deletion.

## Publication-transient continuity

#106 closes a reader-side gap exposed by the completed-recovery model.

`workspace::create_document()` can leave a same-directory hardlink named:

`.<destination-name>.<24-lowercase-hex>.tmp`

when destination publication succeeds but temporary-link cleanup fails. The destination is already authoritative and #103 correctly refuses rollback deletion.

The completed-recovery matrix now uses the real transport filename shape:

`.example-app.json.0123456789abcdef01234567.tmp`

After exact retry, the matrix proves:

- the immutable profile is unchanged;
- the guided artifact is unchanged;
- the leftover hardlink remains unchanged;
- `target list` still returns exactly the canonical target;
- `workspace status` counts only the canonical target record rather than counting the transport hardlink as an additional record.

Target enumeration and status observation do not delete or trust the leftover link. Exact/malformed/foreign transient behavior is covered separately by #106.

## Regression coverage

The source-staged CLI tests cover:

- normal exact activation remains create-only;
- exact profile + exact artifact retry succeeds and leaves both byte-for-byte unchanged;
- profile exists but artifact is absent -> reject without profile mutation;
- profile bytes differ -> reject without artifact/profile repair;
- exact completed state with a changed confirmed preview -> reject without mutation;
- disable receipt exists -> reject without mutation;
- visible exact profile with a real create-document publication transient -> exact retry succeeds while leaving profile, artifact and transient link unchanged;
- the recovered state remains canonical under `target list` and `workspace status`;
- artifact-present/profile-absent inert continuity recovery remains separately covered and still requires the exact preview;
- #105 source regression separately binds final disable-result linearization.

The normal activation test was deliberately changed from “duplicate activation always rejects” to “wrong acknowledgement rejects, exact duplicate is idempotent”. Non-exact duplicate state remains fail-closed through the conditions above.

These integration tests run through the `nxb` CLI and are included by canonical `cargo test --workspace --all-features --locked` gates.

## Remaining platform proof

Source staging is not final admission. Exact-final-head validation must still prove:

- the full CLI matrix on the pinned Rust 1.97.1 toolchain;
- an injected `create_document` published-finalization failure followed by exact retry;
- a real canonical temporary-link-cleanup-failure residue on supported filesystems;
- recovery followed by canonical list/status behavior under that injected real failure;
- no overwrite/delete under concurrent or mismatched retry attempts;
- #105 activation/disable concurrent ordering around the final result gate;
- pathname/permissions/indirection behavior on supported Windows/NTFS and Linux;
- returned activation hashes remain identical to persisted artifact/profile bindings;
- complete NXB-153 Linux + Windows same-head admission and blocker review including #106.

Until those gates succeed, #103 remains open and NXB-154 must not use NXB-153 as an admitted implementation base.
