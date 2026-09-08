# NXB-153 Active Target Observation Linearization Authority

## Status

This document records the source-staged fix for NXB-153 blocker #110.

The source contract is staged only. It does **not** claim exact-final-head Rust execution, Linux concurrency proof, supported Windows/NTFS concurrency proof, or final NXB-153 admission. PR #89 remains draft/not admitted.

## Finding

#105 added a final disable-receipt gate to guided `target activate`, but legacy create and read-only target observers could still construct an `active` result from an earlier receipt observation.

The affected surfaces were:

- legacy `target create`, after create-only profile publication;
- `target list`, after its initial directory enumeration;
- `target show`, after profile loading;
- `target validate`, while policy/authorization validation continued after the original receipt read.

A valid immutable disable receipt becoming visible before the logical result boundary must dominate any provisional active observation.

## Current source authority

Implementation:

`crates/nxb-core/src/target.rs`

Source regression:

`crates/nxb-core/tests/target_active_observation_linearization_source_contract.rs`

The implementation introduces one final-result helper, `reconcile_effective_target(...)`, which either preserves an already validated immutable receipt or performs a final `read_optional_receipt(...)` before constructing `EffectiveTarget`.

## Source contract

### Legacy create

The create path still performs its early receipt preflight and preserves create-only publication. After the profile destination becomes visible, it performs final disable reconciliation before serializing the result.

If a valid receipt becomes visible between profile publication and that final gate, create reports the target as disabled rather than active. A malformed or mismatched receipt fails closed. No receipt/profile overwrite, deletion, repair or rollback authority is added.

### List

Initial enumeration and canonical profile/receipt validation remain unchanged. Before a provisionally active target is filtered or appended to the result, list performs final receipt reconciliation against the canonical target id.

An already validated receipt from enumeration is reused. A target that was provisionally active but whose receipt becomes visible before its final gate is treated as disabled. When `--include-disabled` is absent it is omitted; when present it is returned as disabled.

### Show

Show loads and validates the canonical profile, then performs final receipt reconciliation immediately before result serialization.

### Validate

Validate performs the supplied policy/authorization digest, policy parsing, compilation, metadata and method-boundary checks first. It then performs final receipt reconciliation immediately before constructing the effective target result and attaching the validation result.

Thus expensive validation work cannot leave a stale active observation if a valid disable receipt became visible before the final result gate.

## Linearization boundary

The final receipt reconciliation is the source-level result linearization point. If disable publication completes before that point, the command cannot emit `status = active`. If disable publication completes after that point, the operations may be ordered observer/create first and disable second.

This does not replace #108 directory-lifetime authority. The final check is still subject to the directory/path authority model until #108 closes.

## Regression authority

The platform-independent Rust source regression requires:

- the helper to call `read_optional_receipt(...)` and then `effective_target(...)`;
- create publication to precede final reconciliation, which precedes serialization;
- list enumeration to precede per-target final reconciliation, with disabled filtering after reconciliation;
- show profile read to precede final reconciliation, which precedes serialization;
- validate policy-boundary work to precede final reconciliation, which precedes serialization;
- no `effective_target(profile, None)` bypass in create/list/show/validate.

The regression is included by canonical `cargo test --workspace --all-features --locked` execution.

## Preserved authority

The source fix does not weaken:

- #90 create-only/no-overwrite publication;
- #103 exact completed activation recovery;
- #105 guided activation/disable final-result linearization;
- #106 create-document transient quarantine/accounting;
- #107 opened-file read authority;
- #108 future directory authority lifetime;
- #109 future operator-source opened-file authority;
- #111 future prepared-file publication authority;
- #112 future checked-object destructive cleanup authority.

No persistent mutation lock, overwrite, replace, delete or receipt repair path is introduced.

## Remaining proof

**Source fixed / exact-final-head runtime concurrency proof pending / not admitted.** Final proof still requires at least:

- deterministic exact-head Rust 1.97.1 full workspace/security gates;
- concurrent legacy create/disable where disable wins before the final gate and create never reports active;
- concurrent show/validate/list against disable publication in both legal orderings;
- malformed/mismatched receipt races fail closed;
- Linux permission/path/directory-lifetime proof after #108;
- supported Windows/NTFS sharing/reparse/directory-lifetime proof after #108;
- complete same-head Linux + Windows schema-v2 closure and final blocker review.

No runtime PASS is claimed by this document. NXB-154 must not use NXB-153 as an admitted implementation base until all remaining gates close.
