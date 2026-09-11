# NXB-153 Guided Activation / Disable Linearization Authority

## Status

This document records source authority for NXB-153 blocker #105.

The source contract is staged. No exact-final-head Linux concurrency PASS, supported Windows/NTFS concurrency PASS, or final NXB-153 admission is claimed by this document.

## Finding

Guided activation and target disable are separate product operations over immutable create-only records:

- activation publishes or recovers `targets/<id>.json` plus `state/target-<id>.guided-activation.json`;
- disable publishes `targets/<id>.disabled.json`.

Before #105, guided activation rejected a disable receipt only once, before recovery/publication work. `target disable` has no shared persistent target mutation lock and may independently publish the disable receipt after that early check.

An activation retry could therefore validate an exact profile/artifact and return an `active` result even when a concurrent disable receipt had already become visible before the return.

## Source authority

Guided activation implementation:

`crates/nxb-core/src/target/activation.rs`

Source-hardening commit:

`bac80193a4029f321984a24a425eeeccaa182bea`

Current implementation blob:

`0b225518141800ad9823b8057195a14022478f03`

Cross-platform source regression:

`crates/nxb-core/tests/target_activation_disable_linearization_source_contract.rs`

Regression commits:

- `6638aece52efd80733c4f4221e46e7546a49ee00` — introduced the source-ordering contract;
- `c3f5fc0d5866cac78438601bd54760b09917bf35` — normalized the first regression version to the workspace formatting contract;
- `5e3499ef413750d4c56b426a2fc9673221bbe991` — bound the disable helper implementation itself, not only its call ordering;
- `e6d29609ed87ef2a56f5345894d67ab14bc387ee` — normalized the strengthened regression formatting.

Current regression blob:

`acda28e705e189f0ee7c4ddd837cfc2b1b8c0d78`

## Linearization contract

`activate_value()` now uses one common fail-closed helper for disable-receipt visibility.

The helper itself is regression-bound to inspect `workspace::safe_exists(disable_path)` and to fail closed when the receipt is visible. A call-site-only regression is insufficient because a no-op helper would otherwise preserve source ordering while silently destroying the authority boundary.

The helper is invoked three times:

1. **Early gate** — before profile/artifact recovery or new activation publication begins.
2. **Completed-recovery final gate** — after the exact canonical recovered profile bytes have been verified and recovery durability has been attempted, but before the recovery branch returns `activation_value(...)`.
3. **Normal-publication final gate** — after create-only profile publication succeeds and the published profile bytes are read back and verified, but before the normal branch returns `activation_value(...)`.

If the disable receipt is visible at either final gate, guided activation fails closed and does not emit an active result.

If disable publishes only after activation crosses its final gate, the observable ordering can be treated as activation followed by disable. The final target state is then disabled through the immutable disable receipt.

## Mutation boundary retained

The #105 fix does not introduce a target lock file and does not add rollback behavior.

Guided activation still does not:

- delete a target profile;
- delete a guided activation artifact;
- delete a disable receipt;
- replace an existing profile/artifact/receipt;
- rename an existing target record as recovery;
- overwrite a racing destination.

This preserves the create-only publication authority from #90 and the exact completed-activation recovery contract from #103.

## Source regression authority

The std-only Rust source regression requires:

- the disable helper to use `workspace::safe_exists(disable_path)` and retain a fail-closed rejection path;
- the helper definition to precede `activate_value()`;
- exactly three disable gates inside `activate_value()`;
- the first gate before profile/artifact existence handling;
- the recovery final gate after exact recovered profile verification and durability, before the recovery `activation_value(...)` return;
- the normal final gate after published profile byte verification, before the final `activation_value(...)` return;
- absence of rollback/delete/replace source markers in the guided activation body.

Because canonical full Rust validation executes `cargo test --workspace --all-features --locked`, this regression is intended to participate in both Linux and Windows full Rust paths.

## Remaining runtime proof

Exact-final-head admission must still demonstrate the actual process/filesystem interleavings rather than inferring them from source ordering.

Required runtime evidence includes at least:

- concurrent activation/disable where the disable receipt is published before activation reaches the final gate and activation emits no active result;
- reciprocal ordering where activation crosses the final gate first, disable subsequently succeeds, and final target observation is disabled;
- exact completed-profile recovery under the same race boundary;
- normal profile publication under the same race boundary;
- no overwrite/delete/rollback mutation in either ordering;
- Linux private-permission/path-indirection behavior;
- supported Windows/NTFS create-only, reparse/path and sharing behavior;
- complete Rust 1.97.1 workspace/security gates;
- guarded same-head Linux + Windows schema-v2 closure.

Until those gates pass, #105 remains open and PR #89 remains draft/not admitted.
