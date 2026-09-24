# NXB-153 Create-Document Transient Enumeration Authority

## Status

This document records source authority for NXB-153 blocker #106.

The source contract is staged. No exact-final-head Linux runtime PASS, supported Windows/NTFS runtime PASS, or final NXB-153 admission is claimed by this document.

## Finding

`workspace::create_document()` uses a same-directory private temporary file and atomically hard-links it to the create-only destination. Its canonical temporary name is:

`.<destination-name>.<24-lowercase-hex>.tmp`

If destination publication succeeds but temporary-link cleanup fails, the destination is already authoritative. The temporary hardlink can remain as finalization residue and must not become rollback authority.

#103 exact completed-activation recovery deliberately preserves that state. Before #106, however:

- `target::load_profiles()` rejected the leftover link as an unsupported target record;
- `workspace::status_value()` counted the leftover link as a canonical target record.

An exact activation recovery could therefore succeed while canonical target enumeration or workspace record accounting remained poisoned by create-only transport residue.

## Source authority

Workspace implementation:

`crates/nxb-core/src/workspace/mod.rs`

Current workspace blob:

`86bc19124c658ee98f69f0e7e610e10bcdcf3a17`

Target enumeration implementation:

`crates/nxb-core/src/target.rs`

Current target blob:

`2939de9f1c387ec3f60b4c54cc4e7230d1409ba6`

Completed-recovery integration matrix:

`crates/nxb-core/tests/target_activation_completed_recovery_cli.rs`

Current completed-recovery test blob:

`48780c22fea53ee9ac5c84772150a0f34dcfd71a`

Transient enumeration CLI matrix:

`crates/nxb-core/tests/target_transient_enumeration_cli.rs`

Current transient CLI blob:

`ab76e05e4f0cc7c1419c759ab3345c72b60d8c28`

Cross-platform source contract:

`crates/nxb-core/tests/target_transient_source_contract.rs`

Current source-contract blob:

`fb98b42ad51fc164c2da994dadb7cdc8ac133e05`

Source commits:

- `e1c2e39b516a0f3ce22a7ede25b28c27ba925d01` — add the exact create-document transient recognizer and exclude recognized transport residue from workspace record totals;
- `7f1a0bf07eea39adba086ab8ae881433f3bf4479` — quarantine only target-profile/disable-receipt create-document transients after target path/type/private-permission and bounded-entry checks;
- `3c6ac01862ce81ba376fe75a65dfbd51cee41398` — bind #103 recovery to a real 24-lower-hex transient name and prove target-list/workspace-status continuity;
- `ecb60b59e1f541dbe9f5966ee6a8e5d5f10e1d85` — add exact/malformed/foreign/non-file CLI coverage;
- `9a3ad15581ade64753c8dda33de073b7a8909ade` / `3a0ec5a35a88a9c88190470f2290d03e34483a8f` — add and format the source-ordering/non-mutation contract;
- `eb72e805028cbbe362a5b7f79580072429af4a51` — restore the pre-existing Windows drive/UNC prefix authority comment after the large-file edit, with no behavioral change.

## Exact transient recognizer

The shared recognizer accepts a filename only when all of these conditions hold:

1. the filename begins with `.`;
2. it ends with `.tmp`;
3. the interior splits at the final `.` into a non-empty destination name and nonce;
4. the nonce is exactly 24 bytes;
5. every nonce byte is lowercase hexadecimal `0-9a-f`.

Short/long nonce forms, uppercase hexadecimal, non-hexadecimal bytes, wrong suffixes and ordinary names are not recognized as create-document transients.

The recognizer identifies only the create-document transport filename shape. It does not make the residue a trusted record.

## Target enumeration contract

`target::load_profiles()` retains fail-closed inspection order:

1. reject path indirections;
2. require a regular file;
3. validate private file permissions;
4. increment and enforce the bounded target-directory entry budget;
5. parse the filename;
6. if it is an exact create-document transient, accept it for quarantine only when its embedded destination is a canonical `<valid-target-id>.json` or `<valid-target-id>.disabled.json` destination;
7. otherwise continue ordinary canonical profile/disable-receipt admission.

A quarantined transient is ignored as target authority but still consumes the bounded directory-entry budget. This prevents an accumulation of ignored transport residue from bypassing enumeration bounds.

An exact generic transient for an unrelated destination such as `foreign.txt` remains unsupported in the target directory. Malformed lookalikes, arbitrary ordinary files and non-file entries remain fail-closed.

## Workspace status contract

`workspace::count_regular_files()` excludes exact create-document transient filename shapes from canonical record totals after existing indirection/type checks.

The transient is not counted as an independent record because it is a transport hardlink rather than a canonical workspace record destination. This is accounting behavior only; it does not cause the transient to be parsed or trusted as a target/profile/receipt.

## No-cleanup / no-rollback boundary

#106 does not introduce cleanup authority. Enumeration and status paths do not delete, replace, rename or rewrite transient residue.

This is deliberate. A visible create-only destination may already be authoritative when finalization fails, and an observer cannot safely turn a pathname lookalike into rollback authority merely because its name matches the transport shape.

Actual cleanup remains a separate supported-filesystem/runtime concern.

## Source and CLI coverage

The staged tests prove:

- an exact profile publication transient is ignored by `target list`, excluded from `workspace status`, and remains byte-for-byte present;
- an exact disable-receipt publication transient is likewise quarantined while the canonical disabled target remains enumerable;
- the #103 completed-profile recovery path works with the real 24-lower-hex transient shape and remains enumerable/accounted afterward;
- 23-byte, 25-byte, uppercase-hex, nonhex and wrong-suffix lookalikes remain rejected by target enumeration;
- an exact generic transient whose embedded destination is not a target profile/disable receipt remains rejected;
- an ordinary foreign file remains rejected;
- a non-file target-directory entry remains rejected;
- the source contract binds exact recognizer syntax, bounded entry accounting before quarantine and absence of target-enumeration delete/replace/rename behavior.

Canonical full Rust validation is expected to execute these tests through `cargo test --workspace --all-features --locked` on the final admitted head.

## Remaining runtime proof

Exact-final-head admission must still prove the behavior on real supported filesystems/process boundaries rather than inferring it solely from source and CLI fixtures.

Required runtime evidence includes at least:

- an injected real `create_document` post-claim temporary-link cleanup failure that leaves the canonical transient name, followed by exact #103 retry, target enumeration and workspace status;
- exact transient preservation with no rollback deletion/overwrite;
- target-directory accumulation reaching the bounded entry limit and failing closed;
- Linux private-permission and pathname-indirection behavior;
- supported Windows/NTFS hardlink, ACL, reparse/path and sharing behavior;
- malformed/foreign transient rejection under supported platform semantics;
- complete Rust 1.97.1 workspace/security gates;
- guarded exact-same-head Linux + Windows schema-v2 closure.

Until those gates pass, #106 remains open and PR #89 remains draft/not admitted.
