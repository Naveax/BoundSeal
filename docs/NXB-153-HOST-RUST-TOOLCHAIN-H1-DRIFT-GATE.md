# NXB-153 Host Rust Toolchain H1 Drift Gate

## Status

This document records the source-staged H1 host Rust toolchain identity gate for NXB-153.

H1 is **not** host-toolchain admission. It adds deterministic pre/post tree identity checks around the heavy Rust validation sequence. The schema-v2 evidence value remains deliberately:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

until H2 gate-lifetime immutable/pinned toolchain consumption is implemented and exercised on both supported platforms.

## Canonical tree authority helper

Canonical helper:

`scripts/nxb-153-rust-toolchain-authority.py`

Policy:

`nxb-153-host-rust-toolchain-tree-authority-v1`

The current committed helper uses bounded deterministic file-tree identity. Linux traversal is descriptor-relative and requires `O_DIRECTORY` / `O_NOFOLLOW`; Windows H1 uses the conservative Windows pathname model and rejects reparse points, ambiguous path forms and case collisions.

The tree digest binds sorted relative path identity, platform mode class, exact file length and SHA-256 of stable file bytes. File-count, per-file and total-byte bounds fail closed.

## Linux H1 gate

Canonical entrypoint remains:

`scripts/nxb-153-linux-immutable-source.sh`

The previous workspace/dependency implementation is retained byte-for-byte as:

`scripts/nxb-153-linux-immutable-source-inner.sh`

The canonical wrapper resolves both the inner runner and Rust-tree authority helper as exact-head Git blobs through the inherited repository descriptor. It does not reopen those implementation paths as a new authority source.

For validation mode the wrapper:

1. validates the exact head and inherited repository descriptor;
2. resolves the inner runner and H1 helper from exact-head Git object authority;
3. runs the H1 helper self-test with `python3 -I`;
4. resolves `rustup run 1.97.1 rustc --print sysroot` before the heavy gates;
5. computes the deterministic Linux toolchain-tree digest;
6. runs the existing immutable workspace/dependency/security heavy gate sequence;
7. resolves the Rust sysroot again and requires the exact same path;
8. recomputes/verifies the tree digest after the heavy gates;
9. returns success to the outer validator only after the post-gate tree verification succeeds.

The outer Linux validator therefore cannot publish platform evidence if the H1 wrapper detects start/end toolchain-tree drift.

The wrapper itself passed a local `bash -n` check and a synthetic Git/rustup integration primitive proving exact-head inner/helper resolution, self-test delegation and pre/post digest verification. These are narrow primitives, not current-head platform admission evidence.

## Windows H1 gate

Canonical entrypoint remains:

`scripts/nxb-153-windows-immutable-source.ps1`

The prior immutable workspace/dependency implementation is retained byte-for-byte as:

`scripts/nxb-153-windows-immutable-source-inner.ps1`

The outer Windows validator already pins the `scripts` directory and canonical immutable runner before invocation. The H1 wrapper additionally:

1. opens the inner runner and H1 helper read-only with write/delete sharing withheld;
2. rejects reparse-point files;
3. recomputes the Git blob OID from each pinned stream and requires equality with the exact-head committed object;
4. resolves Python 3.11+ and uses isolated mode for the H1 helper;
5. runs the H1 self-test;
6. resolves the Rust sysroot before heavy gates;
7. computes the deterministic Windows toolchain-tree digest;
8. executes the existing inner immutable workspace/dependency gate sequence while the inner/helper streams remain pinned;
9. requires the same canonical sysroot path after gates;
10. verifies the post-gate tree against the pre-gate digest before returning to the outer validator.

The outer Windows validator publishes evidence only after this wrapper returns successfully.

No supported-Windows runtime/parser PASS is claimed for this source. Real PowerShell/NTFS execution remains required.

## What H1 closes

H1 detects source-staged classes including:

- a different Rust sysroot being selected between the pre- and post-gate observations;
- persistent toolchain file mutation during the gate sequence;
- persistent file addition/removal or path-set drift;
- persistent executable/library/sysroot byte changes that preserve `rustc --version` text;
- Linux helper/tree pathname substitution during digest traversal through descriptor-relative authority;
- Windows wrapper/inner/helper file replacement while the relevant pinned streams/parent namespace are active.

## What H1 deliberately does not claim

Equal pre/post digests do **not** prove that a mutable host toolchain was unchanged at every instant between the two observations.

An attacker or competing local process could theoretically mutate a host toolchain object only while a heavy gate consumes it and restore the original bytes before the post-gate digest. H1 therefore remains insufficient for admission.

The unresolved H2 requirement is:

- **Linux:** copy the admitted Rust toolchain into namespace-private storage, verify the copied tree, make that private tree read-only and execute Cargo/rustc/rustfmt/Clippy/sysroot directly from that snapshot without returning to mutable host rustup paths for heavy gates;
- **Windows:** create a verified copied toolchain snapshot, reject reparse/ambiguous paths, pin the snapshot namespace/files with native handles and write/delete denial, execute the heavy gates from that snapshot, and prove real NTFS process/DLL/sysroot behavior.

## Evidence boundary

H1 does not change the schema-v2 host Rust field. Producers and reviewers must continue requiring:

`version_pinned_object_identity_pending`

until H2 is implemented, both platform producers/reviewers are deliberately migrated to a stronger schema state, and real same-head platform validation proves the new contract.

## Relationship to admission

H1 is a source hardening milestone only. PR #89 remains draft/not admitted, #90–#98 remain open, and NXB-154 must not use the branch as an admitted implementation base until H2 plus the exact-head Linux/Windows validation and guarded dual-platform closure complete.
