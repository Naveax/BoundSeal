# NXB-153 destructive cleanup authority

Status: **reachable destructive production routes source-reduced / legacy compiled quarantine + runtime-platform proof pending / not admitted**.

This note records the NXB-153 / issue #112 destructive-cleanup boundary. It distinguishes reachable production mutation authority from older compiled helpers that are shadowed by the composed workspace entry.

## Threat model

A same-user namespace actor can replace a pathname after validation but before a destructive filesystem mutation. Matching permissions, regular-file type, or pre/post pathname stat does not prove that the object being deleted, renamed, moved or replaced is the object admitted earlier.

Reachable NXB-153 code therefore either binds mutation to retained object/parent authority or removes physical victim mutation from the route. A later pathname `remove_file`, pathname rename or pathname quarantine is not accepted as exact-object authority.

## Migration committed-state cleanup

Committed migration state is retired by verification instead of physical pathname deletion. `migration-active.json`, `migration-source.json`, and `migration-applied.json` may remain present.

They are reported as stable only when journal, deterministic receipt, published manifest, source backup, rebuilt plan and applied marker remain mutually consistent. Malformed or substituted residue fails closed and remains untouched.

## Create-only publication cleanup

Target publication, migration metadata publication and generic production `create_document` retain `PreparedFileAuthority` through creation, private-permission setup, write/sync, namespace claim and post-claim validation.

Reachable publication deliberately keeps private transport residue instead of reopening and deleting a reusable temporary pathname. The historical injected cleanup helper is test-only. Exact recognized transport names are quarantined from target/receipt enumeration without being trusted as authority.

## Linux migration replacement

The Linux replacement route no longer claims a pathname rename/quarantine as exact-victim authority.

### Existing destination

The replacement parent and existing canonical destination are retained and revalidated. If a destination exists, the route then **fails closed before any victim mutation or candidate preparation** because the admitted unprivileged Linux model does not provide the exact-victim namespace mutation primitive required by the same-user threat model.

The route does not move, rename, unlink, quarantine, overwrite, replace or delete the existing destination. A same-permission final-component substitution is detected and both the retained original and substituted object remain untouched. Parent replacement likewise cannot redirect a mutation because no victim mutation is attempted.

Production source forbids the historical `TRUSTED_MV` / `quarantine_no_replace` design and contains no `remove_file`, `remove_regular`, plain `fs::rename`, or recursive-delete fallback in the active Linux replacement module.

`migration::apply` and `migration::recover` reject an existing legacy schema-0 manifest on Linux before creating migration state when completing that operation would require replacement.

### Missing destination

A missing destination can still be published safely without destructive victim mutation. The replacement candidate is retained, claimed create-only from the retained file descriptor via admitted `/usr/bin/ln -L`, and the final device/inode plus parent durability/binding are verified.

## Windows migration replacement

Windows selects `workspace_windows_entry.rs`, which shadows the historical base replacement/migration route.

Before victim mutation the active Windows replacement implementation retains the parent ancestor authority, a prepared candidate authority, and, when present, the current destination as a `GENERIC_READ | DELETE` no-delete-share handle with observed bytes and Win32 identity. Presence/bytes must still match the operation's observation before the current destination is mutated.

If a current destination is admitted, the route:

- renames the exact retained old handle to a random retired child using `SetFileInformationByHandle(FileRenameInfo)` with `ReplaceIfExists = FALSE` and the retained parent handle as `RootDirectory`;
- verifies the retired name against the retained Win32 identity while the old handle remains live;
- claims the canonical destination create-only from the retained prepared object;
- validates destination and parent binding before success.

The unsafe Win32 ABI is isolated in the dependency-free `nxb_core_win32_authority` library target inside the existing `nxb-core` package. The `nxb` binary remains a separate crate target with `#![forbid(unsafe_code)]` and consumes only the helper library's safe API. This source boundary adds no workspace/path package and requires no Cargo dependency-graph change.

## Doctor probe cleanup

The public workspace entry overrides the historical named doctor write-probe. Linux uses an unnamed `O_TMPFILE`; Windows uses `FILE_FLAG_DELETE_ON_CLOSE`. Probe write/sync occurs on the opened object and cleanup follows object lifetime rather than a later pathname delete.

## Legacy compiled mutation quarantine

Older pathname mutation helpers may still compile in base implementation files for historical/tests/base compatibility. Compilation alone does not make them selected authority.

`workspace_legacy_mutation_quarantine_source_contract.rs` binds the selected routing:

- public workspace calls compose through `workspace_authority_entry.rs`;
- entry-local create publication shadows the historical authority writer;
- entry-local doctor probe shadows the historical named probe;
- Windows selects `workspace_windows_entry.rs`, whose local replacement and migration modules shadow the historical non-Unix route;
- the legacy create writer has no selected production call site beyond its own wrapper definition.

Physical removal/refactoring of quarantined helpers remains desirable maintenance after compatibility checks, but it is not a substitute for proving the selected routes.

## Source regressions staged

Source contracts cover:

- verification-only committed migration retirement;
- create-only retained prepared-object publication;
- Linux existing-destination fail-closed behavior with no victim mutation;
- Linux final-component and parent substitution preservation;
- Linux missing-destination create-only publication from the retained prepared descriptor;
- Windows exact-handle identity, no-replace rename, sharing denial, expected-current mismatch, final-component swap and parent replacement;
- object-lifetime doctor probe cleanup;
- legacy mutation-route quarantine/shadowing.

Key sources include:

- `crates/nxb-core/src/workspace/migration.rs`
- `crates/nxb-core/src/workspace_authority_replacement.rs`
- `crates/nxb-core/src/workspace_authority_replacement_windows.rs`
- `crates/nxb-core/src/prepared_file_authority.rs`
- `crates/nxb-core/src/workspace_doctor_probe.rs`
- `crates/nxb-core/tests/workspace_destructive_cleanup_source_contract.rs`
- `crates/nxb-core/tests/workspace_replacement_authority_source_contract.rs`
- `crates/nxb-core/tests/workspace_windows_replacement_authority_source_contract.rs`
- `crates/nxb-core/tests/workspace_doctor_probe_source_contract.rs`
- `crates/nxb-core/tests/workspace_legacy_mutation_quarantine_source_contract.rs`

## Admission still pending

This issue remains open because source staging is not runtime/platform admission. Exact-final-head closure still requires pinned Rust 1.97.1 build/check/Clippy/tests/docs/dependency-policy gates, Linux adversarial namespace execution, supported Windows/NTFS sharing/reparse/handle-relative execution, migration recovery matrices and guarded same-head Linux + Windows admission.

No runtime PASS is claimed. PR #89 remains draft/not admitted, and NXB-154 must not use NXB-153 as an admitted base until exact same-head closure succeeds.
