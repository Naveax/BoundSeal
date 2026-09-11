# NXB-153 destructive cleanup authority

Status: **reachable destructive production routes source-reduced / legacy compiled quarantine + lockfile refresh + runtime-platform proof pending / not admitted**.

This note records the NXB-153 / issue #112 destructive-cleanup boundary. It deliberately distinguishes a reachable production mutation route from older compiled helpers that are shadowed by the composed workspace entry.

## Threat model

A same-user namespace actor can replace a pathname after validation but before a destructive filesystem mutation. Matching permissions, regular-file type, or a final pathname stat do not prove that the object being deleted or moved is the object admitted earlier.

NXB therefore either binds mutation to retained object/parent authority or removes physical cleanup from the reachable production route. A later pathname `remove_file` is not accepted as object authority.

## Migration committed-state cleanup

Committed migration state is retired by verification instead of physical pathname deletion. `migration-active.json`, `migration-source.json`, and `migration-applied.json` may remain present.

They are reported as stable only when journal, deterministic receipt, published manifest, source backup, rebuilt plan and applied marker remain mutually consistent. Malformed or substituted residue fails closed and remains untouched.

This removes the old check-then-delete race from committed migration cleanup while preserving zero pending files for verified retired state.

## Create-only publication cleanup

Target publication, migration metadata publication and the generic `workspace_impl::create_document` production path retain `PreparedFileAuthority` through create/write/sync, namespace claim and post-claim validation.

Reachable create-only publication deliberately keeps private transport residue instead of re-resolving and deleting a reusable temporary pathname. The historical injected cleanup helper in `workspace/mod.rs` is `#[cfg(test)]` only. Recognized private transport names are quarantined from target/receipt enumeration.

## Linux migration replacement

Linux replacement retains the parent directory, previous manifest and prepared candidate. It quarantines the previous canonical name with no-clobber semantics under the retained `/proc/<pid>/fd/<parent-fd>` namespace, proves the retired name still binds the retained inode, then claims the canonical name from the exact prepared FD and proves the final inode.

The production Linux replacement module performs no `remove_file`, `remove_regular`, recursive deletion or plain `fs::rename` cleanup. Failure may leave private retired/prepared residue; it must not delete an unrelated replacement.

## Windows migration replacement

Windows replacement no longer routes through the historical non-Unix `replace_file` production path.

`workspace_windows_entry.rs` is selected as `workspace_impl` on Windows and shadows the base `replace_document` plus base migration module. The active replacement implementation:

- retains the canonical parent ancestor handle chain without delete sharing;
- retains the current manifest with `GENERIC_READ | DELETE`, `FILE_SHARE_READ` only and reparse-point-open semantics;
- retains observed bytes and Win32 volume/file-index identity;
- creates the candidate through `PreparedFileAuthority`;
- renames the exact retained old handle to a random retired child through `SetFileInformationByHandle(FileRenameInfo)` with no replacement;
- verifies the retired name against the exact retained Win32 identity while keeping the old handle alive;
- claims the canonical destination create-only from the retained prepared object;
- validates the destination and parent binding before success.

The Win32 unsafe ABI is isolated in `nxb-win32-fs-authority`; the `nxb` binary remains `#![forbid(unsafe_code)]`.

This removes the historical Windows `remove_regular(destination) -> rename(source, destination)` path from the selected production migration route.

## Doctor probe cleanup

The public workspace entry overrides the historical named doctor write-probe.

Linux uses an unnamed `O_TMPFILE` object; Windows uses `FILE_FLAG_DELETE_ON_CLOSE`. Probe write/sync occurs on the opened object and cleanup follows object lifetime rather than a later pathname delete. The source contract is `workspace_doctor_probe_source_contract.rs`.

## Legacy compiled mutation quarantine

`workspace/mod.rs` and `workspace_authority.rs` still contain older pathname mutation helpers for historical/tests/base compatibility. They are not treated as active authority merely because they compile.

The selected public routes are locked by `workspace_legacy_mutation_quarantine_source_contract.rs`:

- public workspace calls go through `workspace_authority_entry.rs`;
- entry-local `create_document` shadows the base authority writer;
- entry-local `doctor_value` shadows the historical named doctor probe;
- Windows selects `workspace_windows_entry.rs`, whose local `replace_document` and local migration module shadow the historical base replacement route;
- the legacy authority create writer has no internal production call site beyond its own wrapper definition.

Removal/refactoring of those quarantined helpers remains desirable maintenance, but they are no longer the selected Linux/Windows target/workspace mutation authority.

## Source regressions staged

Source contracts cover:

- verification-only committed migration retirement;
- create-only retained prepared-object publication;
- Linux exact old/new inode replacement and namespace substitution;
- Windows exact-handle identity, no-replace rename, sharing denial, expected-current mismatch, final-component swap and parent replacement;
- object-lifetime doctor probe cleanup;
- legacy mutation route quarantine/shadowing.

## Still pending under #112

This issue remains open because source staging is not runtime/platform admission.

- `Cargo.lock` still needs canonical regeneration for the new `nxb-win32-fs-authority` workspace package;
- legacy compiled pathname helpers should eventually be physically removed or reduced after compatibility checks;
- Linux adversarial namespace execution and Windows/NTFS sharing/reparse execution are not yet proven on this head;
- pinned Rust 1.97.1 build/check/clippy/test/doc/dependency-policy evidence is absent.

No runtime PASS is claimed. PR #89 remains draft/not admitted, and NXB-154 must not use NXB-153 as an admitted base until exact same-head closure.
