# NXB-153 destructive cleanup authority

Status: **partial source fix staged / remaining Windows replacement, doctor-probe and legacy base-writer cleanup pending / not admitted**.

This note records the NXB-153 / issue #112 destructive-cleanup authority boundary. It is intentionally narrower than a closure claim.

## Threat model

The relevant adversary is a same-user namespace actor that can replace a pathname after validation but before a destructive filesystem mutation. Matching permissions, regular-file type, or a final pathname stat do not prove that the object being deleted is the object that was admitted earlier.

On Linux, retaining the parent directory authority prevents ancestor substitution but does not make a final-component `unlink` object-bound. Linux does not provide an unlink-by-open-file-descriptor equivalent that would make a prior file-object admission sufficient for a later pathname unlink.

On Windows, a retained handle can deny delete/rename sharing while it remains live. Object-bound physical deletion requires same-handle lifetime semantics such as delete-on-close/delete-disposition rather than reopening a pathname. The `nxb` binary retains `#![forbid(unsafe_code)]`; this work does not relax that boundary.

## Staged migration cleanup model

Committed migration state is retired by verification instead of physical pathname deletion.

The canonical migration files may remain present:

- `state/migration-active.json`
- `state/migration-source.json`
- `state/migration-applied.json`

They are reported as stable only when all of the following remain mutually consistent:

1. the prepared journal is structurally valid;
2. the deterministic migration receipt exists and matches the journal;
3. the published workspace manifest hashes to the journal target;
4. the source backup exists and hashes to the journal source;
5. rebuilding the migration plan from the backup matches the journal;
6. the applied marker exists and matches that plan.

A committed residue that fails any of those checks is not silently ignored and is not deleted. The operation fails closed.

This removes the old `validate/check -> remove_file(path)` race from committed migration cleanup while preserving `pending_files = 0` for fully verified committed state.

## Create-only publication cleanup

Target publication, migration metadata create-only publication, and the generic `workspace_impl::create_document` production path now retain `PreparedFileAuthority` through create/write/sync, namespace claim and post-claim validation.

Production create-only paths deliberately keep private temporary residue instead of re-resolving and deleting a reusable temporary pathname. The historical pathname-cleanup fault-injection helper in `workspace/mod.rs` is `#[cfg(test)]` only.

Exact create-document transient names are quarantined by `create_document_temporary_destination` in record/readiness enumeration. The residue is transport state, not additional target or receipt authority.

## Linux migration replacement cleanup

Linux migration replacement no longer deletes its prepared or prior-manifest transport objects.

The retained parent namespace is used to move the previous canonical manifest to a random private retired name with no-clobber semantics. The retired name is then proven to reference the exact previously retained inode. The new canonical manifest is claimed from the exact retained prepared file descriptor and proven by device/inode before success.

A same-permission final-component substitution or parent-directory substitution fails closed. Substituted objects are not pathname-deleted. Previous manifests and prepared candidates may remain as private residue.

This source slice is covered by `workspace_replacement_authority_source_contract.rs` and remains subject to Linux runtime race proof.

## Source regressions staged

The source tests require that:

- committed migration `cleanup()` performs verification only and contains no pathname delete/rename;
- retired state is verified before `transient_state()` reports zero pending files;
- receipt, manifest, backup, deterministic plan, and applied marker are checked together;
- migration journal/receipt creation routes through prepared-authority publication;
- generic create-only production publication uses retained prepared-file authority and does not pathname-delete transport residue;
- receipt/record counters ignore only the exact recognized create-document temporary shape;
- a same-permission replacement of a retired canonical journal causes an error and is not deleted;
- Linux replacement covers exact old/new inode binding, final-component substitution, parent substitution and missing-manifest publication.

## Still open under #112

The remaining destructive production surface is narrower but not zero:

- Windows/non-Unix migration still reaches the historical `workspace_impl::replace_document` / `replace_file` path; on Windows that can call `remove_regular(destination)` before rename;
- `workspace_impl::write_probe` still creates a named doctor probe and later `remove_file(path)`s it;
- `workspace_impl::remove_regular` remains compiled because the unresolved non-Unix replacement path still uses it;
- `workspace_authority_base` still contains its older create-authority writer with pathname temporary cleanup, even though `workspace_authority_entry` overrides normal target publication with `workspace_authority_publication`.

The previously listed generic production `create_document` cleanup is no longer an open #112 surface.

## Coupled #111 replacement blocker

Generic create-only prepared-object binding and Linux migration replacement are source-staged under #111. Windows migration replacement remains the coupled blocker.

Windows closure must keep the exact prepared source and intended destination/parent authority across the NT namespace mutation. Reopening or deleting a pathname after admission is insufficient. Until that is solved, the historical Windows replacement path and its cleanup remain unapproved.

## Doctor probe direction

The doctor write-probe can be removed from pathname cleanup without weakening the write test by using object-lifetime cleanup primitives: Linux `O_TMPFILE` creates an unnamed inode that disappears at last close, while Windows exposes `FILE_FLAG_DELETE_ON_CLOSE`. This direction is not yet claimed implemented; platform ACL/share behavior and supported-filesystem behavior still require source and runtime validation.

## Admission requirements

NXB-153 is not admitted on the basis of this source work. Closure still requires, at minimum:

- Windows replacement object-binding closure under #111;
- elimination or object-lifetime treatment of the remaining #112 destructive paths;
- Linux and Windows adversarial replacement/swap tests;
- pinned Rust 1.97.1 build, clippy, test, documentation and dependency-policy evidence required by the repository;
- same-head runtime/CI evidence before PR #89 can be treated as merge-ready.

Until those conditions are satisfied, the correct status is **source work staged, runtime/platform proof pending**.
