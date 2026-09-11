# NXB-153 destructive cleanup authority

Status: **partial source fix staged / runtime-platform proof pending / not admitted**.

This note records the NXB-153 / issue #112 destructive-cleanup authority boundary. It is intentionally narrower than a closure claim. The migration committed-state slice no longer performs pathname deletion, but other generic workspace mutation paths remain unresolved.

## Threat model

The relevant adversary is a same-user namespace actor that can replace a pathname after validation but before a destructive filesystem mutation. Matching permissions, regular-file type, or a final pathname stat do not prove that the object being deleted is the object that was admitted earlier.

On Linux, retaining the parent directory authority prevents ancestor substitution but does not make a final-component `unlink` object-bound. Linux does not provide an unlink-by-open-file-descriptor equivalent that would make a prior file-object admission sufficient for a later pathname unlink.

On Windows, a retained handle can deny delete/rename sharing while it remains live. Object-bound physical deletion would require a same-handle delete-disposition primitive rather than reopening a pathname. NXB currently forbids unsafe code and does not yet contain an audited safe wrapper for that operation.

## Staged migration cleanup model

Committed migration state is now retired by verification instead of physical pathname deletion.

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

This removes the old `validate/check -> remove_file(path)` race from committed migration cleanup. It also preserves `pending_files = 0` for a fully verified committed migration without pretending that physical deletion is object-bound.

## Prepared publication for migration metadata

Migration backup, active journal, applied marker, and receipt creation use `workspace_authority_publication::create_document`, which retains a `PreparedFileAuthority` through create-only namespace claim.

The prepared publisher deliberately leaves its private temporary hard-link residue instead of re-resolving and deleting a reusable temporary pathname. Exact create-document transient names are quarantined by `create_document_temporary_destination` in both migration receipt counting and target-readiness receipt counting.

The residue is evidence of conservative finalization, not additional migration authority.

## Source regressions staged with this slice

The source tests require that:

- committed migration `cleanup()` performs verification only and contains no pathname delete/rename;
- retired state is verified before `transient_state()` reports zero pending files;
- receipt, manifest, backup, deterministic plan, and applied marker are checked together;
- migration journal/receipt creation routes through prepared-authority publication;
- receipt counters ignore only the exact recognized create-document temporary shape;
- a same-permission replacement of a retired canonical journal causes an error and is not deleted.

## Still open under #112

This slice does **not** close destructive cleanup authority globally. The following source paths still require separate treatment or removal from production authority:

- generic `workspace_impl::create_document` temporary cleanup;
- generic `workspace_impl::replace_document` failure cleanup;
- generic `workspace_impl::write_probe` pathname cleanup;
- generic `workspace_impl::remove_regular`;
- the older base authority create writer and its pathname temporary cleanup where still compiled;
- any future physical cleanup/quarantine implementation that attempts to mutate a final component by reusable pathname.

No source contract added by this milestone should be interpreted as approving those paths.

## Coupled #111 replacement blocker

Migration manifest replacement still calls the generic `replace_document` path. Its prepared file is currently named, closed, and then used as a pathname source for replacement. This remains part of issue #111 and also retains a destructive cleanup concern under #112 on error.

The replacement path must remain fail-closed until the exact prepared object and the intended manifest transition are bound through finalization. A pre-rename stat is not sufficient.

## Admission requirements

NXB-153 is not admitted on the basis of this source work. Closure still requires, at minimum:

- resolution of the remaining #111 replacement object-binding blocker;
- resolution or explicit elimination/quarantine of the remaining #112 destructive pathname mutations;
- Linux and Windows adversarial replacement/swap tests;
- pinned Rust 1.97.1 build, clippy, test, documentation, and dependency-policy evidence required by the repository;
- same-head CI/runtime evidence before PR #89 can be treated as merge-ready.

Until those conditions are satisfied, the correct status is **source work staged, runtime/platform proof pending**.
