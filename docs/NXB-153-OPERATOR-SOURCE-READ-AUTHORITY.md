# NXB-153 Operator Source Read Authority

Status: source fix staged; runtime/platform closure pending.

This document records the source-level authority contract introduced for BoundSeal NXB-153 blocker #109. It does not admit NXB-153 and it does not claim Linux or Windows runtime PASS.

## Scope

The affected operator-provided inputs are:

- guided scope imports, capped at 64 KiB;
- target policy documents, capped at 1 MiB;
- authorization evidence, capped at 8 MiB.

The old target-local reader validated a pathname and metadata, then opened that pathname separately. That check-then-open sequence allowed namespace mutation between admission and byte consumption.

## Generalized reader

`workspace::read_document()` and `workspace::read_bounded_source()` now converge on `workspace/read_authority.rs::read_bounded()`.

The common primitive:

1. rejects an invalid caller maximum;
2. acquires parent namespace authority;
3. opens the final file without following the final link/reparse point;
4. validates that the opened object is a non-empty regular file at or below the caller maximum;
5. reads from that same opened handle with `maximum + 1` growth detection;
6. re-reads metadata from the same handle;
7. requires byte count and object length to remain stable;
8. performs platform-specific identity/content-metadata stability validation before returning bytes.

No write, delete, repair, normalization, or replacement operation is performed on operator input paths.

When a target authority scope is active and an operator source is inside the admitted workspace, the source file must be directly beneath the retained workspace root or one retained child authority. Deeper workspace-internal parents fail closed instead of re-resolving an unpinned intermediate directory. Operator sources outside the admitted workspace continue through the generalized parent-pinning reader and may use ordinary nested directories.

## Permission modes

The reader has two permission modes:

- `WorkspacePrivate`: preserves the existing workspace-record private-permission contract;
- `OperatorProvided`: applies object/namespace authority and caller bounds without requiring workspace-private directory or file permissions.

This separation is intentional. A legitimate operator policy or authorization document may live in a normal user directory and must not be rejected merely because it is not a BoundSeal-owned `0700`/private-ACL workspace object.

## Linux authority

Linux parent acquisition uses a directory handle opened with `O_DIRECTORY | O_NOFOLLOW`.

The opened parent is compared to the admitted and named parent with device/inode identity. Final child resolution is then performed through `/proc/self/fd/<parent-fd>/<file>` so a later rename/replacement of the original parent pathname cannot redirect the read to another directory.

The final file is opened with `O_NOFOLLOW`. Opened/named device and inode must match. After the read, device/inode plus mtime/ctime values must remain unchanged.

If the required handle-derived `/proc/self/fd` authority cannot be resolved, the read fails closed.

## Windows authority

Windows arbitrary operator paths pin the canonical parent namespace from the filesystem root through the final parent directory. Each ancestor directory handle is opened with:

- `FILE_READ_ATTRIBUTES` for canonical ancestor identity/reparse handles;
- `FILE_READ_ATTRIBUTES | DELETE` for the final canonical parent handle;
- `FILE_FLAG_BACKUP_SEMANTICS`;
- `FILE_FLAG_OPEN_REPARSE_POINT`;
- read/write sharing, but no delete sharing.

The final canonical parent requests `DELETE` access and withholds delete sharing. This retained namespace authority blocks rename/delete of the parent and containing path while the final pathname is resolved, without requiring incompatible DELETE authority on shared system ancestors. The canonical parent is revalidated after the handle chain is acquired.

The final file still uses the existing BoundSeal read-authority handle: `FILE_FLAG_OPEN_REPARSE_POINT` with read sharing only. That share mode denies new write/delete/rename access while the file is consumed. Final type/reparse state and creation/last-write/file-size metadata are revalidated before return.

## Unsupported platforms

The generalized authority remains fail-closed outside the explicitly implemented Linux and Windows paths. There is no pathname-only fallback.

## Regression coverage staged in source

The branch now contains:

- Linux final-symlink rejection;
- Linux caller-cap and non-private operator-source coverage;
- Linux parent-path replacement coverage demonstrating handle-derived resolution is not redirected;
- Linux opened/named final-file identity replacement rejection;
- deterministic Linux post-open final replacement, in-place size drift, and same-size content drift races at the generalized read gate;
- source binding from returned pinned authorization/policy/scope bytes into authorization SHA-256, policy parse/hash, and scope JSON parsing;
- deterministic Linux post-validation pathname-swap tests proving target policy hash, authorization hash, and scope parsing consume the returned pinned bytes rather than reopening the mutable pathname;
- Windows parent-directory rename blocking while authority handles are held;
- a staged Windows junction-based reparse-parent runtime regression proving operator-source reads reject a real reparse indirection before consuming bytes;
- Windows operator-source non-private ACL/caller-cap coverage;
- Windows final-file write/delete/rename blocking while the read handle is held;
- a source contract that forbids restoring target-local metadata-then-open I/O and locks the 64 KiB / 1 MiB / 8 MiB product envelopes.

## Remaining admission work

Before #109 or NXB-153 can be admitted:

- run the canonical Rust 1.97.1 workspace/security gates on the exact head;
- retain exact-head Linux execution of the deterministic final-replacement/in-place-drift/content-drift races; Run #36 executed all three and failed only because the final-replacement test accepted one fail-closed diagnostic spelling, now corrected in staging;
- execute supported Windows parent/final replacement and rename/delete coverage together with the staged real-junction reparse-parent rejection on an exact-head canonical Windows run;
- execute the staged direct consumer-level policy/authorization/scope post-validation pathname-swap races on an exact-head canonical Linux run;
- preserve the existing setup/import/validate/recovery matrices;
- perform guarded same-head Linux + Windows closure under the repository CI execution policy.

Until those checks are available, #109 remains source-fixed but runtime-pending and PR #89 remains draft/not admitted.
