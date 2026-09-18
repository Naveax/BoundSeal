# NXB-153 Workspace Directory Authority

Status: source fix staged; exact-head Linux/Windows runtime admission pending.

This document records the source authority boundary introduced for NXB-153 blocker #108. It does not claim runtime PASS and does not admit PR #89.

## Problem

A canonical workspace pathname is not a durable directory authority. Before this change, target readiness validated a workspace root and later target operations resolved `targets/` and guided activation `state/` through pathnames again. A concurrent local namespace mutation could therefore replace an admitted root or child directory between readiness and later read/enumeration/create-only publication.

Pinned final-file reads from #107 do not solve parent-directory replacement for later enumeration or publication.

## Operation lifetime

Every target CLI command now enters one `TargetAuthorityScope` before dispatch. The scope remains alive through command execution, result construction and output handling. Dropping the scope releases all retained directory handles.

The authority state retains:

- the admitted workspace root;
- canonical child authorities used during target readiness;
- the `targets` authority used for target enumeration/read/publication;
- the `state` authority used for guided activation continuity read/publication.

Target code receives stable authority-derived paths rather than treating canonical path strings as authority.

## Linux

Linux private directory acquisition uses:

- `O_DIRECTORY`;
- `O_NOFOLLOW`;
- opened/admitted/named device + inode identity binding;
- private directory mode validation;
- `/proc/self/fd/<directory-fd>` as the stable namespace used for later child I/O.

Direct child authorities are opened beneath the already pinned parent namespace. Once a root or child directory has been admitted, renaming/replacing its original pathname cannot redirect later target reads, enumeration or create-only publication.

The primitive calls the unscoped workspace implementation for admission checks. It never re-enters the thread-local authority facade while that facade holds a mutable `RefCell` borrow.

## Windows

Windows retains directory handles for the canonical ancestor chain and child authority using:

- `FILE_READ_ATTRIBUTES`;
- `FILE_FLAG_BACKUP_SEMANTICS`;
- `FILE_FLAG_OPEN_REPARSE_POINT`;
- `FILE_SHARE_READ | FILE_SHARE_WRITE`;
- deliberately no `FILE_SHARE_DELETE`.

The omitted delete share is the namespace-lifetime boundary: rename/delete replacement of the retained root/child authority should be denied while the target operation is alive. Private ACL validation remains required for workspace-owned directories.

Supported NTFS runtime proof is still required before admission.

## Workspace facade

`nxb.rs` now composes the original workspace implementation with an authority facade:

- `workspace_impl` remains the original non-target workspace implementation;
- `workspace_authority_base` owns target-operation authority lifetime, stable-path reads and create-only publication;
- `workspace_authority_entry` preserves the normal workspace API surface and restores the existing status record-count semantics;
- migration receipt and workspace-record readiness helpers preserve existing fail-closed checks under the pinned namespace.

When no target authority scope is active, ordinary workspace commands continue to delegate to the original implementation.

## Read and publication binding

Within an active target authority scope:

- workspace documents beneath an admitted stable authority are opened/read through the authority-derived namespace;
- Linux retains final-file `O_NOFOLLOW`, device/inode identity and post-read metadata stability;
- Windows retains final-file `OPEN_REPARSE_POINT` and read-only sharing semantics;
- create-only target profile, disable receipt and guided activation artifact publication requires the publication parent to be an exact retained directory authority;
- temporary preparation, hard-link destination claiming and parent synchronization happen beneath that retained authority;
- public output converts stable Linux `/proc/self/fd/...` authority paths back to the admitted logical workspace path.

If an active target operation accidentally attempts workspace-internal I/O through the logical workspace pathname instead of the retained stable authority, the facade fails closed rather than silently delegating to the pathname implementation.

## Preserved readiness semantics

The authority facade preserves the readiness checks that target commands previously inherited from workspace status/migration status:

- canonical workspace directories are private and non-indirected;
- `targets`, `sessions`, `runs`, `evidence` and `reports` are enumerated under pinned directories;
- exact create-document transient residue is excluded from record counts;
- symbolic-link/reparse record entries fail closed;
- migration `active/source/applied` transient files still block readiness;
- migration receipt directory/file private permissions, non-file rejection and the 1,024 receipt limit are preserved.

## Deliberately not claimed here

This source work does not close neighboring blockers:

- #111 still requires prepared-file object identity to remain bound through publication/replacement finalization;
- #112 still requires destructive cleanup to act on the exact checked object rather than re-resolving a pathname.

The directory-authority publication path intentionally preserves the existing create-only design so those blockers remain separately reviewable.

## Source regressions

The staged source includes:

- Linux root replacement resistance;
- Linux child replacement resistance;
- Windows root rename lifetime coverage;
- Windows child rename lifetime coverage;
- source regression preventing primitive recursion into scoped `RefCell` state;
- source regression proving one target authority scope spans command dispatch through result handling;
- source regression binding `targets` and guided activation `state` to retained child authorities;
- source regression forbidding guided artifact publication through `root.join(...)`;
- source regression preserving workspace record/migration receipt readiness checks;
- source regression rejecting logical-path fallback while authority scope is active.

## Remaining admission work

Before #108 or NXB-153 can be admitted:

- canonical Rust 1.97.1 fmt/check/Clippy/full workspace/security gates must pass on the exact head;
- Linux race injection must demonstrate root/`targets`/`state` rename-replacement cannot redirect enumeration, reads or create-only publication;
- Linux create-only semantics and private permissions must remain correct under the handle-derived namespace;
- supported Windows/NTFS must demonstrate root/`targets`/`state` rename/delete/reparse substitution is denied for the authority lifetime and released afterwards where appropriate;
- existing #103/#105/#106/#107 behavior and target setup/import/validate/recovery matrices must remain green;
- guarded same-head Linux + Windows schema-v2 closure must complete.

Until then #108 is source-fixed/staged but runtime-platform proof remains pending, PR #89 remains draft/not admitted, and NXB-154 must not use NXB-153 as an admitted base.
