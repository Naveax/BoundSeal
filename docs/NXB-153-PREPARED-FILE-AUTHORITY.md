# NXB-153 Prepared File Authority

Status: **Linux + Windows source fixes staged / Rust 1.97.1 + runtime-platform proof pending / not admitted**.

This note records the source boundary for blocker #111. It does not claim canonical runtime proof and it does not close #111.

## Authority contract

Workspace publication must remain bound to the exact prepared file object from successful creation, private-permission setup, write and `sync_all` through namespace claim and post-claim verification. A reusable temporary pathname is residue/diagnostic state only and is never publication authority.

Target profile publication, disable-receipt publication, guided-activation artifact/profile publication, migration metadata publication and generic production `workspace_impl::create_document` route through retained `PreparedFileAuthority`.

## Create-only publication

### Linux

The prepared file descriptor remains live. Create-only claim invokes the admitted absolute `/usr/bin/ln` tool with `-L --` and a source qualified as `/proc/<parent-pid>/fd/<prepared-fd>`. A destination rooted below a retained `/proc/self/fd/<directory-fd>` namespace is likewise qualified for the external child process before invocation.

The tool must be a root-owned regular non-symlink file and must not be group/other writable. Its environment is cleared. After claim, the destination device/inode must match the retained prepared descriptor.

The source regressions require same-permission replacement of the prepared pathname not to redirect the published destination.

### Windows

The prepared file is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and `FILE_SHARE_READ` only. Write and delete/rename sharing are withheld while the authority is live. The named prepared binding is revalidated before hard-link claim and the final destination binding is verified after claim.

### Cleanup boundary

Reachable create-only publication deliberately does not pathname-delete its private transport residue. Exact recognized create-document transient names are quarantined from target/receipt enumeration. Physical cleanup cannot regain authority by reopening a reusable pathname.

## Linux migration replacement

Linux migration replacement routes through `workspace_authority_replacement.rs` and deliberately separates two cases.

### Existing destination

If the canonical destination already exists, the parent directory and existing file are retained and revalidated. The route then **fails closed before any victim namespace mutation or candidate preparation** with the unsupported exact-victim-authority error.

It does not rename, move, unlink, quarantine, overwrite or replace the existing destination. In particular, the production Linux replacement path contains no `TRUSTED_MV`, `quarantine_no_replace`, `remove_file`, `remove_regular`, plain `fs::rename`, or recursive-delete fallback.

A same-user final-component substitution therefore cannot redirect a quarantine/delete operation onto an unrelated object because no such operation is attempted. Regressions require both the originally admitted file and a substituted same-permission file to remain untouched when the binding changes.

This intentionally makes legacy schema-0 migration on Linux fail closed while an existing `workspace.json` would require replacement. `migration::apply`/`recover` reject that boundary before migration state is created.

### Missing destination

When the destination is absent, publication remains create-only and object-bound. The candidate is created under the retained parent, kept open, written/synchronized, claimed from its retained descriptor through admitted `/usr/bin/ln -L -- /proc/<pid>/fd/<fd> ...`, then the final device/inode binding and parent durability/binding are verified.

## Windows migration replacement

Windows selects `workspace_windows_entry.rs`, which shadows the historical base replacement and migration modules with `workspace_authority_replacement_windows.rs`.

The current source contract is:

1. retain the canonical parent ancestor chain with `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` and without delete sharing;
2. create/write/sync and retain the candidate through `PreparedFileAuthority`;
3. retain the current manifest, when present, with `GENERIC_READ | DELETE`, `FILE_SHARE_READ` only and reparse-point-open semantics, including current bytes and Win32 volume/file-index identity;
4. require retained current bytes/presence to equal the operation's observed state before victim namespace mutation;
5. rename the exact retained current handle, when present, to a random retired child using `SetFileInformationByHandle(FileRenameInfo)`, `ReplaceIfExists = FALSE`, and the retained parent as `RootDirectory`;
6. verify the retired name against the retained Win32 identity while the old handle remains live;
7. claim the canonical destination create-only from the retained prepared object and verify the final destination binding;
8. revalidate retained parent authority before success.

The unsafe Win32 ABI is isolated in the dependency-free `nxb_core_win32_authority` library target inside the existing `nxb-core` package. The `nxb` binary remains a separate crate target with `#![forbid(unsafe_code)]` and consumes only the helper library's safe identity/handle-relative rename API. No new workspace package or Cargo dependency graph entry is required.

## Reachable route boundary

The public workspace entry selects `workspace_authority_publication` for create-only publication. Windows selects `workspace_windows_entry` for its retained-handle replacement route. Older pathname mutation helpers may still compile for historical/test/base compatibility but are not selected public Linux/Windows mutation authority. `workspace_legacy_mutation_quarantine_source_contract.rs` binds that routing distinction.

## Source evidence

- `crates/nxb-core/src/prepared_file_authority.rs`
- `crates/nxb-core/src/workspace_authority_publication.rs`
- `crates/nxb-core/src/workspace_authority_entry.rs`
- `crates/nxb-core/src/workspace_authority_replacement.rs`
- `crates/nxb-core/src/workspace_authority_replacement_windows.rs`
- `crates/nxb-core/src/workspace_windows_entry.rs`
- `crates/nxb-core/src/win32_fs_authority_lib.rs`
- `crates/nxb-core/src/workspace/migration.rs`
- `crates/nxb-core/tests/target_prepared_file_authority_source_contract.rs`
- `crates/nxb-core/tests/workspace_create_publication_source_contract.rs`
- `crates/nxb-core/tests/workspace_replacement_authority_source_contract.rs`
- `crates/nxb-core/tests/workspace_windows_replacement_authority_source_contract.rs`
- `crates/nxb-core/tests/workspace_legacy_mutation_quarantine_source_contract.rs`

## Admission still pending

Source staging is not platform admission. Exact-final-head closure still requires pinned Rust 1.97.1 fmt/check/Clippy/tests/docs/dependency-policy gates, Linux namespace/adversarial publication execution, supported Windows/NTFS share/reparse/handle-relative replacement execution, exactly-one-winner/no-overwrite matrices, migration recovery matrices and same-head Linux + Windows NXB-153 admission.

No runtime PASS is claimed by this document. NXB-154 must not use NXB-153 as an admitted base until that closure succeeds.
