# NXB-153 Prepared File Authority

Status: **Linux + Windows source fixes staged / lockfile refresh + runtime-platform proof pending / not admitted**.

This note records the source boundary staged for blocker #111. It does not claim canonical runtime proof and it does not close #111.

## Create-only publication

Target create, disable-receipt publication and guided-activation artifact/profile publication resolve through the target workspace entry facade and the prepared-authority publication writer.

The generic `workspace_impl::create_document` production path uses retained `PreparedFileAuthority` instead of a write/drop/reopen temporary pathname flow. The historical injectable pathname-cleanup helper remains `#[cfg(test)]` only.

A `PreparedFileAuthority` retains the opened prepared file from successful creation, private-permission setup, write and `sync_all` through namespace claim and post-claim destination validation.

### Linux create-only claim

The reusable temporary pathname is not the publication source authority. The retained descriptor is exposed only to the admitted absolute `/usr/bin/ln` process through `/proc/<parent-pid>/fd/<fd>` with logical (`-L`) source resolution. The tool must be a root-owned regular non-symlink file and not group/other writable. The child environment is cleared.

After claim, destination device/inode must match the retained prepared descriptor. The regression suite replaces the prepared pathname with a same-permission attacker file and requires the published destination to remain bound to the retained original object.

### Windows create-only claim

The prepared file is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and `FILE_SHARE_READ` only. Write and delete/rename sharing are withheld while the authority lives. The named binding is revalidated before hard-link claim and the destination binding after claim.

### Create-only cleanup boundary

Production create-only publication deliberately does not pathname-delete its private transport residue. Exact recognized create-document transient names remain quarantined from target/receipt enumeration. Physical cleanup is not allowed to regain authority by merely reopening a reusable pathname.

## Linux migration replacement

Linux migration replacement routes through `workspace_authority_replacement.rs`.

The retained parent directory is opened with `O_DIRECTORY | O_NOFOLLOW`; child opens and creates are rooted through `/proc/<pid>/fd/<parent-fd>`. The previous manifest, if present, and the prepared replacement remain open across namespace mutation.

The previous canonical name is moved to a random private retired name using admitted `/usr/bin/mv -n -T -- ...` under the retained parent namespace. The retired name must resolve to the exact retained device/inode. The canonical destination is then claimed from the exact prepared file descriptor through admitted `/usr/bin/ln -L -- ...`, and the final destination must match the retained prepared device/inode. The parent is synchronized and its logical binding revalidated before success.

The production Linux replacement module contains no pathname deletion and no plain `fs::rename` fallback.

## Windows migration replacement

Windows migration replacement now routes through `workspace_windows_entry.rs` to `workspace_authority_replacement_windows.rs`; it no longer uses the historical Windows `workspace_impl::replace_document` production route.

The source contract is:

1. canonicalize the replacement parent and retain its ancestor handle chain with `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` while withholding delete sharing;
2. open the current manifest, when present, with `GENERIC_READ | DELETE`, `FILE_SHARE_READ` only and `FILE_FLAG_OPEN_REPARSE_POINT`;
3. read and retain the current bytes plus Win32 file identity while the handle prevents write/delete/rename substitution;
4. create/write/sync the candidate through the existing `PreparedFileAuthority`;
5. require the retained current bytes to match the operation's observed state before namespace mutation;
6. rename the exact retained current handle, not a reopened pathname, to a random retired child name using `SetFileInformationByHandle(FileRenameInfo)` with `ReplaceIfExists = FALSE` and the retained parent handle as `RootDirectory`;
7. reopen the retired name only for post-mutation verification with share semantics compatible with the still-retained DELETE-capable handle, and require its Win32 volume/file-index identity to match;
8. create-only claim the canonical destination from the retained prepared object and validate the final destination binding;
9. revalidate the retained parent logical binding before success.

The unsafe Win32 ABI is isolated in the small `nxb-win32-fs-authority` crate. The `nxb` binary keeps `#![forbid(unsafe_code)]`; `nxb-core` calls only the safe wrapper API. The platform crate wraps only `GetFileInformationByHandle` and `SetFileInformationByHandle(FileRenameInfo)` needed for exact identity and handle-relative no-replace rename.

Regression coverage includes exact identity preservation, no-replace quarantine collision, retained-source rename denial, expected-current mismatch before mutation, same-permission final-component swap denial, ancestor/root replacement denial and missing-destination create-only publication.

## Reachable cleanup boundary

The current public workspace entry shadows the older base create-authority writer with `workspace_authority_publication`. On Windows, the selected workspace implementation is `workspace_windows_entry`, which shadows the historical base replacement and migration modules with the exact-handle replacement route.

The older pathname mutation helpers remain compiled as quarantined legacy implementation detail, but are not the selected public target/workspace mutation authority. `workspace_legacy_mutation_quarantine_source_contract.rs` locks that routing distinction.

## Evidence staged in source

- `crates/nxb-core/src/prepared_file_authority.rs`
- `crates/nxb-core/src/workspace_authority_publication.rs`
- `crates/nxb-core/src/workspace_authority_entry.rs`
- `crates/nxb-core/src/workspace_authority_replacement.rs`
- `crates/nxb-core/src/workspace_authority_replacement_windows.rs`
- `crates/nxb-core/src/workspace_windows_entry.rs`
- `crates/nxb-win32-fs-authority/src/lib.rs`
- `crates/nxb-core/tests/target_prepared_file_authority_source_contract.rs`
- `crates/nxb-core/tests/workspace_create_publication_source_contract.rs`
- `crates/nxb-core/tests/workspace_replacement_authority_source_contract.rs`
- `crates/nxb-core/tests/workspace_windows_replacement_authority_source_contract.rs`
- `crates/nxb-core/tests/workspace_legacy_mutation_quarantine_source_contract.rs`

## Still pending

`Cargo.lock` has not yet been regenerated for the new workspace path package. The already-locked registry dependency `windows-sys 0.61.2` is reused, but the path-package records still need a canonical Cargo-generated lock refresh before admission.

Required closure remains pinned Rust 1.97.1 build/check/clippy/test/doc/dependency-policy gates plus supported Linux and Windows/NTFS race/lifetime injection on one exact final head. No runtime PASS is claimed by this document.
