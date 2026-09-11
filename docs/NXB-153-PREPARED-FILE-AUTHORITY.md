# NXB-153 Prepared File Authority

Status: **partial source fix staged / Windows migration replacement + runtime-platform proof pending / not admitted**.

This note records the source boundary staged for blocker #111. It does not claim canonical runtime proof and it does not close #111.

## Create-only publication

Target create, disable-receipt publication and guided-activation artifact/profile publication resolve through the target workspace entry facade and the prepared-authority publication writer.

The generic `workspace_impl::create_document` production path now uses the same retained `PreparedFileAuthority` instead of a write/drop/reopen temporary pathname flow. The old injectable pathname-cleanup helper remains `#[cfg(test)]` only so the historical finalization/error tests remain available without keeping that behavior in production.

A `PreparedFileAuthority` retains the opened prepared file from successful creation, private-permission setup, write and `sync_all` through namespace claim and post-claim destination identity validation.

### Linux create-only claim

The reusable temporary pathname is not the publication source authority. The retained descriptor is exposed only to the trusted absolute `/usr/bin/ln` process through `/proc/<parent-pid>/fd/<fd>`, using logical (`-L`) source resolution. The tool is admitted only when `/usr/bin/ln` is a root-owned regular non-symlink file that is not group/other writable. The child process receives an empty environment.

After the hard-link claim, destination device/inode must match the retained prepared descriptor before success. A regression test replaces the prepared temporary pathname with a same-permission attacker file before claim and requires the destination to contain the retained original inode/bytes.

### Windows create-only claim

The prepared file is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and `FILE_SHARE_READ` only. Write and delete/rename sharing are deliberately withheld while the prepared authority lives. The named binding is revalidated before hard-link claim and the destination is validated after claim.

### Create-only cleanup boundary

Production create-only publication deliberately does not pathname-delete the prepared temporary after claim or failure. A hostile same-user namespace actor can replace a pathname after object admission; pathname deletion would therefore reintroduce blocker #112. Exact create-document transients are quarantined by the existing temporary-shape parser and cannot become target record authority.

## Linux migration replacement source slice

Linux migration manifest replacement now routes through `workspace_authority_replacement.rs` rather than `workspace_impl::replace_document`.

The source contract is:

1. open and retain the replacement parent directory with `O_DIRECTORY | O_NOFOLLOW`;
2. perform child opens/creates beneath the retained directory through `/proc/<pid>/fd/<parent-fd>/<child>`;
3. retain the current manifest object, if present, and retain the newly prepared replacement object from create/write/`sync_all` through namespace mutation;
4. move the current canonical name to a random private retired name using the admitted absolute `/usr/bin/mv -n -T -- ...` tool against the retained parent namespace;
5. validate that the retired name still references the exact previously retained device/inode;
6. claim the now-empty canonical name from the exact prepared file descriptor using the admitted `/usr/bin/ln -L -- ...` path;
7. validate canonical destination device/inode against the retained prepared object;
8. synchronize the retained parent and revalidate the logical parent pathname binding before success.

Both system tools must be root-owned regular non-symlink files and must not be group/other writable. Child environments are cleared.

No production replacement path in this module calls `remove_file`, `remove_regular`, a recursive delete, or plain `fs::rename`. Previous manifests and prepared transport files remain private residue rather than being pathname-deleted.

Regression coverage includes exact old/new inode binding, same-permission final-component substitution, parent-directory replacement, and a missing-destination recovery case. A namespace substitution may make the operation fail after safely quarantining the substituted name; it must not cause an unrelated file to be deleted or published as the replacement.

## Still open in #111

Windows migration replacement still routes to the historical `workspace_impl::replace_document` implementation. That implementation drops prepared-file authority before replacement and contains pathname-based failure cleanup. It is **not** claimed fixed.

A Windows closure must keep the prepared source object and current destination/parent authority across the actual NT namespace mutation. Reopening or deleting a pathname after admission is insufficient under the same-user race model. `#![forbid(unsafe_code)]` remains in force for the `nxb` binary; this staging milestone does not weaken it merely to reach an NT handle API.

## Evidence staged in source

- `crates/nxb-core/src/prepared_file_authority.rs`
- `crates/nxb-core/src/workspace_authority_publication.rs`
- `crates/nxb-core/src/workspace_authority_entry.rs`
- `crates/nxb-core/src/workspace_authority_replacement.rs`
- `crates/nxb-core/src/workspace/mod.rs`
- `crates/nxb-core/src/workspace/migration.rs`
- `crates/nxb-core/tests/target_prepared_file_authority_source_contract.rs`
- `crates/nxb-core/tests/workspace_create_publication_source_contract.rs`
- `crates/nxb-core/tests/workspace_replacement_authority_source_contract.rs`

Required closure remains canonical Rust 1.97.1 gates plus supported Linux and Windows/NTFS race/lifetime injection on one exact final head. No runtime PASS is claimed by this document.
