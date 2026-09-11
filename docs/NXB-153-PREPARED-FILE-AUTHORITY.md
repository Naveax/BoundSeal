# NXB-153 Prepared File Authority

Status: **partial source fix staged / runtime-platform proof pending / not admitted**.

This note records the source boundary staged for blocker #111. It does not claim canonical runtime proof and it does not close #111.

## Closed source slice: target create-only publication

Target create, disable-receipt publication and guided-activation artifact/profile publication now resolve `workspace::create_document` through the target workspace entry facade and the prepared-authority publication writer.

A `PreparedFileAuthority` retains the opened prepared file from successful creation, private-permission setup, write and `sync_all` through namespace claim and post-claim destination identity validation.

### Linux

The reusable temporary pathname is not the publication source authority. The retained descriptor is exposed only to the trusted absolute `/usr/bin/ln` process through `/proc/<parent-pid>/fd/<fd>`, using logical (`-L`) source resolution. The tool is admitted only when `/usr/bin/ln` is a root-owned regular non-symlink file that is not group/other writable. The child process receives an empty environment.

After the hard-link claim, destination device/inode must match the retained prepared descriptor before success. A regression test replaces the prepared temporary pathname with a same-permission attacker file before claim and requires the destination to contain the retained original inode/bytes.

### Windows

The prepared file is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and `FILE_SHARE_READ` only. Write and delete/rename sharing are deliberately withheld while the prepared authority lives. The named binding is revalidated before hard-link claim and the destination is validated after claim.

### Cleanup boundary

The prepared temporary pathname is deliberately not deleted by this source slice. A hostile same-user namespace actor can replace a pathname after object admission; pathname deletion would therefore reintroduce blocker #112. Exact create-document transients are already quarantined by #106 and cannot become target record authority. Checked-object cleanup remains owned by #112.

## Still open in #111

The generic `workspace_impl::create_document` implementation and migration `replace_document` implementation still contain their historical pathname-based prepared-file flow. In particular, migration replacement still drops the prepared handle before pathname replacement. Those paths are not claimed fixed by this staging milestone.

The migration replacement design must also compose with #112 rather than solving prepared-source binding by introducing an unsafe pathname delete of the current manifest.

## Evidence staged in source

- `crates/nxb-core/src/prepared_file_authority.rs`
- `crates/nxb-core/src/workspace_authority_publication.rs`
- `crates/nxb-core/src/workspace_authority_entry.rs`
- `crates/nxb-core/tests/target_prepared_file_authority_source_contract.rs`

Required closure remains canonical Rust 1.97.1 gates plus supported Linux and Windows/NTFS race/lifetime injection on one exact final head.
