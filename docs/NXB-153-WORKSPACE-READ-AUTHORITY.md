# NXB-153 Workspace Document Read Authority

## Status

This document records the source-staged fix for NXB-153 blocker #107.

The source contract is staged. It does **not** claim exact-final-head Rust 1.97.1 validation, Linux runtime admission, supported Windows/NTFS runtime admission, or final NXB-153 closure.

## Finding

The previous `workspace::read_document()` performed a pathname check sequence and then reopened the pathname:

1. reject pathname indirections;
2. inspect pathname metadata/type/size;
3. validate pathname permissions;
4. `File::open(path)` and consume bytes.

That was a check-then-open authority gap. A concurrent local namespace mutation could cause the file object opened for reading to differ from the file object whose pathname/type/permissions had been admitted.

Because `workspace::read_document()` is the central bounded reader for workspace manifests, target records and continuity artifacts, downstream JSON/schema/hash checks could not repair that missing file-object authority binding.

## Current source authority

- workspace delegation: `crates/nxb-core/src/workspace/mod.rs` blob `f711e6a4ab1128ae17822723e93691a8af189e2a`;
- pinned read implementation: `crates/nxb-core/src/workspace/read_authority.rs` blob `51437fd5d13d3ba04e49fff02c44ea0644d04246`;
- Windows pinned-open primitive: `crates/nxb-core/src/workspace/windows.rs` blob `06f30b30c96ae12469a41c89e5912a8cd177a89e`;
- platform-independent source regression: `crates/nxb-core/tests/workspace_read_authority_source_contract.rs` blob `fdfef38a0a9eec7e5896efe423d5bd2972a5c2b3`.

Relevant source commits:

- `eac3320e9828b4d3e713ed35e7ed67781ea3baef` — add the Windows `OPEN_REPARSE_POINT` / read-only-share pinned-open primitive;
- `bb046f49d5cd311830c554d0b0605e242480b19f` — restore the pre-existing ACL broad-principal removal/final inheritance-protection sequence after the large-file edit, with no #107 weakening retained;
- `145250403f1713c951eae0802aec5d4b6219d376` / `87abc944ee216737d703afd06c81f46aaf321cf9` — add the platform read-authority module and keep cfg-specific imports clean;
- `960d7d97d84d720431c57b7e20984ceabbed6637` — make the central workspace reader delegate to the pinned authority module;
- `e1a2e5b9459db4b42104908e3480112cc3b40224` / `fd372b930d1c95fe21ed8d5963ec11a0c17e6f7e` — add and correct the source-order/non-mutation regression contract;
- `04eaf88bb7a469c98d0b4c64072500ecc668cfd8` — add supported-Windows pinned-handle write/delete/rename lifetime coverage.

## Common read contract

The central `workspace::read_document()` no longer performs its own pathname metadata check followed by a second `File::open(path)`. It delegates to one read-authority implementation.

The authority implementation:

1. performs the existing path-indirection precheck;
2. opens/pins the platform file authority;
3. obtains type and initial length from `File::metadata()` on that opened handle;
4. rejects zero-length, non-file and greater-than-64-KiB records;
5. performs platform-specific authority validation while the handle remains alive;
6. consumes bytes only through `(&mut file).take(MAX_DOCUMENT_BYTES + 1)`;
7. re-reads metadata from the same handle;
8. rejects size drift and requires the number of consumed bytes to match the admitted initial size;
9. performs platform-specific post-read stability/path checks before returning bytes.

The read path has no delete, rename, overwrite, replacement or repair authority.

## Linux authority

On supported Linux the open uses `OpenOptionsExt::custom_flags(O_NOFOLLOW)` with Linux `O_NOFOLLOW = 0o400000`.

After open, authority is derived from the opened handle:

- regular-file and 64-KiB size envelope from opened-handle metadata;
- private mode directly from opened-handle permissions (`0600` required and group/other access rejected);
- the named path is rechecked for indirections and regular-file type;
- the opened object and currently named object must have identical `dev()` and `ino()`;
- after reading, same-handle `dev`/`ino` plus `mtime`/`mtime_nsec` and `ctime`/`ctime_nsec` must remain unchanged;
- named-path identity is checked again before returning bytes.

Unit coverage stages two deterministic Linux primitives:

- final symlink open is rejected by the no-follow open itself;
- replacing the pathname after a handle is opened produces a device/inode identity mismatch and is rejected.

Other Unix targets intentionally fail closed rather than borrowing a Linux numeric open flag without a supported-platform contract.

## Windows authority

The Windows helper uses stable Rust 1.97 `OpenOptionsExt` APIs and opens the record with:

- `FILE_FLAG_OPEN_REPARSE_POINT` (`0x00200000`);
- `FILE_SHARE_READ` only.

The share mode deliberately omits write and delete sharing, which denies new write opens and delete/rename operations while the read authority is held. The handle metadata must describe a regular non-reparse file.

While that handle remains alive, the named path is rechecked for path indirection/reparse/type and the existing private ACL contract is validated. Bytes are then read from the pinned handle and path/ACL/type checks are repeated before return.

Rust 1.97 exposes `file_index`/volume identity only as unstable `windows_by_handle` APIs, so the source fix does not enable nightly features merely to obtain those fields. The supported-Windows runtime gate must therefore prove the share/reparse/pathname lifetime contract against actual NTFS semantics.

A Windows-only unit test is source-staged to prove that, while the pinned read handle is alive, new write-open, delete and rename attempts fail; after the handle is dropped, rename/cleanup succeeds.

## Regression contract

`workspace_read_authority_source_contract.rs` runs under normal workspace tests and requires:

- `workspace::read_document()` to delegate rather than reintroduce `File::open(path)` / `fs::read(path)` / pathname metadata authority;
- Linux no-follow, same-handle read, dev/inode identity and post-read metadata stability markers;
- authority validation to occur before the bounded read and stability validation after it;
- production read-authority code to contain no pathname reopen or mutation primitive;
- Windows `OPEN_REPARSE_POINT`, read-only share mode and non-reparse opened-handle checks;
- the Windows path to retain private-permission validation while the pin is alive.

The source regression is structural evidence only. It is not a substitute for platform execution.

## Remaining admission proof

#107 remains open until exact-final-head validation proves at least:

- canonical Rust 1.97.1 `cargo fmt --check`, full workspace tests, Clippy/security and NXB-153 H1/H2 gates including the new unit/source tests;
- Linux final-symlink and post-open pathname replacement rejection on the admitted filesystem/runtime;
- Linux bounded-read behavior under file truncation/growth/in-place mutation attempts;
- supported Windows/NTFS `OPEN_REPARSE_POINT` behavior;
- supported Windows pinned handle write/delete/rename sharing rejection and release-after-drop behavior;
- Windows pathname/reparse substitution attempts while the handle is pinned;
- existing Windows ACL/private-file authority remains unchanged and passes its tests;
- existing target/workspace canonical read suites remain green;
- complete same-head Linux + Windows schema-v2 closure and final blocker review.

No Linux or Windows runtime PASS is claimed by this source staging. PR #89 remains draft/not admitted and NXB-154 must not use this branch as an admitted implementation base until final NXB-153 same-head closure succeeds.
