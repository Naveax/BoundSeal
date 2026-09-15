# NXB-153 Dependency Source Authority

## Status

This document records the dependency-source authority boundary for NXB-153 validation.

Both Linux and Windows dependency-source paths are now **source-staged** but not admitted. Neither state is a platform PASS.

The purpose of this contract is to prevent a successful exact-head validation from meaning only that the workspace source was immutable while registry dependency source directories remained mutable during the heavy Cargo gates.

## Threat model

The contract addresses avoidable local source ambiguity such as:

- fetching checksum-bound registry dependencies into a writable cache and then compiling indefinitely from that mutable extracted cache;
- temporarily modifying an extracted dependency source file during one Cargo invocation and restoring it before a later check;
- introducing an untracked file or directory into a dependency package;
- redirecting Cargo back to the live registry/cache after a dependency snapshot was prepared;
- allowing an external path dependency to escape the exact-head immutable workspace snapshot;
- accepting a vendored package whose package identity/checksum or file checksum map differs from the locked dependency graph;
- allowing a workspace-local `.cargo/config` or `.cargo/config.toml` to override the gate-time vendored source authority.

It does not claim protection against a compromised Cargo/Rust/Python toolchain, malicious kernel/administrator/hypervisor or simultaneous compromise of all trusted platform primitives.

## Canonical verifier

Canonical cross-platform verifier:

`scripts/nxb-153-registry-source.py`

The verifier requires Python 3.11+ because it parses the exact immutable `Cargo.lock` with the standard-library `tomllib` implementation.

It also contains a networkless `self-test` that stages a synthetic checksum-bound registry package, requires valid vendor bytes to pass, mutates the vendored source and requires rejection, and requires a workspace-local Cargo source configuration to be rejected.

## Lockfile source admission

Before dependency preparation, the verifier fails closed unless every package with an external source satisfies all of the following:

- source is exactly `registry+https://github.com/rust-lang/crates.io-index`;
- package name and version are non-empty strings;
- checksum is a canonical lowercase 64-hex SHA-256;
- `(name, version)` is unique for the admitted registry source.

Packages with no source remain subject to Cargo metadata locality validation. Git, alternate-registry and other external source forms are not admitted by the current NXB-153 dependency-source contract.

## Local/path dependency and config locality

After `cargo fetch --locked`, full Cargo metadata is streamed into the verifier.

For every package whose Cargo metadata `source` is null, the package manifest must be a regular non-symlink file whose absolute path remains under the immutable exact-head workspace source root.

Any non-null metadata source must still be the admitted crates.io registry source.

The immutable workspace source must not contain `.cargo/config` or `.cargo/config.toml`. Cargo's configuration hierarchy gives workspace-local configuration higher precedence than the gate CARGO_HOME, so accepting those files would allow exact-head source to redirect dependency resolution away from the controlled vendored source. NXB-153 therefore rejects that ambiguity instead of attempting to merge or out-prioritize it.

## Vendored registry verification

Both platform paths use:

`cargo vendor --locked --versioned-dirs`

against a separately fetched locked registry state. The resulting directory source is validated by `nxb-153-registry-source.py` before it is frozen.

The verifier requires:

- vendor root contains only one versioned package directory for every checksum-bearing crates.io package in `Cargo.lock`;
- package directory set equals the locked registry package set exactly;
- no vendor package directory/file is a symlink or unsupported filesystem object;
- every package contains a bounded strict-JSON `.cargo-checksum.json`;
- its `package` SHA-256 equals the corresponding Cargo.lock checksum;
- its file checksum map uses canonical relative paths and canonical lowercase SHA-256 values;
- actual regular-file set excluding `.cargo-checksum.json` equals the checksum-map file set exactly;
- actual directory namespace equals the directories implied by the checksum-map paths;
- every actual vendored file SHA-256 equals the corresponding checksum-map value;
- total vendored file count and byte count remain inside the explicit validation envelope.

The verifier also derives a deterministic diagnostic `vendor_manifest_sha256` from package identity/checksum plus sorted vendored path/digest records. This digest is diagnostic at present; the canonical admission authority remains exact head + Cargo.lock + the verified immutable vendor snapshot.

Cargo's own directory-source checksum metadata is treated as an integrity input, not a standalone security boundary. The NXB-153 workflow combines it with exact locked package checksums, private preparation context, explicit namespace/file verification and immutable gate-time storage.

## Linux dependency-source staging

Canonical source runner:

`scripts/nxb-153-linux-immutable-source.sh`

Inside the private user/mount namespace it maintains separate runtime mounts for:

- `target` — build outputs;
- `.nxb-153-tmp` — temporary files;
- `.nxb-153-fetch-home` — online locked dependency acquisition;
- `.nxb-153-vendor` — dependency source snapshot;
- `.nxb-153-cargo-home` — gate-time Cargo state;
- `.nxb-153-config` — source-replacement configuration authority.

The exact-head tree is required not to contain any of these reserved runtime roots.

### Linux preparation sequence

The staged Linux sequence is:

1. construct and exact-set-verify the exact-head workspace snapshot;
2. mount all runtime roots as namespace-private writable tmpfs instances;
3. remount the workspace source itself read-only;
4. validate Cargo.lock external source/checksum policy;
5. run `cargo fetch --locked` with `.nxb-153-fetch-home` as CARGO_HOME;
6. run full locked Cargo metadata and reject workspace Cargo config, external local/path packages and unsupported registry sources;
7. run `cargo vendor --locked --versioned-dirs` from the fetched state with Cargo networking disabled for the vendor step;
8. verify the complete vendor package/file/directory/checksum namespace;
9. remount the vendor tmpfs read-only and require a write probe to fail;
10. create a Cargo source-replacement config pointing crates.io to the vendored directory;
11. remount the config authority tmpfs read-only;
12. bind that exact config file read-only onto the otherwise writable gate CARGO_HOME `config.toml`;
13. require config mutation to fail while unrelated gate CARGO_HOME writes still succeed.

### Linux heavy gate sequence

The expensive Cargo gates run with:

- `CARGO_HOME=.nxb-153-cargo-home`;
- the read-only source-replacement config bound at `CARGO_HOME/config.toml`;
- crates.io replaced by the read-only `.nxb-153-vendor` directory source;
- Cargo offline mode enabled for Cargo metadata/fmt/check/Clippy/test invocations;
- build/temp state directed only to the controlled writable runtime mounts.

This means the workspace source and registry dependency source are separate immutable snapshots during fmt/check/Clippy/test execution, while Cargo is still allowed writable non-source state where required.

The RustSec/cargo-deny executable authority remains governed by `NXB-153-VALIDATION-TOOL-OBJECT-INTEGRITY.md`. Advisory-source network behavior is separate from Cargo dependency-source resolution.

### Linux final checks

Before the Linux helper emits gate success it rechecks:

- exact Cargo.lock SHA-256;
- source-replacement config SHA-256;
- complete vendored package/file/directory/checksum authority;
- exact workspace source file/directory namespace excluding only controlled runtime mounts.

The child mount namespace then exits, so the private dependency/source/cache mounts are not persisted as canonical evidence artifacts.

## Windows dependency-source staging

Canonical dependency runner:

`scripts/nxb-153-windows-dependency-source.ps1`

Canonical parent source runner:

`scripts/nxb-153-windows-immutable-source.ps1`

The parent first constructs and pins the exact-head workspace source snapshot. The dependency helper itself is one of those exact-head tracked files, so it is Git-object-verified, held by a read-only source stream and protected by the parent source ACL before it is invoked.

The parent no longer executes a second direct Cargo gate block. It delegates the complete heavy gate sequence once to the dependency runner while the parent workspace file/directory handles remain live, then rechecks workspace and security-tool continuity after the dependency helper returns.

### Windows preparation and pinning sequence

The source-staged Windows dependency path:

1. runs the registry verifier networkless self-test;
2. validates the exact snapshot Cargo.lock source/checksum contract;
3. creates separate `fetch`, `vendor` and `gate` roots beneath the inheritance-protected runtime Cargo-home directory;
4. immediately pins the dependency runtime root plus fetch/vendor/gate directories with native directory handles that omit delete sharing;
5. runs `cargo fetch --locked` in the fetch CARGO_HOME;
6. validates full Cargo metadata for local/path locality, supported registry source and absence of workspace-local Cargo config;
7. disables Cargo networking and runs `cargo vendor --locked --versioned-dirs` into the dedicated vendor root;
8. validates the complete vendor package/file/directory/checksum authority;
9. stores the original vendor ACL and applies an inherited current-identity write/delete deny ACL;
10. requires file and subdirectory creation to fail in the vendor root and every vendored package subdirectory;
11. pins every vendor directory with native handles omitting delete sharing;
12. pins every vendored file with read-only `FileStream` / `FileShare.Read`, withholding write/delete sharing;
13. re-runs complete vendor verification after the ACL/handle transition;
14. creates the gate CARGO_HOME `config.toml` create-new, flushes it, then reopens it read-only with write/delete sharing withheld;
15. requires config mutation to fail while an unrelated gate CARGO_HOME probe remains writable.

### Windows heavy gate sequence

With the parent exact-head source handles still live and the dependency handles/ACL active, the helper runs the required metadata/fmt/check/Clippy/unit/focused/workspace gate set from the exact snapshot. CARGO_HOME points to the gate home and Cargo dependency resolution is forced offline through the pinned source-replacement config and checksum-verified vendor tree.

RustSec/cargo-deny then run under the same pinned source/tool context. Advisory/network behavior for those security tools remains distinct from Cargo dependency-source resolution.

### Windows finalization

Before success, the helper requires:

- gate Cargo config SHA-256 unchanged on the same pinned stream;
- complete vendor package/file/directory/checksum authority still valid;
- environment variables restored to their prior values;
- pinned config/vendor file/vendor directory/runtime directory handles released;
- original vendor ACL restored;
- fetch/vendor/gate runtime trees removed.

Any cleanup failure blocks success. The parent then rechecks exact-head workspace Cargo.lock, every pinned tracked Git blob, source pathname/reparse metadata, exact source namespace and canonical security-tool hashes before its own cleanup/success boundary.

## Runtime acceptance still required

The dependency paths still require exact-current-head platform execution.

### Linux

Supported Linux execution must prove:

- `cargo fetch --locked` succeeds for the final lockfile;
- offline `cargo vendor --locked --versioned-dirs` succeeds from the fetched private cache;
- the registry verifier accepts the real vendored dependency set;
- vendor and config read-only remount/write probes behave as staged;
- the read-only config file bind works while gate CARGO_HOME remains otherwise writable;
- all heavy Cargo gates succeed offline against the vendor source;
- RustSec/cargo-deny remain functional under the gate-time Cargo configuration;
- final vendor/config/workspace rechecks succeed.

### Windows

Supported Windows/NTFS execution must prove:

- Python 3.11+ verifier execution and self-test;
- locked fetch/vendor behavior with the final Cargo.lock;
- the actual repository metadata passes local/path and Cargo-config admission;
- vendor ACL deny semantics prevent file/directory injection and in-place write/delete;
- vendor file/directory handles coexist with Cargo/rustc reads while preventing rename/delete/replacement;
- pinned gate `config.toml` is readable by Cargo while write/delete is denied and gate CARGO_HOME remains otherwise writable;
- heavy Cargo gates operate offline through the vendored source;
- security tools remain functional under the staged configuration;
- final vendor/config/workspace checks and cleanup succeed.

No Linux or Windows dependency-source runtime PASS is claimed merely because the source implementation exists.

## Admission boundary

Dependency-source authority is one layer of NXB-153 admission, not a replacement for the other gates.

The exact final head still requires real Linux and Windows Rust 1.97.1 execution, immutable workspace source, dependency-source authority, exact-head security-tool authority, validation serialization, create-only evidence publication, object-anchored evidence review, same-head dual-platform closure and final blocker review.

PR #89 remains draft/not admitted. Issues #90–#98 remain open. NXB-154 must not use NXB-153 as an admitted implementation base before all of those conditions are satisfied.
