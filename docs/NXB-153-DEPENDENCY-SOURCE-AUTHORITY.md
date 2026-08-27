# NXB-153 Dependency Source Authority

## Status

This document records the dependency-source authority boundary for NXB-153 validation.

The Linux dependency-source path is **source-staged** but not admitted. The equivalent Windows dependency freeze is still an implementation blocker. Neither state is a platform PASS.

The purpose of this contract is to prevent a successful exact-head validation from meaning only that the workspace source was immutable while registry dependency source directories remained mutable during the heavy Cargo gates.

## Threat model

The contract addresses avoidable local source ambiguity such as:

- fetching checksum-bound registry dependencies into a writable cache and then compiling indefinitely from that mutable extracted cache;
- temporarily modifying an extracted dependency source file during one Cargo invocation and restoring it before a later check;
- introducing an untracked file into a dependency package directory;
- redirecting Cargo back to the live registry/cache after a dependency snapshot was prepared;
- allowing an external path dependency to escape the exact-head immutable workspace snapshot;
- accepting a vendored package whose package identity/checksum or file checksum map differs from the locked dependency graph.

It does not claim protection against a compromised Cargo/Rust toolchain, malicious kernel/administrator/hypervisor or simultaneous compromise of all trusted platform primitives.

## Lockfile source admission

Canonical verifier:

`scripts/nxb-153-registry-source.py`

Before dependency preparation, the verifier parses the exact immutable `Cargo.lock` with Python `tomllib` and fails closed unless every package with an external source satisfies all of the following:

- source is exactly `registry+https://github.com/rust-lang/crates.io-index`;
- package name and version are non-empty strings;
- checksum is a canonical lowercase 64-hex SHA-256;
- `(name, version)` is unique for the admitted registry source.

Packages with no source remain subject to Cargo metadata locality validation. Git, alternate-registry and other external source forms are not admitted by the current NXB-153 dependency-source contract.

## Local/path dependency locality

After `cargo fetch --locked`, full Cargo metadata is streamed into the verifier.

For every package whose Cargo metadata `source` is null, the package manifest must be a regular non-symlink file whose absolute path remains under the immutable exact-head workspace source root.

This prevents an otherwise locked validation from silently consuming a local/path package outside the exact-head snapshot.

Any non-null metadata source must still be the admitted crates.io registry source.

## Vendored registry verification

The Linux runner invokes:

`cargo vendor --locked --versioned-dirs`

against the fetched locked registry state inside the private validation mount namespace. The resulting directory source is then validated by `nxb-153-registry-source.py` before it is frozen.

The verifier requires:

- vendor root contains only one versioned package directory for every checksum-bearing crates.io package in `Cargo.lock`;
- package directory set equals the locked registry package set exactly;
- no vendor package directory/file is a symlink or unsupported filesystem object;
- every package contains a bounded strict-JSON `.cargo-checksum.json`;
- its `package` SHA-256 equals the corresponding Cargo.lock checksum;
- its file checksum map uses canonical relative paths and canonical lowercase SHA-256 values;
- actual regular-file set excluding `.cargo-checksum.json` equals the checksum-map file set exactly;
- every actual vendored file SHA-256 equals the corresponding checksum-map value;
- total vendored file count and byte count remain inside the explicit validation envelope.

The verifier also derives a deterministic diagnostic `vendor_manifest_sha256` from package identity/checksum plus sorted vendored path/digest records. This digest is diagnostic at present; the canonical admission authority remains exact head + Cargo.lock + the verified read-only vendor snapshot.

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

### Preparation sequence

The staged Linux sequence is:

1. construct and exact-set-verify the exact-head workspace snapshot;
2. mount all runtime roots as namespace-private writable tmpfs instances;
3. remount the workspace source itself read-only;
4. validate Cargo.lock external source/checksum policy;
5. run `cargo fetch --locked` with `.nxb-153-fetch-home` as CARGO_HOME;
6. run full locked Cargo metadata and reject any local/path package outside the immutable source root;
7. run `cargo vendor --locked --versioned-dirs` from the fetched state with Cargo networking disabled for the vendor step;
8. verify the complete vendor package/file/checksum namespace;
9. remount the vendor tmpfs read-only and require a write probe to fail;
10. create a Cargo source-replacement config pointing crates.io to the vendored directory;
11. remount the config authority tmpfs read-only;
12. bind that exact config file read-only onto the otherwise writable gate CARGO_HOME `config.toml`;
13. require config mutation to fail while unrelated gate CARGO_HOME writes still succeed.

### Heavy gate sequence

The expensive Cargo gates run with:

- `CARGO_HOME=.nxb-153-cargo-home`;
- the read-only source-replacement config bound at `CARGO_HOME/config.toml`;
- crates.io replaced by the read-only `.nxb-153-vendor` directory source;
- Cargo offline mode enabled for the Cargo gate invocations;
- build/temp state directed only to the controlled writable runtime mounts.

This means the workspace source and registry dependency source are separate immutable snapshots during fmt/check/Clippy/test execution, while Cargo is still allowed writable non-source state where required.

The RustSec/cargo-deny executable authority remains governed by `NXB-153-VALIDATION-TOOL-OBJECT-INTEGRITY.md`. Advisory-source network behavior is separate from Cargo dependency-source resolution.

### Final checks

Before the Linux helper emits gate success it rechecks:

- exact Cargo.lock SHA-256;
- source-replacement config SHA-256;
- complete vendored package/file/checksum authority;
- exact workspace source file/directory namespace excluding only controlled runtime mounts.

The child mount namespace then exits, so the private dependency/source/cache mounts are not persisted as canonical evidence artifacts.

## Linux primitive acceptance still required

The new dependency path still requires exact-current-head runtime execution. In particular the supported Linux host must prove:

- `cargo fetch --locked` succeeds for the final lockfile;
- offline `cargo vendor --locked --versioned-dirs` succeeds from the fetched private cache;
- the registry verifier accepts the real vendored dependency set;
- vendor and config read-only remount/write probes behave as staged;
- the read-only config file bind works while gate CARGO_HOME remains otherwise writable;
- all heavy Cargo gates succeed offline against the vendor source;
- RustSec/cargo-deny remain functional under the gate-time Cargo configuration;
- final vendor/config/workspace rechecks succeed.

Until those execute on the exact final head, the Linux dependency authority is source-staged only.

## Windows blocker

Windows currently has exact-head immutable workspace-source staging, pinned security tools and pinned Cargo.lock/tooling receipt authority, but it does **not yet** have an equivalent frozen dependency-source lifecycle.

The Windows implementation must, before admission:

1. use a distinct fetch CARGO_HOME;
2. enforce the same Cargo.lock external-source/checksum policy;
3. reject path dependencies outside the pinned exact-head snapshot;
4. build a versioned vendor directory from the locked fetched dependency state;
5. validate that vendor tree with the same package/checksum/file authority helper;
6. protect vendor directories with write/delete-deny ACLs;
7. pin vendor directories with native handles omitting delete sharing;
8. pin vendored files with read-only `FileStream` objects withholding write/delete sharing;
9. create a gate CARGO_HOME whose `config.toml` is itself pinned read-only while the rest of the gate home remains writable;
10. run the heavy Cargo gates offline through that pinned vendor source;
11. revalidate vendor namespace/bytes/config before releasing handles and cleanup.

No Windows dependency-source PASS or source-closed claim is made until that implementation exists and is exercised on supported Windows/NTFS.

## Admission boundary

Dependency-source authority is one layer of NXB-153 admission, not a replacement for the other gates.

The exact final head still requires real Linux and Windows Rust 1.97.1 execution, immutable workspace source, dependency-source authority, exact-head security-tool authority, validation serialization, create-only evidence publication, object-anchored evidence review, same-head dual-platform closure and final blocker review.

PR #89 remains draft/not admitted. Issues #90–#98 remain open. NXB-154 must not use NXB-153 as an admitted implementation base before all of those conditions are satisfied.
