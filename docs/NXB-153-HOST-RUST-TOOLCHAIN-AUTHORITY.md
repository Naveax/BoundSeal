# NXB-153 Host Rust Toolchain Authority

## Status

This document defines the remaining source/admission boundary for the host Rust toolchain used by NXB-153 validation.

The current platform evidence schema deliberately records:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

That value is accurate. NXB-153 currently enforces Rust 1.97.1 selection and strongly constrains workspace source, registry dependency source, ambient compiler/Cargo/Python variables and cargo-audit/cargo-deny object authority, but it does **not** yet prove immutable object identity for the complete host Rust toolchain tree throughout the heavy validation gates.

No current source or narrow primitive is allowed to silently upgrade this boundary to `passed`.

## Why version output is insufficient

A successful command such as:

`rustup run 1.97.1 rustc --version`

proves only that one invocation reported the expected version token. It does not establish that later gate invocations use the same executable bytes, the same Cargo/rustfmt/Clippy component bytes, or the same sysroot/library tree.

Relevant authority objects include at least:

- the `rustup` executable/proxy used for resolution when rustup remains in the execution path;
- the selected toolchain root;
- `cargo`;
- `rustc`;
- `rustfmt` / `cargo-fmt`;
- `cargo-clippy` / `clippy-driver`;
- supporting DLL/shared-library files shipped in the toolchain;
- `lib/rustlib` target libraries and metadata;
- other regular files under the selected toolchain root that a canonical Rust component may load during the validation lifetime.

A validator that hashes only `rustc` before and after an hours-long run can still consume transiently substituted Cargo, Clippy, rustfmt or sysroot bytes in the middle.

## Threat model

This boundary addresses avoidable local object/path races inside the supported host workflow. It does not attempt to defend against a malicious kernel, hostile administrator with equivalent privilege, compromised hypervisor or simultaneous replacement of the trusted operating-system primitives used to establish the authority boundary.

Source must nevertheless fail closed against ordinary writable-path substitution or mutation that can change toolchain bytes during validation without changing the final version string.

## Canonical toolchain selection

The required logical Rust toolchain remains:

`1.97.1`

Toolchain authority must be resolved before the heavy gates and bound to one canonical toolchain root.

A future admitted implementation must not derive authority from PATH search alone after validation starts.

The resolver must:

1. require the expected Rust version selection;
2. resolve the toolchain component paths through the supported rustup interface before immutable execution begins;
3. derive one canonical toolchain root from those component paths;
4. require all admitted Rust component files to reside under that one root;
5. reject path traversal, symlink/reparse redirection or component escape outside the admitted root;
6. bind the resolved root to deterministic tree identity before the gate sequence.

## Deterministic tree identity

Tree identity is a necessary primitive but not, by itself, gate-lifetime immutability.

The canonical tree digest algorithm should be independent of directory enumeration order and platform locale. For every admitted regular file it must bind at least:

- normalized relative path bytes under the toolchain root;
- file type/mode class required by the supported platform contract;
- exact file length;
- SHA-256 of exact stable file bytes.

The manifest/digest process must:

- sort relative paths by a specified byte/ordinal order;
- reject duplicate normalized relative names;
- reject links/reparse points unless an explicit pinned interpretation is later designed and admitted;
- bound file count, per-file size and total tree bytes;
- stable-read each file and detect metadata/size change during hashing;
- include empty directories only if they are semantically relevant to the execution contract, otherwise define that directories are derived from admitted file paths;
- produce one deterministic tree digest suitable for recording in a preparation receipt or platform evidence.

A before/after equal digest proves equality at those two observations. It does **not** exclude a temporary mid-run mutation that is restored before the final digest.

## Gate-lifetime immutability requirement

Final admission requires the Rust toolchain bytes consumed by the heavy gates to be immutable or equivalently object-pinned for the complete consumption lifetime.

The canonical heavy gate sequence must not merely re-check a mutable host toolchain pathname before and after execution.

### Linux required model

Linux has no Windows-style share mode that prevents another process from writing an already opened ordinary inode. A read-only bind mount alone also does not make the underlying inode immutable against writes through another mount/path.

Therefore an admitted Linux implementation must use one of the following strength-equivalent models:

1. **private immutable snapshot**: construct a bounded private copy of the admitted toolchain tree in namespace-private storage, verify its deterministic tree identity, then make that private tree read-only before any heavy Rust gate consumes it; or
2. another kernel-backed immutable-object mechanism that demonstrably prevents external mutable-host-path writes from changing the bytes observed by Cargo/rustc/rustfmt/Clippy/sysroot consumers during the gate lifetime.

The preferred portable source-staged direction is the private snapshot model because it follows the existing immutable workspace/dependency design and does not depend on optional filesystem features such as fs-verity.

The Linux gate environment must then execute the Rust components from the immutable toolchain snapshot rather than returning to `rustup run` for heavy gates.

At minimum the controlled execution environment must ensure:

- snapshot `bin` components are the ones found by Cargo subcommand/component dispatch;
- Cargo uses the snapshot rustc;
- rustfmt and Clippy resolve inside the same snapshot root;
- the default sysroot observed by rustc remains inside the same snapshot;
- final tree identity still matches the admitted snapshot digest;
- no success output is emitted after snapshot cleanup/finalization failure.

The exact interaction with native build tools remains governed separately by the environment-authority contract; a Rust toolchain snapshot must not accidentally claim authority over the host C/C++ compiler/linker toolchain.

### Windows required model

A supported Windows implementation may use a copied exact toolchain snapshot combined with the existing native handle/ACL approach.

An admitted design must:

1. create the snapshot in a create-new unique validation location;
2. reject reparse points and ambiguous Windows path forms;
3. exact-hash every admitted file into the deterministic tree identity;
4. pin the snapshot root, source directories and relevant component files with native handles;
5. apply write/delete denial that prevents mutation/injection while preserving required read/execute behavior;
6. execute Cargo/rustc/rustfmt/Clippy from the snapshot root;
7. prove the sysroot and component dispatch remain inside the pinned snapshot;
8. revalidate tree identity after gates;
9. keep cleanup/finalization part of success.

Real supported Windows/NTFS execution must prove that the resulting ACL/share-mode configuration still permits normal Rust process creation and DLL/library loading.

## Rustup authority after snapshot creation

Once an immutable toolchain snapshot is admitted for the heavy gates, rustup should no longer remain an authority dependency for those heavy gate invocations.

Rustup may be used during preparation/resolution to locate and provision the required 1.97.1 toolchain, but the heavy validation phase should consume the already verified snapshot directly.

This reduces the remaining rustup trust boundary to preparation/resolution rather than allowing a mutable proxy executable to participate in every Cargo/rustc invocation.

Preparation still requires explicit rustup executable/path handling and must not claim that the host rustup binary itself is immutable merely because the resulting snapshot tree is verified.

## Evidence evolution

Current schema-v2 platform evidence must retain:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

until both platform producers and both semantic reviewers are deliberately migrated to a stronger value backed by real source implementation and platform primitives.

A future admitted value should bind a deterministic tree digest and a named authority policy, for example conceptually:

- host Rust authority policy identifier;
- toolchain tree SHA-256;
- immutable/pinned snapshot result;
- exact Rust version;
- platform-specific snapshot method.

The exact field names/version must be changed atomically across producers, reviewers and closure contract. Historical schema-v2 evidence using `pending` must never be reinterpreted as proof of the stronger contract.

## Narrow primitives required before integration

Before changing the evidence state from `pending`, source work should demonstrate at least:

- deterministic tree digest is independent of enumeration order;
- trusted tree acceptance;
- tracked toolchain-byte mutation changes/rejects the digest;
- symlink/reparse substitution rejection;
- duplicate/case-collision rejection under the relevant platform pathname model;
- component escape outside the selected root rejection;
- bounded file-count/total-byte enforcement;
- Linux private-snapshot read-only behavior while mutable original-tree changes do not affect snapshot bytes;
- Windows snapshot ACL/share-mode primitive behavior on supported NTFS.

These are primitives only. They still do not replace the complete exact-head NXB-153 platform validation.

## Admission acceptance

The host Rust toolchain boundary can be marked solved only when the same exact NXB-153 source head has real Linux and Windows evidence showing:

- Rust 1.97.1 was resolved;
- deterministic toolchain tree identity was established;
- heavy gates consumed only the admitted immutable/pinned toolchain snapshot;
- component/sysroot resolution stayed inside that snapshot;
- final identity and cleanup succeeded;
- schema/closure reviewers bind the stronger authority state;
- all other #90–#98 admission gates remain satisfied on that same head.

Until then the explicit `version_pinned_object_identity_pending` value is intentional and PR #89 remains draft/not admitted.