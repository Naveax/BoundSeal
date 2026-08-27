# NXB-153 Immutable Source Authority

## Status

This document records the **source-staged** exact-head source-authority contract for NXB-153 validation. It does **not** claim that the current feature head has passed the required Linux or Windows admission gates.

The goal is narrower and more precise: when a platform validator reports that it validated Git head `H`, the Rust/Cargo/security gates must consume source bytes attributable to `H`, not merely a working tree that happened to be clean before and after a long validation run.

A start/end `git status` check is still useful for repository continuity, but it cannot by itself exclude a temporary mid-run source mutation that is restored before the final check.

## Threat model

The contract removes avoidable local validation races and source-substitution ambiguity inside the supported workflow. It does not attempt to protect validation from a malicious host administrator, kernel compromise, hostile hypervisor, or a party able to replace the trusted Git implementation and operating-system primitives simultaneously.

Relevant race classes include:

- modifying a tracked Rust/TOML/test file after the initial clean-tree check and restoring it before final `git status`;
- temporarily replacing `Cargo.lock` while locked Cargo operations run;
- redirecting a source directory or helper pathname between check and use;
- substituting an extracted snapshot file after its Git object identity was checked;
- introducing a new untracked source file into the snapshot while Cargo/build scripts execute;
- allowing cleanup/finalization failure while still emitting a successful platform-gate message.

## Common exact-head rule

Both platform paths derive validation source from the exact 40-hex Git head captured before the heavy gate sequence. The mutable operator working tree is not the source authority for the expensive Cargo/test/security phase.

Canonical expected Cargo.lock SHA-256 for the current NXB-153 line remains:

`f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff`

The final platform evidence still records the exact head and lockfile digest, and the outer validators still require final repository HEAD/worktree continuity before evidence publication.

## Linux immutable source authority

Canonical runner:

`scripts/nxb-153-linux-immutable-source.sh`

### Source construction

The Linux validator resolves the immutable-source runner itself from the exact-head Git object graph and streams those committed bytes to Bash. The runner then:

1. rejects unsupported Git tree entries such as symlinks, gitlinks and special modes;
2. streams `git archive --format=tar <exact-head>` into a child user/mount namespace;
3. mounts a namespace-private tmpfs for the extracted exact-head source tree;
4. validates the exact-head Cargo.lock digest and committed sealed-tool helper bytes;
5. reserves `target`, `.nxb-153-tmp` and `.nxb-153-cargo-home` as untracked runtime locations;
6. mounts separate private writable tmpfs instances at those runtime locations;
7. remounts the source tmpfs itself read-only before any Cargo gate executes;
8. fails closed if a source-root write probe succeeds.

Because the source tmpfs contains copied exact-head archive bytes rather than bind-mounted working-tree inodes, a writer outside the validation mount namespace cannot modify the source objects being compiled by mutating the ordinary working tree.

### Gate execution

Inside the read-only exact-head snapshot the runner executes:

- `cargo metadata --locked`;
- `cargo fmt --all -- --check`;
- nxb-policy check / Clippy / tests;
- nxb-core check / Clippy / unit tests;
- the focused NXB-153 target test set;
- workspace all-target/all-feature check / Clippy / tests;
- RustSec `cargo-audit`;
- `cargo-deny check`.

Build artifacts, Cargo cache/network state and temporary files are directed only to the separate writable private tmpfs mounts.

The security tools are reached through the already pinned repository descriptor and are executed through the receipt-hash-checked sealed-memfd model described in `NXB-153-VALIDATION-TOOL-OBJECT-INTEGRITY.md`.

### Linux primitive evidence currently available

Narrow local primitive checks have demonstrated:

- unprivileged user + mount namespace availability in the available Linux environment;
- namespace-private tmpfs isolation;
- read-only source remount rejecting writes with `EROFS`;
- nested private `target` / temp mounts remaining writable;
- sealed executable memfd execution and required seal enforcement;
- committed helper/validator Git-object loading surviving repository pathname substitution.

These checks are primitive/source checks only. They are **not** an exact-current-head Rust 1.97.1 Linux admission PASS.

## Windows immutable source authority

Canonical runner:

`scripts/nxb-153-windows-immutable-source.ps1`

Canonical outer validator:

`scripts/validate-nxb-153-windows.ps1`

Windows does not have the Linux namespace/private-tmpfs model, so the source-staged Windows contract combines exact Git-object verification, Win32 share-mode pinning, directory handles and a write-denied snapshot ACL.

### Exact-head manifest constraints

Before extraction, the Windows runner builds an exact-head manifest from `git ls-tree -rl --full-tree` and fails closed unless all tracked entries fit the intentionally conservative supported shape:

- object type must be `blob`;
- mode must be `100644` or `100755`;
- path grammar is restricted to ASCII `[A-Za-z0-9._/-]`;
- empty, `.` and `..` path components are rejected;
- trailing dot/space components are rejected;
- Win32 reserved device stems such as `CON`, `NUL`, `COM1` and `LPT1` are rejected;
- paths must be unique under `OrdinalIgnoreCase` comparison;
- tracked file count is bounded to 4096;
- total tracked bytes are bounded to 512 MiB;
- `target`, `.nxb-153-tmp` and `.nxb-153-cargo-home` must not already be tracked.

This intentionally rejects source trees whose pathname semantics would be ambiguous on the supported Windows filesystem model instead of attempting clever normalization.

### Snapshot construction and object identity

The runner:

1. creates a unique snapshot under the pinned NXB-153 validation directory;
2. creates a bounded exact-head tar archive with `git archive`;
3. pins that archive read-only while extraction occurs;
4. extracts into the unique snapshot root;
5. rejects any extracted reparse point;
6. requires the extracted regular-file set to match the exact-head manifest count and paths;
7. pins the snapshot root and every extracted source directory with native `CreateFileW` directory handles that omit delete sharing and validates final handle paths with `GetFinalPathNameByHandleW`;
8. opens every tracked file read-only with `FileShare.Read`, withholding write/delete sharing;
9. recomputes the Git blob SHA-1 representation (`blob <length>\0<bytes>`) from each pinned file stream and requires equality with the exact-head manifest object ID;
10. verifies the snapshot Cargo.lock SHA-256 before heavy gates begin.

The outer validator additionally pins the `scripts` directory and the immutable-source runner file, resolves the runner's exact-head Git blob, recomputes its Git blob object ID from the pinned stream and refuses to invoke it if the pinned implementation bytes differ from the exact-head committed object.

### Windows write-denied source tree

After exact Git-object verification, the runner creates three dedicated runtime directories:

- `target`;
- `.nxb-153-tmp`;
- `.nxb-153-cargo-home`.

Those directories have ACL inheritance protected **before** the source-root deny rule is applied so build/cache/temp state can remain writable.

The runner then adds an inherited deny ACE for the current validation identity covering source write/delete operations on the snapshot tree. It fails closed unless primitive probes prove both:

- an existing source file cannot be modified and its bytes remain unchanged;
- a new file cannot be injected into the source root and no partial path becomes visible.

A separate runtime probe must prove that the protected `target` directory remains writable.

The file and directory handles remain open while the heavy gate sequence runs, adding object/namespace pinning on top of the source ACL.

### Windows heavy gates

The outer validator no longer runs the expensive Cargo/test/security sequence directly against the operator working tree. It delegates the complete gate set to the exact-head snapshot runner.

Inside that snapshot, the runner redirects:

- `CARGO_TARGET_DIR` to the protected snapshot runtime target directory;
- `CARGO_HOME` to the protected snapshot runtime Cargo-home directory;
- `TMP` and `TEMP` to the protected snapshot temp directory.

It then runs the same fmt/check/Clippy/unit/focused/workspace/RustSec/cargo-deny gate set required by the NXB-153 platform contract.

After the gate sequence it rechecks:

- snapshot Cargo.lock SHA-256;
- every pinned tracked file's Git blob object ID;
- tracked pathname size/reparse metadata;
- canonical cargo-audit/cargo-deny path hashes.

The outer validator then performs its existing pinned Cargo.lock, tooling-receipt, security-tool, exact-head and clean-worktree continuity checks before publishing Windows platform evidence create-only.

### Cleanup is part of success

The Windows snapshot runner treats finalization as part of the gate result.

- the original snapshot-root ACL must be restored;
- all pinned file/directory/archive handles must be released;
- the snapshot tree must be removed;
- the temporary exact-head archive must be removed.

Cleanup failures are not silently ignored. A gate-success message is emitted only **after** the cleanup `finally` block has completed successfully. Therefore “tests passed but immutable snapshot finalization failed” is not represented as a successful helper invocation.

## Windows runtime acceptance still required

No Windows runtime PASS is claimed from the current environment. Real supported Windows/NTFS execution must exercise at least:

- PowerShell parsing and Add-Type compilation of the exact current-head scripts;
- exact-head tree manifest parsing for the real repository;
- Git archive extraction and Git blob object-ID recomputation;
- file and directory handle acquisition while Cargo/rustc reads the snapshot;
- source ACL denial of existing-file mutation, new-file injection and delete/rename attempts;
- continued writability of protected target/temp/Cargo-home directories;
- ordinary cargo-audit/cargo-deny launch while their file + ancestor namespace handles are open;
- source-file and source-directory rename/delete/replacement attempts while handles are pinned;
- cleanup/finalization success and explicit failure behavior;
- final create-new Windows platform evidence publication and same-handle read-back.

Any real supported-Windows behavior that contradicts the source-staged assumptions keeps admission blocked and requires source hardening before #90/#98 can close.

## Admission boundary

The immutable-source model narrows what a platform PASS is allowed to mean, but it does not itself constitute that PASS.

The exact final NXB-153 head still requires real Rust 1.97.1 Linux and Windows execution, immutable-source primitive checks on those platform runs, the complete platform gate sets, exact-head tooling receipts/evidence, guarded dual-platform closure and final blocker review.

PR #89 remains draft/not admitted. Issues #90–#98 remain open. NXB-154 must not use the NXB-153 feature branch as an admitted implementation base until the same-head dual-platform closure and blocker review complete.
