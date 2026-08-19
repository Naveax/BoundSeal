# BSL-150 Pinned Validation Bootstrap

## Purpose

The BSL-150 validation bootstrap prepares one reproducible local tool environment and immediately runs the exact-head validation harness.

It does not enable GitHub Actions, modify the user's global Cargo installation, change the repository toolchain override or claim validation success when preparation alone completes.

## Pinned tools

| Component | Version |
|---|---:|
| Rust toolchain | `1.97.1` |
| rustfmt | Rust `1.97.1` component |
| Clippy | Rust `1.97.1` component |
| cargo-audit | `0.22.2` |
| cargo-deny | `0.20.2` |

`cargo-audit` and `cargo-deny` are installed with `cargo install --locked` under:

```text
target/bsl-tools/bin/
```

They are never resolved from an arbitrary global `PATH` during validation.

## Canonical lockfile checkout bytes

BSL-150 binds the root `Cargo.lock` by byte-level SHA-256. The repository therefore contains this mandatory attribute:

```gitattributes
/Cargo.lock text eol=lf
```

This keeps the working-tree lockfile byte-identical on Windows, Linux and macOS regardless of the user's `core.autocrlf` setting.

A Windows checkout created before this attribute was added may still contain a clean-but-CRLF `Cargo.lock`. After pulling the current branch, run the fail-closed checkout repair:

```powershell
git pull --ff-only
pwsh -NoProfile -File .\scripts\repair-bsl-150-windows-lockfile-checkout.ps1
```

The repair refuses dirty working trees and user-authored lockfile differences. It verifies the `eol=lf` attribute, rematerializes only a clean tracked `Cargo.lock`, verifies the canonical SHA-256 and requires the working tree to remain clean.

Manual equivalent:

```powershell
git pull --ff-only
Remove-Item -LiteralPath .\Cargo.lock -Force
git restore --source=HEAD --worktree -- .\Cargo.lock
```

Then verify the canonical hash:

```powershell
(Get-FileHash -LiteralPath .\Cargo.lock -Algorithm SHA256).Hash.ToLowerInvariant()
```

Expected value:

```text
f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff
```

Do not rewrite the lockfile manually and do not accept the CRLF checkout hash as canonical evidence.

## Locked-resolution contract

The committed `Cargo.lock` is the dependency-resolution authority. Validation does not run plain `cargo generate-lockfile`, because that command intentionally rebuilds an existing lockfile with the newest currently available compatible registry packages. A future compatible registry publication must not invalidate an otherwise valid committed lockfile.

Instead, each platform harness:

1. verifies the committed lockfile byte-level SHA-256;
2. verifies that Git reports no lockfile difference;
3. runs `cargo metadata --locked`;
4. runs every package and workspace build/test gate with `--locked`;
5. verifies that the lockfile and working tree remain unchanged.

This proves that both platforms accepted and used the same exact committed dependency graph without allowing Cargo to rewrite it.

## Windows

From a clean checkout of the current PR #68 head:

```powershell
pwsh -NoProfile -File .\scripts\prepare-and-validate-bsl-150-windows.ps1
```

Prepare tools without starting the full validation matrix:

```powershell
pwsh -NoProfile -File .\scripts\prepare-and-validate-bsl-150-windows.ps1 -PrepareOnly
```

Prerequisites:

- Git;
- rustup from the official Rust distribution;
- outbound access to Rust toolchain and crates.io sources during preparation.

## Linux

From a clean checkout of the same current PR #68 head:

```bash
bash scripts/prepare-and-validate-bsl-150-linux.sh
```

Prepare tools without starting the full validation matrix:

```bash
BSL_PREPARE_ONLY=1 bash scripts/prepare-and-validate-bsl-150-linux.sh
```

Prerequisites:

- Git;
- rustup from the official Rust distribution;
- `sha256sum`;
- outbound access to Rust toolchain and crates.io sources during preparation.

## Preparation receipt

Successful preparation writes an ignored local JSON receipt under:

```text
target/bsl-validation/bsl-150-tooling-<platform>-<exact-head>.json
```

The receipt records:

- exact Git head;
- exact Rust compiler version;
- exact cargo-audit and cargo-deny versions;
- SHA-256 of both installed tool binaries;
- local tools root;
- preparation timestamp;
- bounded network-activity classification.

A preparation receipt is not validation evidence. It only proves which tools were prepared.

## Validation execution

The platform harnesses invoke:

```text
rustup run 1.97.1 rustc
rustup run 1.97.1 cargo
```

Security checks invoke only these exact local binaries:

```text
target/bsl-tools/bin/cargo-audit[.exe]
target/bsl-tools/bin/cargo-deny[.exe]
```

The harness rejects:

- missing rustup;
- a missing Rust `1.97.1` toolchain;
- missing local security tools;
- cargo-audit other than `0.22.2`;
- cargo-deny other than `0.20.2`;
- dirty working trees;
- changed Git head;
- an unexpected committed `Cargo.lock` SHA-256;
- any Cargo `--locked` resolution failure;
- any lockfile or working-tree change during validation;
- any failed package, workspace, RustSec or cargo-deny gate.

## Validation evidence schema v2

Successful Linux or Windows validation writes schema-v2 evidence that binds:

- cargo-audit executable SHA-256;
- cargo-deny executable SHA-256;
- exact tool versions;
- exact Rust and Cargo versions;
- exact lockfile SHA-256;
- unchanged exact Git head.

The `lockfile_reproduced_without_diff` evidence field means that the canonical committed lockfile was accepted by Cargo locked mode throughout the full platform harness and remained byte-identical. It does not mean that the mutable registry index was asked to construct a new lockfile from scratch.

## Network boundary

Preparation may access only the official Rust distribution and crates.io dependency sources required to install the pinned tools.

The validation phase may access dependency and advisory sources required by Cargo, RustSec and cargo-deny. It performs no target scanning, browser automation, credential access or report submission.

## Acceptance rule

The final PR #68 head may leave draft only when:

1. both platforms verify the same canonical committed `Cargo.lock` through Cargo locked mode without byte or Git diff;
2. Linux validation passes on one exact head;
3. Windows validation passes on the same exact head;
4. both schema-v2 evidence files and tool-preparation receipts are reviewed;
5. deterministic closure reports `ready_for_manual_pr_review`;
6. no review thread remains unresolved;
7. no workflow has been added or re-enabled.

Any commit after closure changes the exact head and invalidates the prior platform evidence for merge authorization.
