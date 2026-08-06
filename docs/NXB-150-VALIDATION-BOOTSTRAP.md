# NXB-150 Pinned Validation Bootstrap

## Purpose

The NXB-150 validation bootstrap prepares one reproducible local tool environment and immediately runs the exact-head validation harness.

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
target/nxb-tools/bin/
```

They are never resolved from an arbitrary global `PATH` during validation.

## Windows

From a clean checkout of PR #68:

```powershell
pwsh -NoProfile -File .\scripts\prepare-and-validate-nxb-150-windows.ps1
```

Prepare tools without starting the full validation matrix:

```powershell
pwsh -NoProfile -File .\scripts\prepare-and-validate-nxb-150-windows.ps1 -PrepareOnly
```

Prerequisites:

- Git;
- rustup from the official Rust distribution;
- outbound access to Rust toolchain and crates.io sources during preparation.

## Linux

From a clean checkout of PR #68:

```bash
bash scripts/prepare-and-validate-nxb-150-linux.sh
```

Prepare tools without starting the full validation matrix:

```bash
NXB_PREPARE_ONLY=1 bash scripts/prepare-and-validate-nxb-150-linux.sh
```

Prerequisites:

- Git;
- rustup from the official Rust distribution;
- `sha256sum`;
- outbound access to Rust toolchain and crates.io sources during preparation.

## Preparation receipt

Successful preparation writes an ignored local JSON receipt under:

```text
target/nxb-validation/nxb-150-tooling-<platform>-<exact-head>.json
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
target/nxb-tools/bin/cargo-audit[.exe]
target/nxb-tools/bin/cargo-deny[.exe]
```

The harness rejects:

- missing rustup;
- a missing Rust `1.97.1` toolchain;
- missing local security tools;
- cargo-audit other than `0.22.2`;
- cargo-deny other than `0.20.2`;
- dirty working trees;
- changed Git head;
- reproduced `Cargo.lock` differences;
- unexpected `Cargo.lock` SHA-256;
- any failed package, workspace, RustSec or cargo-deny gate.

## Validation evidence schema v2

Successful Linux or Windows validation writes schema-v2 evidence that additionally binds:

- cargo-audit executable SHA-256;
- cargo-deny executable SHA-256;
- exact tool versions;
- exact Rust and Cargo versions;
- exact lockfile SHA-256;
- unchanged exact Git head.

## Network boundary

Preparation may access only the official Rust distribution and crates.io dependency sources required to install the pinned tools.

The validation phase may access dependency and advisory sources required by Cargo, RustSec and cargo-deny. It performs no target scanning, browser automation, credential access or report submission.

## Acceptance rule

PR #68 remains draft until:

1. the candidate `Cargo.lock` reproduces byte-for-byte with Rust `1.97.1`;
2. Linux validation passes on one exact head;
3. Windows validation passes on the same exact head;
4. both schema-v2 evidence files and tool-preparation receipts are reviewed;
5. no workflow has been added or re-enabled.
