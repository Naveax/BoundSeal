# NXB-151 validation procedure

NXB-151 validation is external to GitHub Actions. Repository workflows remain disabled.

## Exact-head requirement

Validation must start from a clean working tree. Each harness records the exact 40-character Git commit and rejects a dirty checkout. Evidence is valid only for that exact commit.

The required toolchain is defined by `rust-toolchain.toml` and currently requires Rust `1.97.1` with rustfmt and Clippy.

## Windows

Run from PowerShell:

```powershell
pwsh -NoProfile -File .\scripts\validate-nxb-151-windows.ps1
```

The harness performs:

1. clean-tree and exact-head checks;
2. pinned rustc, Cargo, rustfmt and Clippy discovery;
3. formatting;
4. all-target/all-feature `nxb-core` check;
5. all-target/all-feature Clippy with warnings denied;
6. serial all-feature `nxb-core` tests;
7. explicit `nxb-product` build;
8. clean workspace initialization;
9. healthy doctor result;
10. redacted status result;
11. non-empty destination rejection with exit code `10`;
12. missing canonical directory detection with exit code `20`;
13. product binary SHA-256 calculation;
14. JSON evidence publication under `target/nxb-validation/`.

## Linux

Run:

```bash
bash scripts/validate-nxb-151-linux.sh
```

The Linux harness applies the same gates and additionally exercises the Unix private-permission contract enforced by the product shell. Python 3 is used only to serialize the final local evidence document; it is not part of the product runtime.

## Evidence files

Successful runs create one local file:

```text
target/nxb-validation/nxb-151-<platform>-<head-sha>.json
```

The document contains:

- schema version;
- milestone and platform;
- exact head SHA;
- UTC generation time;
- exact Rust tool versions;
- product binary SHA-256;
- gate names, commands, timestamps and exit codes.

It contains no workspace record contents, credentials, cookies, tokens, provider handles or evidence bodies.

## Acceptance rule

A Linux result alone is insufficient. A Windows result alone is insufficient. NXB-151 can move out of draft only when:

- NXB-150 has validated and merged;
- both platform harnesses pass on the same final NXB-151 head;
- Windows ACL and reparse-point checks are implemented and pass;
- the generated evidence documents are reviewed and their exact command results are recorded in the PR description;
- no GitHub Actions workflow has been added or re-enabled.
