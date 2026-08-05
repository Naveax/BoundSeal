# NXB-151 validation procedure

NXB-151 validation is external to GitHub Actions. Repository workflows remain disabled.

## Exact-head requirement

Validation must start from a clean working tree. Each harness records the exact 40-character Git commit and rejects a dirty checkout. Evidence is valid only for that exact commit.

The required toolchain is defined by `rust-toolchain.toml` and currently requires Rust `1.97.1` with rustfmt and Clippy.

## Product workspace validation

Windows:

```powershell
pwsh -NoProfile -File .\scripts\validate-nxb-151-windows.ps1
```

Linux:

```bash
bash scripts/validate-nxb-151-linux.sh
```

These harnesses perform clean-tree and exact-head checks, pinned tool discovery, formatting, all-target/all-feature check, Clippy with warnings denied, serial tests and an explicit build of only:

```text
cargo build -p nxb-core --bin nxb --all-features --locked
```

They then exercise initialization, doctor, status, non-empty rejection and missing-directory detection. Windows additionally verifies protected ACLs, junction/reparse rejection and broad-ACE rejection. Linux exercises private permission and durable publication behavior.

## Migration validation

```text
bash scripts/validate-nxb-151-migration-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-migration-windows.ps1
```

These harnesses invoke migration only through:

```text
nxb workspace migrate ...
```

They verify schema `0 → 1`, one immutable receipt, transient cleanup and orphan-backup recovery.

## Linked single-binary entry-point validation

```text
bash scripts/validate-nxb-151-entrypoint-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-entrypoint-windows.ps1
```

These harnesses additionally inspect Cargo metadata and require exactly one binary target named `nxb`. They verify migration-aware doctor/status behavior and pending-migration exit codes `20` and `30` using only the single executable.

## Target-profile validation

```text
bash scripts/validate-nxb-151-target-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-target-windows.ps1
```

These harnesses use only the single `nxb` executable and verify:

- immutable target create, list, show and disable lifecycle;
- fixed read-only methods `GET`, `HEAD` and `OPTIONS`;
- active-only and include-disabled views;
- unsafe origin and ambiguous path rejection with exit code `50`;
- pending migration rejection with exit code `51`;
- profile tamper and disable-receipt tamper rejection with exit code `52`;
- networkless status metadata;
- exact-head and executable SHA-256 evidence.

Linux additionally verifies private `0600` target-profile and disable-receipt modes. Windows additionally injects a broad Everyone allow ACE into a target profile and requires fail-closed rejection.

## Evidence files

Successful runs create local files under:

```text
target/nxb-validation/
```

Each document contains milestone, platform, exact head, toolchain details where applicable, gate results and the single `nxb` executable SHA-256. It contains no workspace contents, credentials, cookies, tokens, provider handles or evidence bodies.

## Acceptance rule

NXB-151 can move out of draft only when:

- NXB-150 has validated and merged;
- all required Linux and Windows harnesses pass on the same final NXB-151 head;
- Cargo metadata confirms exactly one binary target;
- Windows ACL and reparse checks pass;
- Linux permission and parent-sync checks pass;
- target profile and disable-receipt tamper tests pass on both platforms;
- generated evidence is reviewed and recorded in the PR;
- no GitHub Actions workflow has been added or re-enabled.

A source implementation or one-platform result alone is insufficient.
