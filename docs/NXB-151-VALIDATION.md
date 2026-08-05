# NXB-151 Validation Procedure

NXB-151 validation is external to GitHub Actions. Repository workflows remain disabled. Evidence is accepted only when every required gate completes on one unchanged exact Git head.

## Exact-head requirement

Validation must start from a clean working tree. Every harness records the exact 40-character Git commit and rejects a dirty checkout. The required toolchain is Rust `1.97.1` with rustfmt and Clippy.

Required Rust gates:

```text
cargo fmt --all -- --check
cargo check -p nxb-core --all-targets --all-features --locked
cargo clippy -p nxb-core --all-targets --all-features --locked -- -D warnings
cargo test -p nxb-core --all-features --locked -- --test-threads=1
cargo build -p nxb-core --bin nxb --all-features --locked
```

Workspace-level check, Clippy and test regressions remain mandatory before merge.

## Single-binary requirement

Cargo metadata must expose exactly one binary target:

```json
["nxb"]
```

No helper, product, migration or temporary executable target is permitted. Validation evidence records only the SHA-256 of `nxb` or `nxb.exe`.

## Product workspace validation

```text
bash scripts/validate-nxb-151-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-windows.ps1
```

These harnesses verify initialization, doctor, status, non-empty rejection, missing-directory detection, private filesystem permissions and single-binary build behavior. Windows additionally verifies protected ACLs, junction/reparse rejection and broad-ACE rejection. Linux exercises private modes and durable publication behavior.

## Migration validation

```text
bash scripts/validate-nxb-151-migration-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-migration-windows.ps1
```

These harnesses invoke migration only through `nxb workspace migrate ...` and verify schema `0 → 1`, immutable receipt publication, transient cleanup and orphan-backup recovery.

## Linked entry-point validation

```text
bash scripts/validate-nxb-151-entrypoint-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-entrypoint-windows.ps1
```

These harnesses inspect Cargo metadata, require exactly one binary target and verify migration-aware doctor/status behavior with pending-migration exit codes `20` and `30`.

## Authorization-bound target validation

```text
bash scripts/validate-nxb-151-target-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-target-windows.ps1
```

These harnesses use only the single `nxb` executable and verify:

- create, validate, list, show and disable lifecycle;
- policy parsing and current-time compilation;
- exact origin-host scope binding;
- program metadata derived from the policy;
- read-only method intersection;
- authorization-document SHA-256 binding;
- target-policy SHA-256 binding;
- active-profile identity SHA-256 tamper rejection;
- raw authorization bytes, policy bytes and local source-path non-persistence;
- unsafe origin, path and authorization-reference rejection with exit code `50`;
- pending migration rejection with exit code `51`;
- profile and disable-receipt tamper rejection with exit code `52`;
- source-document digest drift rejection with exit code `54`;
- machine-readable target diagnostic codes;
- networkless behavior and exact-head evidence.

Linux additionally verifies private `0600` target-profile and disable-receipt modes. Windows injects a broad Everyone allow ACE into a target profile and requires fail-closed rejection.

## Machine-readable diagnostic validation

The following integration-test targets are part of the mandatory serial Rust test gate:

```text
crates/nxb-core/tests/product_diagnostics.rs
crates/nxb-core/tests/target_cli.rs
```

They verify the diagnostic schema, exact subcodes, domains, operations, process exit codes, compact JSON stderr and bounded single-line messages for workspace, migration and target failures. Registered target codes include `target validate` exit `54` and `NXB151-TARGET-VALIDATE-INVALID`.

Message wording is not an acceptance surface. Tests bind only to structured fields.

## Full synthetic product validation

```text
bash scripts/validate-nxb-151-synthetic-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-synthetic-windows.ps1
```

These harnesses execute one complete networkless local product flow using the canonical synthetic policy and authorization fixtures:

1. initialize and diagnose a private workspace;
2. create an authorization-bound target profile;
3. revalidate exact policy and authorization source digests;
4. verify that source bytes and local source paths were not persisted;
5. validate the program policy;
6. create a bounded dry-run scan plan and manual report bundle;
7. require zero network requests and automatic submission disabled;
8. generate and verify the deterministic architecture receipt;
9. require final healthy/ready workspace state;
10. bind the single executable and generated artifacts to SHA-256 evidence.

The synthetic authorization fixture explicitly grants no authority over real systems and is accepted only for offline product testing.

## Evidence files

Successful runs create local files under:

```text
target/nxb-validation/
```

Each document contains milestone, platform, exact head, pinned toolchain, explicit gate results and the single executable SHA-256. Synthetic evidence additionally records SHA-256 values for the target profile, plan, report, manifest and demo receipt. Evidence must contain no workspace contents, credentials, cookies, tokens, provider handles, source policy bytes, authorization bytes or evidence bodies.

## Acceptance rule

NXB-151 can move out of draft only when:

- NXB-150 has validated and merged;
- all Linux and Windows harnesses pass on one final NXB-151 head;
- Cargo metadata confirms exactly one binary target;
- full workspace check, Clippy and tests pass;
- Windows ACL/reparse checks pass;
- Linux permission/parent-sync checks pass;
- authorization-bound target and tamper tests pass on both platforms;
- diagnostic integration tests pass;
- full synthetic product flow passes on both platforms;
- generated evidence is reviewed and recorded in the PR;
- no GitHub Actions workflow is added or re-enabled.

Source implementation, static inspection, a failed remote-job submission or a one-platform result is insufficient.

## Current infrastructure limitation

The available Hugging Face Jobs integration has failed before job creation with `Tool hf_jobs not found`. Repository GitHub Actions remain disabled. These infrastructure failures are not compiler or platform evidence, so PR #70 remains draft.
