# NXB-151 — Product shell and canonical workspace

## Status

Draft implementation. This block is stacked on NXB-150 and is not release-complete until NXB-150 is validated and merged and the pinned Rust, Windows and Linux acceptance gates pass.

## Purpose

NXB-151 turns the internal security-contract crates into one Windows-first, networkless local product workflow. It provides deterministic workspace structure, a versioned manifest, local diagnostics, redacted status, crash-safe migration, fail-closed path handling and private platform permissions.

This block does not enable browser access, credential discovery, automatic submission or unrestricted network traffic.

## Executable and module layout

The product declares exactly one Cargo binary target:

```text
nxb -> crates/nxb-core/src/nxb.rs
```

The existing command implementation remains in `src/main.rs` and is included by the crate entry point. Workspace functionality is linked from:

```text
crates/nxb-core/src/workspace/mod.rs
crates/nxb-core/src/workspace/migration.rs
crates/nxb-core/src/workspace/windows.rs
crates/nxb-core/src/workspace_facade.rs
```

Cargo automatic binary discovery is disabled. The former `nxb-product` and `nxb-workspace-migrate` targets and sources were removed.

## Supported commands

```text
nxb workspace init --workspace <path> [--name <name>] [--json]
nxb workspace doctor --workspace <path> [--json]
nxb workspace status --workspace <path> [--json]
nxb workspace migrate apply --workspace <path> [--json]
nxb workspace migrate recover --workspace <path> [--json]
nxb workspace migrate status --workspace <path> [--json]
```

`init` creates a workspace only when the destination is absent or empty. `doctor` validates structure, manifest, permissions, path safety, write safety and migration state. `status` emits non-secret metadata and shallow record counts. Migration commands implement the deterministic schema `0 → 1` prepare/apply/commit/recovery lifecycle.

## Canonical workspace layout

```text
<workspace>/
  workspace.json
  config/
  targets/
  sessions/
  runs/
  evidence/
  reports/
  state/
    migrations/
  tmp/
```

The current manifest schema is version `1`:

```json
{
  "schema_version": 1,
  "product": "NXBounty",
  "workspace_id": "nxb-workspace-...",
  "name": "Default Workspace",
  "created_at": "2026-08-05T00:00:00Z",
  "secret_storage": "external_provider_only"
}
```

The manifest contains no credential, cookie, token, key material or provider handle.

## Stable failure classes

| Operation | Failure exit code |
|---|---:|
| Workspace initialization | 10 |
| Workspace doctor | 20 |
| Workspace status | 30 |
| Migration apply | 40 |
| Migration recover | 41 |
| Migration status | 42 |

Errors are prefixed with `NXB-WORKSPACE-<code>` on stderr. Argument parsing errors remain owned by Clap.

## Windows security boundary

Windows workspaces use a protected DACL with explicit full control for the current user, Local System and Builtin Administrators. Allow entries for Everyone, Authenticated Users and Builtin Users are rejected.

The shared Windows module:

- identifies the current SID through absolute `System32\\whoami.exe`;
- changes and verifies ACLs through absolute `System32\\icacls.exe`;
- invokes no shell, CMD script or PowerShell process;
- clears the child environment and restores only `SystemRoot` and `WINDIR`;
- validates system-tool paths as absolute regular files without reparse traversal;
- validates bounded SDDL output;
- rejects junctions and other reparse points in every existing path component.

These operating-system tool calls are ACL implementation details, not workspace command dispatch.

## Unix security boundary

- Workspace directories are `0700`.
- Workspace documents are `0600`.
- Group and other permission bits are rejected.
- Parent directories are synchronized after durable publication where supported.
- Symbolic links in roots, canonical directories and records are rejected.

## Security invariants

- Workspace and migration operations are linked directly into `nxb`.
- No workspace helper process or sibling executable is required.
- No network access is performed.
- Existing non-empty directories are not adopted or modified.
- JSON documents are bounded to 64 KiB and reject unknown fields where schemas are defined.
- Status output is metadata-only.
- Temporary files use unpredictable names and create-new semantics.
- Cleanup never recursively follows a detected path indirection.
- Migration receipts are immutable and digest-bound.

## Tests and validation harnesses

Source tests cover canonical initialization, non-empty rejection, missing-directory diagnostics, record counting, path-indirection rejection, schema migration, orphan-backup recovery, tamper rejection and future-schema rejection. Windows-only tests cover SID, verbatim path and SDDL parsing.

Platform harnesses:

```text
pwsh -NoProfile -File .\scripts\validate-nxb-151-windows.ps1
bash scripts/validate-nxb-151-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-migration-windows.ps1
bash scripts/validate-nxb-151-migration-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-entrypoint-windows.ps1
bash scripts/validate-nxb-151-entrypoint-linux.sh
```

The entry-point harnesses additionally require Cargo metadata to expose exactly one binary target named `nxb`.

## Remaining NXB-151 slices

- Run and repair the exact Rust, Windows and Linux validation matrices.
- Define the initial fail-closed `target` command group.
- Add machine-readable diagnostic subcodes.
- Add full synthetic end-to-end acceptance tests.
- Add product quick-start and release-installation documentation.

## Validation gates

```text
cargo fmt --all -- --check
cargo check -p nxb-core --all-targets --all-features --locked
cargo clippy -p nxb-core --all-targets --all-features --locked -- -D warnings
cargo test -p nxb-core --all-features --locked -- --test-threads=1
```

No compiler, Clippy, test or platform acceptance success is claimed by this document alone. NXB-151 remains draft until these gates pass on the pinned toolchain and NXB-150 is merged.
