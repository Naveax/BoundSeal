# NXB-151 — Product shell and canonical workspace

## Status

Draft implementation. This block is stacked on NXB-150 and is not release-complete until NXB-150 is validated and merged and the pinned Rust/Windows/Linux acceptance gates pass.

## Purpose

NXB-151 begins the transition from a collection of internal security-contract crates to one supported local product workflow. The current slice provides a Windows-first, networkless workspace shell with deterministic structure, a versioned manifest, local diagnostics, redacted status output, fail-closed path handling and private platform permissions.

This block does not enable scanning, browser access, credential discovery, automatic submission or unrestricted network traffic.

## Initial executable

The product binary is built from:

```text
crates/nxb-core/src/bin/nxb-product.rs
```

The Windows-only security implementation is isolated in:

```text
crates/nxb-core/src/bin/nxb-product-windows.rs
```

`nxb-core` disables automatic binary discovery and explicitly declares only `nxb` and `nxb-product`. The Windows support module therefore cannot be interpreted as a third binary target.

A later NXB-151 slice will consolidate the supported product command surface under the final `nxb` entry point after compatibility and migration behavior are defined.

## Implemented commands

### `init`

```text
nxb-product init --workspace <path> [--name <name>] [--json]
```

Creates a new workspace only when the destination is absent or empty. It validates every existing path component, rejects symbolic links and Windows reparse points, creates the canonical directory layout, applies private platform permissions, writes the manifest through a create-new temporary file, flushes it and atomically renames it into place.

Partial initialization is cleaned up without recursively following symlinks, junctions or other reparse points. Existing non-empty directories are never modified.

### `doctor`

```text
nxb-product doctor --workspace <path> [--json]
```

Performs networkless checks for:

- canonical workspace root;
- supported manifest schema and product identity;
- external-provider-only secret boundary;
- required directories;
- all-component symbolic-link and Windows reparse-point rejection;
- private Unix permissions or protected Windows ACLs;
- bounded manifest size and bounded read;
- create-new, private-permission, sync and cleanup write probe.

An unhealthy workspace returns exit code `20`.

### `status`

```text
nxb-product status --workspace <path> [--json]
```

Prints only non-secret workspace metadata and shallow record counts for targets, sessions, runs, evidence and reports. Symbolic links and Windows reparse points inside record directories are rejected.

A status failure returns exit code `30`.

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
  tmp/
```

The manifest schema is currently version `1`:

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

| Command | Failure exit code |
|---|---:|
| `init` | 10 |
| `doctor` | 20 |
| `status` | 30 |

Errors are prefixed with `NXB-PRODUCT-<code>` on stderr. Argument parsing errors remain owned by Clap and use its standard exit behavior.

## Windows security boundary

Windows workspaces use a protected DACL. The implementation requires explicit full-control allow entries for:

- the current user SID;
- Local System (`S-1-5-18` / `SY`);
- Builtin Administrators (`S-1-5-32-544` / `BA`).

Allow entries for Everyone, Authenticated Users and Builtin Users are rejected in either SID or SDDL alias form.

The implementation:

- identifies the current SID through absolute `System32\\whoami.exe`;
- changes and verifies ACLs through absolute `System32\\icacls.exe`;
- invokes no shell, command script or PowerShell process;
- clears the child environment and restores only `SystemRoot` and `WINDIR`;
- validates system-tool paths as absolute regular files with no symlink/reparse traversal;
- removes the Rust `\\?\\` verbatim prefix only for the validated `icacls` argument representation;
- exports a bounded ACL document and checks protected SDDL and exact allow principals;
- rejects junctions and other reparse points in every existing workspace path component.

These source contracts are not counted as Windows validation until the committed Windows harness succeeds on the exact PR head.

## Unix security boundary

- Workspace directories are set to `0700`.
- Manifest and probe files are set to `0600`.
- Group/other permission bits are rejected by `doctor` and `status`.
- Symbolic links in roots, canonical directories and record entries are rejected.

## Security invariants

- No network access is performed.
- Existing non-empty directories are not adopted or modified.
- Manifest input is bounded to 64 KiB and rejects unknown fields.
- Workspace IDs use operating-system randomness and do not encode secrets.
- Secrets remain external-provider-only.
- Status output is metadata-only.
- Temporary files use unpredictable names and create-new semantics.
- Cleanup never recursively follows a detected path indirection.
- Windows ACL mutation is restricted to validated absolute operating-system tools and does not invoke a shell.

## Current tests

Source tests cover:

- canonical initialization and manifest validation;
- rejection of non-empty destinations;
- doctor failure on a missing required directory;
- shallow regular-file counting;
- no workspace creation for invalid names;
- Unix ancestor-symlink rejection;
- Windows SID validation;
- Windows verbatim drive and UNC path normalization;
- required and forbidden SDDL entry parsing.

The Windows acceptance harness additionally covers:

- protected ACLs on the workspace root, every canonical directory and the manifest;
- rejection of a canonical directory replaced by a junction;
- rejection of an injected Everyone allow ACE;
- stable command failure exit codes.

These tests are committed but not yet counted as validation evidence because the available external Rust job runner failed before job creation and the local execution environment has no Rust toolchain or outbound DNS.

## Validation harnesses

```text
pwsh -NoProfile -File .\scripts\validate-nxb-151-windows.ps1
bash scripts/validate-nxb-151-linux.sh
```

Each harness requires a clean exact head and Rust `1.97.1`. It runs format, check, Clippy, tests, product build, `init → doctor → status`, adversarial failure cases and immutable local evidence generation.

## Remaining NXB-151 slices

- Merge the product shell into the final supported `nxb` entry point.
- Add a schema migration journal and crash-safe migration tests.
- Define the initial `target` command group without exposing unsafe defaults.
- Add machine-readable diagnostic codes below command-level exit-code classes.
- Add full synthetic end-to-end acceptance tests.
- Add product quick-start documentation.
- Execute and repair the exact Windows and Linux validation matrices.

## Validation gates

```text
cargo fmt --all -- --check
cargo check -p nxb-core --all-targets --all-features --locked
cargo clippy -p nxb-core --all-targets --all-features --locked -- -D warnings
cargo test -p nxb-core --all-features --locked -- --test-threads=1
```

NXB-151 must remain draft until these commands pass on the pinned toolchain and NXB-150 is merged.
