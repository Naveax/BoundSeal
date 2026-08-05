# NXB-151 — Product shell and canonical workspace

## Status

Draft implementation. This block is stacked on NXB-150 and is not release-complete until NXB-150 is validated and merged.

## Purpose

NXB-151 begins the transition from a collection of internal security-contract crates to one supported local product workflow. The first slice provides a Windows-first, networkless workspace shell with deterministic structure, a versioned manifest, local diagnostics and redacted status output.

This block does not enable scanning, browser access, credential discovery, automatic submission or unrestricted network traffic.

## Initial executable

The initial product binary is built from:

```text
crates/nxb-core/src/bin/nxb-product.rs
```

Cargo discovers it as the `nxb-product` binary. A later NXB-151 slice will consolidate the supported product command surface under the final `nxb` entry point after compatibility and migration behavior are defined.

## Implemented commands

### `init`

```text
nxb-product init --workspace <path> [--name <name>] [--json]
```

Creates a new workspace only when the destination is absent or empty. It rejects symbolic-link roots, validates the human-readable name, creates the canonical directory layout, applies private Unix permissions, writes the manifest through a create-new temporary file, flushes it and atomically renames it into place.

Partial initialization is cleaned up. Existing non-empty directories are never modified.

### `doctor`

```text
nxb-product doctor --workspace <path> [--json]
```

Performs networkless checks for:

- canonical workspace root;
- supported manifest schema and product identity;
- external-provider-only secret boundary;
- required directories;
- symbolic-link rejection;
- private Unix permissions;
- bounded manifest size;
- create-new, sync and cleanup write probe.

An unhealthy workspace returns exit code `20`.

### `status`

```text
nxb-product status --workspace <path> [--json]
```

Prints only non-secret workspace metadata and shallow record counts for targets, sessions, runs, evidence and reports. Symbolic links inside record directories are rejected.

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

The initial binary uses command-specific process exit codes:

| Command | Failure exit code |
|---|---:|
| `init` | 10 |
| `doctor` | 20 |
| `status` | 30 |

Errors are prefixed with `NXB-PRODUCT-<code>` on stderr. Argument parsing errors remain owned by Clap and use its standard exit behavior.

## Security invariants

- No network access is performed.
- Workspace roots and canonical child directories must not be symbolic links.
- Existing non-empty directories are not adopted or modified.
- Manifest input is bounded to 64 KiB and rejects unknown fields.
- Workspace IDs use operating-system randomness and do not encode secrets.
- Secrets remain external-provider-only.
- Status output is metadata-only.
- Temporary files use unpredictable names and create-new semantics.
- Unix directories are `0700`; the manifest is `0600`.
- Windows ACL hardening remains an explicit follow-up before NXB-151 completion.

## Current tests

The source includes acceptance tests for:

- canonical initialization and manifest validation;
- rejection of non-empty destinations;
- doctor failure on a missing required directory;
- shallow regular-file counting;
- no workspace creation for invalid names.

These tests are committed but not yet counted as validation evidence because the available external Rust job runner failed before job creation and the local execution environment has no Rust toolchain or outbound DNS.

## Remaining NXB-151 slices

- Merge the product shell into the final supported `nxb` entry point.
- Define `target`, `session`, `plan`, `run`, `resume`, `evidence`, `report` and `verify` command groups without exposing unsafe defaults.
- Add Windows ACL inspection and hardening.
- Add schema migration journal and crash-safe migration tests.
- Add machine-readable diagnostic codes below the command-level exit-code classes.
- Add full synthetic end-to-end acceptance tests.
- Add product quick-start documentation.

## Validation gates

```text
cargo fmt --all -- --check
cargo check -p nxb-core --all-targets --all-features --locked
cargo clippy -p nxb-core --all-targets --all-features --locked -- -D warnings
cargo test -p nxb-core --all-features --locked -- --test-threads=1
```

NXB-151 must remain draft until these commands pass on the pinned toolchain and NXB-150 is merged.
