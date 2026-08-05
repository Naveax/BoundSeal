# NXB-151 — Unified workspace entry point

## Status

Draft implementation. This contract remains stacked on NXB-150 and is not release-complete until the exact Rust, Windows and Linux gates pass.

## Supported user-facing surface

The supported workspace interface is now rooted at the primary `nxb` executable:

```text
nxb workspace init --workspace <path> [--name <name>] [--json]
nxb workspace doctor --workspace <path> [--json]
nxb workspace status --workspace <path> [--json]
nxb workspace migrate apply --workspace <path> [--json]
nxb workspace migrate recover --workspace <path> [--json]
nxb workspace migrate status --workspace <path> [--json]
```

The existing `nxb-product` and `nxb-workspace-migrate` executables are transitional internal helpers. Their command surfaces are not the long-term installation contract. The facade isolates them so their implementation can later be linked into `nxb` without changing the supported user commands.

## Exit-code contract

| Operation | Failure code |
|---|---:|
| Workspace initialization | 10 |
| Workspace doctor | 20 |
| Workspace status | 30 |
| Migration apply | 40 |
| Migration recover | 41 |
| Migration status | 42 |
| Internal dispatch invariant | 90 |

Legacy non-workspace commands continue to return the primary CLI failure code `1`.

## Combined doctor and status

`nxb workspace doctor` combines structural workspace diagnostics with migration state.

A stable workspace adds a `migration_state` passing check. Any pending migration file changes the doctor result to `unhealthy` and returns exit code `20`.

`nxb workspace status` includes a nested `migration` object. Pending migration state changes the top-level status to `recovery_required` and returns exit code `30`.

This prevents normal product use while a prepare/apply/commit migration transaction is incomplete.

## Transitional helper boundary

The facade does not invoke a shell, CMD script or PowerShell process. It resolves only fixed sibling executable names:

```text
nxb-product[.exe]
nxb-workspace-migrate[.exe]
```

Before execution it requires:

- the primary executable, executable directory and helper path to contain no symbolic link or Windows reparse-point traversal;
- the helper to be a regular file in the exact primary executable directory;
- a cleared child environment with only the bounded Windows runtime variables restored;
- null stdin;
- separately captured stdout and stderr;
- a 256 KiB limit for each output stream;
- a 120-second execution deadline;
- valid JSON from internal helpers;
- the expected command-specific helper exit code.

The facade never searches `PATH` and never accepts a caller-selected helper name or helper path.

## Packaging requirement

Until helper logic is linked directly into `nxb`, installation and release packages must place all three binaries in the same protected directory:

```text
nxb[.exe]
nxb-product[.exe]
nxb-workspace-migrate[.exe]
```

A package containing only `nxb` is incomplete for workspace operations in this transitional slice.

## Acceptance harnesses

Linux:

```text
bash scripts/validate-nxb-151-entrypoint-linux.sh
```

Windows:

```text
pwsh -NoProfile -File .\scripts\validate-nxb-151-entrypoint-windows.ps1
```

Each harness requires a clean exact head and Rust `1.97.1`, then runs formatting, check, Clippy with warnings denied, serial tests and a three-binary build.

The harnesses verify:

- unified initialization;
- migration-aware doctor output;
- migration-aware status output;
- migration status through the primary CLI;
- fail-closed doctor exit code `20` during pending migration;
- fail-closed status exit code `30` during pending migration;
- restoration after transient state removal;
- SHA-256 values for all three binaries;
- exact-head-bound local JSON evidence.

## Remaining consolidation work

- Replace sibling helper execution with linked shared modules while preserving the exact `nxb workspace` contract.
- Remove the transitional helper binaries from the required installation set.
- Add signed release-manifest binding for the final single-binary package.
- Add the first fail-closed `target` command group.
- Add machine-readable diagnostic subcodes and a full quick-start flow.

No compiler, Clippy, test or platform acceptance success is claimed by this document alone.
