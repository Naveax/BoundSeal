# NXB-151 — Crash-safe workspace migration journal

## Status

Draft implementation on PR #70. This slice is stacked on NXB-150 and is not release evidence until the pinned Rust 1.97.1 Windows and Linux validation harnesses pass.

## Purpose

The migration layer upgrades an existing local NXBounty workspace without silently adopting unknown schemas, losing the original manifest, following path indirections or leaving an ambiguous partially migrated state.

The initial supported transition is:

```text
workspace schema 0 → workspace schema 1
```

Schema 1 adds the explicit non-secret boundary:

```json
"secret_storage": "external_provider_only"
```

No credential, cookie, token, key material or provider handle is introduced into the workspace manifest or migration journal.

## Temporary command surface

The migration engine is exposed through a dedicated support binary until the final NXB-151 command consolidation:

```text
nxb-workspace-migrate status  --workspace <absolute-path> [--json]
nxb-workspace-migrate apply   --workspace <absolute-path> [--json]
nxb-workspace-migrate recover --workspace <absolute-path> [--json]
```

Command-level failure exit codes are:

| Command | Exit code |
|---|---:|
| `apply` | 40 |
| `recover` | 41 |
| `status` | 42 |

## Journal files

Migration state is stored below the existing private `state` directory:

```text
state/
  migration-source.json
  migration-active.json
  migration-applied.json
  migrations/
    nxb-migration-0-1-<digest>.json
```

The files have distinct roles:

- `migration-source.json` is an exact bounded backup of the source manifest.
- `migration-active.json` is the prepared journal binding source and target SHA-256 values.
- `migration-applied.json` records that the target manifest was published and verified.
- `migrations/<id>.json` is the immutable commit receipt.

Transient files are deleted only after the immutable receipt exists and the published manifest matches the target digest.

## Deterministic migration identity

The target manifest is derived only from the validated source manifest and the canonical schema transition. The migration identifier binds:

- migration protocol domain;
- source manifest SHA-256;
- target manifest SHA-256;
- exact `0 → 1` transition.

Repeating the plan for identical source bytes produces the same migration ID and target digest.

## Prepare → apply → commit

### Prepare

1. Validate the workspace root, `state` directory, permissions and all existing path components.
2. Reject symlinks, Windows junctions and other reparse points.
3. Parse the exact legacy schema with unknown fields denied.
4. Produce canonical schema-1 bytes and source/target SHA-256 values.
5. Publish the exact source backup with create-new semantics.
6. Publish the prepared journal with create-new semantics.

A crash after the backup but before the journal creates an orphan-backup state that is deterministically recoverable.

### Apply

1. Accept only a missing manifest, the exact source digest or the exact target digest.
2. Reject any third manifest digest as out-of-band tampering.
3. Publish the canonical target through a private temporary file.
4. Flush the target before publication.
5. Re-read and verify the target digest and schema contract.
6. Publish the applied marker with create-new semantics.

On Unix the manifest replacement uses filesystem rename semantics. On Windows, where replacing an existing path through the standard library is not portable, the prepared journal and source backup make the bounded remove-and-publish interval recoverable.

### Commit

1. Create an immutable receipt containing transition and source/target digests.
2. Verify an existing receipt rather than replacing it.
3. Remove applied marker, prepared journal and source backup in bounded order.
4. Retain the receipt for independent history and status inspection.

## Recovery matrix

| Observed state | Recovery action |
|---|---|
| No transient files | No operation |
| Source backup only | Reconstruct the deterministic journal and continue |
| Prepared journal + source manifest | Publish target, mark applied and commit |
| Prepared journal + target manifest | Verify target, mark applied and commit |
| Prepared journal + immutable receipt | Verify receipt and target, then clean transient files |
| Manifest missing with valid journal + backup | Re-publish deterministic target |
| Applied marker without journal or backup | Fail closed |
| Backup digest differs from journal | Fail closed |
| Manifest digest is neither source nor target | Fail closed and preserve recovery evidence |
| Future or unknown schema | Fail closed |

## Filesystem and permission rules

- All document reads are bounded to 64 KiB.
- All journal documents reject unknown JSON fields.
- New files use unpredictable temporary names and create-new publication.
- Unix directories require private permissions and documents require mode `0600`.
- Windows reuses the NXB-151 protected-DACL and reparse-point security layer.
- Migration status validates the `state` parent before inspecting child paths.
- Receipt directories reject symlinks, reparse points and non-file entries.
- No shell or command script is executed by the migration binary.

## Source tests

The migration binary includes tests for:

- successful schema-0 to schema-1 migration;
- immutable receipt creation;
- recovery from prepared journal with the source still published;
- recovery after target publication but before applied marker creation;
- recovery from an orphan source backup created before the prepared journal;
- fail-closed rejection of manifest tampering during an active migration;
- rejection of an unsupported future schema.

## Platform acceptance harnesses

Linux:

```text
bash scripts/validate-nxb-151-migration-linux.sh
```

Windows:

```text
pwsh -NoProfile -File .\scripts\validate-nxb-151-migration-windows.ps1
```

Both harnesses require a clean exact head and Rust 1.97.1. They run formatting, package check, Clippy with warnings denied, serial migration tests, a real schema-0 fixture migration, orphan-backup recovery, receipt verification and transient-file cleanup.

Evidence is written beneath:

```text
target/nxb-validation/nxb-151-migration-<platform>-<head>.json
```

## Remaining acceptance requirements

- Actual `cargo fmt`, `check`, Clippy and tests on the pinned toolchain.
- Real Windows ACL and reparse-point execution.
- Real Linux permission and parent-directory sync execution.
- Consolidation into the final supported `nxb` command surface.
- Integration of migration status into the main product `doctor` result.

The PR remains draft until those gates complete.
