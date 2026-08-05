# NXBounty NXB-151 Quick Start

## Current status

NXB-151 is a draft product milestone. The supported product shape is one executable:

```text
nxb.exe   # Windows
nxb       # Linux
```

The commands below describe the intended exact-head acceptance flow. They are not a release claim until the pinned Rust 1.97.1, Windows and Linux gates pass and PRs #68 and #70 are merged.

## Safety model

Before using NXB on a real program:

- read the current program policy;
- confirm that automated testing is allowed;
- record a current authorization policy snapshot;
- use only accounts, tenants and assets that you are authorized to test;
- keep automatic submission disabled;
- do not place cookies, tokens, passwords or API keys in workspace JSON files.

A local target profile narrows product behavior. It does **not** prove ownership, permission or program scope.

## 1. Create a private workspace

Windows PowerShell:

```powershell
.\nxb.exe workspace init `
  --workspace "$HOME\NXBounty" `
  --name "My NXBounty Workspace" `
  --json
```

Linux:

```bash
./nxb workspace init \
  --workspace "$HOME/NXBounty" \
  --name 'My NXBounty Workspace' \
  --json
```

The product creates a fixed schema-versioned layout and stores no secret values.

## 2. Check workspace health

```text
nxb workspace doctor --workspace <workspace> --json
nxb workspace status --workspace <workspace> --json
```

Expected healthy state:

```json
{
  "status": "healthy",
  "migration": {
    "status": "stable"
  }
}
```

A pending migration blocks target and later product operations. Recover it explicitly:

```text
nxb workspace migrate recover --workspace <workspace> --json
```

## 3. Create one narrow target profile

```text
nxb target create \
  --workspace <workspace> \
  --id example-app \
  --name "Example App" \
  --origin https://example.org \
  --include-path /api \
  --exclude-path /api/logout \
  --json
```

The profile is networkless and immutable. It fixes the later method boundary to:

```text
GET
HEAD
OPTIONS
```

Review it:

```text
nxb target show --workspace <workspace> --id example-app --json
nxb target list --workspace <workspace> --json
```

Disable it without modifying the original profile:

```text
nxb target disable \
  --workspace <workspace> \
  --id example-app \
  --reason operator-hold \
  --json
```

Disabling publishes a separate SHA-256-bound receipt. NXB-151 does not support reactivation.

## 4. Validate a program policy

NXB requires a separately reviewed TOML program policy. The repository contains a local synthetic fixture for acceptance only:

```text
fixtures/nxb-151/synthetic-policy.toml
```

Validate it without network access:

```text
nxb validate-policy \
  --path fixtures/nxb-151/synthetic-policy.toml \
  --now 2026-08-05T12:00:00Z
```

Do not reuse the synthetic fixture as authorization for any real asset.

## 5. Produce a networkless scan and report bundle

```text
nxb scan \
  --program fixtures/nxb-151/synthetic-policy.toml \
  --target https://example.org/ \
  --output-directory <workspace>/reports/synthetic-run \
  --run-id synthetic-run-001 \
  --maximum-depth 1 \
  --maximum-endpoints 16 \
  --maximum-requests 8 \
  --dry-run true \
  --now 2026-08-05T12:00:00Z
```

This command does not contact the target. Without a supplied local response snapshot, it produces a bounded plan and explicitly records untested areas.

Expected artifacts:

```text
scan-plan.json
report.json
report.md
hackerone-draft.md
manifest.json
```

The HackerOne document is a manual-review draft only. NXB does not submit it.

## 6. Generate and verify the architecture receipt

```text
nxb demo-run --output <workspace>/reports/demo-receipt.json
nxb verify-demo <workspace>/reports/demo-receipt.json
```

## 7. Confirm final local state

```text
nxb workspace doctor --workspace <workspace> --json
nxb workspace status --workspace <workspace> --json
nxb system-status
```

## Machine-readable failures

Product commands invoked with `--json` emit a versioned diagnostic JSON document on stderr and preserve operation-specific exit codes.

Example:

```json
{
  "schema_version": 1,
  "status": "error",
  "code": "NXB151-TARGET-CREATE-REJECTED",
  "domain": "target",
  "operation": "create",
  "exit_code": 50,
  "message": "..."
}
```

Automation must use `code` and `exit_code`, not parse the message.

## Full synthetic acceptance

Linux:

```bash
bash scripts/validate-nxb-151-synthetic-linux.sh
```

Windows:

```powershell
pwsh -NoProfile -File .\scripts\validate-nxb-151-synthetic-windows.ps1
```

These harnesses execute the full sequence using the pinned toolchain, a clean exact head and the single `nxb` executable. They generate local evidence under:

```text
target/nxb-validation/
```

No successful acceptance result is claimed until those files are generated and reviewed on the same final head.
