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
- preserve the exact policy bytes reviewed by the operator;
- preserve a separate authorization document or approval export;
- use only accounts, tenants and assets that you are authorized to test;
- keep automatic submission disabled;
- do not place cookies, tokens, passwords or API keys in workspace JSON files.

A local target profile narrows product behavior and binds source digests. It does **not** prove that an authorization document is genuine or sufficient.

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

## 3. Prepare and validate source documents

NXB target profiles require two local source files:

```text
<program-policy.toml>
<authorization-document>
```

The policy is parsed and compiled. The authorization document is treated as opaque bytes and is only represented in the profile by SHA-256 plus a safe external reference.

Validate the policy without network access:

```text
nxb validate-policy \
  --path <program-policy.toml> \
  --now <current-rfc3339-time>
```

The repository contains synthetic fixtures for acceptance only:

```text
fixtures/nxb-151/synthetic-policy.toml
fixtures/nxb-151/synthetic-authorization.txt
```

They are not authorization to test any real asset.

## 4. Create and validate one narrow target profile

```text
nxb target create \
  --workspace <workspace> \
  --id example-app \
  --name "Example App" \
  --origin https://example.org \
  --include-path /api \
  --exclude-path /api/logout \
  --authorization-reference <safe-program-or-approval-reference> \
  --authorization-document <authorization-document> \
  --policy <program-policy.toml> \
  --json
```

The profile is networkless, immutable and contains only safe metadata and source digests. Raw policy bytes, authorization bytes and local source paths are not persisted.

Re-read the current source files and verify that their SHA-256 values, policy scope, program metadata and method intersection still match:

```text
nxb target validate \
  --workspace <workspace> \
  --id example-app \
  --authorization-document <authorization-document> \
  --policy <program-policy.toml> \
  --json
```

Review the stored profile:

```text
nxb target show --workspace <workspace> --id example-app --json
nxb target list --workspace <workspace> --json
```

The stored method set is the intersection of the supplied policy and the product maximum:

```text
GET
HEAD
OPTIONS
```

Disable the target without modifying the original profile:

```text
nxb target disable \
  --workspace <workspace> \
  --id example-app \
  --reason operator-hold \
  --json
```

Disabling publishes a separate SHA-256-bound receipt. NXB-151 does not support reactivation.

## 5. Produce a networkless scan and report bundle

```text
nxb scan \
  --program <program-policy.toml> \
  --target https://example.org/ \
  --output-directory <workspace>/reports/synthetic-run \
  --run-id synthetic-run-001 \
  --maximum-depth 1 \
  --maximum-endpoints 16 \
  --maximum-requests 8 \
  --dry-run true \
  --now <current-rfc3339-time>
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

Automation must use `code` and `exit_code`, not parse the message. `target validate` failures use exit code `54` and diagnostic code `NXB151-TARGET-VALIDATE-INVALID`.

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
