# NXB-151 Windows Installer Lifecycle

## Purpose

The Windows lifecycle installs the single `nxb.exe` product only after two independent trust checks:

1. Windows Authenticode validation against a pinned publisher certificate thumbprint.
2. NXBounty Ed25519 manifest-v2 validation against a pinned release-public-key file SHA-256.

The candidate executable is never run before its Authenticode signature and exact publisher certificate are validated. After that bootstrap check, the candidate executes its networkless `release verify-manifest` command to verify its own bytes, CycloneDX SBOM, checksum manifest, source commit, monotonic release sequence and external Ed25519 signature.

No installer operation downloads files or contacts a network service.

## Package contract

`-PackageDirectory` must contain exactly five private regular files:

```text
nxb.exe
nxb.cdx.json
SHA256SUMS
nxb-release-manifest.json
release-public-key.hex
```

Nested directories, extra files, symlinks, junctions and reparse points are rejected. Installer scripts are distributed separately and are not Cargo binary targets.

## Install command

```powershell
.\scripts\install-nxb-windows.ps1 `
  -PackageDirectory C:\path\to\release `
  -ExpectedPublisherThumbprint <40-hex-cert-thumbprint> `
  -ExpectedReleasePublicKeySha256 <64-hex-file-sha256>
```

Defaults:

```text
Install root: %LOCALAPPDATA%\Programs\NXBounty
Data root:    %LOCALAPPDATA%\NXBounty
```

Optional integration:

```powershell
-AddToUserPath $true|$false
-CreateStartMenuShortcut $true|$false
```

Package, install and data roots must be independent. Equality and nesting in either direction are rejected.

## Bootstrap trust sequence

Before publication, the installer requires:

- exact five-file layout;
- no reparse point in any path component;
- valid Authenticode status for `nxb.exe`;
- exact signer-certificate thumbprint;
- exact release-public-key file SHA-256;
- 32-byte lowercase hexadecimal Ed25519 public key;
- Windows x86_64 NXBounty manifest schema `2`;
- positive bounded release sequence;
- successful networkless `verify-manifest` result.

Checksum equality alone is never sufficient.

## Signed release ordering

The installer orders releases by:

```text
(SemVer, release_sequence)
```

Rules:

- lower SemVer is denied;
- equal SemVer with lower sequence is denied as downgrade/replay;
- equal order is idempotent only for the exact same manifest SHA-256;
- equal order with different evidence is denied;
- higher order must bind a different exact source commit;
- rollback requires a strictly lower signed order and different source commit.

This permits two source revisions to remain package version `0.1.0` while receiving signed sequences `1` and `2`. The sequence is part of the Ed25519 payload, so it cannot be changed after signing.

## Atomic install and upgrade

The transaction uses an exclusive sibling lock and unique protected staging directory:

1. Validate source package.
2. Validate existing installation.
3. Compare signed release order.
4. Reject downgrade, replay or sequence-only reissue of the same source commit.
5. Copy exactly five files to staging.
6. Re-run Authenticode, key and Ed25519 verification against staging.
7. Write schema-v2 `install-state.json`.
8. Move current installation to `<InstallRoot>.previous`.
9. Atomically publish staging.
10. Register bounded PATH, Start Menu and HKCU uninstall integration.
11. Revalidate final installation.

Failure removes staging and restores the prior installation and its integrations.

## Installed state

The install root contains exactly:

```text
nxb.exe
nxb.cdx.json
SHA256SUMS
nxb-release-manifest.json
release-public-key.hex
install-state.json
```

Unexpected entries are rejected. State schema `2` records:

- SemVer and release sequence;
- release ID and exact source commit;
- manifest, signature, document and binary SHA-256 values;
- publisher thumbprint and release-key file SHA-256;
- install/data roots and integration policy;
- UTC installation timestamp.

## Rollback

```powershell
.\scripts\rollback-nxb-windows.ps1 `
  -ExpectedPublisherThumbprint <thumbprint> `
  -ExpectedReleasePublicKeySha256 <sha256>
```

Both current and previous slots must pass complete verification. The previous slot must have a strictly lower signed release order, different manifest and different source commit.

Rollback moves the current release to a temporary failure slot, publishes the previous release and revalidates it. Only then is the newer release stored as the new previous slot. If a later step fails, files, PATH, shortcut and uninstall registry data are restored to the newer release.

The receipt records both SemVer values, release sequences, source commits and manifest SHA-256 values.

## Uninstall

```powershell
.\scripts\uninstall-nxb-windows.ps1 `
  -ExpectedPublisherThumbprint <thumbprint> `
  -ExpectedReleasePublicKeySha256 <sha256>
```

Active and rollback installations are verified before deletion. Roots are moved to tombstones before integration removal. Failure restores roots and integration metadata, including release sequence.

The data root is preserved by default. Explicit data deletion requires:

```powershell
-PurgeData
```

Uninstall receipts use schema `2` and bind the removed release sequence.

## ACL and integration boundary

Install, rollback and maintenance directories receive protected per-user ACLs granting full control only to the current user and Local System.

When enabled, integration consists of:

- one exact user PATH entry;
- one NXBounty Start Menu shortcut;
- one HKCU uninstall record including `DisplayVersion` and `ReleaseSequence`.

Uninstall removes only NXBounty-owned entries.

## Two-revision acceptance harness

```powershell
pwsh -NoProfile -File .\scripts\validate-nxb-151-installer-windows.ps1
```

The default previous source is:

```text
a8aef038449edbe1dbe1ecc6d57e160f82f44c7b
```

It is an ancestor containing manifest-v2 support. The harness:

1. validates the final clean exact head;
2. builds the final head with Rust 1.97.1;
3. creates a detached worktree for the previous exact commit and builds it;
4. signs both binaries with one temporary trusted Authenticode certificate;
5. creates one external Ed25519 key;
6. produces signed sequence-1 and sequence-2 packages;
7. installs sequence 1;
8. verifies idempotent reinstall;
9. upgrades to sequence 2;
10. rejects sequence-1 replay/downgrade;
11. rolls back sequence 2 to sequence 1;
12. upgrades to sequence 2 again;
13. rejects an Authenticode-tampered package;
14. uninstalls while preserving a data sentinel;
15. writes exact-head, two-source and two-manifest evidence.

The previous commit must resolve to a distinct ancestor of the final head. The same package SemVer is intentional; signed release sequence supplies the revision order.

## Validation status

Source and harness coverage are present. No successful Windows result is claimed until the harness runs on Windows with Rust 1.97.1, Authenticode support and OpenSSL Ed25519 support on one unchanged final head. PR #70 remains draft.
