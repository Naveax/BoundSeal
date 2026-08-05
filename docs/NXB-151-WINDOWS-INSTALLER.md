# NXB-151 Windows Installer Lifecycle

## Purpose

The NXB-151 Windows installer lifecycle installs the single `nxb.exe` product only after two independent trust checks:

1. Windows Authenticode validation against an operator-pinned publisher certificate thumbprint.
2. NXBounty Ed25519 release-manifest validation against an operator-pinned public-key file SHA-256.

The candidate executable is never run before its Authenticode signature and exact publisher certificate are validated. After that bootstrap check, the candidate executes its networkless `release verify-manifest` command to verify its own binary bytes, CycloneDX SBOM, checksum manifest, source commit and external Ed25519 signature.

No installer operation downloads files or contacts a network service.

## Package contract

`-PackageDirectory` must contain exactly five private regular release files:

```text
nxb.exe
nxb.cdx.json
SHA256SUMS
nxb-release-manifest.json
release-public-key.hex
```

Nested directories, extra files, symlinks, junctions and Windows reparse points are rejected.

The installer scripts are distributed separately from this five-file release payload:

```text
nxb-installer-common.ps1
install-nxb-windows.ps1
rollback-nxb-windows.ps1
uninstall-nxb-windows.ps1
```

They are maintenance scripts, not additional Cargo binary targets.

## Install and upgrade command

```powershell
.\scripts\install-nxb-windows.ps1 `
  -PackageDirectory C:\path\to\release `
  -ExpectedPublisherThumbprint <40-hex-cert-thumbprint> `
  -ExpectedReleasePublicKeySha256 <64-hex-file-sha256>
```

Default paths:

```text
Install root: %LOCALAPPDATA%\Programs\NXBounty
Data root:    %LOCALAPPDATA%\NXBounty
```

Optional behavior:

```powershell
-AddToUserPath $true|$false
-CreateStartMenuShortcut $true|$false
```

## Bootstrap trust sequence

Before any installation directory is created or switched, the installer requires:

- exact five-file package layout;
- no reparse point in any package path component;
- valid Authenticode status for `nxb.exe`;
- exact signer-certificate thumbprint equality;
- exact release-public-key file SHA-256 equality;
- a 32-byte lowercase hexadecimal Ed25519 public key;
- valid Windows x86_64 NXBounty release manifest;
- successful `nxb.exe release verify-manifest` result;
- `network_activity: none` in the verifier response.

Checksum equality alone is never sufficient.

## Atomic install transaction

The install script uses an exclusive sibling lock file and a unique staging directory.

The transaction is:

1. Validate the source package.
2. Validate any existing installation.
3. Reject version downgrade.
4. Reject same-version replacement when the signed manifest differs.
5. Copy exactly the five release files into a private staging directory.
6. Re-run Authenticode, public-key and Ed25519 release verification against the staged copy.
7. Write bounded `install-state.json` metadata.
8. Move the current installation to `<InstallRoot>.previous` when upgrading.
9. Atomically move the staged directory to the final install root.
10. Register optional user PATH and Start Menu integration.
11. Register the per-user Windows uninstall entry.
12. Revalidate the final published installation.

If publication or integration fails, the staged installation is removed and the prior installation is restored.

## Version boundary

The initial installer contract accepts stable three-component semantic versions:

```text
MAJOR.MINOR.PATCH
```

A candidate version lower than the installed version is rejected. A candidate with the same version is idempotent only when its signed manifest SHA-256 is identical. A same-version package with different release evidence is rejected.

## Installed files

The install root contains:

```text
nxb.exe
nxb.cdx.json
SHA256SUMS
nxb-release-manifest.json
release-public-key.hex
install-state.json
```

Only `nxb.exe` is an executable product target. The remaining files are immutable release evidence and local installation state.

`install-state.json` records:

- package and schema identity;
- version and release ID;
- exact source commit;
- manifest, signature and document SHA-256 values;
- executable SHA-256;
- publisher certificate thumbprint;
- release-public-key file SHA-256;
- install and data roots;
- PATH and shortcut policy;
- UTC installation timestamp.

## Rollback

```powershell
.\scripts\rollback-nxb-windows.ps1 `
  -ExpectedPublisherThumbprint <thumbprint> `
  -ExpectedReleasePublicKeySha256 <sha256>
```

Rollback requires both the current root and `<InstallRoot>.previous` to pass the complete Authenticode and Ed25519 verification chain. The previous slot must contain a strictly older semantic version and a different signed manifest.

The current installation is moved to a temporary failure slot, the previous version is published, and the restored version is revalidated. Only then is the newer version moved into the previous slot. If any step fails, the newer installation is restored.

The rollback receipt records both source commits and manifest SHA-256 values. No workspace or user data is moved.

## Uninstall

```powershell
.\scripts\uninstall-nxb-windows.ps1 `
  -ExpectedPublisherThumbprint <thumbprint> `
  -ExpectedReleasePublicKeySha256 <sha256>
```

Before deletion, uninstall verifies the active installation and any rollback slot. The roots are first moved to unique tombstone directories, then PATH, Start Menu and registry integration are removed. If cleanup fails, the installation and integrations are restored.

The data root is preserved by default. This includes workspaces, evidence and operator state outside the install root.

Explicit data deletion requires:

```powershell
-PurgeData
```

## ACL boundary

Install, rollback and installer-maintenance directories receive protected per-user ACLs. Inheritance is removed and full control is granted only to:

- the current user SID;
- Local System.

Unexpected reparse points cause fail-closed rejection before copy, move or deletion.

## Windows integration

When enabled, the installer creates:

- one exact user PATH entry for the install root;
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\NXBounty\NXBounty.lnk`;
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\NXBounty`.

Uninstall removes only the exact NXBounty PATH entry and NXBounty Start Menu directory. Other user PATH entries are preserved.

## Acceptance harness

```powershell
pwsh -NoProfile -File .\scripts\validate-nxb-151-installer-windows.ps1
```

The harness requires Rust 1.97.1 and OpenSSL with Ed25519 support. It:

- parses all installer scripts with the PowerShell language parser;
- runs Rust format, check, Clippy, tests and release build;
- creates and trusts a temporary self-signed code-signing certificate;
- Authenticode-signs the candidate `nxb.exe`;
- creates an external OpenSSL Ed25519 release key;
- produces and signs a canonical NXBounty release manifest;
- performs a clean installation;
- repeats the installation idempotently;
- rejects an Authenticode-tampered executable;
- uninstalls while preserving a data sentinel;
- writes exact-head evidence under `target/nxb-validation/`.

A positive upgrade and rollback execution requires two distinct, correctly signed NXBounty versions. Until that version pair exists, the harness records those two runtime checks as pending rather than claiming success.

## Current validation status

The installer, rollback, uninstall and acceptance sources are present on the NXB-151 draft branch. No successful Windows acceptance result is claimed yet because the current environment has no available Rust/Windows execution path. PR #70 remains draft.
