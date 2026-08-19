Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:BslInstallerSchemaVersion = 3
$script:BslLegacyInstallerSchemaVersion = 2
$script:BslBundledHelperFileName =
    'bsl-windows-credential-evidence-key-helper.exe'

$script:BslPackageFileNames = @(
    'bsl.exe',
    $script:BslBundledHelperFileName,
    'bsl.cdx.json',
    'SHA256SUMS',
    'bsl-release-manifest.json',
    'release-public-key.hex'
)

$script:BslInstalledFileNames = @(
    'bsl.exe',
    $script:BslBundledHelperFileName,
    'bsl.cdx.json',
    'SHA256SUMS',
    'bsl-release-manifest.json',
    'release-public-key.hex',
    'install-state.json'
)

$script:BslLegacyInstalledFileNames = @(
    'bsl.exe',
    'bsl.cdx.json',
    'SHA256SUMS',
    'bsl-release-manifest.json',
    'release-public-key.hex',
    'install-state.json'
)

function Get-BslCanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.Contains([string][char]0) -or
        $Path.Contains("`r") -or
        $Path.Contains("`n")) {
        throw 'Path is empty or contains forbidden control characters.'
    }
    return [IO.Path]::GetFullPath($Path)
}

function Test-BslPathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $candidatePath = (Get-BslCanonicalPath $Candidate).TrimEnd('\')
    $parentPath = (Get-BslCanonicalPath $Parent).TrimEnd('\')
    return $candidatePath.Equals($parentPath, [StringComparison]::OrdinalIgnoreCase) -or
        $candidatePath.StartsWith(
            $parentPath + '\',
            [StringComparison]::OrdinalIgnoreCase
        )
}

function Assert-BslNoReparseChain {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Get-BslCanonicalPath $Path
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label has no filesystem root."
    }
    $relative = $fullPath.Substring($root.Length)
    $segments = $relative.Split(
        [char[]]@('\'),
        [StringSplitOptions]::RemoveEmptyEntries
    )
    $current = $root.TrimEnd('\')
    foreach ($segment in $segments) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            continue
        }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a symbolic link, junction or reparse point: $current"
        }
    }
}

function Assert-BslManagedRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Get-BslCanonicalPath $Path
    $driveRoot = ([IO.Path]::GetPathRoot($fullPath)).TrimEnd('\')
    if ($fullPath.TrimEnd('\').Equals($driveRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must not be a drive root."
    }
    $windowsRoot = ([Environment]::GetFolderPath('Windows')).TrimEnd('\')
    if (-not [string]::IsNullOrWhiteSpace($windowsRoot) -and
        (Test-BslPathWithin $fullPath $windowsRoot)) {
        throw "$Label must not be inside the Windows directory."
    }
    Assert-BslNoReparseChain $fullPath $Label
    return $fullPath
}

function Move-BslDirectoryStrict {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $sourcePath = Assert-BslManagedRoot $Source "$Label source"
    $destinationPath = Assert-BslManagedRoot $Destination "$Label destination"

    if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
        throw "$Label source directory is missing: $sourcePath"
    }

    if (Test-Path -LiteralPath $destinationPath) {
        throw "$Label destination already exists: $destinationPath"
    }

    $sourceParent = Get-BslCanonicalPath (
        Split-Path -Parent $sourcePath
    )

    $destinationParent = Get-BslCanonicalPath (
        Split-Path -Parent $destinationPath
    )

    if (-not $sourceParent.Equals(
        $destinationParent,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Label must remain within one parent directory."
    }

    try {
        [IO.Directory]::Move(
            $sourcePath,
            $destinationPath
        )
    }
    catch {
        $sourceStillExists = (
            Test-Path -LiteralPath $sourcePath
        )

        $destinationExists = (
            Test-Path -LiteralPath $destinationPath
        )

        if ($sourceStillExists -and $destinationExists) {
            throw (
                "$Label failed and left both source and destination present. " +
                "source=$sourcePath destination=$destinationPath " +
                "error=$($_.Exception.Message)"
            )
        }

        throw
    }

    if (Test-Path -LiteralPath $sourcePath) {
        throw (
            "$Label completed but source still exists: $sourcePath"
        )
    }

    if (-not (
        Test-Path `
            -LiteralPath $destinationPath `
            -PathType Container
    )) {
        throw (
            "$Label completed without a destination directory: " +
            $destinationPath
        )
    }
}
function Assert-BslRegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [long]$MaximumBytes = 536870912
    )

    Assert-BslNoReparseChain $Path $Label
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing or is not a regular file: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or
        $item.Length -gt $MaximumBytes) {
        throw "$Label size, type or indirection state is outside the supported boundary."
    }
}

function Assert-BslExactDirectoryEntries {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string[]]$ExpectedNames,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-BslNoReparseChain $Directory $Label
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw "$Label is missing: $Directory"
    }
    $entries = @(Get-ChildItem -LiteralPath $Directory -Force)
    if ($entries.Count -ne $ExpectedNames.Count) {
        throw "$Label contains an unexpected number of entries."
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not ($ExpectedNames -contains $entry.Name)) {
            throw "$Label contains an unsupported entry: $($entry.Name)"
        }
    }
}

function Get-BslPackagePaths {
    param([Parameter(Mandatory = $true)][string]$PackageDirectory)

    $root = Get-BslCanonicalPath $PackageDirectory
    Assert-BslExactDirectoryEntries $root $script:BslPackageFileNames 'package directory'
    $paths = [pscustomobject]@{
        Root = $root
        Binary = Join-Path $root 'bsl.exe'
        Helper = Join-Path $root $script:BslBundledHelperFileName
        Sbom = Join-Path $root 'bsl.cdx.json'
        Checksums = Join-Path $root 'SHA256SUMS'
        Manifest = Join-Path $root 'bsl-release-manifest.json'
        PublicKey = Join-Path $root 'release-public-key.hex'
    }
    Assert-BslRegularFile $paths.Binary 'candidate bsl.exe'
    Assert-BslRegularFile $paths.Helper 'candidate bundled credential helper'
    Assert-BslRegularFile $paths.Sbom 'candidate CycloneDX SBOM' 33554432
    Assert-BslRegularFile $paths.Checksums 'candidate checksum manifest' 1048576
    Assert-BslRegularFile $paths.Manifest 'candidate signed release manifest' 65536
    Assert-BslRegularFile $paths.PublicKey 'candidate release public key' 4096
    return $paths
}

function Normalize-BslHex {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $normalized = $Value.Replace(' ', '').ToLowerInvariant()
    if ($normalized.Length -ne $Length -or $normalized -notmatch '^[0-9a-f]+$') {
        throw "$Label must contain exactly $Length hexadecimal characters."
    }
    return $normalized
}

function Get-BslChecksumSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ChecksumsPath,

        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [switch]$AllowMissing
    )

    Assert-BslRegularFile `
        $ChecksumsPath `
        'checksum manifest' `
        1048576

    $text = [IO.File]::ReadAllText($ChecksumsPath)

    if ([string]::IsNullOrEmpty($text) -or
        -not $text.EndsWith("`n") -or
        $text.Contains("`r") -or
        $text.Contains([string][char]0)) {
        throw 'Checksum manifest is not canonical LF-terminated text.'
    }

    $body = $text.Substring(0, $text.Length - 1)

    if ([string]::IsNullOrEmpty($body)) {
        throw 'Checksum manifest is empty.'
    }

    $entries =
        [Collections.Generic.Dictionary[string,string]]::new(
            [StringComparer]::Ordinal
        )

    foreach ($line in $body.Split("`n")) {
        $match = [regex]::Match(
            $line,
            '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$'
        )

        if (-not $match.Success) {
            throw 'Checksum manifest contains an invalid canonical line.'
        }

        $sha256 = $match.Groups[1].Value
        $name = $match.Groups[2].Value

        if ($entries.ContainsKey($name)) {
            throw "Checksum manifest contains duplicate file name: $name"
        }

        $entries.Add($name, $sha256)
    }

    if (-not $entries.ContainsKey($FileName)) {
        if ($AllowMissing) {
            return $null
        }

        throw "Checksum manifest does not bind required file: $FileName"
    }

    return $entries[$FileName]
}

function Assert-BslBundledHelperBinding {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HelperPath,

        [Parameter(Mandatory = $true)]
        [string]$ChecksumsPath
    )

    Assert-BslRegularFile `
        $HelperPath `
        'bundled credential helper'

    $expected = Get-BslChecksumSha256 `
        $ChecksumsPath `
        $script:BslBundledHelperFileName

    $actual = (
        Get-FileHash `
            -LiteralPath $HelperPath `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()

    if ($actual -ne $expected) {
        throw 'Bundled credential helper does not match the signed checksum manifest.'
    }

    return $actual
}

function Assert-BslReleaseSequence {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        $sequence = [uint64]$Value
    }
    catch {
        throw "$Label must be an unsigned integer."
    }
    if ($sequence -eq 0 -or $sequence -gt [uint64][int64]::MaxValue) {
        throw "$Label must be between 1 and 9223372036854775807."
    }
    return $sequence
}

function Assert-BslAuthenticode {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$ExpectedPublisherThumbprint
    )

    $expected = Normalize-BslHex $ExpectedPublisherThumbprint 40 'publisher certificate thumbprint'
    $signature = Get-AuthenticodeSignature -LiteralPath $BinaryPath
    if ($signature.Status.ToString() -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
        throw "Authenticode verification failed for $BinaryPath with status $($signature.Status)."
    }
    $actual = Normalize-BslHex $signature.SignerCertificate.Thumbprint 40 'actual publisher certificate thumbprint'
    if ($actual -ne $expected) {
        throw 'Authenticode signer does not match the pinned publisher certificate.'
    }
    return $actual
}

function Assert-BslReleasePublicKey {
    param(
        [Parameter(Mandatory = $true)][string]$PublicKeyPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    $expected = Normalize-BslHex $ExpectedSha256 64 'release public-key SHA-256'
    $actual = (Get-FileHash -LiteralPath $PublicKeyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw 'Release public key does not match the pinned SHA-256 trust anchor.'
    }
    $keyText = [IO.File]::ReadAllText($PublicKeyPath).Trim()
    [void](Normalize-BslHex $keyText 64 'release public key')
    return $actual
}

function Invoke-BslReleaseVerification {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$PublicKeyPath,
        [Parameter(Mandatory = $true)][string]$SbomPath,
        [Parameter(Mandatory = $true)][string]$ChecksumsPath
    )

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('bsl-verify-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    Protect-BslDirectoryAcl $temporaryRoot
    $stdoutPath = Join-Path $temporaryRoot 'stdout.json'
    $stderrPath = Join-Path $temporaryRoot 'stderr.json'
    $arguments = @(
        'release', 'verify-manifest',
        '--document', $ManifestPath,
        '--public-key', $PublicKeyPath,
        '--binary', $BinaryPath,
        '--sbom', $SbomPath,
        '--checksums', $ChecksumsPath,
        '--json'
    )
    try {
        & $BinaryPath @arguments 1>$stdoutPath 2>$stderrPath
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            $errorText = if (Test-Path -LiteralPath $stderrPath) {
                [IO.File]::ReadAllText($stderrPath)
            } else {
                ''
            }
            throw "Signed release verification failed with exit code $exitCode. $errorText"
        }
        $value = [IO.File]::ReadAllText($stdoutPath) | ConvertFrom-Json
        if ($value.status -ne 'valid' -or
            $value.network_activity -ne 'none' -or
            (Assert-BslReleaseSequence $value.release_sequence 'verified release sequence') -ne [uint64]$value.release_sequence) {
            throw 'Signed release verifier returned an invalid success document.'
        }
        return $value
    }
    finally {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-BslManifestDocument {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $value = [IO.File]::ReadAllText($ManifestPath) | ConvertFrom-Json
    if ($null -eq $value.manifest -or
        $value.manifest.manifest_version -ne 2 -or
        $value.manifest.product -ne 'BoundSeal' -or
        $value.manifest.platform -ne 'windows' -or
        $value.manifest.architecture -ne 'x86_64' -or
        $value.manifest.binary.file_name -ne 'bsl.exe') {
        throw 'Signed release manifest is not a supported Windows x86_64 package.'
    }
    [void](Assert-BslReleaseSequence $value.manifest.release_sequence 'manifest release sequence')
    return $value
}

function Compare-BslVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    $pattern = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
    $leftMatch = [regex]::Match($Left, $pattern)
    $rightMatch = [regex]::Match($Right, $pattern)
    if (-not $leftMatch.Success -or -not $rightMatch.Success) {
        throw 'Installer currently accepts stable three-component semantic versions only.'
    }
    for ($index = 1; $index -le 3; $index++) {
        $leftValue = [uint64]$leftMatch.Groups[$index].Value
        $rightValue = [uint64]$rightMatch.Groups[$index].Value
        if ($leftValue -lt $rightValue) { return -1 }
        if ($leftValue -gt $rightValue) { return 1 }
    }
    return 0
}

function Compare-BslReleaseOrder {
    param(
        [Parameter(Mandatory = $true)][string]$LeftVersion,
        [Parameter(Mandatory = $true)]$LeftSequence,
        [Parameter(Mandatory = $true)][string]$RightVersion,
        [Parameter(Mandatory = $true)]$RightSequence
    )

    $versionComparison = Compare-BslVersion $LeftVersion $RightVersion
    if ($versionComparison -ne 0) {
        return $versionComparison
    }
    $left = Assert-BslReleaseSequence $LeftSequence 'left release sequence'
    $right = Assert-BslReleaseSequence $RightSequence 'right release sequence'
    if ($left -lt $right) { return -1 }
    if ($left -gt $right) { return 1 }
    return 0
}

function Protect-BslDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Cannot protect missing directory: $Path"
    }
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    if (-not (Test-Path -LiteralPath $icacls -PathType Leaf)) {
        throw 'icacls.exe is unavailable.'
    }
    & $icacls $Path '/inheritance:r' '/grant:r' `
        ('*{0}:(OI)(CI)F' -f $userSid) `
        '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not apply protected ACL to $Path"
    }
}

function Open-BslInstallerLock {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $parent = Split-Path -Parent (Get-BslCanonicalPath $InstallRoot)
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Assert-BslNoReparseChain $parent 'install parent'
    return [IO.File]::Open(
        (Join-Path $parent '.boundseal-install.lock'),
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}

function Add-BslUserPath {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $canonical = (Get-BslCanonicalPath $InstallRoot).TrimEnd('\')
    $raw = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = if ([string]::IsNullOrWhiteSpace($raw)) {
        @()
    } else {
        @($raw.Split(';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    foreach ($entry in $entries) {
        if ($entry.Trim().TrimEnd('\').Equals($canonical, [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }
    [Environment]::SetEnvironmentVariable('Path', (@($entries + $canonical) -join ';'), 'User')
    return $true
}

function Remove-BslUserPath {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $canonical = (Get-BslCanonicalPath $InstallRoot).TrimEnd('\')
    $raw = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ([string]::IsNullOrWhiteSpace($raw)) { return $false }
    $entries = @($raw.Split(';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $filtered = @($entries | Where-Object {
        -not $_.Trim().TrimEnd('\').Equals($canonical, [StringComparison]::OrdinalIgnoreCase)
    })
    if ($filtered.Count -eq $entries.Count) { return $false }
    [Environment]::SetEnvironmentVariable('Path', ($filtered -join ';'), 'User')
    return $true
}

function Set-BslStartMenuShortcut {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $directory = Join-Path ([Environment]::GetFolderPath('Programs')) 'BoundSeal'
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $shortcutPath = Join-Path $directory 'BoundSeal.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $InstallRoot 'bsl.exe'
    $shortcut.Arguments = '--help'
    $shortcut.WorkingDirectory = $InstallRoot
    $shortcut.Description = 'BoundSeal command-line security research tool'
    $shortcut.Save()
    return $shortcutPath
}

function Remove-BslStartMenuShortcut {
    $directory = Join-Path ([Environment]::GetFolderPath('Programs')) 'BoundSeal'
    if (Test-Path -LiteralPath $directory) {
        Remove-Item -LiteralPath $directory -Recurse -Force
        return $true
    }
    return $false
}

function Write-BslJsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    [IO.File]::WriteAllText(
        $Path,
        (($Value | ConvertTo-Json -Depth 12) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false)
    )
}

function Get-BslInstalledPaths {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $root = Get-BslCanonicalPath $InstallRoot

    return [pscustomobject]@{
        Root = $root
        Binary = Join-Path $root 'bsl.exe'
        Helper = Join-Path $root $script:BslBundledHelperFileName
        Sbom = Join-Path $root 'bsl.cdx.json'
        Checksums = Join-Path $root 'SHA256SUMS'
        Manifest = Join-Path $root 'bsl-release-manifest.json'
        PublicKey = Join-Path $root 'release-public-key.hex'
        State = Join-Path $root 'install-state.json'
    }
}

function Assert-BslInstalledRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallRoot,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedPublisherThumbprint,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedReleasePublicKeySha256,

        [string]$ExpectedStateInstallRoot = ''
    )

    $paths = Get-BslInstalledPaths $InstallRoot
    $paths.Root = Assert-BslManagedRoot `
        $paths.Root `
        'installed BoundSeal root'

    $expectedStateInstallRoot =
        if ([string]::IsNullOrWhiteSpace(
            $ExpectedStateInstallRoot
        )) {
            $paths.Root
        }
        else {
            Assert-BslManagedRoot `
                $ExpectedStateInstallRoot `
                'expected installed-state root'
        }

    #
    # Before executing bsl.exe, permit only one of the two known
    # revision layouts. This blocks arbitrary extra local binaries/DLLs
    # before the signed verifier process is started.
    #

    $physicalHelperPresent =
        Test-Path `
            -LiteralPath $paths.Helper `
            -PathType Leaf

    $physicalExpectedNames =
        if ($physicalHelperPresent) {
            $script:BslInstalledFileNames
        }
        else {
            $script:BslLegacyInstalledFileNames
        }

    Assert-BslExactDirectoryEntries `
        $paths.Root `
        $physicalExpectedNames `
        'installed BoundSeal root'

    foreach ($name in @(
        'Binary',
        'Sbom',
        'Checksums',
        'Manifest',
        'PublicKey',
        'State'
    )) {
        Assert-BslRegularFile `
            $paths.$name `
            "installed $name"
    }

    if ($physicalHelperPresent) {
        Assert-BslRegularFile `
            $paths.Helper `
            'installed bundled credential helper'
    }

    [void](
        Assert-BslAuthenticode `
            $paths.Binary `
            $ExpectedPublisherThumbprint
    )

    [void](
        Assert-BslReleasePublicKey `
            $paths.PublicKey `
            $ExpectedReleasePublicKeySha256
    )

    #
    # The verifier authenticates the SHA256SUMS artifact through the
    # signed manifest before the helper entry is trusted.
    #

    $verification = Invoke-BslReleaseVerification `
        $paths.Binary `
        $paths.Manifest `
        $paths.PublicKey `
        $paths.Sbom `
        $paths.Checksums

    $signedHelperSha256 = Get-BslChecksumSha256 `
        $paths.Checksums `
        $script:BslBundledHelperFileName `
        -AllowMissing

    if ($physicalHelperPresent -and
        [string]::IsNullOrWhiteSpace($signedHelperSha256)) {
        throw 'Installed helper exists but the signed checksum manifest does not bind it.'
    }

    if (-not $physicalHelperPresent -and
        -not [string]::IsNullOrWhiteSpace($signedHelperSha256)) {
        throw 'Signed checksum manifest requires a bundled helper that is missing.'
    }

    $expectedSchemaVersion =
        if ($physicalHelperPresent) {
            $script:BslInstallerSchemaVersion
        }
        else {
            $script:BslLegacyInstallerSchemaVersion
        }

    $helperSha256 =
        if ($physicalHelperPresent) {
            Assert-BslBundledHelperBinding `
                $paths.Helper `
                $paths.Checksums
        }
        else {
            $null
        }

    $state =
        [IO.File]::ReadAllText(
            $paths.State
        ) |
        ConvertFrom-Json

    $helperStateProperty =
        $state.PSObject.Properties['helper_sha256']

    $stateHelperSha256 =
        if ($null -eq $helperStateProperty) {
            ''
        }
        else {
            [string]$state.helper_sha256
        }

    $helperStateMatches =
        if ($physicalHelperPresent) {
            $stateHelperSha256 -eq $helperSha256
        }
        else {
            [string]::IsNullOrWhiteSpace(
                $stateHelperSha256
            )
        }

    if ($state.schema_version -ne $expectedSchemaVersion -or
        $state.product -ne 'BoundSeal' -or
        $state.install_root -ne $expectedStateInstallRoot -or
        $state.manifest_sha256 -ne $verification.manifest_sha256 -or
        $state.source_commit -ne $verification.source_commit -or
        $state.version -ne $verification.version -or
        [uint64]$state.release_sequence -ne
            [uint64]$verification.release_sequence -or
        -not $helperStateMatches) {

        $diagnostic = [ordered]@{
            schema_match = (
                $state.schema_version -eq
                $expectedSchemaVersion
            )
            state_schema =
                [string]$state.schema_version
            expected_schema =
                [string]$expectedSchemaVersion

            product_match =
                ($state.product -eq 'BoundSeal')
            state_product =
                [string]$state.product
            expected_product =
                'BoundSeal'

            install_root_match = (
                $state.install_root -eq
                $expectedStateInstallRoot
            )
            state_install_root =
                [string]$state.install_root
            expected_install_root =
                [string]$expectedStateInstallRoot

            manifest_sha256_match = (
                $state.manifest_sha256 -eq
                $verification.manifest_sha256
            )
            state_manifest_sha256 =
                [string]$state.manifest_sha256
            expected_manifest_sha256 =
                [string]$verification.manifest_sha256

            source_commit_match = (
                $state.source_commit -eq
                $verification.source_commit
            )
            state_source_commit =
                [string]$state.source_commit
            expected_source_commit =
                [string]$verification.source_commit

            version_match = (
                $state.version -eq
                $verification.version
            )
            state_version =
                [string]$state.version
            expected_version =
                [string]$verification.version

            release_sequence_match = (
                [uint64]$state.release_sequence -eq
                [uint64]$verification.release_sequence
            )
            state_release_sequence =
                [string]$state.release_sequence
            expected_release_sequence =
                [string]$verification.release_sequence

            helper_layout =
                if ($physicalHelperPresent) {
                    'bundled'
                }
                else {
                    'legacy'
                }

            helper_state_match =
                $helperStateMatches

            state_helper_sha256 =
                $stateHelperSha256

            expected_helper_sha256 =
                if ($null -eq $helperSha256) {
                    ''
                }
                else {
                    $helperSha256
                }
        }

        throw (
            'Installed state does not match the verified release package. diagnostic=' +
            (
                $diagnostic |
                ConvertTo-Json `
                    -Depth 4 `
                    -Compress
            )
        )
    }

    [void](
        Assert-BslReleaseSequence `
            $state.release_sequence `
            'installed release sequence'
    )

    return [pscustomobject]@{
        Paths = $paths
        State = $state
        Verification = $verification
        HelperSha256 = $helperSha256
        BundledHelper = $physicalHelperPresent
    }
}