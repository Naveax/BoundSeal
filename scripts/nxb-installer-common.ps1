Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:NxbInstallerSchemaVersion = 1
$script:NxbPackageFileNames = @(
    'nxb.exe',
    'nxb.cdx.json',
    'SHA256SUMS',
    'nxb-release-manifest.json',
    'release-public-key.hex'
)

function Get-NxbCanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.Contains([string][char]0) -or
        $Path.Contains("`r") -or
        $Path.Contains("`n")) {
        throw 'Path is empty or contains forbidden control characters.'
    }
    return [IO.Path]::GetFullPath($Path)
}

function Test-NxbPathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $candidatePath = (Get-NxbCanonicalPath $Candidate).TrimEnd('\')
    $parentPath = (Get-NxbCanonicalPath $Parent).TrimEnd('\')
    return $candidatePath.StartsWith(
        $parentPath + '\',
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-NxbNoReparseChain {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Get-NxbCanonicalPath $Path
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

function Assert-NxbManagedRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Get-NxbCanonicalPath $Path
    $driveRoot = [IO.Path]::GetPathRoot($fullPath).TrimEnd('\')
    if ($fullPath.TrimEnd('\').Equals($driveRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must not be a drive root."
    }
    $windowsRoot = [Environment]::GetFolderPath('Windows').TrimEnd('\')
    if (-not [string]::IsNullOrWhiteSpace($windowsRoot) -and
        ($fullPath.TrimEnd('\').Equals($windowsRoot, [StringComparison]::OrdinalIgnoreCase) -or
         (Test-NxbPathWithin $fullPath $windowsRoot))) {
        throw "$Label must not be inside the Windows directory."
    }
    Assert-NxbNoReparseChain $fullPath $Label
    return $fullPath
}

function Assert-NxbRegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [long]$MaximumBytes = 536870912
    )

    Assert-NxbNoReparseChain $Path $Label
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing or is not a regular file: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "$Label size is outside the supported boundary."
    }
}

function Get-NxbPackagePaths {
    param([Parameter(Mandatory = $true)][string]$PackageDirectory)

    $root = Get-NxbCanonicalPath $PackageDirectory
    Assert-NxbNoReparseChain $root 'package directory'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "Package directory is missing: $root"
    }
    $entries = @(Get-ChildItem -LiteralPath $root -Force)
    if ($entries.Count -ne $script:NxbPackageFileNames.Count) {
        throw 'Package directory must contain exactly the five supported release files.'
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not ($script:NxbPackageFileNames -contains $entry.Name)) {
            throw "Package directory contains an unsupported entry: $($entry.Name)"
        }
    }

    $paths = [pscustomobject]@{
        Root = $root
        Binary = Join-Path $root 'nxb.exe'
        Sbom = Join-Path $root 'nxb.cdx.json'
        Checksums = Join-Path $root 'SHA256SUMS'
        Manifest = Join-Path $root 'nxb-release-manifest.json'
        PublicKey = Join-Path $root 'release-public-key.hex'
    }
    Assert-NxbRegularFile $paths.Binary 'candidate nxb.exe'
    Assert-NxbRegularFile $paths.Sbom 'candidate CycloneDX SBOM' 33554432
    Assert-NxbRegularFile $paths.Checksums 'candidate checksum manifest' 1048576
    Assert-NxbRegularFile $paths.Manifest 'candidate signed release manifest' 65536
    Assert-NxbRegularFile $paths.PublicKey 'candidate release public key' 4096
    return $paths
}

function Normalize-NxbHex {
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

function Assert-NxbAuthenticode {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$ExpectedPublisherThumbprint
    )

    $expected = Normalize-NxbHex $ExpectedPublisherThumbprint 40 'publisher certificate thumbprint'
    $signature = Get-AuthenticodeSignature -LiteralPath $BinaryPath
    if ($signature.Status.ToString() -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
        throw "Authenticode verification failed for $BinaryPath with status $($signature.Status)."
    }
    $actual = Normalize-NxbHex $signature.SignerCertificate.Thumbprint 40 'actual publisher certificate thumbprint'
    if ($actual -ne $expected) {
        throw 'Authenticode signer does not match the pinned publisher certificate.'
    }
    return $actual
}

function Assert-NxbReleasePublicKey {
    param(
        [Parameter(Mandatory = $true)][string]$PublicKeyPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    $expected = Normalize-NxbHex $ExpectedSha256 64 'release public-key SHA-256'
    $actual = (Get-FileHash -LiteralPath $PublicKeyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw 'Release public key does not match the pinned SHA-256 trust anchor.'
    }
    $keyText = [IO.File]::ReadAllText($PublicKeyPath).Trim()
    [void](Normalize-NxbHex $keyText 64 'release public key')
    return $actual
}

function Invoke-NxbReleaseVerification {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$PublicKeyPath,
        [Parameter(Mandatory = $true)][string]$SbomPath,
        [Parameter(Mandatory = $true)][string]$ChecksumsPath
    )

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('nxb-verify-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $stdoutPath = Join-Path $temporaryRoot 'stdout.json'
    $stderrPath = Join-Path $temporaryRoot 'stderr.json'
    try {
        & $BinaryPath @(
            'release', 'verify-manifest',
            '--document', $ManifestPath,
            '--public-key', $PublicKeyPath,
            '--binary', $BinaryPath,
            '--sbom', $SbomPath,
            '--checksums', $ChecksumsPath,
            '--json'
        ) 1>$stdoutPath 2>$stderrPath
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
        if ($value.status -ne 'valid' -or $value.network_activity -ne 'none') {
            throw 'Signed release verifier returned an invalid success document.'
        }
        return $value
    }
    finally {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-NxbManifestDocument {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $value = [IO.File]::ReadAllText($ManifestPath) | ConvertFrom-Json
    if ($null -eq $value.manifest -or
        $value.manifest.manifest_version -ne 1 -or
        $value.manifest.product -ne 'NXBounty' -or
        $value.manifest.platform -ne 'windows' -or
        $value.manifest.architecture -ne 'x86_64' -or
        $value.manifest.binary.file_name -ne 'nxb.exe') {
        throw 'Signed release manifest is not a supported Windows x86_64 package.'
    }
    return $value
}

function Compare-NxbVersion {
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

function Protect-NxbDirectoryAcl {
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

function Open-NxbInstallerLock {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $parent = Split-Path -Parent (Get-NxbCanonicalPath $InstallRoot)
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Assert-NxbNoReparseChain $parent 'install parent'
    return [IO.File]::Open(
        (Join-Path $parent '.nxbounty-install.lock'),
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}

function Add-NxbUserPath {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $canonical = (Get-NxbCanonicalPath $InstallRoot).TrimEnd('\')
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

function Remove-NxbUserPath {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $canonical = (Get-NxbCanonicalPath $InstallRoot).TrimEnd('\')
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

function Set-NxbStartMenuShortcut {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $directory = Join-Path ([Environment]::GetFolderPath('Programs')) 'NXBounty'
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $shortcutPath = Join-Path $directory 'NXBounty.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $InstallRoot 'nxb.exe'
    $shortcut.Arguments = '--help'
    $shortcut.WorkingDirectory = $InstallRoot
    $shortcut.Description = 'NXBounty command-line security research tool'
    $shortcut.Save()
    return $shortcutPath
}

function Remove-NxbStartMenuShortcut {
    $directory = Join-Path ([Environment]::GetFolderPath('Programs')) 'NXBounty'
    if (Test-Path -LiteralPath $directory) {
        Remove-Item -LiteralPath $directory -Recurse -Force
        return $true
    }
    return $false
}

function Write-NxbJsonFile {
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

function Get-NxbInstalledPaths {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $root = Get-NxbCanonicalPath $InstallRoot
    return [pscustomobject]@{
        Root = $root
        Binary = Join-Path $root 'nxb.exe'
        Sbom = Join-Path $root 'nxb.cdx.json'
        Checksums = Join-Path $root 'SHA256SUMS'
        Manifest = Join-Path $root 'nxb-release-manifest.json'
        PublicKey = Join-Path $root 'release-public-key.hex'
        State = Join-Path $root 'install-state.json'
    }
}

function Assert-NxbInstalledRoot {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedPublisherThumbprint,
        [Parameter(Mandatory = $true)][string]$ExpectedReleasePublicKeySha256
    )

    $paths = Get-NxbInstalledPaths $InstallRoot
    $paths.Root = Assert-NxbManagedRoot $paths.Root 'installed NXBounty root'
    if (-not (Test-Path -LiteralPath $paths.Root -PathType Container)) {
        throw "Installed NXBounty root is missing: $($paths.Root)"
    }
    foreach ($name in @('Binary', 'Sbom', 'Checksums', 'Manifest', 'PublicKey', 'State')) {
        Assert-NxbRegularFile $paths.$name "installed $name"
    }
    [void](Assert-NxbAuthenticode $paths.Binary $ExpectedPublisherThumbprint)
    [void](Assert-NxbReleasePublicKey $paths.PublicKey $ExpectedReleasePublicKeySha256)
    $verification = Invoke-NxbReleaseVerification `
        $paths.Binary $paths.Manifest $paths.PublicKey $paths.Sbom $paths.Checksums
    $state = [IO.File]::ReadAllText($paths.State) | ConvertFrom-Json
    if ($state.schema_version -ne $script:NxbInstallerSchemaVersion -or
        $state.product -ne 'NXBounty' -or
        $state.install_root -ne $paths.Root -or
        $state.manifest_sha256 -ne $verification.manifest_sha256 -or
        $state.source_commit -ne $verification.source_commit -or
        $state.version -ne $verification.version) {
        throw 'Installed state does not match the verified release package.'
    }
    return [pscustomobject]@{
        Paths = $paths
        State = $state
        Verification = $verification
    }
}
