[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDirectory,

    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\NXBounty'),

    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'NXBounty'),

    [Parameter(Mandatory = $true)]
    [string]$ExpectedPublisherThumbprint,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedReleasePublicKeySha256,

    [bool]$AddToUserPath = $true,

    [bool]$CreateStartMenuShortcut = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonPath = Join-Path $PSScriptRoot 'nxb-installer-common.ps1'
if (-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) {
    throw "Installer support library is missing: $commonPath"
}
. $commonPath

if ($env:OS -ne 'Windows_NT') {
    throw 'NXBounty Windows installation is supported only on Windows.'
}

function Set-NxbUninstallEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Data,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][uint64]$ReleaseSequence,
        [Parameter(Mandatory = $true)][string]$PublisherThumbprint,
        [Parameter(Mandatory = $true)][string]$ReleasePublicKeySha256
    )

    $keyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NXBounty'
    New-Item -Path $keyPath -Force | Out-Null
    $uninstaller = Join-Path $Data 'installer\uninstall-nxb-windows.ps1'
    $command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{0}" -InstallRoot "{1}" -DataRoot "{2}" -ExpectedPublisherThumbprint {3} -ExpectedReleasePublicKeySha256 {4}' -f `
        $uninstaller, $Root, $Data, $PublisherThumbprint, $ReleasePublicKeySha256
    New-ItemProperty -Path $keyPath -Name DisplayName -Value 'NXBounty' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name DisplayVersion -Value $Version -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name ReleaseSequence -Value ([string]$ReleaseSequence) -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name Publisher -Value 'Naveax' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name InstallLocation -Value $Root -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name DisplayIcon -Value (Join-Path $Root 'nxb.exe') -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name UninstallString -Value $command -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
}

function Copy-NxbMaintenanceScripts {
    param([Parameter(Mandatory = $true)][string]$Destination)

    $required = @(
        'nxb-installer-common.ps1',
        'install-nxb-windows.ps1',
        'rollback-nxb-windows.ps1',
        'uninstall-nxb-windows.ps1'
    )
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($name in $required) {
        $source = Join-Path $PSScriptRoot $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Required maintenance script is missing: $source"
        }
        Assert-NxbNoReparseChain $source "maintenance script $name"
        Copy-Item -LiteralPath $source -Destination (Join-Path $Destination $name) -Force
    }
    Protect-NxbDirectoryAcl $Destination
}

$installRootPath = Assert-NxbManagedRoot $InstallRoot 'install root'
$dataRootPath = Assert-NxbManagedRoot $DataRoot 'data root'
$package = Get-NxbPackagePaths $PackageDirectory

if ((Test-NxbPathWithin $package.Root $installRootPath) -or
    (Test-NxbPathWithin $installRootPath $package.Root) -or
    (Test-NxbPathWithin $package.Root $dataRootPath) -or
    (Test-NxbPathWithin $dataRootPath $package.Root) -or
    (Test-NxbPathWithin $installRootPath $dataRootPath) -or
    (Test-NxbPathWithin $dataRootPath $installRootPath)) {
    throw 'Package, install and data roots must be independent directories.'
}

$publisherThumbprint = Assert-NxbAuthenticode `
    $package.Binary $ExpectedPublisherThumbprint
$releaseKeySha256 = Assert-NxbReleasePublicKey `
    $package.PublicKey $ExpectedReleasePublicKeySha256
$manifestDocument = Get-NxbManifestDocument $package.Manifest
$verification = Invoke-NxbReleaseVerification `
    $package.Binary $package.Manifest $package.PublicKey $package.Sbom $package.Checksums

if ($verification.version -ne $manifestDocument.manifest.version -or
    [uint64]$verification.release_sequence -ne [uint64]$manifestDocument.manifest.release_sequence -or
    $verification.source_commit -ne $manifestDocument.manifest.source_commit -or
    $verification.manifest_sha256 -ne $manifestDocument.manifest.manifest_sha256) {
    throw 'Candidate verification result does not match the signed manifest document.'
}

$installParent = Split-Path -Parent $installRootPath
New-Item -ItemType Directory -Path $installParent -Force | Out-Null
New-Item -ItemType Directory -Path $dataRootPath -Force | Out-Null
Protect-NxbDirectoryAcl $dataRootPath
$maintenanceRoot = Join-Path $dataRootPath 'installer'
Copy-NxbMaintenanceScripts $maintenanceRoot

$lock = Open-NxbInstallerLock $installRootPath
$stageRoot = $installRootPath + '.stage.' + [Guid]::NewGuid().ToString('N')
$previousRoot = $installRootPath + '.previous'
$existing = $null
$movedExisting = $false
$publishedStage = $false
$pathAddedThisRun = $false
$shortcutCreatedThisRun = $false
try {
    if (Test-Path -LiteralPath $installRootPath) {
        $existing = Assert-NxbInstalledRoot `
            $installRootPath $publisherThumbprint $releaseKeySha256
        $comparison = Compare-NxbReleaseOrder `
            $verification.version $verification.release_sequence `
            $existing.Verification.version $existing.Verification.release_sequence
        if ($comparison -lt 0) {
            throw "Release downgrade or replay is denied: installed=$($existing.Verification.version)+$($existing.Verification.release_sequence) candidate=$($verification.version)+$($verification.release_sequence)"
        }
        if ($comparison -eq 0) {
            if ($verification.manifest_sha256 -ne $existing.Verification.manifest_sha256) {
                throw 'Same release order with a different signed manifest is denied.'
            }
            if ($AddToUserPath) {
                [void](Add-NxbUserPath $installRootPath)
            }
            if ($CreateStartMenuShortcut) {
                [void](Set-NxbStartMenuShortcut $installRootPath)
            }
            Set-NxbUninstallEntry `
                $installRootPath $dataRootPath $verification.version `
                ([uint64]$verification.release_sequence) `
                $publisherThumbprint $releaseKeySha256
            $result = [ordered]@{
                schema_version = 2
                status = 'already_installed'
                version = $verification.version
                release_sequence = [uint64]$verification.release_sequence
                source_commit = $verification.source_commit
                manifest_sha256 = $verification.manifest_sha256
                binary_sha256 = (Get-FileHash -LiteralPath $package.Binary -Algorithm SHA256).Hash.ToLowerInvariant()
                install_root = $installRootPath
                data_root = $dataRootPath
                rollback_available = (Test-Path -LiteralPath $previousRoot -PathType Container)
                network_activity = 'none'
            }
            $result | ConvertTo-Json -Depth 8
            return
        }
        if ($verification.source_commit -eq $existing.Verification.source_commit) {
            throw 'A higher release order must bind a different exact source commit.'
        }
    }

    New-Item -ItemType Directory -Path $stageRoot | Out-Null
    foreach ($name in $script:NxbPackageFileNames) {
        Copy-Item -LiteralPath (Join-Path $package.Root $name) `
            -Destination (Join-Path $stageRoot $name)
    }
    Protect-NxbDirectoryAcl $stageRoot

    $stagePaths = Get-NxbInstalledPaths $stageRoot
    [void](Assert-NxbAuthenticode $stagePaths.Binary $publisherThumbprint)
    [void](Assert-NxbReleasePublicKey $stagePaths.PublicKey $releaseKeySha256)
    $stageVerification = Invoke-NxbReleaseVerification `
        $stagePaths.Binary $stagePaths.Manifest $stagePaths.PublicKey `
        $stagePaths.Sbom $stagePaths.Checksums
    if ($stageVerification.manifest_sha256 -ne $verification.manifest_sha256 -or
        [uint64]$stageVerification.release_sequence -ne [uint64]$verification.release_sequence -or
        $stageVerification.source_commit -ne $verification.source_commit) {
        throw 'Staged package does not match the verified source package.'
    }

    $state = [ordered]@{
        schema_version = 2
        product = 'NXBounty'
        version = $verification.version
        release_sequence = [uint64]$verification.release_sequence
        release_id = $manifestDocument.manifest.release_id
        source_commit = $verification.source_commit
        manifest_sha256 = $verification.manifest_sha256
        signature_sha256 = $verification.signature_sha256
        manifest_document_sha256 = $verification.document_sha256
        binary_sha256 = (Get-FileHash -LiteralPath $stagePaths.Binary -Algorithm SHA256).Hash.ToLowerInvariant()
        publisher_thumbprint = $publisherThumbprint
        release_public_key_sha256 = $releaseKeySha256
        install_root = $installRootPath
        data_root = $dataRootPath
        add_to_user_path = $AddToUserPath
        create_start_menu_shortcut = $CreateStartMenuShortcut
        installed_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    }
    Write-NxbJsonFile $stagePaths.State $state

    if (Test-Path -LiteralPath $previousRoot) {
        [void](Assert-NxbInstalledRoot `
            $previousRoot $publisherThumbprint $releaseKeySha256)
        Remove-Item -LiteralPath $previousRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $installRootPath) {
        Move-Item -LiteralPath $installRootPath -Destination $previousRoot
        $movedExisting = $true
    }
    Move-Item -LiteralPath $stageRoot -Destination $installRootPath
    $publishedStage = $true

    if ($AddToUserPath) {
        $pathAddedThisRun = Add-NxbUserPath $installRootPath
    }
    if ($CreateStartMenuShortcut) {
        [void](Set-NxbStartMenuShortcut $installRootPath)
        $shortcutCreatedThisRun = $true
    }
    Set-NxbUninstallEntry `
        $installRootPath $dataRootPath $verification.version `
        ([uint64]$verification.release_sequence) `
        $publisherThumbprint $releaseKeySha256

    $installed = Assert-NxbInstalledRoot `
        $installRootPath $publisherThumbprint $releaseKeySha256
    if ($installed.Verification.manifest_sha256 -ne $verification.manifest_sha256) {
        throw 'Published installation does not match the candidate release.'
    }
    if ($movedExisting) {
        Protect-NxbDirectoryAcl $previousRoot
    }
    Write-NxbJsonFile (Join-Path $maintenanceRoot 'current-install.json') $state

    $result = [ordered]@{
        schema_version = 2
        status = if ($movedExisting) { 'upgraded' } else { 'installed' }
        version = $verification.version
        release_sequence = [uint64]$verification.release_sequence
        source_commit = $verification.source_commit
        manifest_sha256 = $verification.manifest_sha256
        signature_sha256 = $verification.signature_sha256
        binary_sha256 = $state.binary_sha256
        install_root = $installRootPath
        data_root = $dataRootPath
        rollback_available = $movedExisting
        path_registered = $AddToUserPath
        shortcut_registered = $CreateStartMenuShortcut
        network_activity = 'none'
    }
    $result | ConvertTo-Json -Depth 8
}
catch {
    $failure = $_
    try {
        if ($publishedStage -and (Test-Path -LiteralPath $installRootPath)) {
            Assert-NxbNoReparseChain $installRootPath 'failed published installation'
            Remove-Item -LiteralPath $installRootPath -Recurse -Force
        }
        if ($movedExisting -and (Test-Path -LiteralPath $previousRoot)) {
            Move-Item -LiteralPath $previousRoot -Destination $installRootPath
        }
        if (Test-Path -LiteralPath $stageRoot) {
            Assert-NxbNoReparseChain $stageRoot 'failed staging directory'
            Remove-Item -LiteralPath $stageRoot -Recurse -Force
        }
        if ($pathAddedThisRun -and -not $movedExisting) {
            [void](Remove-NxbUserPath $installRootPath)
        }
        if ($shortcutCreatedThisRun -and -not $movedExisting) {
            [void](Remove-NxbStartMenuShortcut)
        }
        if ($movedExisting -and $null -ne $existing) {
            Set-NxbUninstallEntry `
                $installRootPath $dataRootPath $existing.Verification.version `
                ([uint64]$existing.Verification.release_sequence) `
                $publisherThumbprint $releaseKeySha256
        }
    }
    catch {
        Write-Error "Installer rollback also failed: $($_.Exception.Message)"
    }
    throw $failure
}
finally {
    if ($null -ne $lock) {
        $lock.Dispose()
    }
}
