[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\NXBounty'),

    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'NXBounty'),

    [Parameter(Mandatory = $true)]
    [string]$ExpectedPublisherThumbprint,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedReleasePublicKeySha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonPath = Join-Path $PSScriptRoot 'nxb-installer-common.ps1'
if (-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) {
    throw "Installer support library is missing: $commonPath"
}
. $commonPath

if ($env:OS -ne 'Windows_NT') {
    throw 'NXBounty rollback is supported only on Windows.'
}

function Set-NxbRollbackUninstallEntry {
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

function Restore-NxbIntegration {
    param(
        [Parameter(Mandatory = $true)]$Installed,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Data,
        [Parameter(Mandatory = $true)][string]$PublisherThumbprint,
        [Parameter(Mandatory = $true)][string]$ReleasePublicKeySha256
    )

    if ($Installed.State.add_to_user_path) {
        [void](Add-NxbUserPath $Root)
    } else {
        [void](Remove-NxbUserPath $Root)
    }
    if ($Installed.State.create_start_menu_shortcut) {
        [void](Set-NxbStartMenuShortcut $Root)
    } else {
        [void](Remove-NxbStartMenuShortcut)
    }
    Set-NxbRollbackUninstallEntry `
        $Root $Data $Installed.Verification.version `
        ([uint64]$Installed.Verification.release_sequence) `
        $PublisherThumbprint $ReleasePublicKeySha256
}

$installRootPath = Assert-NxbManagedRoot $InstallRoot 'install root'
$dataRootPath = Assert-NxbManagedRoot $DataRoot 'data root'
if ((Test-NxbPathWithin $installRootPath $dataRootPath) -or
    (Test-NxbPathWithin $dataRootPath $installRootPath)) {
    throw 'Install and data roots must be independent directories.'
}

$previousRoot = $installRootPath + '.previous'
$failedRoot = $installRootPath + '.rollback-failed.' + [Guid]::NewGuid().ToString('N')
$maintenanceRoot = Join-Path $dataRootPath 'installer'

$lock = Open-NxbInstallerLock $installRootPath
$currentMoved = $false
$previousPublished = $false
$current = $null
try {
    $current = Assert-NxbInstalledRoot `
        $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
    $previous = Assert-NxbInstalledRoot `
        $previousRoot $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256

    $comparison = Compare-NxbReleaseOrder `
        $previous.Verification.version $previous.Verification.release_sequence `
        $current.Verification.version $current.Verification.release_sequence
    if ($comparison -ge 0) {
        throw 'Rollback slot must contain a strictly older signed release order.'
    }
    if ($previous.Verification.manifest_sha256 -eq $current.Verification.manifest_sha256 -or
        $previous.Verification.source_commit -eq $current.Verification.source_commit) {
        throw 'Rollback slot must bind a different manifest and exact source commit.'
    }

    Move-Item -LiteralPath $installRootPath -Destination $failedRoot
    $currentMoved = $true
    Move-Item -LiteralPath $previousRoot -Destination $installRootPath
    $previousPublished = $true

    $restored = Assert-NxbInstalledRoot `
        $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
    if ($restored.Verification.manifest_sha256 -ne $previous.Verification.manifest_sha256 -or
        [uint64]$restored.Verification.release_sequence -ne [uint64]$previous.Verification.release_sequence) {
        throw 'Published rollback installation does not match the validated previous slot.'
    }

    Restore-NxbIntegration `
        $restored $installRootPath $dataRootPath `
        $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256

    Move-Item -LiteralPath $failedRoot -Destination $previousRoot
    $currentMoved = $false
    Protect-NxbDirectoryAcl $installRootPath
    Protect-NxbDirectoryAcl $previousRoot
    New-Item -ItemType Directory -Path $maintenanceRoot -Force | Out-Null
    Protect-NxbDirectoryAcl $maintenanceRoot
    Write-NxbJsonFile `
        (Join-Path $maintenanceRoot 'current-install.json') $restored.State

    $receipt = [ordered]@{
        schema_version = 2
        status = 'rolled_back'
        from_version = $current.Verification.version
        from_release_sequence = [uint64]$current.Verification.release_sequence
        from_source_commit = $current.Verification.source_commit
        from_manifest_sha256 = $current.Verification.manifest_sha256
        to_version = $restored.Verification.version
        to_release_sequence = [uint64]$restored.Verification.release_sequence
        to_source_commit = $restored.Verification.source_commit
        to_manifest_sha256 = $restored.Verification.manifest_sha256
        newer_release_preserved_in_previous_slot = $true
        install_root = $installRootPath
        data_root = $dataRootPath
        rolled_back_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        network_activity = 'none'
    }
    Write-NxbJsonFile `
        (Join-Path $maintenanceRoot 'last-rollback.json') $receipt
    $receipt | ConvertTo-Json -Depth 8
}
catch {
    $failure = $_
    try {
        if ($previousPublished -and (Test-Path -LiteralPath $installRootPath)) {
            Assert-NxbNoReparseChain $installRootPath 'failed rollback publication'
            if (-not (Test-Path -LiteralPath $previousRoot)) {
                Move-Item -LiteralPath $installRootPath -Destination $previousRoot
            } else {
                Remove-Item -LiteralPath $installRootPath -Recurse -Force
            }
        }
        if ($currentMoved -and (Test-Path -LiteralPath $failedRoot)) {
            Move-Item -LiteralPath $failedRoot -Destination $installRootPath
        }
        if ($null -ne $current -and (Test-Path -LiteralPath $installRootPath)) {
            $recovered = Assert-NxbInstalledRoot `
                $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
            Restore-NxbIntegration `
                $recovered $installRootPath $dataRootPath `
                $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
        }
    }
    catch {
        Write-Error "Rollback restoration also failed: $($_.Exception.Message)"
    }
    throw $failure
}
finally {
    if ($null -ne $lock) {
        $lock.Dispose()
    }
}
