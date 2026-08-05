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
    New-ItemProperty -Path $keyPath -Name Publisher -Value 'Naveax' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name InstallLocation -Value $Root -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name DisplayIcon -Value (Join-Path $Root 'nxb.exe') -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name UninstallString -Value $command -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
}

$installRootPath = Assert-NxbManagedRoot $InstallRoot 'install root'
$dataRootPath = Assert-NxbManagedRoot $DataRoot 'data root'
$previousRoot = $installRootPath + '.previous'
$failedRoot = $installRootPath + '.rollback-failed.' + [Guid]::NewGuid().ToString('N')
$maintenanceRoot = Join-Path $dataRootPath 'installer'

$lock = Open-NxbInstallerLock $installRootPath
$currentMoved = $false
$previousPublished = $false
try {
    $current = Assert-NxbInstalledRoot `
        $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
    $previous = Assert-NxbInstalledRoot `
        $previousRoot $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256

    if ((Compare-NxbVersion $previous.Verification.version $current.Verification.version) -ge 0) {
        throw 'Rollback slot must contain a strictly older semantic version.'
    }
    if ($previous.Verification.manifest_sha256 -eq $current.Verification.manifest_sha256) {
        throw 'Rollback slot must not contain the currently installed manifest.'
    }

    Move-Item -LiteralPath $installRootPath -Destination $failedRoot
    $currentMoved = $true
    Move-Item -LiteralPath $previousRoot -Destination $installRootPath
    $previousPublished = $true

    $restored = Assert-NxbInstalledRoot `
        $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
    if ($restored.Verification.manifest_sha256 -ne $previous.Verification.manifest_sha256) {
        throw 'Published rollback installation does not match the validated previous slot.'
    }

    if ($restored.State.add_to_user_path) {
        [void](Add-NxbUserPath $installRootPath)
    } else {
        [void](Remove-NxbUserPath $installRootPath)
    }
    if ($restored.State.create_start_menu_shortcut) {
        [void](Set-NxbStartMenuShortcut $installRootPath)
    } else {
        [void](Remove-NxbStartMenuShortcut)
    }
    Set-NxbRollbackUninstallEntry `
        $installRootPath $dataRootPath $restored.Verification.version `
        $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256

    Move-Item -LiteralPath $failedRoot -Destination $previousRoot
    $currentMoved = $false
    Protect-NxbDirectoryAcl $installRootPath
    Protect-NxbDirectoryAcl $previousRoot
    New-Item -ItemType Directory -Path $maintenanceRoot -Force | Out-Null
    Write-NxbJsonFile `
        (Join-Path $maintenanceRoot 'current-install.json') $restored.State

    $receipt = [ordered]@{
        schema_version = 1
        status = 'rolled_back'
        from_version = $current.Verification.version
        from_source_commit = $current.Verification.source_commit
        from_manifest_sha256 = $current.Verification.manifest_sha256
        to_version = $restored.Verification.version
        to_source_commit = $restored.Verification.source_commit
        to_manifest_sha256 = $restored.Verification.manifest_sha256
        newer_version_preserved_in_previous_slot = $true
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
            if (-not (Test-Path -LiteralPath $previousRoot)) {
                Move-Item -LiteralPath $installRootPath -Destination $previousRoot
            } else {
                Remove-Item -LiteralPath $installRootPath -Recurse -Force
            }
        }
        if ($currentMoved -and (Test-Path -LiteralPath $failedRoot)) {
            Move-Item -LiteralPath $failedRoot -Destination $installRootPath
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
