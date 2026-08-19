[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\BoundSeal'),

    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'BoundSeal'),

    [Parameter(Mandatory = $true)]
    [string]$ExpectedPublisherThumbprint,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedReleasePublicKeySha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonPath = Join-Path $PSScriptRoot 'bsl-installer-common.ps1'
if (-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) {
    throw "Installer support library is missing: $commonPath"
}
. $commonPath

if ($env:OS -ne 'Windows_NT') {
    throw 'BoundSeal rollback is supported only on Windows.'
}

function Set-BslRollbackUninstallEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Data,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][uint64]$ReleaseSequence,
        [Parameter(Mandatory = $true)][string]$PublisherThumbprint,
        [Parameter(Mandatory = $true)][string]$ReleasePublicKeySha256
    )

    $keyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\BoundSeal'
    New-Item -Path $keyPath -Force | Out-Null
    $uninstaller = Join-Path $Data 'installer\uninstall-bsl-windows.ps1'
    $command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{0}" -InstallRoot "{1}" -DataRoot "{2}" -ExpectedPublisherThumbprint {3} -ExpectedReleasePublicKeySha256 {4}' -f `
        $uninstaller, $Root, $Data, $PublisherThumbprint, $ReleasePublicKeySha256
    New-ItemProperty -Path $keyPath -Name DisplayName -Value 'BoundSeal' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name DisplayVersion -Value $Version -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name ReleaseSequence -Value ([string]$ReleaseSequence) -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name Publisher -Value 'Naveax' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name InstallLocation -Value $Root -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name DisplayIcon -Value (Join-Path $Root 'bsl.exe') -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name UninstallString -Value $command -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
}

function Restore-BslIntegration {
    param(
        [Parameter(Mandatory = $true)]$Installed,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Data,
        [Parameter(Mandatory = $true)][string]$PublisherThumbprint,
        [Parameter(Mandatory = $true)][string]$ReleasePublicKeySha256
    )

    if ([bool]$Installed.State.add_to_user_path) {
        [void](Add-BslUserPath $Root)
    } else {
        [void](Remove-BslUserPath $Root)
    }
    if ([bool]$Installed.State.create_start_menu_shortcut) {
        [void](Set-BslStartMenuShortcut $Root)
    } else {
        [void](Remove-BslStartMenuShortcut)
    }
    Set-BslRollbackUninstallEntry `
        $Root $Data $Installed.Verification.version `
        ([uint64]$Installed.Verification.release_sequence) `
        $PublisherThumbprint $ReleasePublicKeySha256
}

function Restore-BslRollbackSlots {
    param(
        [Parameter(Mandatory = $true)][string]$ActiveRoot,
        [Parameter(Mandatory = $true)][string]$PreviousRoot,
        [Parameter(Mandatory = $true)][string]$FailedRoot,
        [Parameter(Mandatory = $true)][string]$ScratchRoot,
        [Parameter(Mandatory = $true)][bool]$CurrentMovedToFailed,
        [Parameter(Mandatory = $true)][bool]$PreviousPublished,
        [Parameter(Mandatory = $true)][bool]$NewerMovedToPrevious
    )

    if ($NewerMovedToPrevious) {
        if (-not (Test-Path -LiteralPath $ActiveRoot -PathType Container) -or
            -not (Test-Path -LiteralPath $PreviousRoot -PathType Container) -or
            (Test-Path -LiteralPath $FailedRoot)) {
            throw 'Completed slot swap is not in a restorable layout.'
        }
        Move-BslDirectoryStrict $ActiveRoot $ScratchRoot 'rollback active scratch publication'
        Move-BslDirectoryStrict $PreviousRoot $ActiveRoot 'rollback previous active restoration'
        Move-BslDirectoryStrict $ScratchRoot $PreviousRoot 'rollback scratch previous restoration'
        return
    }
    if ($PreviousPublished) {
        if (-not (Test-Path -LiteralPath $ActiveRoot -PathType Container) -or
            -not (Test-Path -LiteralPath $FailedRoot -PathType Container) -or
            (Test-Path -LiteralPath $PreviousRoot)) {
            throw 'Published previous slot is not in a restorable layout.'
        }
        Move-BslDirectoryStrict $ActiveRoot $PreviousRoot 'rollback active previous restoration'
        Move-BslDirectoryStrict $FailedRoot $ActiveRoot 'rollback failed-slot active restoration'
        return
    }
    if ($CurrentMovedToFailed) {
        if ((Test-Path -LiteralPath $ActiveRoot) -or
            -not (Test-Path -LiteralPath $FailedRoot -PathType Container)) {
            throw 'Moved active slot is not in a restorable layout.'
        }
        Move-BslDirectoryStrict $FailedRoot $ActiveRoot 'rollback failed-slot active restoration'
    }
}

function Backup-BslFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Backup
    )

    if (Test-Path -LiteralPath $Backup) {
        throw "Backup path already exists: $Backup"
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Assert-BslRegularFile $Path 'rollback metadata file' 1048576
        Move-Item -LiteralPath $Path -Destination $Backup
    }
}

function Restore-BslPublishedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Backup,
        [Parameter(Mandatory = $true)][bool]$Published
    )

    if ($Published -and (Test-Path -LiteralPath $Path)) {
        Remove-Item -LiteralPath $Path -Force
    }
    if (Test-Path -LiteralPath $Backup -PathType Leaf) {
        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force
        }
        Move-Item -LiteralPath $Backup -Destination $Path
    }
}

$installRootPath = Assert-BslManagedRoot $InstallRoot 'install root'
$dataRootPath = Assert-BslManagedRoot $DataRoot 'data root'
if ((Test-BslPathWithin $installRootPath $dataRootPath) -or
    (Test-BslPathWithin $dataRootPath $installRootPath)) {
    throw 'Install and data roots must be independent directories.'
}

$nonce = [Guid]::NewGuid().ToString('N')
$previousRoot = $installRootPath + '.previous'
$failedRoot = $installRootPath + '.rollback-failed.' + $nonce
$restoreScratch = $installRootPath + '.rollback-restore.' + $nonce
$maintenanceRoot = Join-Path $dataRootPath 'installer'
$currentStatePath = Join-Path $maintenanceRoot 'current-install.json'
$currentStatePending = $currentStatePath + '.pending.' + $nonce
$currentStateBackup = $currentStatePath + '.backup.' + $nonce
$receiptPath = Join-Path $maintenanceRoot 'last-rollback.json'
$receiptPending = $receiptPath + '.pending.' + $nonce
$receiptBackup = $receiptPath + '.backup.' + $nonce

$lock = Open-BslInstallerLock $installRootPath
$current = $null
$currentMovedToFailed = $false
$previousPublished = $false
$newerMovedToPrevious = $false
$currentStatePublished = $false
$receiptPublished = $false
$transactionCommitted = $false
$result = $null
try {
    $current = Assert-BslInstalledRoot `
        $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
    $previous = Assert-BslInstalledRoot `
        $previousRoot $ExpectedPublisherThumbprint `
        $ExpectedReleasePublicKeySha256 $installRootPath

    $comparison = Compare-BslReleaseOrder `
        $previous.Verification.version $previous.Verification.release_sequence `
        $current.Verification.version $current.Verification.release_sequence
    if ($comparison -ge 0) {
        throw 'Rollback slot must contain a strictly older signed release order.'
    }
    if ($previous.Verification.manifest_sha256 -eq $current.Verification.manifest_sha256 -or
        $previous.Verification.source_commit -eq $current.Verification.source_commit) {
        throw 'Rollback slot must bind a different manifest and exact source commit.'
    }

    Move-BslDirectoryStrict $installRootPath $failedRoot 'rollback active deactivation'
    $currentMovedToFailed = $true
    Move-BslDirectoryStrict $previousRoot $installRootPath 'rollback previous publication'
    $previousPublished = $true

    $restored = Assert-BslInstalledRoot `
        $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
    if ($restored.Verification.manifest_sha256 -ne $previous.Verification.manifest_sha256 -or
        [uint64]$restored.Verification.release_sequence -ne [uint64]$previous.Verification.release_sequence) {
        throw 'Published rollback installation does not match the validated previous slot.'
    }

    Restore-BslIntegration `
        $restored $installRootPath $dataRootPath `
        $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
    Protect-BslDirectoryAcl $installRootPath
    Protect-BslDirectoryAcl $failedRoot

    New-Item -ItemType Directory -Path $maintenanceRoot -Force | Out-Null
    Protect-BslDirectoryAcl $maintenanceRoot

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
    Write-BslJsonFile $currentStatePending $restored.State
    Write-BslJsonFile $receiptPending $receipt

    Move-BslDirectoryStrict $failedRoot $previousRoot 'rollback newer previous preservation'
    $newerMovedToPrevious = $true
    $preserved = Assert-BslInstalledRoot `
        $previousRoot $ExpectedPublisherThumbprint `
        $ExpectedReleasePublicKeySha256 $installRootPath
    if ($preserved.Verification.manifest_sha256 -ne $current.Verification.manifest_sha256) {
        throw 'Newer release was not preserved in the previous slot.'
    }

    Backup-BslFile $currentStatePath $currentStateBackup
    Backup-BslFile $receiptPath $receiptBackup
    Move-Item -LiteralPath $currentStatePending -Destination $currentStatePath
    $currentStatePublished = $true
    Move-Item -LiteralPath $receiptPending -Destination $receiptPath
    $receiptPublished = $true

    $result = $receipt
    $transactionCommitted = $true
}
catch {
    $failure = $_
    if (-not $transactionCommitted) {
        try {
            Restore-BslPublishedFile `
                $currentStatePath $currentStateBackup $currentStatePublished
            Restore-BslPublishedFile `
                $receiptPath $receiptBackup $receiptPublished
            Remove-Item -LiteralPath $currentStatePending -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $receiptPending -Force -ErrorAction SilentlyContinue

            Restore-BslRollbackSlots `
                $installRootPath $previousRoot $failedRoot $restoreScratch `
                $currentMovedToFailed $previousPublished $newerMovedToPrevious
            if ($null -ne $current -and
                (Test-Path -LiteralPath $installRootPath -PathType Container)) {
                $recovered = Assert-BslInstalledRoot `
                    $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
                if ($recovered.Verification.manifest_sha256 -ne $current.Verification.manifest_sha256) {
                    throw 'Rollback restoration recovered the wrong active release.'
                }
                Restore-BslIntegration `
                    $recovered $installRootPath $dataRootPath `
                    $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
            }
        }
        catch {
            Write-Error "Rollback restoration also failed: $($_.Exception.Message)"
        }
    }
    throw $failure
}
finally {
    if ($null -ne $lock) {
        $lock.Dispose()
    }
}

if ($transactionCommitted) {
    foreach ($path in @($currentStateBackup, $receiptBackup, $restoreScratch)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $result | ConvertTo-Json -Depth 8
}
