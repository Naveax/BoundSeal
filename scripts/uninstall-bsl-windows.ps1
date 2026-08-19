[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\BoundSeal'),

    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'BoundSeal'),

    [Parameter(Mandatory = $true)]
    [string]$ExpectedPublisherThumbprint,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedReleasePublicKeySha256,

    [switch]$PurgeData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonPath = Join-Path $PSScriptRoot 'bsl-installer-common.ps1'
if (-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) {
    throw "Installer support library is missing: $commonPath"
}
. $commonPath

if ($env:OS -ne 'Windows_NT') {
    throw 'BoundSeal uninstall is supported only on Windows.'
}

function Set-BslUninstallEntryForRestore {
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

function Restore-BslUninstallIntegration {
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
    Set-BslUninstallEntryForRestore `
        $Root $Data $Installed.Verification.version `
        ([uint64]$Installed.Verification.release_sequence) `
        $PublisherThumbprint $ReleasePublicKeySha256
}

function Publish-BslUninstallReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Nonce
    )

    $pending = $Path + '.pending.' + $Nonce
    $backup = $Path + '.backup.' + $Nonce
    $backedUp = $false
    $published = $false
    try {
        Write-BslJsonFile $pending $Value
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            Assert-BslRegularFile $Path 'previous uninstall receipt' 1048576
            Move-Item -LiteralPath $Path -Destination $backup
            $backedUp = $true
        }
        Move-Item -LiteralPath $pending -Destination $Path
        $published = $true
    }
    catch {
        if ($published -and (Test-Path -LiteralPath $Path)) {
            Remove-Item -LiteralPath $Path -Force
        }
        if ($backedUp -and (Test-Path -LiteralPath $backup -PathType Leaf)) {
            Move-Item -LiteralPath $backup -Destination $Path
        }
        Remove-Item -LiteralPath $pending -Force -ErrorAction SilentlyContinue
        throw
    }
    finally {
        if ($published) {
            Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
        }
    }
}

$installRootPath = Assert-BslManagedRoot $InstallRoot 'install root'
$dataRootPath = Assert-BslManagedRoot $DataRoot 'data root'
if ((Test-BslPathWithin $installRootPath $dataRootPath) -or
    (Test-BslPathWithin $dataRootPath $installRootPath)) {
    throw 'Install and data roots must be independent directories.'
}

$previousRoot = $installRootPath + '.previous'
$nonce = [Guid]::NewGuid().ToString('N')
$currentTombstone = $installRootPath + '.uninstall.' + $nonce
$previousTombstone = $previousRoot + '.uninstall.' + $nonce
$lock = Open-BslInstallerLock $installRootPath
$current = $null
$previous = $null
$receipt = $null
$cleanupWarnings = [Collections.Generic.List[string]]::new()
try {
    try {
        $current = Assert-BslInstalledRoot `
            $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
        if (Test-Path -LiteralPath $previousRoot) {
            $previous = Assert-BslInstalledRoot `
                $previousRoot $ExpectedPublisherThumbprint `
                $ExpectedReleasePublicKeySha256 $installRootPath
        }

        Move-BslDirectoryStrict $installRootPath $currentTombstone 'uninstall active deactivation'
        if ($null -ne $previous) {
            Move-BslDirectoryStrict $previousRoot $previousTombstone 'uninstall previous deactivation'
        }

        [void](Remove-BslUserPath $installRootPath)
        [void](Remove-BslStartMenuShortcut)
        $uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\BoundSeal'
        if (Test-Path -LiteralPath $uninstallKey) {
            Remove-Item -LiteralPath $uninstallKey -Recurse -Force
        }

        $receipt = [ordered]@{
            schema_version = 2
            status = 'uninstalled'
            version = $current.Verification.version
            release_sequence = [uint64]$current.Verification.release_sequence
            source_commit = $current.Verification.source_commit
            manifest_sha256 = $current.Verification.manifest_sha256
            binary_sha256 = $current.State.binary_sha256
            install_root = $installRootPath
            data_root = $dataRootPath
            data_preserved = (-not $PurgeData)
            rollback_slot_deactivated = ($null -ne $previous)
            cleanup_complete = $false
            cleanup_warnings = @()
            uninstalled_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
            network_activity = 'none'
        }
    }
    catch {
        $failure = $_
        try {
            if (Test-Path -LiteralPath $currentTombstone -PathType Container) {
                if (Test-Path -LiteralPath $installRootPath) {
                    throw 'Cannot restore active installation because its root is occupied.'
                }
                Move-BslDirectoryStrict $currentTombstone $installRootPath 'failed uninstall active restoration'
            }
            if (Test-Path -LiteralPath $previousTombstone -PathType Container) {
                if (Test-Path -LiteralPath $previousRoot) {
                    throw 'Cannot restore rollback slot because its root is occupied.'
                }
                Move-BslDirectoryStrict $previousTombstone $previousRoot 'failed uninstall previous restoration'
            }
            if ($null -ne $current -and
                (Test-Path -LiteralPath $installRootPath -PathType Container)) {
                $restored = Assert-BslInstalledRoot `
                    $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
                Restore-BslUninstallIntegration `
                    $restored $installRootPath $dataRootPath `
                    $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
            }
        }
        catch {
            Write-Error "Uninstall restoration also failed: $($_.Exception.Message)"
        }
        throw $failure
    }

    # Active paths and Windows integrations are now gone. Cleanup failures below
    # must never recreate integrations that point to missing binaries.
    foreach ($entry in @(
        [pscustomobject]@{ Path = $currentTombstone; Label = 'active uninstall tombstone' },
        [pscustomobject]@{ Path = $previousTombstone; Label = 'rollback uninstall tombstone' }
    )) {
        if (Test-Path -LiteralPath $entry.Path) {
            try {
                Assert-BslNoReparseChain $entry.Path $entry.Label
                Remove-Item -LiteralPath $entry.Path -Recurse -Force
            }
            catch {
                $cleanupWarnings.Add("$($entry.Label): $($_.Exception.Message)")
            }
        }
    }

    $installerStateRoot = Join-Path $dataRootPath 'installer'
    if ($PurgeData) {
        if (Test-Path -LiteralPath $dataRootPath) {
            try {
                Assert-BslNoReparseChain $dataRootPath 'data root purge target'
                Remove-Item -LiteralPath $dataRootPath -Recurse -Force
            }
            catch {
                $cleanupWarnings.Add("data root purge: $($_.Exception.Message)")
            }
        }
    } else {
        try {
            New-Item -ItemType Directory -Path $installerStateRoot -Force | Out-Null
            Protect-BslDirectoryAcl $installerStateRoot
            Remove-Item -LiteralPath (Join-Path $installerStateRoot 'current-install.json') `
                -Force -ErrorAction SilentlyContinue
        }
        catch {
            $cleanupWarnings.Add("installer state cleanup: $($_.Exception.Message)")
        }
    }

    $receipt.data_preserved = Test-Path -LiteralPath $dataRootPath -PathType Container
    $receipt.cleanup_complete = ($cleanupWarnings.Count -eq 0)
    $receipt.cleanup_warnings = @($cleanupWarnings)
    if (-not $receipt.cleanup_complete) {
        $receipt.status = 'uninstalled_cleanup_incomplete'
    }

    if (-not $PurgeData -and (Test-Path -LiteralPath $installerStateRoot -PathType Container)) {
        try {
            Publish-BslUninstallReceipt `
                (Join-Path $installerStateRoot 'last-uninstall.json') $receipt $nonce
        }
        catch {
            $cleanupWarnings.Add("uninstall receipt: $($_.Exception.Message)")
            $receipt.cleanup_complete = $false
            $receipt.cleanup_warnings = @($cleanupWarnings)
            $receipt.status = 'uninstalled_cleanup_incomplete'
        }
    }

    $receipt | ConvertTo-Json -Depth 8
}
finally {
    if ($null -ne $lock) {
        $lock.Dispose()
    }
}
