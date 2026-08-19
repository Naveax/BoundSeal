[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDirectory,

    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\BoundSeal'),

    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'BoundSeal'),

    [Parameter(Mandatory = $true)]
    [string]$ExpectedPublisherThumbprint,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedReleasePublicKeySha256,

    [bool]$AddToUserPath = $true,

    [bool]$CreateStartMenuShortcut = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonPath = Join-Path $PSScriptRoot 'bsl-installer-common.ps1'
if (-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) {
    throw "Installer support library is missing: $commonPath"
}
. $commonPath

if ($env:OS -ne 'Windows_NT') {
    throw 'BoundSeal Windows installation is supported only on Windows.'
}

function Set-BslUninstallEntry {
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

function Remove-BslUninstallEntry {
    $keyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\BoundSeal'
    if (Test-Path -LiteralPath $keyPath) {
        Remove-Item -LiteralPath $keyPath -Recurse -Force
    }
}

function Set-BslIntegrationState {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Data,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][uint64]$ReleaseSequence,
        [Parameter(Mandatory = $true)][string]$PublisherThumbprint,
        [Parameter(Mandatory = $true)][string]$ReleasePublicKeySha256,
        [Parameter(Mandatory = $true)][bool]$UsePath,
        [Parameter(Mandatory = $true)][bool]$UseShortcut
    )

    if ($UsePath) {
        [void](Add-BslUserPath $Root)
    } else {
        [void](Remove-BslUserPath $Root)
    }
    if ($UseShortcut) {
        [void](Set-BslStartMenuShortcut $Root)
    } else {
        [void](Remove-BslStartMenuShortcut)
    }
    Set-BslUninstallEntry `
        $Root $Data $Version $ReleaseSequence `
        $PublisherThumbprint $ReleasePublicKeySha256
}

function Copy-BslMaintenanceScripts {
    param([Parameter(Mandatory = $true)][string]$Destination)

    $required = @(
        'bsl-installer-common.ps1',
        'install-bsl-windows.ps1',
        'rollback-bsl-windows.ps1',
        'uninstall-bsl-windows.ps1'
    )
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($name in $required) {
        $source = Join-Path $PSScriptRoot $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Required maintenance script is missing: $source"
        }
        Assert-BslNoReparseChain $source "maintenance script $name"
        Copy-Item -LiteralPath $source -Destination (Join-Path $Destination $name) -Force
    }
    Protect-BslDirectoryAcl $Destination
}

function Publish-BslMaintenanceScripts {
    param(
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Backup
    )

    if (Test-Path -LiteralPath $Backup) {
        throw "Maintenance backup path already exists: $Backup"
    }
    if (Test-Path -LiteralPath $Destination) {
        Assert-BslNoReparseChain $Destination 'existing maintenance directory'
        Move-BslDirectoryStrict $Destination $Backup 'maintenance backup publication'
    }
    try {
        Copy-BslMaintenanceScripts $Destination
        foreach ($name in @('last-rollback.json', 'last-uninstall.json')) {
            $source = Join-Path $Backup $name
            if (Test-Path -LiteralPath $source -PathType Leaf) {
                Assert-BslRegularFile $source "preserved maintenance receipt $name" 1048576
                Copy-Item -LiteralPath $source -Destination (Join-Path $Destination $name)
            }
        }
    }
    catch {
        if (Test-Path -LiteralPath $Destination) {
            Assert-BslNoReparseChain $Destination 'failed maintenance publication'
            Remove-Item -LiteralPath $Destination -Recurse -Force
        }
        if (Test-Path -LiteralPath $Backup) {
            Move-BslDirectoryStrict $Backup $Destination 'maintenance publication restoration'
        }
        throw
    }
}

function Restore-BslMaintenanceScripts {
    param(
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Backup
    )

    if (Test-Path -LiteralPath $Destination) {
        Assert-BslNoReparseChain $Destination 'maintenance rollback target'
        Remove-Item -LiteralPath $Destination -Recurse -Force
    }
    if (Test-Path -LiteralPath $Backup) {
        Move-BslDirectoryStrict $Backup $Destination 'maintenance rollback restoration'
    }
}

function Restore-BslIdempotentState {
    param(
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)][string]$PendingPath,
        [Parameter(Mandatory = $true)][string]$BackupPath,
        [Parameter(Mandatory = $true)][bool]$BackedUp,
        [Parameter(Mandatory = $true)][bool]$Published
    )

    if ($Published -and (Test-Path -LiteralPath $StatePath)) {
        Remove-Item -LiteralPath $StatePath -Force
    }
    if ($BackedUp -and (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
        if (Test-Path -LiteralPath $StatePath) {
            Remove-Item -LiteralPath $StatePath -Force
        }
        Move-Item -LiteralPath $BackupPath -Destination $StatePath
    }
    Remove-Item -LiteralPath $PendingPath -Force -ErrorAction SilentlyContinue
}

$installRootPath = Assert-BslManagedRoot $InstallRoot 'install root'
$dataRootPath = Assert-BslManagedRoot $DataRoot 'data root'
$package = Get-BslPackagePaths $PackageDirectory

if ((Test-BslPathWithin $package.Root $installRootPath) -or
    (Test-BslPathWithin $installRootPath $package.Root) -or
    (Test-BslPathWithin $package.Root $dataRootPath) -or
    (Test-BslPathWithin $dataRootPath $package.Root) -or
    (Test-BslPathWithin $installRootPath $dataRootPath) -or
    (Test-BslPathWithin $dataRootPath $installRootPath)) {
    throw 'Package, install and data roots must be independent directories.'
}

$publisherThumbprint = Assert-BslAuthenticode `
    $package.Binary $ExpectedPublisherThumbprint
$releaseKeySha256 = Assert-BslReleasePublicKey `
    $package.PublicKey $ExpectedReleasePublicKeySha256
$manifestDocument = Get-BslManifestDocument $package.Manifest
$verification = Invoke-BslReleaseVerification `
    $package.Binary $package.Manifest $package.PublicKey $package.Sbom $package.Checksums

if ($verification.version -ne $manifestDocument.manifest.version -or
    [uint64]$verification.release_sequence -ne [uint64]$manifestDocument.manifest.release_sequence -or
    $verification.source_commit -ne $manifestDocument.manifest.source_commit -or
    $verification.manifest_sha256 -ne $manifestDocument.manifest.manifest_sha256) {
    throw 'Candidate verification result does not match the signed manifest document.'
}

$candidateHelperSha256 = Assert-BslBundledHelperBinding `
    $package.Helper `
    $package.Checksums

$installParent = Split-Path -Parent $installRootPath
New-Item -ItemType Directory -Path $installParent -Force | Out-Null
$lock = Open-BslInstallerLock $installRootPath
$nonce = [Guid]::NewGuid().ToString('N')
$stageRoot = $installRootPath + '.stage.' + $nonce
$previousRoot = $installRootPath + '.previous'
$previousBackupRoot = $previousRoot + '.backup.' + $nonce
$maintenanceRoot = Join-Path $dataRootPath 'installer'
$maintenanceBackup = $maintenanceRoot + '.backup.' + $nonce
$idempotentStatePath = Join-Path $installRootPath 'install-state.json'
$idempotentStatePending = $idempotentStatePath + '.pending.' + $nonce
$idempotentStateBackup = $idempotentStatePath + '.backup.' + $nonce
$existing = $null
$existingPathSetting = $false
$existingShortcutSetting = $false
$movedExisting = $false
$publishedStage = $false
$previousSlotBackedUp = $false
$maintenancePublished = $false
$idempotentStateBackedUp = $false
$idempotentStatePublished = $false
$transactionCommitted = $false
$result = $null
try {
    if (Test-Path -LiteralPath $installRootPath) {
        $existing = Assert-BslInstalledRoot `
            $installRootPath $publisherThumbprint $releaseKeySha256
        $existingPathSetting = [bool]$existing.State.add_to_user_path
        $existingShortcutSetting = [bool]$existing.State.create_start_menu_shortcut
    } elseif (Test-Path -LiteralPath $previousRoot) {
        throw 'Rollback slot exists without an active installation.'
    }

    $comparison = $null
    if ($null -ne $existing) {
        $comparison = Compare-BslReleaseOrder `
            $verification.version $verification.release_sequence `
            $existing.Verification.version $existing.Verification.release_sequence
        if ($comparison -lt 0) {
            throw "Release downgrade or replay is denied: installed=$($existing.Verification.version)+$($existing.Verification.release_sequence) candidate=$($verification.version)+$($verification.release_sequence)"
        }
        if ($comparison -eq 0 -and
            $verification.manifest_sha256 -ne $existing.Verification.manifest_sha256) {
            throw 'Same release order with a different signed manifest is denied.'
        }
        if ($comparison -gt 0 -and
            $verification.source_commit -eq $existing.Verification.source_commit) {
            throw 'A higher release order must bind a different exact source commit.'
        }
    }

    New-Item -ItemType Directory -Path $dataRootPath -Force | Out-Null
    Protect-BslDirectoryAcl $dataRootPath
    Publish-BslMaintenanceScripts $maintenanceRoot $maintenanceBackup
    $maintenancePublished = $true

    if ($null -ne $existing -and $comparison -eq 0) {
        $existing.State.add_to_user_path = $AddToUserPath
        $existing.State.create_start_menu_shortcut = $CreateStartMenuShortcut
        Write-BslJsonFile $idempotentStatePending $existing.State
        Move-Item -LiteralPath $idempotentStatePath -Destination $idempotentStateBackup
        $idempotentStateBackedUp = $true
        Move-Item -LiteralPath $idempotentStatePending -Destination $idempotentStatePath
        $idempotentStatePublished = $true

        Set-BslIntegrationState `
            $installRootPath $dataRootPath $verification.version `
            ([uint64]$verification.release_sequence) `
            $publisherThumbprint $releaseKeySha256 `
            $AddToUserPath $CreateStartMenuShortcut
        Write-BslJsonFile `
            (Join-Path $maintenanceRoot 'current-install.json') $existing.State

        $result = [ordered]@{
            schema_version = 3
            status = 'already_installed'
            version = $verification.version
            release_sequence = [uint64]$verification.release_sequence
            source_commit = $verification.source_commit
            manifest_sha256 = $verification.manifest_sha256
            binary_sha256 = (Get-FileHash -LiteralPath $package.Binary -Algorithm SHA256).Hash.ToLowerInvariant()
            helper_sha256 = $candidateHelperSha256
            install_root = $installRootPath
            data_root = $dataRootPath
            rollback_available = (Test-Path -LiteralPath $previousRoot -PathType Container)
            path_registered = $AddToUserPath
            shortcut_registered = $CreateStartMenuShortcut
            network_activity = 'none'
        }
        $transactionCommitted = $true
    } else {
        New-Item -ItemType Directory -Path $stageRoot | Out-Null
        foreach ($name in $script:BslPackageFileNames) {
            Copy-Item -LiteralPath (Join-Path $package.Root $name) `
                -Destination (Join-Path $stageRoot $name)
        }
        Protect-BslDirectoryAcl $stageRoot

        $stagePaths = Get-BslInstalledPaths $stageRoot
        [void](Assert-BslAuthenticode $stagePaths.Binary $publisherThumbprint)
        [void](Assert-BslReleasePublicKey $stagePaths.PublicKey $releaseKeySha256)
        $stageVerification = Invoke-BslReleaseVerification `
            $stagePaths.Binary $stagePaths.Manifest $stagePaths.PublicKey `
            $stagePaths.Sbom $stagePaths.Checksums
        if ($stageVerification.manifest_sha256 -ne $verification.manifest_sha256 -or
            [uint64]$stageVerification.release_sequence -ne [uint64]$verification.release_sequence -or
            $stageVerification.source_commit -ne $verification.source_commit) {
            throw 'Staged package does not match the verified source package.'
        }

        $stageHelperSha256 = Assert-BslBundledHelperBinding `
            $stagePaths.Helper `
            $stagePaths.Checksums

        if ($stageHelperSha256 -ne $candidateHelperSha256) {
            throw 'Staged bundled helper does not match the verified source package.'
        }

        $state = [ordered]@{
            schema_version = 3
            product = 'BoundSeal'
            version = $verification.version
            release_sequence = [uint64]$verification.release_sequence
            release_id = $manifestDocument.manifest.release_id
            source_commit = $verification.source_commit
            manifest_sha256 = $verification.manifest_sha256
            signature_sha256 = $verification.signature_sha256
            manifest_document_sha256 = $verification.document_sha256
            binary_sha256 = (Get-FileHash -LiteralPath $stagePaths.Binary -Algorithm SHA256).Hash.ToLowerInvariant()
            helper_sha256 = $stageHelperSha256
            publisher_thumbprint = $publisherThumbprint
            release_public_key_sha256 = $releaseKeySha256
            install_root = $installRootPath
            data_root = $dataRootPath
            add_to_user_path = $AddToUserPath
            create_start_menu_shortcut = $CreateStartMenuShortcut
            installed_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        }
        Write-BslJsonFile $stagePaths.State $state

        if (Test-Path -LiteralPath $previousRoot) {
            [void](Assert-BslInstalledRoot `
                $previousRoot $publisherThumbprint $releaseKeySha256 `
                $installRootPath)
            Move-BslDirectoryStrict $previousRoot $previousBackupRoot 'previous slot backup'
            $previousSlotBackedUp = $true
        }
        if (Test-Path -LiteralPath $installRootPath) {
            Move-BslDirectoryStrict $installRootPath $previousRoot 'active slot demotion'
            $movedExisting = $true
        }
        Move-BslDirectoryStrict $stageRoot $installRootPath 'staged release publication'
        $publishedStage = $true

        Set-BslIntegrationState `
            $installRootPath $dataRootPath $verification.version `
            ([uint64]$verification.release_sequence) `
            $publisherThumbprint $releaseKeySha256 `
            $AddToUserPath $CreateStartMenuShortcut

        $installed = Assert-BslInstalledRoot `
            $installRootPath $publisherThumbprint $releaseKeySha256
        if ($installed.Verification.manifest_sha256 -ne $verification.manifest_sha256) {
            throw 'Published installation does not match the candidate release.'
        }
        if ($movedExisting) {
            Protect-BslDirectoryAcl $previousRoot
        }
        Write-BslJsonFile (Join-Path $maintenanceRoot 'current-install.json') $state

        $result = [ordered]@{
            schema_version = 3
            status = if ($movedExisting) { 'upgraded' } else { 'installed' }
            version = $verification.version
            release_sequence = [uint64]$verification.release_sequence
            source_commit = $verification.source_commit
            manifest_sha256 = $verification.manifest_sha256
            signature_sha256 = $verification.signature_sha256
            binary_sha256 = $state.binary_sha256
            helper_sha256 = $state.helper_sha256
            install_root = $installRootPath
            data_root = $dataRootPath
            rollback_available = $movedExisting
            path_registered = $AddToUserPath
            shortcut_registered = $CreateStartMenuShortcut
            network_activity = 'none'
        }
        $transactionCommitted = $true
    }
}
catch {
    $failure = $_
    if (-not $transactionCommitted) {
        try {
            Restore-BslIdempotentState `
                $idempotentStatePath $idempotentStatePending $idempotentStateBackup `
                $idempotentStateBackedUp $idempotentStatePublished

            if ($publishedStage -and (Test-Path -LiteralPath $installRootPath)) {
                Assert-BslNoReparseChain $installRootPath 'failed published installation'
                Remove-Item -LiteralPath $installRootPath -Recurse -Force
            }
            if ($movedExisting -and (Test-Path -LiteralPath $previousRoot)) {
                Move-BslDirectoryStrict $previousRoot $installRootPath 'failed upgrade active restoration'
            }
            if ($previousSlotBackedUp -and (Test-Path -LiteralPath $previousBackupRoot)) {
                Move-BslDirectoryStrict $previousBackupRoot $previousRoot 'failed upgrade previous-slot restoration'
            }
            if (Test-Path -LiteralPath $stageRoot) {
                Assert-BslNoReparseChain $stageRoot 'failed staging directory'
                Remove-Item -LiteralPath $stageRoot -Recurse -Force
            }

            if ($null -ne $existing -and
                (Test-Path -LiteralPath $installRootPath -PathType Container)) {
                Set-BslIntegrationState `
                    $installRootPath $dataRootPath $existing.Verification.version `
                    ([uint64]$existing.Verification.release_sequence) `
                    $publisherThumbprint $releaseKeySha256 `
                    $existingPathSetting $existingShortcutSetting
            } else {
                [void](Remove-BslUserPath $installRootPath)
                [void](Remove-BslStartMenuShortcut)
                Remove-BslUninstallEntry
            }

            if ($maintenancePublished -or (Test-Path -LiteralPath $maintenanceBackup)) {
                Restore-BslMaintenanceScripts $maintenanceRoot $maintenanceBackup
            }
        }
        catch {
            Write-Error "Installer rollback also failed: $($_.Exception.Message)"
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
    foreach ($path in @(
        $previousBackupRoot,
        $maintenanceBackup,
        $idempotentStateBackup,
        $idempotentStatePending
    )) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $result | ConvertTo-Json -Depth 8
}
