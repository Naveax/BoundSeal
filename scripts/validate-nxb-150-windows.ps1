[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,

    [string]$ExpectedCargoLockSha256 = 'f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-NxbCargo {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

function Get-NxbCommandVersion {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $value = (& cargo @Arguments | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value)) {
        throw "$Label is unavailable."
    }
    return $value
}

Push-Location $RepoRoot
$lockBackup = $null
try {
    foreach ($command in @('git', 'rustc', 'cargo')) {
        if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "$command is unavailable."
        }
    }

    $headSha = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $headSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Exact Git HEAD could not be resolved.'
    }
    $status = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $status) {
        throw 'Working tree must be clean.'
    }

    $rustcVersion = (& rustc --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $rustcVersion.StartsWith('rustc 1.97.1 ')) {
        throw "Expected rustc 1.97.1, found '$rustcVersion'."
    }
    $cargoVersion = (& cargo --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not resolve Cargo version.'
    }
    $auditVersion = Get-NxbCommandVersion @('audit', '--version') 'cargo-audit'
    $denyVersion = Get-NxbCommandVersion @('deny', '--version') 'cargo-deny'

    $lockPath = Join-Path $RepoRoot 'Cargo.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'Cargo.lock is missing.'
    }
    $lockBackup = Join-Path ([IO.Path]::GetTempPath()) (
        'nxb-150-cargo-lock-' + [Guid]::NewGuid().ToString('N')
    )
    Copy-Item -LiteralPath $lockPath -Destination $lockBackup

    Invoke-NxbCargo @('generate-lockfile') 'cargo generate-lockfile'
    git diff --exit-code -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        git --no-pager diff -- Cargo.lock | Write-Error
        throw 'cargo generate-lockfile changed the committed Cargo.lock.'
    }

    $lockSha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($lockSha256 -ne $ExpectedCargoLockSha256.ToLowerInvariant()) {
        throw "Cargo.lock SHA-256 mismatch: expected $ExpectedCargoLockSha256, found $lockSha256"
    }

    Invoke-NxbCargo @('metadata', '--format-version', '1', '--locked', '--no-deps') 'cargo metadata'
    Invoke-NxbCargo @('fmt', '--all', '--', '--check') 'cargo fmt'
    Invoke-NxbCargo @(
        'check', '-p', 'nxb-evidence-key-provider-process', '--all-features', '--locked'
    ) 'package cargo check'
    Invoke-NxbCargo @(
        'clippy', '-p', 'nxb-evidence-key-provider-process',
        '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings'
    ) 'package cargo clippy'
    Invoke-NxbCargo @(
        'test', '-p', 'nxb-evidence-key-provider-process',
        '--all-features', '--locked', '--', '--test-threads=1'
    ) 'serial process-adapter tests'
    Invoke-NxbCargo @(
        'test', '-p', 'nxb-vault-provider', '--locked', '--', '--test-threads=1'
    ) 'vault-provider regression tests'

    Invoke-NxbCargo @(
        'check', '--workspace', '--all-targets', '--all-features', '--locked'
    ) 'workspace cargo check'
    Invoke-NxbCargo @(
        'clippy', '--workspace', '--all-targets', '--all-features',
        '--locked', '--', '-D', 'warnings'
    ) 'workspace cargo clippy'
    Invoke-NxbCargo @(
        'test', '--workspace', '--all-features', '--locked', '--', '--test-threads=1'
    ) 'workspace cargo test'

    Invoke-NxbCargo @('audit') 'RustSec cargo audit'
    Invoke-NxbCargo @('deny', 'check') 'cargo-deny checks'

    $finalHead = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $finalHead -ne $headSha) {
        throw 'Git HEAD changed during validation.'
    }
    $finalStatus = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $finalStatus) {
        throw 'Working tree changed during validation.'
    }

    $validationDirectory = Join-Path $RepoRoot 'target\nxb-validation'
    New-Item -ItemType Directory -Path $validationDirectory -Force | Out-Null
    $evidencePath = Join-Path $validationDirectory "nxb-150-windows-$headSha.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = 'NXB-150'
        gate = 'pinned_process_evidence_key_provider'
        platform = 'windows'
        head_sha = $headSha
        rustc = $rustcVersion
        cargo = $cargoVersion
        cargo_audit = $auditVersion
        cargo_deny = $denyVersion
        cargo_lock_sha256 = $lockSha256
        lockfile_reproduced_without_diff = $true
        package_fmt_check_clippy_tests = 'passed'
        vault_provider_regressions = 'passed'
        workspace_check_clippy_tests = 'passed'
        rustsec = 'passed'
        cargo_deny_checks = 'passed'
        process_fixture_serial = $true
        network_activity = 'dependency_and_advisory_sources_only'
        validated_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    [IO.File]::WriteAllText(
        $evidencePath,
        (($evidence | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host 'NXB-150 Windows validation passed.'
    Write-Host "HEAD: $headSha"
    Write-Host "Cargo.lock SHA-256: $lockSha256"
    Write-Host "Evidence: $evidencePath"
}
finally {
    if ($null -ne $lockBackup -and (Test-Path -LiteralPath $lockBackup -PathType Leaf)) {
        Copy-Item -LiteralPath $lockBackup -Destination (Join-Path $RepoRoot 'Cargo.lock') -Force
        Remove-Item -LiteralPath $lockBackup -Force -ErrorAction SilentlyContinue
    }
    Pop-Location
}
