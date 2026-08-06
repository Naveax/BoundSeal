[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rustToolchain = '1.97.1'
$cargoAuditVersion = '0.22.2'
$cargoDenyVersion = '0.20.2'
$expectedCargoLockSha256 = 'f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff'
$toolsBin = Join-Path $RepoRoot 'target\nxb-tools\bin'
$auditPath = Join-Path $toolsBin 'cargo-audit.exe'
$denyPath = Join-Path $toolsBin 'cargo-deny.exe'

function Invoke-NxbCargo {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    & rustup run $rustToolchain cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

function Invoke-NxbTool {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    & $Path @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

function Get-NxbToolVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is unavailable at $Path. Run prepare-and-validate-nxb-150-windows.ps1 first."
    }
    $value = (& $Path --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $value -notmatch ('(^|\s)' + [regex]::Escape($ExpectedVersion) + '($|\s)')) {
        throw "$Label version mismatch: expected $ExpectedVersion, found '$value'."
    }
    return $value
}

Push-Location $RepoRoot
try {
    foreach ($command in @('git', 'rustup')) {
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

    $rustcVersion = (& rustup run $rustToolchain rustc --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $rustcVersion.StartsWith('rustc 1.97.1 ')) {
        throw "Expected rustc 1.97.1, found '$rustcVersion'."
    }
    $cargoVersion = (& rustup run $rustToolchain cargo --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not resolve pinned Cargo version.'
    }
    $auditVersion = Get-NxbToolVersion `
        -Path $auditPath `
        -ExpectedVersion $cargoAuditVersion `
        -Label 'cargo-audit'
    $denyVersion = Get-NxbToolVersion `
        -Path $denyPath `
        -ExpectedVersion $cargoDenyVersion `
        -Label 'cargo-deny'
    $auditSha256 = (Get-FileHash -LiteralPath $auditPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $denySha256 = (Get-FileHash -LiteralPath $denyPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $lockPath = Join-Path $RepoRoot 'Cargo.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'Cargo.lock is missing.'
    }
    $lockSha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($lockSha256 -ne $expectedCargoLockSha256) {
        throw "Cargo.lock SHA-256 mismatch: expected $expectedCargoLockSha256, found $lockSha256"
    }

    git diff --exit-code -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        throw 'Committed Cargo.lock differs before locked validation.'
    }
    Invoke-NxbCargo `
        -Arguments @('metadata', '--format-version', '1', '--locked', '--no-deps') `
        -Label 'cargo metadata --locked'
    git diff --exit-code -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        throw 'Cargo.lock changed during cargo metadata --locked.'
    }

    Invoke-NxbCargo `
        -Arguments @('fmt', '--all', '--', '--check') `
        -Label 'cargo fmt'
    Invoke-NxbCargo `
        -Arguments @(
            'check', '-p', 'nxb-evidence-key-provider-process', '--all-features', '--locked'
        ) `
        -Label 'package cargo check'
    Invoke-NxbCargo `
        -Arguments @(
            'clippy', '-p', 'nxb-evidence-key-provider-process',
            '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings'
        ) `
        -Label 'package cargo clippy'
    Invoke-NxbCargo `
        -Arguments @(
            'test', '-p', 'nxb-evidence-key-provider-process',
            '--all-features', '--locked', '--', '--test-threads=1'
        ) `
        -Label 'serial process-adapter tests'
    Invoke-NxbCargo `
        -Arguments @(
            'test', '-p', 'nxb-vault-provider', '--locked', '--', '--test-threads=1'
        ) `
        -Label 'vault-provider regression tests'

    Invoke-NxbCargo `
        -Arguments @(
            'check', '--workspace', '--all-targets', '--all-features', '--locked'
        ) `
        -Label 'workspace cargo check'
    Invoke-NxbCargo `
        -Arguments @(
            'clippy', '--workspace', '--all-targets', '--all-features',
            '--locked', '--', '-D', 'warnings'
        ) `
        -Label 'workspace cargo clippy'
    Invoke-NxbCargo `
        -Arguments @(
            'test', '--workspace', '--all-features', '--locked', '--', '--test-threads=1'
        ) `
        -Label 'workspace cargo test'

    Invoke-NxbTool -Path $auditPath -Arguments @() -Label 'RustSec cargo audit'
    Invoke-NxbTool -Path $denyPath -Arguments @('check') -Label 'cargo-deny checks'

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
        schema_version = 2
        milestone = 'NXB-150'
        gate = 'pinned_process_evidence_key_provider'
        platform = 'windows'
        head_sha = $headSha
        rustc = $rustcVersion
        cargo = $cargoVersion
        cargo_audit = $auditVersion
        cargo_audit_sha256 = $auditSha256
        cargo_deny = $denyVersion
        cargo_deny_sha256 = $denySha256
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
    Pop-Location
}
