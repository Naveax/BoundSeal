[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rustToolchain = '1.97.1'
$expectedCargoLockSha256 = 'f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff'
$focusedTests = @(
    'target_setup_cli',
    'target_activation_cli',
    'target_guided_artifact_cli',
    'target_import_cli',
    'target_import_failclosed_cli',
    'target_path_binding_cli'
)

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
        -Arguments @('check', '-p', 'nxb-policy', '--all-targets', '--locked') `
        -Label 'nxb-policy cargo check'
    Invoke-NxbCargo `
        -Arguments @(
            'clippy', '-p', 'nxb-policy', '--all-targets', '--locked', '--', '-D', 'warnings'
        ) `
        -Label 'nxb-policy cargo clippy'
    Invoke-NxbCargo `
        -Arguments @('test', '-p', 'nxb-policy', '--locked', '--', '--test-threads=1') `
        -Label 'nxb-policy cargo test'

    Invoke-NxbCargo `
        -Arguments @('check', '-p', 'nxb-core', '--all-targets', '--locked') `
        -Label 'nxb-core cargo check'
    Invoke-NxbCargo `
        -Arguments @(
            'clippy', '-p', 'nxb-core', '--all-targets', '--locked', '--', '-D', 'warnings'
        ) `
        -Label 'nxb-core cargo clippy'
    Invoke-NxbCargo `
        -Arguments @('test', '-p', 'nxb-core', '--lib', '--locked', '--', '--test-threads=1') `
        -Label 'nxb-core unit tests'

    foreach ($testName in $focusedTests) {
        Invoke-NxbCargo `
            -Arguments @(
                'test', '-p', 'nxb-core', '--test', $testName,
                '--locked', '--', '--test-threads=1'
            ) `
            -Label "focused test $testName"
    }

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

    $finalLockSha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($finalLockSha256 -ne $expectedCargoLockSha256) {
        throw 'Cargo.lock bytes changed during validation.'
    }
    git diff --exit-code -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        throw 'Cargo.lock Git diff appeared during validation.'
    }

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
    $evidencePath = Join-Path $validationDirectory "nxb-153-windows-$headSha.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = 'NXB-153'
        gate = 'guided_target_authorization_setup'
        platform = 'windows'
        head_sha = $headSha
        rustc = $rustcVersion
        cargo = $cargoVersion
        cargo_lock_sha256 = $lockSha256
        cargo_lock_expected_sha256 = $expectedCargoLockSha256
        lockfile_pinned_and_unchanged = $true
        fmt = 'passed'
        nxb_policy_check_clippy_tests = 'passed'
        nxb_core_check_clippy_unit_tests = 'passed'
        focused_target_tests = 'passed'
        workspace_check_clippy_tests_all_features = 'passed'
        test_threads = 1
        network_activity = 'cargo_dependency_resolution_only'
        validated_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    [IO.File]::WriteAllText(
        $evidencePath,
        (($evidence | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host 'NXB-153 Windows validation passed.'
    Write-Host "HEAD: $headSha"
    Write-Host "Cargo.lock SHA-256: $lockSha256"
    Write-Host "Evidence: $evidencePath"
}
finally {
    Pop-Location
}
