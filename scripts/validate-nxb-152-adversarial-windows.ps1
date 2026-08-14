[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$branch = 'nxb-152-windows-credential-helper'
$baseD3 = 'adbf01ea6dcf9caac42df4c79947f4b9bb4f2654'
$expectedMain = 'a43d0777339d74b86ef03730f53bc0c35c4301fb'
$expectedLockSha256 = 'f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff'
$expectedRust = '1.97.1'
$expectedCargoAudit = '0.22.2'
$expectedCargoDeny = '0.20.2'
$adversarialTest = 'crates/nxb-evidence-key-provider-process/tests/windows_credential_adversarial.rs'
$validatorRelative = 'scripts/validate-nxb-152-adversarial-windows.ps1'

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    Write-Host ''
    Write-Host ('=== {0} ===' -f $Label)
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw ('{0} failed with exit code {1}' -f $Label, $LASTEXITCODE)
    }
    Write-Host ('{0}: PASS' -f $Label)
}

function Assert-PowerShellScriptParses {
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$tokens,
        [ref]$errors
    )
    if ($errors.Count -ne 0) {
        $messages = ($errors | ForEach-Object {
            'line={0} column={1} message={2}' -f `
                $_.Extent.StartLineNumber,
                $_.Extent.StartColumnNumber,
                $_.Message
        }) -join '; '
        throw ('PowerShell parser rejected {0}: {1}' -f $Path, $messages)
    }
}

function Get-PinnedToolVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ('{0} is unavailable at {1}' -f $Label, $Path)
    }

    $output = (& $Path --version | Out-String).Trim()

    if ($LASTEXITCODE -ne 0) {
        throw ('{0} --version failed' -f $Label)
    }

    if ([string]::IsNullOrWhiteSpace($output)) {
        throw ('{0} --version returned no output' -f $Label)
    }

    return $output
}

Push-Location $RepoRoot
try {
    Write-Host ''
    Write-Host '=================================================='
    Write-Host 'NXB-152 PASS-E ADVERSARIAL WINDOWS VALIDATION'
    Write-Host '=================================================='

    $head = (git rev-parse HEAD).Trim()
    $currentBranch = (git branch --show-current).Trim()
    $dirty = @(git status --porcelain=v1 --untracked-files=all)

    Write-Host ('BRANCH:       {0}' -f $currentBranch)
    Write-Host ('HEAD:         {0}' -f $head)
    Write-Host ('DIRTY COUNT:  {0}' -f $dirty.Count)

    if ($currentBranch -ne $branch) {
        throw 'Pass E is running on the wrong branch.'
    }
    if ($head -notmatch '^[0-9a-f]{40}$') {
        throw 'Pass E HEAD is not an exact commit SHA.'
    }
    if ($head -eq $baseD3) {
        throw 'Pass E requires the staged adversarial test/validator commits after D3.'
    }
    if ($dirty.Count -ne 0) {
        $dirty | ForEach-Object { Write-Host $_ }
        throw 'Pass E requires a clean working tree.'
    }

    git merge-base --is-ancestor $baseD3 $head
    if ($LASTEXITCODE -ne 0) {
        throw 'Validated D3 authority is not an ancestor of Pass E HEAD.'
    }

    $branchRefSpec = '+refs/heads/{0}:refs/remotes/origin/{0}' -f $branch
    $mainRefSpec = '+refs/heads/main:refs/remotes/origin/main'
    git fetch origin $mainRefSpec $branchRefSpec
    if ($LASTEXITCODE -ne 0) {
        throw 'Pass E authority fetch failed.'
    }

    $remoteHead = (git rev-parse ('origin/{0}' -f $branch)).Trim()
    $remoteMain = (git rev-parse 'origin/main').Trim()

    Write-Host ('REMOTE HEAD:  {0}' -f $remoteHead)
    Write-Host ('REMOTE MAIN:  {0}' -f $remoteMain)

    if ($remoteHead -ne $head) {
        throw 'Local and remote Pass E authority differ.'
    }
    if ($remoteMain -ne $expectedMain) {
        throw 'main authority moved during NXB-152 validation.'
    }

    $allowedDelta = @(
        $adversarialTest,
        $validatorRelative
    ) | Sort-Object
    $actualDelta = @(git diff --name-only ('{0}..{1}' -f $baseD3, $head)) | Sort-Object

    Write-Host ''
    Write-Host 'PASS-E DELTA FROM D3:'
    $actualDelta | ForEach-Object { Write-Host ('  {0}' -f $_) }

    if ($actualDelta.Count -ne $allowedDelta.Count) {
        throw 'Pass E changed production scope after the admitted D3 head.'
    }
    for ($index = 0; $index -lt $allowedDelta.Count; $index++) {
        if ($actualDelta[$index] -ne $allowedDelta[$index]) {
            throw ('Unexpected Pass E delta path: {0}' -f $actualDelta[$index])
        }
    }

    $lockSha256 = (
        Get-FileHash -LiteralPath (Join-Path $RepoRoot 'Cargo.lock') -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($lockSha256 -ne $expectedLockSha256) {
        throw 'Canonical Cargo.lock identity changed.'
    }

    $rustc = (& rustup run $expectedRust rustc --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $rustc.StartsWith(('rustc {0} ' -f $expectedRust))) {
        throw ('Expected rustc {0}, found {1}' -f $expectedRust, $rustc)
    }

    Write-Host ''
    Write-Host '=== PINNED SUPPLY-CHAIN TOOL PREPARATION ==='

    $prepareScript =
        Join-Path $RepoRoot 'scripts\prepare-and-validate-nxb-150-windows.ps1'

    if (-not (Test-Path -LiteralPath $prepareScript -PathType Leaf)) {
        throw 'Canonical NXB-150 Windows preparation script is missing.'
    }

    & $prepareScript `
        -RepoRoot $RepoRoot `
        -PrepareOnly

    $toolsBin =
        Join-Path $RepoRoot 'target\nxb-tools\bin'

    $auditPath =
        Join-Path $toolsBin 'cargo-audit.exe'

    $denyPath =
        Join-Path $toolsBin 'cargo-deny.exe'

    $cargoAudit =
        Get-PinnedToolVersion `
            -Path $auditPath `
            -Label 'cargo-audit'

    $cargoDeny =
        Get-PinnedToolVersion `
            -Path $denyPath `
            -Label 'cargo-deny'
    if ($cargoAudit -notmatch ('(^|\s){0}(\s|$)' -f [regex]::Escape($expectedCargoAudit))) {
        throw ('Expected cargo-audit {0}, found {1}' -f $expectedCargoAudit, $cargoAudit)
    }
    if ($cargoDeny -notmatch ('(^|\s){0}(\s|$)' -f [regex]::Escape($expectedCargoDeny))) {
        throw ('Expected cargo-deny {0}, found {1}' -f $expectedCargoDeny, $cargoDeny)
    }

    Write-Host ('RUSTC:        {0}' -f $rustc)
    Write-Host ('CARGO AUDIT:  {0}' -f $cargoAudit)
    Write-Host ('CARGO DENY:   {0}' -f $cargoDeny)
    Write-Host ('LOCK SHA256:  {0}' -f $lockSha256)

    Write-Host ''
    Write-Host '=== POWERSHELL PARSER ==='
    foreach ($script in @(
        (Join-Path $RepoRoot 'scripts\nxb-installer-common.ps1'),
        (Join-Path $RepoRoot 'scripts\install-nxb-windows.ps1'),
        (Join-Path $RepoRoot 'scripts\rollback-nxb-windows.ps1'),
        (Join-Path $RepoRoot 'scripts\uninstall-nxb-windows.ps1'),
        (Join-Path $RepoRoot 'scripts\validate-nxb-152-clean-install-evidence-windows.ps1'),
        (Join-Path $RepoRoot $validatorRelative)
    )) {
        Assert-PowerShellScriptParses $script
    }
    Write-Host 'POWERSHELL PARSER: PASS'

    Write-Host ''
    Write-Host '=== SECRET-SURFACE STATIC CLOSURE ==='
    $processSourcePath = Join-Path $RepoRoot 'crates\nxb-vault-provider-process\src\lib.rs'
    $processSource = [IO.File]::ReadAllText($processSourcePath)
    $spawnStartMarker = 'let mut command = Command::new(&executable_path);'
    $spawnEndMarker = 'let mut child = command'
    $spawnStart = $processSource.IndexOf($spawnStartMarker, [StringComparison]::Ordinal)
    if ($spawnStart -lt 0) {
        throw 'Pinned-process spawn start marker is missing.'
    }
    $spawnEnd = $processSource.IndexOf($spawnEndMarker, $spawnStart, [StringComparison]::Ordinal)
    if ($spawnEnd -lt 0 -or $spawnEnd -le $spawnStart) {
        throw 'Pinned-process spawn end marker is missing.'
    }
    $spawnSlice = $processSource.Substring($spawnStart, $spawnEnd - $spawnStart)
    if (-not $spawnSlice.Contains('.env_clear()')) {
        throw 'Pinned-process provider no longer clears the inherited environment.'
    }
    if (-not $spawnSlice.Contains('.stderr(Stdio::null())')) {
        throw 'Pinned-process protocol helper stderr suppression is missing.'
    }
    if ([regex]::IsMatch($spawnSlice, '\.args?\s*\(')) {
        throw 'Pinned-process provider unexpectedly adds process arguments.'
    }
    if (-not $spawnSlice.Contains('.stdin(Stdio::piped())') -or
        -not $spawnSlice.Contains('.stdout(Stdio::piped())')) {
        throw 'Pinned-process secret protocol pipes are missing.'
    }

    $helperSource = [IO.File]::ReadAllText(
        (Join-Path $RepoRoot 'crates\nxb-evidence-key-provider-process\src\bin\nxb-windows-credential-evidence-key-helper.rs')
    )
    if (-not $helperSource.Contains('std::env::args_os().count() == 1')) {
        throw 'Helper protocol/lifecycle mode boundary changed.'
    }
    if (-not $helperSource.Contains('write_provider_message(') -or
        -not $helperSource.Contains('&record.value')) {
        throw 'Helper no longer emits key bytes only through the provider secret frame.'
    }

    $installSource = [IO.File]::ReadAllText(
        (Join-Path $RepoRoot 'scripts\install-nxb-windows.ps1')
    )
    foreach ($forbiddenStateToken in @(
        'credential_blob',
        'key_material',
        'raw_key',
        'secret_bytes'
    )) {
        if ($installSource.IndexOf($forbiddenStateToken, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw ('Installer persistent-state source contains forbidden secret token: {0}' -f $forbiddenStateToken)
        }
    }
    Write-Host 'SECRET-SURFACE STATIC CLOSURE: PASS'

    Invoke-CheckedNative 'FMT' {
        & rustup run $expectedRust cargo fmt --all -- --check
    }

    Invoke-CheckedNative 'EVIDENCE PROVIDER CHECK' {
        & rustup run $expectedRust cargo check `
            -p nxb-evidence-key-provider-process `
            --all-targets `
            --all-features `
            --locked
    }

    Invoke-CheckedNative 'EVIDENCE PROVIDER CLIPPY' {
        & rustup run $expectedRust cargo clippy `
            -p nxb-evidence-key-provider-process `
            --all-targets `
            --all-features `
            --locked `
            -- `
            -D warnings
    }

    Invoke-CheckedNative 'REAL WINDOWS ADVERSARIAL TESTS' {
        & rustup run $expectedRust cargo test `
            -p nxb-evidence-key-provider-process `
            --test windows_credential_adversarial `
            --locked `
            -- `
            --test-threads=1
    }

    Invoke-CheckedNative 'PROCESS ADAPTER TESTS' {
        & rustup run $expectedRust cargo test `
            -p nxb-evidence-key-provider-process `
            --all-features `
            --test process_adapter `
            --locked `
            -- `
            --test-threads=1
    }

    Invoke-CheckedNative 'PROCESS BACKEND ADVERSARIAL FIXTURE' {
        & rustup run $expectedRust cargo test `
            -p nxb-vault-provider-process `
            --features fixture `
            --test process_backend `
            --locked `
            -- `
            --test-threads=1
    }

    Invoke-CheckedNative 'WORKSPACE CHECK' {
        & rustup run $expectedRust cargo check `
            --workspace `
            --all-targets `
            --all-features `
            --locked
    }

    Invoke-CheckedNative 'WORKSPACE CLIPPY' {
        & rustup run $expectedRust cargo clippy `
            --workspace `
            --all-targets `
            --all-features `
            --locked `
            -- `
            -D warnings
    }

    Invoke-CheckedNative 'WORKSPACE TESTS' {
        & rustup run $expectedRust cargo test `
            --workspace `
            --all-features `
            --locked `
            -- `
            --test-threads=1
    }

    Invoke-CheckedNative 'RUSTSEC AUDIT' {
        & $auditPath audit
    }

    Invoke-CheckedNative 'CARGO DENY' {
        & $denyPath check
    }

    $finalHead = (git rev-parse HEAD).Trim()
    $finalRemote = (git rev-parse ('origin/{0}' -f $branch)).Trim()
    $finalMain = (git rev-parse 'origin/main').Trim()
    $finalLockSha256 = (
        Get-FileHash -LiteralPath (Join-Path $RepoRoot 'Cargo.lock') -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $finalDirty = @(git status --porcelain=v1 --untracked-files=all)

    if ($finalHead -ne $head -or $finalRemote -ne $head) {
        throw 'Pass E exact branch authority changed during validation.'
    }
    if ($finalMain -ne $expectedMain) {
        throw 'main authority changed during Pass E validation.'
    }
    if ($finalLockSha256 -ne $expectedLockSha256) {
        throw 'Cargo.lock changed during Pass E validation.'
    }
    if ($finalDirty.Count -ne 0) {
        $finalDirty | ForEach-Object { Write-Host $_ }
        throw 'Pass E left the repository dirty.'
    }

    $evidenceDirectory = Join-Path $RepoRoot 'target\nxb-validation'
    New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
    $evidencePath = Join-Path $evidenceDirectory ('nxb-152-pass-e-windows-{0}.json' -f $head)

    $evidence = [ordered]@{
        schema_version = 1
        milestone = 'NXB-152'
        gate = 'pass_e_adversarial_windows'
        platform = 'windows'
        head_sha = $head
        base_d3_sha = $baseD3
        main_sha = $expectedMain
        rustc = $rustc
        cargo_audit = $cargoAudit
        cargo_deny = $cargoDeny
        cargo_lock_sha256 = $finalLockSha256
        checks = [ordered]@{
            wrong_executable_digest = 'passed'
            wrong_provider_identity_capability = 'passed'
            wrong_handle = 'passed'
            wrong_key_store_binding = 'passed'
            stale_required_version = 'passed'
            timeout_kill = 'passed'
            corrupt_credential = 'passed'
            missing_credential = 'passed'
            duplicate_create = 'passed'
            missing_delete = 'passed'
            failed_rotate = 'passed'
            malformed_truncated_protocol = 'passed'
            lifecycle_metadata_only = 'passed'
            spawn_has_no_secret_argv = 'passed'
            provider_environment_cleared = 'passed'
            protocol_stderr_suppressed = 'passed'
            secret_frame_only = 'passed'
            persistent_installer_state_has_no_raw_key = 'passed'
            uninstall_key_preservation = 'inherited_from_exact_d3'
            explicit_key_deletion = 'inherited_from_exact_d3'
            workspace_check = 'passed'
            workspace_clippy = 'passed'
            workspace_tests = 'passed'
            rustsec = 'passed'
            cargo_deny = 'passed'
            root_lockfile_unchanged = 'passed'
            network_activity_for_product_tests = 'none'
        }
    }

    [IO.File]::WriteAllText(
        $evidencePath,
        ($evidence | ConvertTo-Json -Depth 12) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host ''
    Write-Host '=================================================='
    Write-Host 'NXB-152 PASS-E COMPLETE'
    Write-Host '=================================================='
    Write-Host ('HEAD:         {0}' -f $head)
    Write-Host ('BASE D3:      {0}' -f $baseD3)
    Write-Host ('MAIN:         {0}' -f $expectedMain)
    Write-Host ('LOCK SHA256:  {0}' -f $finalLockSha256)
    Write-Host ('DIRTY COUNT:  {0}' -f $finalDirty.Count)
    Write-Host ('EVIDENCE:     {0}' -f $evidencePath)
    Write-Host ''
    Write-Host 'STATUS: PASS'
    Write-Host 'NEXT:   NXB-152 FINAL CLOSURE'
    Write-Host '=================================================='
}
finally {
    Pop-Location
}
