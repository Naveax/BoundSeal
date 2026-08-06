[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedLockSha256 = 'f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff'
$closureSource = Join-Path $RepoRoot 'scripts\review-nxb-150-evidence.ps1'

function Assert-LastExitCode {
    param([Parameter(Mandatory = $true)][string]$Operation)
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE."
    }
}

function Write-JsonDocument {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $json = $Value | ConvertTo-Json -Depth 16
    [IO.File]::WriteAllText(
        $Path,
        $json + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
}

function Expect-Failure {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    $unexpectedPass = $false
    try {
        & $Action *> $null
        $unexpectedPass = $true
    }
    catch {
        # Expected fail-closed result.
    }
    if ($unexpectedPass) {
        throw "NXB-150 closure self-test case '$Label' unexpectedly passed."
    }
}

if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'git is unavailable.'
}
if (-not (Test-Path -LiteralPath $closureSource -PathType Leaf)) {
    throw "Closure source is missing: $closureSource"
}

$lockSource = Join-Path $RepoRoot 'Cargo.lock'
if (-not (Test-Path -LiteralPath $lockSource -PathType Leaf)) {
    throw 'Cargo.lock is missing.'
}
$actualLockSha256 = (Get-FileHash -LiteralPath $lockSource -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualLockSha256 -cne $expectedLockSha256) {
    throw "Cargo.lock SHA-256 mismatch: expected $expectedLockSha256, found $actualLockSha256"
}

$sandbox = Join-Path ([IO.Path]::GetTempPath()) ("nxb-150-closure-self-test-" + [Guid]::NewGuid().ToString('N'))
$fixtureRepo = Join-Path $sandbox 'repository'
$fixtureScripts = Join-Path $fixtureRepo 'scripts'
$evidenceDirectory = Join-Path $sandbox 'evidence'
$fixtureClosure = Join-Path $fixtureScripts 'review-nxb-150-evidence.ps1'

try {
    New-Item -ItemType Directory -Path $fixtureScripts -Force | Out-Null
    New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
    Copy-Item -LiteralPath $lockSource -Destination (Join-Path $fixtureRepo 'Cargo.lock')
    Copy-Item -LiteralPath $closureSource -Destination $fixtureClosure

    & git -C $fixtureRepo init -q
    Assert-LastExitCode -Operation 'git init'
    & git -C $fixtureRepo config user.name 'NXB Closure Self-Test'
    Assert-LastExitCode -Operation 'git config user.name'
    & git -C $fixtureRepo config user.email 'nxb-closure-self-test@example.invalid'
    Assert-LastExitCode -Operation 'git config user.email'
    & git -C $fixtureRepo add Cargo.lock scripts/review-nxb-150-evidence.ps1
    Assert-LastExitCode -Operation 'git add'
    & git -C $fixtureRepo commit -qm 'Create NXB-150 closure fixture'
    Assert-LastExitCode -Operation 'git commit'
    $headSha = (& git -C $fixtureRepo rev-parse HEAD).Trim()
    Assert-LastExitCode -Operation 'git rev-parse HEAD'
    if ($headSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Fixture Git head is invalid.'
    }

    $closurePath = Join-Path $evidenceDirectory "nxb-150-closure-$headSha.json"
    $pendingPath = "$closurePath.pending"

    function Write-ValidEvidence {
        if (Test-Path -LiteralPath $evidenceDirectory) {
            Remove-Item -LiteralPath $evidenceDirectory -Recurse -Force
        }
        New-Item -ItemType Directory -Path $evidenceDirectory | Out-Null
        $validatedAt = [DateTimeOffset]::UtcNow.ToString(
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture
        )
        foreach ($platform in @('linux', 'windows')) {
            $auditMarker = if ($platform -ceq 'linux') { '1' } else { '2' }
            $denyMarker = if ($platform -ceq 'linux') { '3' } else { '4' }
            $evidence = [ordered]@{
                schema_version = 2
                milestone = 'NXB-150'
                gate = 'pinned_process_evidence_key_provider'
                platform = $platform
                head_sha = $headSha
                rustc = 'rustc 1.97.1 (fixture 2026-08-01)'
                cargo = 'cargo 1.97.1 (fixture 2026-08-01)'
                cargo_audit = 'cargo-audit 0.22.2'
                cargo_audit_sha256 = $auditMarker * 64
                cargo_deny = 'cargo-deny 0.20.2'
                cargo_deny_sha256 = $denyMarker * 64
                cargo_lock_sha256 = $expectedLockSha256
                lockfile_reproduced_without_diff = $true
                package_fmt_check_clippy_tests = 'passed'
                vault_provider_regressions = 'passed'
                workspace_check_clippy_tests = 'passed'
                rustsec = 'passed'
                cargo_deny_checks = 'passed'
                process_fixture_serial = $true
                network_activity = 'dependency_and_advisory_sources_only'
                validated_at = $validatedAt
            }
            Write-JsonDocument -Path (Join-Path $evidenceDirectory "nxb-150-$platform-$headSha.json") -Value $evidence
        }
    }

    function Mutate-Evidence {
        param(
            [Parameter(Mandatory = $true)][string]$Platform,
            [Parameter(Mandatory = $true)][string]$Operation
        )

        $path = Join-Path $evidenceDirectory "nxb-150-$Platform-$headSha.json"
        $evidence = [IO.File]::ReadAllText(
            $path,
            [Text.UTF8Encoding]::new($false, $true)
        ) | ConvertFrom-Json -Depth 16
        switch ($Operation) {
            'mixed-head' {
                $evidence.head_sha = '0' * 40
            }
            'unknown-field' {
                $evidence | Add-Member -NotePropertyName unexpected -NotePropertyValue 'blocked' -Force
            }
            'wrong-type' {
                $evidence.process_fixture_serial = 'true'
            }
            'future-time' {
                $evidence.validated_at = [DateTimeOffset]::UtcNow.AddHours(1).ToString(
                    'yyyy-MM-ddTHH:mm:ssZ',
                    [Globalization.CultureInfo]::InvariantCulture
                )
            }
            'failed-gate' {
                $evidence.rustsec = 'failed'
            }
            default {
                throw "Unknown evidence mutation: $Operation"
            }
        }
        Write-JsonDocument -Path $path -Value $evidence
    }

    function Invoke-Closure {
        & $fixtureClosure -RepoRoot $fixtureRepo -EvidenceDirectory $evidenceDirectory
    }

    Write-ValidEvidence
    Invoke-Closure | Out-Null
    $firstClosureSha256 = (Get-FileHash -LiteralPath $closurePath -Algorithm SHA256).Hash
    Invoke-Closure | Out-Null
    $secondClosureSha256 = (Get-FileHash -LiteralPath $closurePath -Algorithm SHA256).Hash
    if ($firstClosureSha256 -cne $secondClosureSha256) {
        throw 'Idempotent closure output changed.'
    }

    foreach ($operation in @('mixed-head', 'unknown-field', 'wrong-type', 'future-time', 'failed-gate')) {
        Write-ValidEvidence
        Mutate-Evidence -Platform 'windows' -Operation $operation
        Expect-Failure -Label $operation -Action { Invoke-Closure }
    }

    Write-ValidEvidence
    $windowsEvidencePath = Join-Path $evidenceDirectory "nxb-150-windows-$headSha.json"
    Remove-Item -LiteralPath $windowsEvidencePath -Force
    New-Item -ItemType Directory -Path $windowsEvidencePath | Out-Null
    Expect-Failure -Label 'evidence-non-file' -Action { Invoke-Closure }

    Write-ValidEvidence
    $realEvidenceDirectory = Join-Path $sandbox 'evidence-real'
    Move-Item -LiteralPath $evidenceDirectory -Destination $realEvidenceDirectory
    New-Item -ItemType Junction -Path $evidenceDirectory -Target $realEvidenceDirectory | Out-Null
    Expect-Failure -Label 'evidence-directory-junction' -Action { Invoke-Closure }
    [IO.Directory]::Delete($evidenceDirectory)
    Move-Item -LiteralPath $realEvidenceDirectory -Destination $evidenceDirectory

    Write-ValidEvidence
    New-Item -ItemType Directory -Path $closurePath | Out-Null
    Expect-Failure -Label 'closure-non-file' -Action { Invoke-Closure }

    Write-ValidEvidence
    [IO.File]::WriteAllText(
        $closurePath,
        '{"tampered":true}' + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    Expect-Failure -Label 'closure-tamper' -Action { Invoke-Closure }

    Write-ValidEvidence
    [IO.File]::WriteAllText(
        $pendingPath,
        'orphan' + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    Expect-Failure -Label 'orphan-pending' -Action { Invoke-Closure }

    Write-ValidEvidence
    New-Item -ItemType Directory -Path $pendingPath | Out-Null
    Expect-Failure -Label 'pending-non-file' -Action { Invoke-Closure }

    Write-Host 'NXB-150 Windows evidence closure self-test passed.'
    Write-Host "Fixture HEAD: $headSha"
    Write-Host 'Cases: success, idempotency, mixed head, unknown field, wrong type, future time, failed gate, evidence non-file, evidence-directory junction, closure non-file, closure tamper, orphan pending and pending non-file.'
}
finally {
    if (Test-Path -LiteralPath $sandbox) {
        Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
}
