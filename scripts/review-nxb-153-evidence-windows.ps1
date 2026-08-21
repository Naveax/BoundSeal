[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$EvidenceDirectory = (Join-Path $RepoRoot 'target\nxb-validation')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedLockSha256 = 'f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff'

if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'git is unavailable.'
}

Push-Location $RepoRoot
try {
    $initialHead = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $initialHead -notmatch '^[0-9a-f]{40}$') {
        throw 'Exact Git HEAD could not be resolved before evidence review.'
    }

    $initialStatus = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $initialStatus) {
        throw 'Working tree must be clean before evidence review.'
    }

    $lockPath = Join-Path $RepoRoot 'Cargo.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'Cargo.lock is missing before evidence review.'
    }
    $initialLockSha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($initialLockSha256 -cne $expectedLockSha256) {
        throw "Cargo.lock SHA-256 mismatch before evidence review: expected $expectedLockSha256, found $initialLockSha256"
    }

    & (Join-Path $PSScriptRoot 'review-nxb-153-evidence.ps1') `
        -RepoRoot $RepoRoot `
        -EvidenceDirectory $EvidenceDirectory

    $finalHead = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $finalHead -cne $initialHead) {
        throw "Git HEAD changed during evidence review: initial=$initialHead final=$finalHead. Any newly published closure requires explicit recovery/review."
    }

    $finalStatus = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $finalStatus) {
        throw 'Working tree changed during evidence review. Any newly published closure requires explicit recovery/review.'
    }

    $finalLockSha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($finalLockSha256 -cne $initialLockSha256) {
        throw 'Cargo.lock bytes changed during evidence review. Any newly published closure requires explicit recovery/review.'
    }

    Write-Host 'NXB-153 guarded Windows closure authority remained stable.'
    Write-Host "HEAD: $initialHead"
    Write-Host "Cargo.lock SHA-256: $initialLockSha256"
}
finally {
    Pop-Location
}
