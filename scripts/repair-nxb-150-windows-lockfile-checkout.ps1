[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedCargoLockSha256 = 'f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff'

if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'git is unavailable.'
}

Push-Location $RepoRoot
try {
    $headSha = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $headSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Exact Git HEAD could not be resolved.'
    }

    $status = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $status) {
        throw 'Working tree must be clean before lockfile checkout repair.'
    }

    $attribute = (git check-attr eol -- Cargo.lock | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $attribute -cne 'Cargo.lock: eol: lf') {
        throw "Cargo.lock checkout contract is unavailable. Expected 'Cargo.lock: eol: lf', found '$attribute'. Pull the current NXB-150 branch first."
    }

    $lockPath = Join-Path $RepoRoot 'Cargo.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'Cargo.lock is missing.'
    }

    $beforeSha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($beforeSha256 -ceq $expectedCargoLockSha256) {
        Write-Host 'NXB-150 Cargo.lock checkout is already canonical.'
        Write-Host "HEAD: $headSha"
        Write-Host "Cargo.lock SHA-256: $beforeSha256"
        return
    }

    git diff --quiet -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        throw 'Cargo.lock has user-authored or staged differences; refusing checkout repair.'
    }

    Remove-Item -LiteralPath $lockPath -Force
    git restore --source=HEAD --worktree -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        throw 'Git could not rematerialize Cargo.lock from HEAD.'
    }

    $afterSha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($afterSha256 -cne $expectedCargoLockSha256) {
        throw "Cargo.lock remains non-canonical after rematerialization: expected $expectedCargoLockSha256, found $afterSha256"
    }

    $finalStatus = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $finalStatus) {
        throw 'Working tree changed during lockfile checkout repair.'
    }

    Write-Host 'NXB-150 Cargo.lock checkout repair passed.'
    Write-Host "HEAD: $headSha"
    Write-Host "Previous SHA-256: $beforeSha256"
    Write-Host "Canonical SHA-256: $afterSha256"
}
finally {
    Pop-Location
}
