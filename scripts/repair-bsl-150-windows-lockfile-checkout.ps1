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

function Get-GitStatusLines {
    $lines = @(git status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) {
        throw 'git status failed.'
    }
    return $lines
}

Push-Location $RepoRoot
try {
    $headSha = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $headSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Exact Git HEAD could not be resolved.'
    }

    $status = @(Get-GitStatusLines)
    if ($status.Count -ne 0) {
        throw "Working tree must be clean before lockfile checkout repair.`n$($status -join [Environment]::NewLine)"
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
        throw 'Cargo.lock has user-authored working-tree differences; refusing checkout repair.'
    }
    git diff --cached --quiet -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        throw 'Cargo.lock has staged differences; refusing checkout repair.'
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

    git diff --quiet -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        $lockDiff = git --no-pager diff -- Cargo.lock | Out-String
        throw "Canonical Cargo.lock bytes differ from the index after rematerialization.`n$lockDiff"
    }
    git diff --cached --quiet -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        throw 'Cargo.lock unexpectedly differs from HEAD in the index after rematerialization.'
    }

    git update-index --really-refresh -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        throw 'Git could not refresh the Cargo.lock index stat cache.'
    }

    $finalStatus = @(Get-GitStatusLines)
    if ($finalStatus.Count -ne 0) {
        throw "Working tree changed during lockfile checkout repair.`n$($finalStatus -join [Environment]::NewLine)"
    }

    Write-Host 'NXB-150 Cargo.lock checkout repair passed.'
    Write-Host "HEAD: $headSha"
    Write-Host "Previous SHA-256: $beforeSha256"
    Write-Host "Canonical SHA-256: $afterSha256"
}
finally {
    Pop-Location
}
