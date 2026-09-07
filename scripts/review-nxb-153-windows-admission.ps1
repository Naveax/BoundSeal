[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail-NxbWindowsAdmission {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows admission review failed: $Message"
}

function Get-NxbGitValue {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $value = (& $GitPath @Arguments | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256) {
        Fail-NxbWindowsAdmission "$Label did not return one bounded value"
    }
    return $value
}

function Open-NxbPinnedExactHeadScript {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$HeadSha,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    $path = Join-Path $RepoRoot ($RelativePath -replace '/', [IO.Path]::DirectorySeparatorChar)
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbWindowsAdmission "admission script must be a regular non-reparse file: $RelativePath"
    }
    $stream = $null
    try {
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $expected = Get-NxbGitValue -GitPath $GitPath -Arguments @('-C', $RepoRoot, 'rev-parse', "${HeadSha}:$RelativePath") -Label "Git object for $RelativePath"
        $actual = Get-NxbGitValue -GitPath $GitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $path) -Label "working-tree object for $RelativePath"
        if ($expected -notmatch '^[0-9a-f]{40}$' -or $actual -cne $expected) {
            Fail-NxbWindowsAdmission "admission script bytes differ from exact-head Git authority: $RelativePath"
        }
        return [pscustomobject]@{
            RelativePath = $RelativePath
            Path = $path
            ObjectId = $expected
            Stream = $stream
        }
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Assert-NxbPinnedAuthority {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)]$Authority
    )
    $actual = Get-NxbGitValue -GitPath $GitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $Authority.Path) -Label "final object for $($Authority.RelativePath)"
    if ($actual -cne $Authority.ObjectId) {
        Fail-NxbWindowsAdmission "admission script authority changed during review: $($Authority.RelativePath)"
    }
}

if (-not $IsWindows) {
    Fail-NxbWindowsAdmission 'canonical Windows admission review must run on Windows'
}
if ($PSVersionTable.PSEdition -cne 'Core') {
    Fail-NxbWindowsAdmission 'canonical Windows admission review requires PowerShell Core'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$canonicalScripts = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'scripts'))
if (-not [string]::Equals($canonicalScripts, [IO.Path]::GetFullPath($PSScriptRoot), [StringComparison]::OrdinalIgnoreCase)) {
    Fail-NxbWindowsAdmission 'admission wrapper must execute from the canonical repository scripts directory'
}

$git = Get-Command git -CommandType Application -ErrorAction Stop
$gitPath = $git.Source
$headSha = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'initial exact Git HEAD'
if ($headSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbWindowsAdmission 'exact Git HEAD is not canonical 40-hex SHA-1'
}

$authorities = [Collections.Generic.List[object]]::new()
$primaryFailure = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
try {
    foreach ($relative in @(
        'scripts/review-nxb-153-windows-admission.ps1',
        'scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1',
        'scripts/review-nxb-153-evidence-windows.ps1'
    )) {
        $authorities.Add((Open-NxbPinnedExactHeadScript -GitPath $gitPath -HeadSha $headSha -RelativePath $relative))
    }

    $processReviewer = $authorities[1]
    $mainReviewer = $authorities[2]

    & $processReviewer.Path -RepoRoot $RepoRoot
    foreach ($authority in $authorities) {
        Assert-NxbPinnedAuthority -GitPath $gitPath -Authority $authority
    }
    $middleHead = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'post-process-review Git HEAD'
    if ($middleHead -cne $headSha) {
        Fail-NxbWindowsAdmission 'Git HEAD changed after process-lifecycle evidence review'
    }

    & $mainReviewer.Path -RepoRoot $RepoRoot
    foreach ($authority in $authorities) {
        Assert-NxbPinnedAuthority -GitPath $gitPath -Authority $authority
    }
    $finalHead = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'final exact Git HEAD'
    if ($finalHead -cne $headSha) {
        Fail-NxbWindowsAdmission 'Git HEAD changed during canonical Windows admission review'
    }
}
catch {
    $primaryFailure = $_
}
finally {
    for ($index = $authorities.Count - 1; $index -ge 0; $index--) {
        try { $authorities[$index].Stream.Dispose() }
        catch { $cleanupErrors.Add("pinned admission script disposal failed: $($authorities[$index].RelativePath): $($_.Exception.Message)") }
    }
}

if ($null -ne $primaryFailure) {
    if ($cleanupErrors.Count -gt 0) {
        throw "NXB-153 Windows admission review failed: $($primaryFailure.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
    }
    throw $primaryFailure
}
if ($cleanupErrors.Count -gt 0) {
    Fail-NxbWindowsAdmission ("cleanup failed after otherwise successful admission review: " + ($cleanupErrors -join ' | '))
}

Write-Host "NXB-153 canonical Windows admission review passed for HEAD $headSha."
