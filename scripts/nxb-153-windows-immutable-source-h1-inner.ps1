[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$ValidationDirectory,
    [Parameter(Mandatory = $true)][string]$HeadSha,
    [Parameter(Mandatory = $true)][string]$RustToolchain,
    [Parameter(Mandatory = $true)][string]$CargoAuditVersion,
    [Parameter(Mandatory = $true)][string]$CargoDenyVersion,
    [Parameter(Mandatory = $true)][string]$AuditSha256,
    [Parameter(Mandatory = $true)][string]$DenySha256,
    [Parameter(Mandatory = $true)][string]$ExpectedCargoLockSha256,
    [Parameter(Mandatory = $true)][string]$AuditPath,
    [Parameter(Mandatory = $true)][string]$DenyPath,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail-NxbH1 {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows host Rust toolchain H1 wrapper failed: $Message"
}

function Resolve-NxbH1Python {
    foreach ($candidate in @('python3', 'python')) {
        $command = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            $version = (& $command.Source -I --version 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -eq 0 -and $version -match '^Python 3\.(1[1-9]|[2-9][0-9])(?:\.|$)') {
                return $command.Source
            }
        }
    }
    Fail-NxbH1 'Python 3.11 or newer with isolated-mode support is required'
}

function ConvertTo-NxbH1Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Open-NxbH1PinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH1 "$Label must be a regular non-reparse file: $Path"
    }
    try {
        return [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
    }
    catch {
        Fail-NxbH1 "could not pin $Label with write/delete sharing withheld: $($_.Exception.Message)"
    }
}

function Get-NxbH1GitBlobOidFromStream {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        Fail-NxbH1 "$Label stream must be readable and seekable"
    }
    $savedPosition = $Stream.Position
    try {
        $Stream.Position = 0
        $length = $Stream.Length
        if ($length -le 0 -or $length -gt 1048576) {
            Fail-NxbH1 "$Label size is outside the supported 1..1048576-byte implementation envelope"
        }
        $sha1 = [Security.Cryptography.SHA1]::Create()
        try {
            $header = [Text.Encoding]::ASCII.GetBytes("blob $length`0")
            [void]$sha1.TransformBlock($header, 0, $header.Length, $null, 0)
            $buffer = [byte[]]::new(65536)
            [Int64]$total = 0
            while (($read = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $total += $read
                [void]$sha1.TransformBlock($buffer, 0, $read, $null, 0)
            }
            if ($total -ne $length) {
                Fail-NxbH1 "$Label changed size while hashing"
            }
            [void]$sha1.TransformFinalBlock([byte[]]::new(0), 0, 0)
            return (ConvertTo-NxbH1Hex -Bytes $sha1.Hash)
        }
        finally {
            $sha1.Dispose()
        }
    }
    finally {
        $Stream.Position = $savedPosition
    }
}

function Assert-NxbH1CommittedFile {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expected = (git rev-parse "${HeadSha}:$RelativePath").Trim()
    if ($LASTEXITCODE -ne 0 -or $expected -notmatch '^[0-9a-f]{40}$') {
        Fail-NxbH1 "exact-head $Label Git object could not be resolved"
    }
    $objectType = (git cat-file -t $expected).Trim()
    if ($LASTEXITCODE -ne 0 -or $objectType -cne 'blob') {
        Fail-NxbH1 "exact-head $Label authority is not a Git blob"
    }
    $actual = Get-NxbH1GitBlobOidFromStream -Stream $Stream -Label $Label
    if ($actual -cne $expected) {
        Fail-NxbH1 "pinned $Label bytes differ from the exact-head committed Git object"
    }
    return $expected
}

function Invoke-NxbH1Python {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$HelperPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$Capture
    )

    if ($Capture) {
        $output = (& $PythonPath -I $HelperPath @Arguments | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            Fail-NxbH1 "$Label failed with exit code $LASTEXITCODE"
        }
        return $output
    }

    & $PythonPath -I $HelperPath @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail-NxbH1 "$Label failed with exit code $LASTEXITCODE"
    }
}

if (-not $IsWindows) {
    Fail-NxbH1 'Windows H1 wrapper must run on Windows'
}
if ($HeadSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbH1 'exact head is not canonical 40-hex SHA-1'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$scriptsRoot = Join-Path $RepoRoot 'scripts'
$innerRelative = 'scripts/nxb-153-windows-immutable-source-inner.ps1'
$authorityRelative = 'scripts/nxb-153-rust-toolchain-authority.py'
$innerPath = Join-Path $scriptsRoot 'nxb-153-windows-immutable-source-inner.ps1'
$authorityPath = Join-Path $scriptsRoot 'nxb-153-rust-toolchain-authority.py'
$innerStream = $null
$authorityStream = $null

try {
    $innerStream = Open-NxbH1PinnedFile -Path $innerPath -Label 'immutable Windows inner source runner'
    $authorityStream = Open-NxbH1PinnedFile -Path $authorityPath -Label 'host Rust toolchain authority helper'
    [void](Assert-NxbH1CommittedFile -Stream $innerStream -RelativePath $innerRelative -Label 'immutable Windows inner source runner')
    [void](Assert-NxbH1CommittedFile -Stream $authorityStream -RelativePath $authorityRelative -Label 'host Rust toolchain authority helper')

    $pythonPath = Resolve-NxbH1Python
    Invoke-NxbH1Python `
        -PythonPath $pythonPath `
        -HelperPath $authorityPath `
        -Arguments @('self-test') `
        -Label 'host Rust toolchain authority helper self-test'

    $innerParameters = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $innerParameters[$entry.Key] = $entry.Value
    }

    if ($SelfTest) {
        & $innerPath @innerParameters
        return
    }

    $sysrootBefore = (& rustup run $RustToolchain rustc --print sysroot | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($sysrootBefore) -or -not (Test-Path -LiteralPath $sysrootBefore -PathType Container)) {
        Fail-NxbH1 "could not resolve Rust $RustToolchain sysroot before heavy gates"
    }
    $sysrootBefore = [IO.Path]::GetFullPath($sysrootBefore)

    $beforeJson = Invoke-NxbH1Python `
        -PythonPath $pythonPath `
        -HelperPath $authorityPath `
        -Arguments @('digest', $sysrootBefore, '--platform-model', 'windows') `
        -Label 'pre-gate Rust toolchain tree identity' `
        -Capture
    try {
        $before = $beforeJson | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Fail-NxbH1 "pre-gate Rust toolchain tree identity is invalid JSON: $($_.Exception.Message)"
    }
    $beforeSha256 = [string]$before.tree_sha256
    if ($beforeSha256 -notmatch '^[0-9a-f]{64}$') {
        Fail-NxbH1 'pre-gate Rust toolchain tree identity is invalid'
    }

    & $innerPath @innerParameters

    $sysrootAfter = (& rustup run $RustToolchain rustc --print sysroot | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($sysrootAfter)) {
        Fail-NxbH1 "could not resolve Rust $RustToolchain sysroot after heavy gates"
    }
    $sysrootAfter = [IO.Path]::GetFullPath($sysrootAfter)
    if (-not [string]::Equals($sysrootAfter, $sysrootBefore, [StringComparison]::OrdinalIgnoreCase)) {
        Fail-NxbH1 'Rust sysroot path changed across heavy gates'
    }

    Invoke-NxbH1Python `
        -PythonPath $pythonPath `
        -HelperPath $authorityPath `
        -Arguments @('verify', $sysrootAfter, $beforeSha256, '--platform-model', 'windows') `
        -Label 'post-gate Rust toolchain tree identity'

    Write-Host 'NXB-153 Windows host Rust toolchain H1 pre/post identity check passed; gate-lifetime immutability remains pending.'
}
finally {
    if ($null -ne $authorityStream) {
        $authorityStream.Dispose()
    }
    if ($null -ne $innerStream) {
        $innerStream.Dispose()
    }
}
