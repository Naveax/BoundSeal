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

function Fail-NxbH2EnumerationGuard {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows H2 enumeration guard failed: $Message"
}

function ConvertTo-NxbH2EnumerationHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Open-NxbH2EnumerationPinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2EnumerationGuard "$Label must be a regular non-reparse file: $Path"
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
        Fail-NxbH2EnumerationGuard "could not pin $Label with write/delete sharing withheld: $($_.Exception.Message)"
    }
}

function Get-NxbH2EnumerationGitBlobOid {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        Fail-NxbH2EnumerationGuard "$Label stream must be readable and seekable"
    }
    $saved = $Stream.Position
    try {
        $Stream.Position = 0
        $length = $Stream.Length
        if ($length -le 0 -or $length -gt 2097152) {
            Fail-NxbH2EnumerationGuard "$Label size is outside the supported implementation envelope"
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
                Fail-NxbH2EnumerationGuard "$Label changed size while hashing"
            }
            [void]$sha1.TransformFinalBlock([byte[]]::new(0), 0, 0)
            return (ConvertTo-NxbH2EnumerationHex -Bytes $sha1.Hash)
        }
        finally {
            $sha1.Dispose()
        }
    }
    finally {
        $Stream.Position = $saved
    }
}

function Assert-NxbH2EnumerationCommittedFile {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $expected = (git -C $RepoRoot rev-parse "${HeadSha}:$RelativePath").Trim()
    if ($LASTEXITCODE -ne 0 -or $expected -notmatch '^[0-9a-f]{40}$') {
        Fail-NxbH2EnumerationGuard "exact-head $Label Git object could not be resolved"
    }
    $type = (git -C $RepoRoot cat-file -t $expected).Trim()
    if ($LASTEXITCODE -ne 0 -or $type -cne 'blob') {
        Fail-NxbH2EnumerationGuard "exact-head $Label is not a Git blob"
    }
    $actual = Get-NxbH2EnumerationGitBlobOid -Stream $Stream -Label $Label
    if ($actual -cne $expected) {
        Fail-NxbH2EnumerationGuard "pinned $Label bytes differ from exact-head Git authority"
    }
    return $expected
}

if ($null -eq ('Nxb153H2EnumerationNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class Nxb153H2EnumerationNative
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    public static SafeFileHandle OpenDirectoryNoDeleteShare(string path)
    {
        SafeFileHandle handle = CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "CreateFileW failed for " + path);
        }
        return handle;
    }
}
'@
}

if (-not $IsWindows) {
    Fail-NxbH2EnumerationGuard 'Windows H2 enumeration guard must run on Windows'
}
if ($HeadSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbH2EnumerationGuard 'exact head is not canonical 40-hex SHA-1'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ValidationDirectory = [IO.Path]::GetFullPath($ValidationDirectory)
$scriptsRoot = Join-Path $RepoRoot 'scripts'
$innerRelative = 'scripts/nxb-153-windows-immutable-source-bounded-inner.ps1'
$innerPath = Join-Path $scriptsRoot 'nxb-153-windows-immutable-source-bounded-inner.ps1'
$innerStream = $null
$scriptsHandle = $null
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$script:NxbH2EnumerationLimit = 131072

function Get-ChildItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [switch]$Force,
        [switch]$Recurse,
        [switch]$Directory,
        [switch]$File
    )

    if ($Directory -and $File) {
        Fail-NxbH2EnumerationGuard 'bounded Get-ChildItem proxy rejects simultaneous -Directory and -File'
    }

    $invoke = @{ LiteralPath = $LiteralPath }
    if ($Force) { $invoke.Force = $true }
    if ($Recurse) { $invoke.Recurse = $true }
    if ($Directory) { $invoke.Directory = $true }
    if ($File) { $invoke.File = $true }

    [Int64]$count = 0
    Microsoft.PowerShell.Management\Get-ChildItem @invoke | ForEach-Object {
        $count++
        if ($count -gt $script:NxbH2EnumerationLimit) {
            Fail-NxbH2EnumerationGuard "Get-ChildItem enumeration-count bound exceeded for $LiteralPath"
        }
        $_
    }
}

function Invoke-NxbH2EnumerationSelfTest {
    param([Parameter(Mandatory = $true)][string]$Root)

    $probeRoot = Join-Path $Root ('.nxb-153-h2-enumeration-' + [Guid]::NewGuid().ToString('N'))
    $savedLimit = $script:NxbH2EnumerationLimit
    $primary = $null
    $cleanup = $null
    try {
        [void][IO.Directory]::CreateDirectory($probeRoot)
        [IO.File]::WriteAllText((Join-Path $probeRoot 'a'), 'a')
        [IO.File]::WriteAllText((Join-Path $probeRoot 'b'), 'b')
        [IO.File]::WriteAllText((Join-Path $probeRoot 'c'), 'c')

        $script:NxbH2EnumerationLimit = 4
        $normal = @(Get-ChildItem -LiteralPath $probeRoot -Force -ErrorAction Stop)
        if ($normal.Count -ne 3) {
            Fail-NxbH2EnumerationGuard 'enumeration self-test normal result count differs'
        }

        $script:NxbH2EnumerationLimit = 2
        $rejected = $false
        try {
            @(Get-ChildItem -LiteralPath $probeRoot -Force -ErrorAction Stop) | Out-Null
        }
        catch {
            if ($_.Exception.Message -notlike '*enumeration-count bound exceeded*') {
                throw
            }
            $rejected = $true
        }
        if (-not $rejected) {
            Fail-NxbH2EnumerationGuard 'enumeration self-test did not reject an oversized result set'
        }
    }
    catch {
        $primary = $_
    }
    finally {
        $script:NxbH2EnumerationLimit = $savedLimit
        if (Test-Path -LiteralPath $probeRoot) {
            try {
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction Stop
            }
            catch {
                $cleanup = $_
            }
        }
    }

    if ($null -ne $primary) {
        if ($null -ne $cleanup) {
            throw "enumeration self-test failed: $($primary.Exception.Message); cleanup: $($cleanup.Exception.Message)"
        }
        throw $primary
    }
    if ($null -ne $cleanup) {
        Fail-NxbH2EnumerationGuard "enumeration self-test cleanup failed: $($cleanup.Exception.Message)"
    }
}

try {
    $scriptsItem = Get-Item -LiteralPath $scriptsRoot -Force -ErrorAction Stop
    if (-not $scriptsItem.PSIsContainer -or ($scriptsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2EnumerationGuard 'scripts namespace must be a normal non-reparse directory'
    }
    $scriptsHandle = [Nxb153H2EnumerationNative]::OpenDirectoryNoDeleteShare($scriptsRoot)
    $innerStream = Open-NxbH2EnumerationPinnedFile -Path $innerPath -Label 'bounded Windows H2 inner wrapper'
    [void](Assert-NxbH2EnumerationCommittedFile -Stream $innerStream -RelativePath $innerRelative -Label 'bounded Windows H2 inner wrapper')

    if ($SelfTest) {
        Invoke-NxbH2EnumerationSelfTest -Root $ValidationDirectory
    }

    $innerParameters = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $innerParameters[$entry.Key] = $entry.Value
    }
    . $innerPath @innerParameters

    $finalOid = Get-NxbH2EnumerationGitBlobOid -Stream $innerStream -Label 'bounded Windows H2 inner wrapper final pinned object'
    $expectedOid = (git -C $RepoRoot rev-parse "${HeadSha}:$innerRelative").Trim()
    if ($LASTEXITCODE -ne 0 -or $finalOid -cne $expectedOid) {
        Fail-NxbH2EnumerationGuard 'bounded Windows H2 inner wrapper authority changed during execution'
    }
}
catch {
    $primaryError = $_
}
finally {
    Remove-Item Function:\Get-ChildItem -ErrorAction SilentlyContinue
    if ($null -ne $innerStream) {
        try { $innerStream.Dispose() }
        catch { $cleanupErrors.Add("inner wrapper handle disposal failed: $($_.Exception.Message)") }
    }
    if ($null -ne $scriptsHandle) {
        try { $scriptsHandle.Dispose() }
        catch { $cleanupErrors.Add("scripts namespace handle disposal failed: $($_.Exception.Message)") }
    }
}

if ($null -ne $primaryError) {
    if ($cleanupErrors.Count -gt 0) {
        throw "NXB-153 Windows H2 enumeration guard failed: $($primaryError.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
    }
    throw $primaryError
}
if ($cleanupErrors.Count -gt 0) {
    Fail-NxbH2EnumerationGuard ("cleanup failed after otherwise successful validation: " + ($cleanupErrors -join ' | '))
}
if ($SelfTest) {
    Write-Host 'NXB-153 Windows H2 bounded enumeration source self-test chain passed; real Windows runtime admission remains required.'
}
