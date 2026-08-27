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

function Fail-NxbH2StringGuard {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows H2 string-capture guard failed: $Message"
}

function ConvertTo-NxbH2StringGuardHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Open-NxbH2StringGuardPinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2StringGuard "$Label must be a regular non-reparse file: $Path"
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
        Fail-NxbH2StringGuard "could not pin $Label with write/delete sharing withheld: $($_.Exception.Message)"
    }
}

function Get-NxbH2StringGuardBlobOid {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $saved = $Stream.Position
    try {
        $Stream.Position = 0
        $length = $Stream.Length
        if ($length -le 0 -or $length -gt 2097152) {
            Fail-NxbH2StringGuard "$Label size is outside the supported implementation envelope"
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
                Fail-NxbH2StringGuard "$Label changed size while hashing"
            }
            [void]$sha1.TransformFinalBlock([byte[]]::new(0), 0, 0)
            return (ConvertTo-NxbH2StringGuardHex -Bytes $sha1.Hash)
        }
        finally {
            $sha1.Dispose()
        }
    }
    finally {
        $Stream.Position = $saved
    }
}

if ($null -eq ('Nxb153H2StringGuardNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class Nxb153H2StringGuardNative
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
    Fail-NxbH2StringGuard 'Windows H2 string-capture guard must run on Windows'
}
if ($HeadSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbH2StringGuard 'exact head is not canonical 40-hex SHA-1'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ValidationDirectory = [IO.Path]::GetFullPath($ValidationDirectory)
$scriptsRoot = Join-Path $RepoRoot 'scripts'
$innerRelative = 'scripts/nxb-153-windows-immutable-source-git-output-inner.ps1'
$innerPath = Join-Path $scriptsRoot 'nxb-153-windows-immutable-source-git-output-inner.ps1'
$innerStream = $null
$scriptsHandle = $null
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$script:NxbH2OutStringByteLimit = 67108864

$gitCommand = Get-Command git -CommandType Application -ErrorAction Stop
$gitApplication = $gitCommand.Source
$expectedInnerOid = (& $gitApplication -C $RepoRoot rev-parse "${HeadSha}:$innerRelative").Trim()
if ($LASTEXITCODE -ne 0 -or $expectedInnerOid -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbH2StringGuard 'exact-head Git-output inner object could not be resolved'
}
$expectedInnerType = (& $gitApplication -C $RepoRoot cat-file -t $expectedInnerOid).Trim()
if ($LASTEXITCODE -ne 0 -or $expectedInnerType -cne 'blob') {
    Fail-NxbH2StringGuard 'exact-head Git-output inner authority is not a Git blob'
}

if (Test-Path Function:\Out-String) {
    Fail-NxbH2StringGuard 'ambient Out-String function authority is not admitted'
}

function Out-String {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]$InputObject
    )
    begin {
        $builder = [Text.StringBuilder]::new()
        $encoding = [Text.UTF8Encoding]::new($false, $true)
        [Int64]$total = 0
    }
    process {
        $piece = Microsoft.PowerShell.Utility\Out-String -InputObject $InputObject
        $total += $encoding.GetByteCount($piece)
        if ($total -gt $script:NxbH2OutStringByteLimit) {
            Fail-NxbH2StringGuard "Out-String capture exceeds $($script:NxbH2OutStringByteLimit) UTF-8 bytes"
        }
        [void]$builder.Append($piece)
    }
    end {
        $builder.ToString()
    }
}

function Invoke-NxbH2StringGuardSelfTest {
    $normal = ('abc' | Out-String).Trim()
    if ($normal -cne 'abc') {
        Fail-NxbH2StringGuard 'bounded Out-String normal self-test changed string content'
    }

    $saved = $script:NxbH2OutStringByteLimit
    try {
        $script:NxbH2OutStringByteLimit = 4
        $rejected = $false
        try {
            'abcdef' | Out-String | Out-Null
        }
        catch {
            if ($_.Exception.Message -notlike '*capture exceeds*') {
                throw
            }
            $rejected = $true
        }
        if (-not $rejected) {
            Fail-NxbH2StringGuard 'bounded Out-String self-test did not reject oversized capture'
        }
    }
    finally {
        $script:NxbH2OutStringByteLimit = $saved
    }
}

try {
    $scriptsItem = Get-Item -LiteralPath $scriptsRoot -Force -ErrorAction Stop
    if (-not $scriptsItem.PSIsContainer -or ($scriptsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2StringGuard 'scripts namespace must be a normal non-reparse directory'
    }
    $scriptsHandle = [Nxb153H2StringGuardNative]::OpenDirectoryNoDeleteShare($scriptsRoot)
    $innerStream = Open-NxbH2StringGuardPinnedFile -Path $innerPath -Label 'Windows H2 Git-output inner wrapper'
    $actualInnerOid = Get-NxbH2StringGuardBlobOid -Stream $innerStream -Label 'Windows H2 Git-output inner wrapper'
    if ($actualInnerOid -cne $expectedInnerOid) {
        Fail-NxbH2StringGuard 'pinned Git-output inner bytes differ from exact-head Git authority'
    }

    if ($SelfTest) {
        Invoke-NxbH2StringGuardSelfTest
    }

    $innerParameters = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $innerParameters[$entry.Key] = $entry.Value
    }
    . $innerPath @innerParameters

    $finalOid = Get-NxbH2StringGuardBlobOid -Stream $innerStream -Label 'Windows H2 Git-output inner final pinned object'
    $finalExpected = (& $gitApplication -C $RepoRoot rev-parse "${HeadSha}:$innerRelative").Trim()
    if ($LASTEXITCODE -ne 0 -or $finalExpected -cne $expectedInnerOid -or $finalOid -cne $expectedInnerOid) {
        Fail-NxbH2StringGuard 'Windows H2 Git-output inner authority changed during execution'
    }
}
catch {
    $primaryError = $_
}
finally {
    Remove-Item Function:\Out-String -ErrorAction SilentlyContinue
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
        throw "NXB-153 Windows H2 string-capture guard failed: $($primaryError.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
    }
    throw $primaryError
}
if ($cleanupErrors.Count -gt 0) {
    Fail-NxbH2StringGuard ("cleanup failed after otherwise successful validation: " + ($cleanupErrors -join ' | '))
}
if ($SelfTest) {
    Write-Host 'NXB-153 Windows H2 bounded string-capture source self-test chain passed; real Windows runtime admission remains required.'
}
