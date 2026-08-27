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

function Fail-NxbH2GitGuard {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows H2 Git-output guard failed: $Message"
}

function ConvertTo-NxbH2GitGuardHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Open-NxbH2GitGuardPinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2GitGuard "$Label must be a regular non-reparse file: $Path"
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
        Fail-NxbH2GitGuard "could not pin $Label with write/delete sharing withheld: $($_.Exception.Message)"
    }
}

function Get-NxbH2GitGuardBlobOid {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        Fail-NxbH2GitGuard "$Label stream must be readable and seekable"
    }
    $saved = $Stream.Position
    try {
        $Stream.Position = 0
        $length = $Stream.Length
        if ($length -le 0 -or $length -gt 2097152) {
            Fail-NxbH2GitGuard "$Label size is outside the supported implementation envelope"
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
                Fail-NxbH2GitGuard "$Label changed size while hashing"
            }
            [void]$sha1.TransformFinalBlock([byte[]]::new(0), 0, 0)
            return (ConvertTo-NxbH2GitGuardHex -Bytes $sha1.Hash)
        }
        finally {
            $sha1.Dispose()
        }
    }
    finally {
        $Stream.Position = $saved
    }
}

if ($null -eq ('Nxb153H2GitGuardNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class Nxb153H2GitGuardNative
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
    Fail-NxbH2GitGuard 'Windows H2 Git-output guard must run on Windows'
}
if ($HeadSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbH2GitGuard 'exact head is not canonical 40-hex SHA-1'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ValidationDirectory = [IO.Path]::GetFullPath($ValidationDirectory)
$scriptsRoot = Join-Path $RepoRoot 'scripts'
$innerRelative = 'scripts/nxb-153-windows-immutable-source-enumeration-inner.ps1'
$innerPath = Join-Path $scriptsRoot 'nxb-153-windows-immutable-source-enumeration-inner.ps1'
$innerStream = $null
$scriptsHandle = $null
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$script:NxbH2GitOutputByteLimit = 67108864
$script:NxbH2GitOutputLineLimit = 4096

$gitCommand = Get-Command git -CommandType Application -ErrorAction Stop
$script:NxbH2GitApplication = $gitCommand.Source

if (Test-Path Function:\git) {
    Fail-NxbH2GitGuard 'ambient git function authority is not admitted'
}

function git {
    $arguments = @($args | ForEach-Object { [string]$_ })
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:NxbH2GitApplication
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $false
    foreach ($argument in $arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $memory = [IO.MemoryStream]::new()
    try {
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            Fail-NxbH2GitGuard 'could not start bounded Git process'
        }
        $buffer = [byte[]]::new(65536)
        [Int64]$total = 0
        while (($read = $process.StandardOutput.BaseStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $read
            if ($total -gt $script:NxbH2GitOutputByteLimit) {
                try { $process.Kill($true) } catch {}
                Fail-NxbH2GitGuard "Git stdout exceeds $($script:NxbH2GitOutputByteLimit) bytes"
            }
            $memory.Write($buffer, 0, $read)
        }
        $process.WaitForExit()
        $global:LASTEXITCODE = $process.ExitCode

        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        try {
            $text = $utf8.GetString($memory.ToArray())
        }
        catch {
            Fail-NxbH2GitGuard "Git stdout is not strict UTF-8: $($_.Exception.Message)"
        }

        $reader = [IO.StringReader]::new($text)
        try {
            [Int64]$lineCount = 0
            while ($null -ne ($line = $reader.ReadLine())) {
                $lineCount++
                if ($lineCount -gt $script:NxbH2GitOutputLineLimit) {
                    Fail-NxbH2GitGuard "Git stdout record count exceeds $($script:NxbH2GitOutputLineLimit)"
                }
                $line
            }
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $memory.Dispose()
        $process.Dispose()
    }
}

function Assert-NxbH2GitGuardCommittedFile {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $expected = (& $script:NxbH2GitApplication -C $RepoRoot rev-parse "${HeadSha}:$RelativePath" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $expected -notmatch '^[0-9a-f]{40}$') {
        Fail-NxbH2GitGuard "exact-head $Label Git object could not be resolved"
    }
    $type = (& $script:NxbH2GitApplication -C $RepoRoot cat-file -t $expected | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $type -cne 'blob') {
        Fail-NxbH2GitGuard "exact-head $Label is not a Git blob"
    }
    $actual = Get-NxbH2GitGuardBlobOid -Stream $Stream -Label $Label
    if ($actual -cne $expected) {
        Fail-NxbH2GitGuard "pinned $Label bytes differ from exact-head Git authority"
    }
    return $expected
}

function Invoke-NxbH2GitGuardSelfTest {
    $version = (& git --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^git version ') {
        Fail-NxbH2GitGuard 'generic bounded Git proxy self-test failed'
    }

    $savedLineLimit = $script:NxbH2GitOutputLineLimit
    $savedByteLimit = $script:NxbH2GitOutputByteLimit
    try {
        $script:NxbH2GitOutputLineLimit = 1
        $rejected = $false
        try {
            @(& git -C $RepoRoot -c core.quotePath=false ls-tree -rl --full-tree $HeadSha) | Out-Null
        }
        catch {
            if ($_.Exception.Message -notlike '*record count exceeds*') {
                throw
            }
            $rejected = $true
        }
        if (-not $rejected) {
            Fail-NxbH2GitGuard 'bounded Git self-test did not reject exact-head ls-tree at a one-record limit'
        }

        $script:NxbH2GitOutputLineLimit = $savedLineLimit
        $script:NxbH2GitOutputByteLimit = 4
        $rejected = $false
        try {
            @(& git --version) | Out-Null
        }
        catch {
            if ($_.Exception.Message -notlike '*stdout exceeds*') {
                throw
            }
            $rejected = $true
        }
        if (-not $rejected) {
            Fail-NxbH2GitGuard 'bounded Git self-test did not reject stdout at a four-byte limit'
        }
    }
    finally {
        $script:NxbH2GitOutputLineLimit = $savedLineLimit
        $script:NxbH2GitOutputByteLimit = $savedByteLimit
        $global:LASTEXITCODE = 0
    }
}

try {
    $scriptsItem = Get-Item -LiteralPath $scriptsRoot -Force -ErrorAction Stop
    if (-not $scriptsItem.PSIsContainer -or ($scriptsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2GitGuard 'scripts namespace must be a normal non-reparse directory'
    }
    $scriptsHandle = [Nxb153H2GitGuardNative]::OpenDirectoryNoDeleteShare($scriptsRoot)
    $innerStream = Open-NxbH2GitGuardPinnedFile -Path $innerPath -Label 'Windows H2 enumeration-guard inner wrapper'
    [void](Assert-NxbH2GitGuardCommittedFile -Stream $innerStream -RelativePath $innerRelative -Label 'Windows H2 enumeration-guard inner wrapper')

    if ($SelfTest) {
        Invoke-NxbH2GitGuardSelfTest
    }

    $innerParameters = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $innerParameters[$entry.Key] = $entry.Value
    }
    . $innerPath @innerParameters

    $finalOid = Get-NxbH2GitGuardBlobOid -Stream $innerStream -Label 'Windows H2 enumeration-guard inner final pinned object'
    $expectedOid = (& $script:NxbH2GitApplication -C $RepoRoot rev-parse "${HeadSha}:$innerRelative" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $finalOid -cne $expectedOid) {
        Fail-NxbH2GitGuard 'Windows H2 enumeration-guard inner authority changed during execution'
    }
}
catch {
    $primaryError = $_
}
finally {
    Remove-Item Function:\git -ErrorAction SilentlyContinue
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
        throw "NXB-153 Windows H2 Git-output guard failed: $($primaryError.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
    }
    throw $primaryError
}
if ($cleanupErrors.Count -gt 0) {
    Fail-NxbH2GitGuard ("cleanup failed after otherwise successful validation: " + ($cleanupErrors -join ' | '))
}
if ($SelfTest) {
    Write-Host 'NXB-153 Windows H2 bounded Git-output source self-test chain passed; real Windows runtime admission remains required.'
}
