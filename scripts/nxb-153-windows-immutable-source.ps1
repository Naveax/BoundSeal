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

function Fail-NxbH2CopyEntry {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows bounded H2 entrypoint failed: $Message"
}

function ConvertTo-NxbH2CopyHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Open-NxbH2CopyPinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2CopyEntry "$Label must be a regular non-reparse file: $Path"
    }
    try {
        return [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    }
    catch {
        Fail-NxbH2CopyEntry "could not pin $Label with write/delete sharing withheld: $($_.Exception.Message)"
    }
}

function Get-NxbH2CopyGitBlobOid {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        Fail-NxbH2CopyEntry "$Label stream must be readable and seekable"
    }
    $saved = $Stream.Position
    try {
        $Stream.Position = 0
        $length = $Stream.Length
        if ($length -le 0 -or $length -gt 2097152) {
            Fail-NxbH2CopyEntry "$Label size is outside the supported implementation envelope"
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
                Fail-NxbH2CopyEntry "$Label changed size while hashing"
            }
            [void]$sha1.TransformFinalBlock([byte[]]::new(0), 0, 0)
            return (ConvertTo-NxbH2CopyHex -Bytes $sha1.Hash)
        }
        finally {
            $sha1.Dispose()
        }
    }
    finally {
        $Stream.Position = $saved
    }
}

function Assert-NxbH2CopyCommittedFile {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $expected = (git -C $RepoRoot rev-parse "${HeadSha}:$RelativePath").Trim()
    if ($LASTEXITCODE -ne 0 -or $expected -notmatch '^[0-9a-f]{40}$') {
        Fail-NxbH2CopyEntry "exact-head $Label Git object could not be resolved"
    }
    $type = (git -C $RepoRoot cat-file -t $expected).Trim()
    if ($LASTEXITCODE -ne 0 -or $type -cne 'blob') {
        Fail-NxbH2CopyEntry "exact-head $Label is not a Git blob"
    }
    $actual = Get-NxbH2CopyGitBlobOid -Stream $Stream -Label $Label
    if ($actual -cne $expected) {
        Fail-NxbH2CopyEntry "pinned $Label bytes differ from exact-head Git authority"
    }
    return $expected
}

function Resolve-NxbH2CopyPython {
    foreach ($candidate in @('python3', 'python')) {
        $command = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            $version = (& $command.Source -I --version 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -eq 0 -and $version -match '^Python 3\.(1[1-9]|[2-9][0-9])(?:\.|$)') {
                return $command.Source
            }
        }
    }
    Fail-NxbH2CopyEntry 'Python 3.11 or newer with isolated-mode support is required'
}

if ($null -eq ('Nxb153H2CopyEntryNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class Nxb153H2CopyEntryNative
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
    Fail-NxbH2CopyEntry 'Windows bounded H2 entrypoint must run on Windows'
}
if ($HeadSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbH2CopyEntry 'exact head is not canonical 40-hex SHA-1'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ValidationDirectory = [IO.Path]::GetFullPath($ValidationDirectory)
$scriptsRoot = Join-Path $RepoRoot 'scripts'
$entryInnerRelative = 'scripts/nxb-153-windows-immutable-source-h2-entry-inner.ps1'
$copyHelperRelative = 'scripts/nxb-153-rust-toolchain-snapshot-copy.py'
$entryInnerPath = Join-Path $scriptsRoot 'nxb-153-windows-immutable-source-h2-entry-inner.ps1'
$copyHelperPath = Join-Path $scriptsRoot 'nxb-153-rust-toolchain-snapshot-copy.py'
$entryInnerStream = $null
$copyHelperStream = $null
$scriptsHandle = $null
$script:NxbH2CopyExpected = $null
$script:NxbH2CopySourceRoot = $null
$script:NxbH2CopyDestination = $null
$script:NxbH2CopyInvoked = $false
$script:NxbH2CopyPython = $null
$script:NxbH2CopyHelperPath = $null
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()

try {
    $scriptsItem = Get-Item -LiteralPath $scriptsRoot -Force -ErrorAction Stop
    if (-not $scriptsItem.PSIsContainer -or ($scriptsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2CopyEntry 'scripts namespace must be a normal non-reparse directory'
    }
    $scriptsHandle = [Nxb153H2CopyEntryNative]::OpenDirectoryNoDeleteShare($scriptsRoot)
    $entryInnerStream = Open-NxbH2CopyPinnedFile -Path $entryInnerPath -Label 'Windows H2 entry inner runner'
    $copyHelperStream = Open-NxbH2CopyPinnedFile -Path $copyHelperPath -Label 'bounded Rust snapshot-copy helper'
    [void](Assert-NxbH2CopyCommittedFile -Stream $entryInnerStream -RelativePath $entryInnerRelative -Label 'Windows H2 entry inner runner')
    [void](Assert-NxbH2CopyCommittedFile -Stream $copyHelperStream -RelativePath $copyHelperRelative -Label 'bounded Rust snapshot-copy helper')

    $script:NxbH2CopyPython = Resolve-NxbH2CopyPython
    $script:NxbH2CopyHelperPath = $copyHelperPath
    & $script:NxbH2CopyPython -I $script:NxbH2CopyHelperPath self-test | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail-NxbH2CopyEntry "bounded Rust snapshot-copy helper self-test failed with exit $LASTEXITCODE"
    }

    if (-not $SelfTest) {
        function Copy-Item {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)][string]$LiteralPath,
                [Parameter(Mandatory = $true)][string]$Destination,
                [switch]$Recurse,
                [switch]$Force
            )

            if (-not $Recurse -or -not $Force) {
                Fail-NxbH2CopyEntry 'bounded Copy-Item shim rejected non-recursive/non-force invocation'
            }

            $sourceFull = [IO.Path]::GetFullPath($LiteralPath)
            $destinationFull = [IO.Path]::GetFullPath($Destination)
            $sourceRoot = [IO.Path]::GetDirectoryName($sourceFull)
            if ([string]::IsNullOrWhiteSpace($sourceRoot)) {
                Fail-NxbH2CopyEntry 'bounded Copy-Item shim could not resolve source root'
            }
            $sourceRoot = [IO.Path]::GetFullPath($sourceRoot)

            if ($null -eq $script:NxbH2CopyExpected) {
                $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($item in Get-ChildItem -LiteralPath $sourceRoot -Force -ErrorAction Stop) {
                    [void]$expected.Add([IO.Path]::GetFullPath($item.FullName))
                }
                if ($expected.Count -eq 0 -or -not $expected.Contains($sourceFull)) {
                    Fail-NxbH2CopyEntry 'bounded Copy-Item shim source enumeration disagrees with H2 capture loop'
                }
                $script:NxbH2CopyExpected = $expected
                $script:NxbH2CopySourceRoot = $sourceRoot
                $script:NxbH2CopyDestination = $destinationFull

                & $script:NxbH2CopyPython -I $script:NxbH2CopyHelperPath copy $sourceRoot $destinationFull --platform-model windows | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Fail-NxbH2CopyEntry "bounded Rust sysroot copy failed with exit $LASTEXITCODE"
                }
                $script:NxbH2CopyInvoked = $true
            }
            else {
                if (-not [string]::Equals($sourceRoot, $script:NxbH2CopySourceRoot, [StringComparison]::OrdinalIgnoreCase)) {
                    Fail-NxbH2CopyEntry 'bounded Copy-Item shim observed a second source root'
                }
                if (-not [string]::Equals($destinationFull, $script:NxbH2CopyDestination, [StringComparison]::OrdinalIgnoreCase)) {
                    Fail-NxbH2CopyEntry 'bounded Copy-Item shim observed a second destination root'
                }
            }

            if (-not $script:NxbH2CopyExpected.Remove($sourceFull)) {
                Fail-NxbH2CopyEntry "bounded Copy-Item shim observed duplicate/unexpected source entry: $sourceFull"
            }
        }
    }

    $innerParameters = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $innerParameters[$entry.Key] = $entry.Value
    }
    & $entryInnerPath @innerParameters

    if (-not $SelfTest) {
        if (-not $script:NxbH2CopyInvoked) {
            Fail-NxbH2CopyEntry 'Windows H2 validation returned without invoking bounded sysroot copy'
        }
        if ($null -eq $script:NxbH2CopyExpected -or $script:NxbH2CopyExpected.Count -ne 0) {
            Fail-NxbH2CopyEntry 'Windows H2 capture loop did not consume the complete bounded source enumeration'
        }
    }

    $finalEntryOid = Get-NxbH2CopyGitBlobOid -Stream $entryInnerStream -Label 'Windows H2 entry inner runner final pinned object'
    $expectedEntryOid = (git -C $RepoRoot rev-parse "${HeadSha}:$entryInnerRelative").Trim()
    if ($LASTEXITCODE -ne 0 -or $finalEntryOid -cne $expectedEntryOid) {
        Fail-NxbH2CopyEntry 'Windows H2 entry inner runner authority changed during execution'
    }
    $finalCopyOid = Get-NxbH2CopyGitBlobOid -Stream $copyHelperStream -Label 'bounded Rust snapshot-copy helper final pinned object'
    $expectedCopyOid = (git -C $RepoRoot rev-parse "${HeadSha}:$copyHelperRelative").Trim()
    if ($LASTEXITCODE -ne 0 -or $finalCopyOid -cne $expectedCopyOid) {
        Fail-NxbH2CopyEntry 'bounded Rust snapshot-copy helper authority changed during execution'
    }
}
catch {
    $primaryError = $_
}
finally {
    Remove-Item Function:\Copy-Item -ErrorAction SilentlyContinue
    if ($null -ne $copyHelperStream) {
        try { $copyHelperStream.Dispose() }
        catch { $cleanupErrors.Add("copy helper handle disposal failed: $($_.Exception.Message)") }
    }
    if ($null -ne $entryInnerStream) {
        try { $entryInnerStream.Dispose() }
        catch { $cleanupErrors.Add("entry inner handle disposal failed: $($_.Exception.Message)") }
    }
    if ($null -ne $scriptsHandle) {
        try { $scriptsHandle.Dispose() }
        catch { $cleanupErrors.Add("scripts namespace handle disposal failed: $($_.Exception.Message)") }
    }
}

if ($null -ne $primaryError) {
    if ($cleanupErrors.Count -gt 0) {
        throw "NXB-153 Windows bounded H2 failed: $($primaryError.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
    }
    throw $primaryError
}
if ($cleanupErrors.Count -gt 0) {
    Fail-NxbH2CopyEntry ("cleanup failed after otherwise successful validation: " + ($cleanupErrors -join ' | '))
}
if ($SelfTest) {
    Write-Host 'NXB-153 Windows bounded H2 entrypoint source self-test chain passed; real Windows runtime admission remains required.'
}
