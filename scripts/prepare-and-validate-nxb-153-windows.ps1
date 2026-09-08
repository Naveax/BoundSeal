[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [switch]$PrepareOnly,
    [string]$EvidenceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$gitOutputByteLimit = 67108864
$gitOutputLineLimit = 4096
$gitReadInactivityTimeoutMilliseconds = 300000
$gitExitTimeoutMilliseconds = 30000
$maximumInnerBytes = 2097152

function Fail-NxbWindowsEntryGitGuard {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows entry Git-output guard failed: $Message"
}

function ConvertTo-NxbWindowsEntryHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function ConvertFrom-NxbWindowsEntryFinalPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $value = $Path
    if ($value.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        $value = '\\' + $value.Substring(8)
    }
    elseif ($value.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
        $value = $value.Substring(4)
    }
    $full = [IO.Path]::GetFullPath($value)
    $root = [IO.Path]::GetPathRoot($full)
    if ($full.Length -gt $root.Length) {
        $full = $full.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    }
    return $full
}

function Open-NxbWindowsEntryPinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expected = ConvertFrom-NxbWindowsEntryFinalPath -Path ([IO.Path]::GetFullPath($Path))
    $item = Get-Item -LiteralPath $expected -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbWindowsEntryGitGuard "$Label must be a regular non-reparse file: $expected"
    }
    $stream = $null
    try {
        $stream = [IO.File]::Open(
            $expected,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $resolved = ConvertFrom-NxbWindowsEntryFinalPath -Path ([Nxb153WindowsEntryGitGuardNative]::GetFinalPath($stream.SafeFileHandle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbWindowsEntryGitGuard "$Label resolved through redirected authority: expected '$expected', resolved '$resolved'"
        }
        return $stream
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        Fail-NxbWindowsEntryGitGuard "could not pin $Label with canonical path and write/delete sharing withheld: $($_.Exception.Message)"
    }
}

function Get-NxbWindowsEntryBlobOid {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        Fail-NxbWindowsEntryGitGuard "$Label stream must be readable and seekable"
    }
    $saved = $Stream.Position
    try {
        $Stream.Position = 0
        $length = $Stream.Length
        if ($length -le 0 -or $length -gt $maximumInnerBytes) {
            Fail-NxbWindowsEntryGitGuard "$Label size is outside the supported implementation envelope"
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
                Fail-NxbWindowsEntryGitGuard "$Label changed size while hashing"
            }
            [void]$sha1.TransformFinalBlock([byte[]]::new(0), 0, 0)
            return (ConvertTo-NxbWindowsEntryHex -Bytes $sha1.Hash)
        }
        finally {
            $sha1.Dispose()
        }
    }
    finally {
        $Stream.Position = $saved
    }
}

function Get-NxbWindowsEntryGitControlValue {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $GitPath
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $false
    $start.CreateNoWindow = $true
    foreach ($argument in $Arguments) {
        [void]$start.ArgumentList.Add([string]$argument)
    }

    $process = [Diagnostics.Process]::new()
    $memory = [IO.MemoryStream]::new()
    try {
        $process.StartInfo = $start
        if (-not $process.Start()) {
            Fail-NxbWindowsEntryGitGuard "$Label Git process could not be started"
        }

        $buffer = [byte[]]::new(1024)
        [Int64]$total = 0
        while ($true) {
            $readTask = $process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $readTask.Wait(30000)) {
                Fail-NxbWindowsEntryGitGuard "$Label Git stdout made no progress for 30000 ms"
            }
            $read = $readTask.Result
            if ($read -le 0) { break }
            $total += $read
            if ($total -gt 4096) {
                Fail-NxbWindowsEntryGitGuard "$Label Git stdout exceeds the 4096-byte control-plane envelope"
            }
            $memory.Write($buffer, 0, $read)
        }

        if (-not $process.WaitForExit(30000)) {
            Fail-NxbWindowsEntryGitGuard "$Label Git process did not exit after stdout closed"
        }
        if ($process.ExitCode -ne 0) {
            Fail-NxbWindowsEntryGitGuard "$Label Git command failed with exit code $($process.ExitCode)"
        }

        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        try {
            $value = $utf8.GetString($memory.ToArray()).Trim()
        }
        catch {
            Fail-NxbWindowsEntryGitGuard "$Label Git stdout is not strict UTF-8: $($_.Exception.Message)"
        }
        if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256) {
            Fail-NxbWindowsEntryGitGuard "$Label did not return one bounded control value"
        }
        return $value
    }
    finally {
        try {
            if (-not $process.HasExited) {
                $process.Kill($true)
                [void]$process.WaitForExit(30000)
            }
        }
        catch {}
        $memory.Dispose()
        $process.Dispose()
    }
}

if ($null -eq ('Nxb153WindowsEntryGitGuardNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Nxb153WindowsEntryGitGuardNative
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle hFile,
        StringBuilder lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

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

    public static string GetFinalPath(SafeFileHandle handle)
    {
        var builder = new StringBuilder(32768);
        uint result = GetFinalPathNameByHandleW(handle, builder, (uint)builder.Capacity, 0);
        if (result == 0)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (result >= builder.Capacity)
            throw new InvalidOperationException("Resolved path exceeds supported buffer.");
        return builder.ToString();
    }
}
'@
}

function Open-NxbWindowsEntryPinnedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expected = ConvertFrom-NxbWindowsEntryFinalPath -Path ([IO.Path]::GetFullPath($Path))
    $item = Get-Item -LiteralPath $expected -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbWindowsEntryGitGuard "$Label must be a normal non-reparse directory"
    }
    $handle = [Nxb153WindowsEntryGitGuardNative]::OpenDirectoryNoDeleteShare($expected)
    try {
        $resolved = ConvertFrom-NxbWindowsEntryFinalPath -Path ([Nxb153WindowsEntryGitGuardNative]::GetFinalPath($handle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbWindowsEntryGitGuard "$Label resolved through redirected authority: expected '$expected', resolved '$resolved'"
        }
        return $handle
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Open-NxbWindowsEntryPinnedHostTool {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expected = ConvertFrom-NxbWindowsEntryFinalPath -Path ([IO.Path]::GetFullPath($Path))
    $item = Get-Item -LiteralPath $expected -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbWindowsEntryGitGuard "$Label executable must be a regular non-reparse file"
    }
    $directory = [IO.Path]::GetDirectoryName($expected)
    if ([string]::IsNullOrWhiteSpace($directory)) {
        Fail-NxbWindowsEntryGitGuard "$Label executable parent directory is unavailable"
    }

    $directoryHandle = $null
    $stream = $null
    try {
        $directoryHandle = Open-NxbWindowsEntryPinnedDirectory -Path $directory -Label "$Label executable directory"
        $stream = [IO.File]::Open($expected, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $resolved = ConvertFrom-NxbWindowsEntryFinalPath -Path ([Nxb153WindowsEntryGitGuardNative]::GetFinalPath($stream.SafeFileHandle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbWindowsEntryGitGuard "$Label executable resolved through redirected authority: expected '$expected', resolved '$resolved'"
        }
        return [pscustomobject]@{
            Path = $expected
            Directory = (ConvertFrom-NxbWindowsEntryFinalPath -Path ([IO.Path]::GetFullPath($directory)))
            Stream = $stream
            DirectoryHandle = $directoryHandle
        }
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $directoryHandle) { $directoryHandle.Dispose() }
        throw
    }
}

if (-not $IsWindows) {
    Fail-NxbWindowsEntryGitGuard 'Windows entry Git-output guard must run on Windows'
}

$ambientGitAuthority = [Collections.Generic.List[string]]::new()
foreach ($entry in [Environment]::GetEnvironmentVariables().Keys) {
    $name = [string]$entry
    if ($name.StartsWith('GIT_', [StringComparison]::OrdinalIgnoreCase)) {
        $ambientGitAuthority.Add($name)
    }
}
if ($ambientGitAuthority.Count -gt 0) {
    $orderedGitAuthority = @($ambientGitAuthority | Sort-Object { $_.ToUpperInvariant() })
    Fail-NxbWindowsEntryGitGuard ('ambient Git authority variables are not admitted before exact-head resolution: ' + ($orderedGitAuthority -join ', '))
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$canonicalScriptsRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'scripts'))
$actualScriptsRoot = [IO.Path]::GetFullPath($PSScriptRoot)
if (-not [string]::Equals(
    $canonicalScriptsRoot,
    $actualScriptsRoot,
    [StringComparison]::OrdinalIgnoreCase
)) {
    Fail-NxbWindowsEntryGitGuard 'entrypoint must execute from the canonical repository scripts directory'
}

$entryName = [IO.Path]::GetFileName($MyInvocation.MyCommand.Path)
$innerName = $null
$innerParameters = @{}
$innerParameters['RepoRoot'] = $RepoRoot

switch -CaseSensitive ($entryName) {
    'prepare-and-validate-nxb-153-windows.ps1' {
        if ($PSBoundParameters.ContainsKey('EvidenceDirectory')) {
            Fail-NxbWindowsEntryGitGuard 'prepare entrypoint does not accept EvidenceDirectory'
        }
        $innerName = 'prepare-and-validate-nxb-153-windows-inner.ps1'
        if ($PrepareOnly) {
            $innerParameters['PrepareOnly'] = $true
        }
    }
    'validate-nxb-153-windows.ps1' {
        if ($PSBoundParameters.ContainsKey('PrepareOnly') -or $PSBoundParameters.ContainsKey('EvidenceDirectory')) {
            Fail-NxbWindowsEntryGitGuard 'validator entrypoint received an unsupported parameter'
        }
        $innerName = 'validate-nxb-153-windows-inner.ps1'
    }
    'review-nxb-153-evidence-windows.ps1' {
        if ($PSBoundParameters.ContainsKey('PrepareOnly')) {
            Fail-NxbWindowsEntryGitGuard 'evidence-review entrypoint does not accept PrepareOnly'
        }
        $innerName = 'review-nxb-153-evidence-windows-inner.ps1'
        if ($PSBoundParameters.ContainsKey('EvidenceDirectory')) {
            if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
                Fail-NxbWindowsEntryGitGuard 'EvidenceDirectory must not be empty'
            }
            $innerParameters['EvidenceDirectory'] = [IO.Path]::GetFullPath($EvidenceDirectory)
        }
        else {
            $innerParameters['EvidenceDirectory'] = Join-Path $RepoRoot 'target\nxb-validation'
        }
    }
    default {
        Fail-NxbWindowsEntryGitGuard "unsupported canonical entrypoint name: $entryName"
    }
}

$innerRelative = "scripts/$innerName"
$innerPath = Join-Path $PSScriptRoot $innerName
$gitCommand = Get-Command git -CommandType Application -ErrorAction Stop
$gitApplication = ConvertFrom-NxbWindowsEntryFinalPath -Path ([IO.Path]::GetFullPath([string]$gitCommand.Source))
$initialHead = $null

function Assert-NxbWindowsEntryCommittedFile {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expected = Get-NxbWindowsEntryGitControlValue `
        -GitPath $gitApplication `
        -Arguments @('-C', $RepoRoot, 'rev-parse', "${initialHead}:$RelativePath") `
        -Label "exact-head $Label Git object"
    if ($expected -notmatch '^[0-9a-f]{40}$') {
        Fail-NxbWindowsEntryGitGuard "exact-head $Label Git object could not be resolved"
    }
    $type = Get-NxbWindowsEntryGitControlValue `
        -GitPath $gitApplication `
        -Arguments @('-C', $RepoRoot, 'cat-file', '-t', $expected) `
        -Label "exact-head $Label Git object type"
    if ($type -cne 'blob') {
        Fail-NxbWindowsEntryGitGuard "exact-head $Label is not a Git blob"
    }
    $actual = Get-NxbWindowsEntryBlobOid -Stream $Stream -Label $Label
    if ($actual -cne $expected) {
        Fail-NxbWindowsEntryGitGuard "pinned $Label bytes differ from exact-head Git authority"
    }
    return $expected
}

$repoRootForGit = $RepoRoot
$gitProxyApplication = $gitApplication
$gitProxyLimits = @{
    Byte = $gitOutputByteLimit
    Lines = $gitOutputLineLimit
}
$gitProxyReadTimeout = $gitReadInactivityTimeoutMilliseconds
$gitProxyExitTimeout = $gitExitTimeoutMilliseconds
$gitProxy = {
    $arguments = @($args | ForEach-Object { [string]$_ })
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $gitProxyApplication
    $startInfo.WorkingDirectory = $repoRootForGit
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
            throw 'NXB-153 Windows entry Git-output guard could not start Git'
        }
        $buffer = [byte[]]::new(65536)
        [Int64]$total = 0
        while ($true) {
            $readTask = $process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $readTask.Wait($gitProxyReadTimeout)) {
                try { $process.Kill($true) } catch {}
                try { [void]$process.WaitForExit($gitProxyExitTimeout) } catch {}
                throw "NXB-153 Windows entry Git-output guard timed out waiting for Git stdout after $gitProxyReadTimeout ms"
            }
            $read = $readTask.Result
            if ($read -le 0) {
                break
            }
            $total += $read
            if ($total -gt $gitProxyLimits.Byte) {
                try { $process.Kill($true) } catch {}
                try { [void]$process.WaitForExit($gitProxyExitTimeout) } catch {}
                throw "NXB-153 Windows entry Git-output guard rejected stdout above $($gitProxyLimits.Byte) bytes"
            }
            $memory.Write($buffer, 0, $read)
        }
        if (-not $process.WaitForExit($gitProxyExitTimeout)) {
            try { $process.Kill($true) } catch {}
            try { [void]$process.WaitForExit($gitProxyExitTimeout) } catch {}
            throw 'NXB-153 Windows entry Git-output guard timed out waiting for Git exit after stdout closed'
        }
        $global:LASTEXITCODE = $process.ExitCode

        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        try {
            $text = $utf8.GetString($memory.ToArray())
        }
        catch {
            throw "NXB-153 Windows entry Git-output guard rejected non-UTF-8 stdout: $($_.Exception.Message)"
        }

        $reader = [IO.StringReader]::new($text)
        try {
            [Int64]$lineCount = 0
            while ($null -ne ($line = $reader.ReadLine())) {
                $lineCount++
                if ($lineCount -gt $gitProxyLimits.Lines) {
                    throw "NXB-153 Windows entry Git-output guard rejected stdout above $($gitProxyLimits.Lines) records"
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
}.GetNewClosure()

$previousGlobalGit = Get-Item Function:\global:git -ErrorAction SilentlyContinue
$previousGlobalGitScriptBlock = if ($null -ne $previousGlobalGit) { $previousGlobalGit.ScriptBlock } else { $null }
$innerStream = $null
$namespaceHandles = [Collections.Generic.List[IDisposable]]::new()
$gitAuthority = $null
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$originalPath = [string]$env:PATH
$pathWasRebound = $false

try {
    $gitAuthority = Open-NxbWindowsEntryPinnedHostTool -Path $gitApplication -Label 'host Git'
    $gitApplication = [string]$gitAuthority.Path
    $gitProxyApplication = $gitApplication

    if ([string]::IsNullOrEmpty($originalPath)) {
        $env:PATH = [string]$gitAuthority.Directory
    }
    else {
        $env:PATH = ([string]$gitAuthority.Directory) + [IO.Path]::PathSeparator + $originalPath
    }
    $pathWasRebound = $true

    $resolvedGit = Get-Command git -CommandType Application -ErrorAction Stop
    $resolvedGitPath = ConvertFrom-NxbWindowsEntryFinalPath -Path ([IO.Path]::GetFullPath([string]$resolvedGit.Source))
    if (-not [string]::Equals($resolvedGitPath, $gitApplication, [StringComparison]::OrdinalIgnoreCase)) {
        Fail-NxbWindowsEntryGitGuard "nested Git resolution differs from pinned host Git: expected '$gitApplication', resolved '$resolvedGitPath'"
    }

    $initialHead = Get-NxbWindowsEntryGitControlValue `
        -GitPath $gitApplication `
        -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') `
        -Label 'initial exact Git HEAD'
    if ($initialHead -notmatch '^[0-9a-f]{40}$') {
        Fail-NxbWindowsEntryGitGuard 'exact Git HEAD could not be resolved before bounded entry delegation'
    }

    foreach ($entry in @(
        [pscustomobject]@{ Path = $RepoRoot; Label = 'repository root' },
        [pscustomobject]@{ Path = $canonicalScriptsRoot; Label = 'scripts namespace' }
    )) {
        $namespaceHandles.Add((Open-NxbWindowsEntryPinnedDirectory -Path $entry.Path -Label $entry.Label))
    }

    $innerStream = Open-NxbWindowsEntryPinnedFile -Path $innerPath -Label "$entryName preserved inner implementation"
    [void](Assert-NxbWindowsEntryCommittedFile -Stream $innerStream -RelativePath $innerRelative -Label "$entryName preserved inner implementation")

    Set-Item -Path Function:\global:git -Value $gitProxy -Force

    $version = (& git --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^git version ') {
        Fail-NxbWindowsEntryGitGuard 'bounded Git proxy self-test failed'
    }

    $savedLineLimit = $gitProxyLimits.Lines
    $savedByteLimit = $gitProxyLimits.Byte
    try {
        $gitProxyLimits.Lines = 1
        $rejected = $false
        try {
            @(& git -C $RepoRoot -c core.quotePath=false ls-tree -rl --full-tree $initialHead) | Out-Null
        }
        catch {
            if ($_.Exception.Message -notlike '*above 1 records*') {
                throw
            }
            $rejected = $true
        }
        if (-not $rejected) {
            Fail-NxbWindowsEntryGitGuard 'bounded Git proxy did not reject exact-head ls-tree at a one-record test limit'
        }

        $gitProxyLimits.Lines = $savedLineLimit
        $gitProxyLimits.Byte = 4
        $rejected = $false
        try {
            @(& git --version) | Out-Null
        }
        catch {
            if ($_.Exception.Message -notlike '*above 4 bytes*') {
                throw
            }
            $rejected = $true
        }
        if (-not $rejected) {
            Fail-NxbWindowsEntryGitGuard 'bounded Git proxy did not reject stdout at a four-byte test limit'
        }
    }
    finally {
        $gitProxyLimits.Lines = $savedLineLimit
        $gitProxyLimits.Byte = $savedByteLimit
        $global:LASTEXITCODE = 0
    }

    . $innerPath @innerParameters

    $finalHead = Get-NxbWindowsEntryGitControlValue `
        -GitPath $gitApplication `
        -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') `
        -Label 'final exact Git HEAD'
    if ($finalHead -cne $initialHead) {
        Fail-NxbWindowsEntryGitGuard "Git HEAD changed during $entryName delegation"
    }
    $finalOid = Get-NxbWindowsEntryBlobOid -Stream $innerStream -Label "$entryName preserved inner final pinned object"
    $expectedOid = Get-NxbWindowsEntryGitControlValue `
        -GitPath $gitApplication `
        -Arguments @('-C', $RepoRoot, 'rev-parse', "${initialHead}:$innerRelative") `
        -Label 'final exact-head inner Git object'
    if ($expectedOid -notmatch '^[0-9a-f]{40}$' -or $finalOid -cne $expectedOid) {
        Fail-NxbWindowsEntryGitGuard "$entryName preserved inner authority changed during execution"
    }
}
catch {
    $primaryError = $_
}
finally {
    try {
        Remove-Item Function:\global:git -Force -ErrorAction SilentlyContinue
        if ($null -ne $previousGlobalGitScriptBlock) {
            Set-Item -Path Function:\global:git -Value $previousGlobalGitScriptBlock -Force
        }
    }
    catch {
        $cleanupErrors.Add("global Git proxy restoration failed: $($_.Exception.Message)")
    }
    if ($null -ne $innerStream) {
        try { $innerStream.Dispose() }
        catch { $cleanupErrors.Add("inner implementation handle disposal failed: $($_.Exception.Message)") }
    }
    for ($index = $namespaceHandles.Count - 1; $index -ge 0; $index--) {
        try { $namespaceHandles[$index].Dispose() }
        catch { $cleanupErrors.Add("entry namespace handle disposal failed at index ${index}: $($_.Exception.Message)") }
    }
    if ($pathWasRebound) {
        try { $env:PATH = $originalPath }
        catch { $cleanupErrors.Add("host PATH restoration failed: $($_.Exception.Message)") }
    }
    if ($null -ne $gitAuthority) {
        try { $gitAuthority.Stream.Dispose() }
        catch { $cleanupErrors.Add("pinned host Git file disposal failed: $($_.Exception.Message)") }
        try { $gitAuthority.DirectoryHandle.Dispose() }
        catch { $cleanupErrors.Add("pinned host Git directory disposal failed: $($_.Exception.Message)") }
    }
}

if ($null -ne $primaryError) {
    if ($cleanupErrors.Count -gt 0) {
        throw "NXB-153 Windows entry Git-output guard failed: $($primaryError.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
    }
    throw $primaryError
}
if ($cleanupErrors.Count -gt 0) {
    Fail-NxbWindowsEntryGitGuard ("cleanup failed after otherwise successful delegation: " + ($cleanupErrors -join ' | '))
}
