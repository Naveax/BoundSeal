[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$maximumBufferedReviewerBytes = 65536
$maximumBufferedReviewerRecords = 4096

function Fail-NxbWindowsAdmission {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows admission review failed: $Message"
}

if ($null -eq ('Nxb153WindowsAdmissionNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Nxb153WindowsAdmissionNative
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

function ConvertFrom-NxbFinalPath {
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

function Open-NxbPinnedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $expected = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath($Path))
    if (-not (Test-Path -LiteralPath $expected -PathType Container)) {
        Fail-NxbWindowsAdmission "$Label is missing: $expected"
    }
    $item = Get-Item -LiteralPath $expected -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbWindowsAdmission "$Label must not be a reparse point"
    }
    $handle = [Nxb153WindowsAdmissionNative]::OpenDirectoryNoDeleteShare($expected)
    try {
        $resolved = ConvertFrom-NxbFinalPath -Path ([Nxb153WindowsAdmissionNative]::GetFinalPath($handle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbWindowsAdmission "$Label resolved through redirected authority: expected '$expected', resolved '$resolved'"
        }
        return $handle
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Open-NxbPinnedHostTool {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expected = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath($Path))
    if (-not (Test-Path -LiteralPath $expected -PathType Leaf)) {
        Fail-NxbWindowsAdmission "$Label executable is missing: $expected"
    }
    $item = Get-Item -LiteralPath $expected -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbWindowsAdmission "$Label executable must be a regular non-reparse file"
    }

    $directory = [IO.Path]::GetDirectoryName($expected)
    if ([string]::IsNullOrWhiteSpace($directory)) {
        Fail-NxbWindowsAdmission "$Label executable parent directory is unavailable"
    }

    $directoryHandle = $null
    $stream = $null
    try {
        $directoryHandle = Open-NxbPinnedDirectory -Path $directory -Label "$Label executable directory"
        $stream = [IO.File]::Open($expected, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $resolved = ConvertFrom-NxbFinalPath -Path ([Nxb153WindowsAdmissionNative]::GetFinalPath($stream.SafeFileHandle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbWindowsAdmission "$Label executable resolved through redirected authority: expected '$expected', resolved '$resolved'"
        }
        return [pscustomobject]@{
            Path = $expected
            Directory = (ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath($directory)))
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

function Get-NxbGitValue {
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
            Fail-NxbWindowsAdmission "$Label Git process could not be started"
        }

        $buffer = [byte[]]::new(1024)
        [Int64]$total = 0
        while ($true) {
            $readTask = $process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $readTask.Wait(30000)) {
                Fail-NxbWindowsAdmission "$Label Git stdout made no progress for 30000 ms"
            }
            $read = $readTask.Result
            if ($read -le 0) { break }
            $total += $read
            if ($total -gt 4096) {
                Fail-NxbWindowsAdmission "$Label Git stdout exceeds the 4096-byte control-plane envelope"
            }
            $memory.Write($buffer, 0, $read)
        }

        if (-not $process.WaitForExit(30000)) {
            Fail-NxbWindowsAdmission "$Label Git process did not exit after stdout closed"
        }
        if ($process.ExitCode -ne 0) {
            Fail-NxbWindowsAdmission "$Label Git command failed with exit code $($process.ExitCode)"
        }

        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        try {
            $value = $utf8.GetString($memory.ToArray()).Trim()
        }
        catch {
            Fail-NxbWindowsAdmission "$Label Git stdout is not strict UTF-8: $($_.Exception.Message)"
        }
        if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256) {
            Fail-NxbWindowsAdmission "$Label did not return one bounded value"
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
        $expectedPath = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath($path))
        $resolvedPath = ConvertFrom-NxbFinalPath -Path ([Nxb153WindowsAdmissionNative]::GetFinalPath($stream.SafeFileHandle))
        if (-not [string]::Equals($resolvedPath, $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbWindowsAdmission "admission script resolved through redirected authority: expected '$expectedPath', resolved '$resolvedPath'"
        }
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

function Invoke-NxbBufferedReviewer {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $records = [Collections.Generic.List[string]]::new()
    [Int64]$totalBytes = 0
    & $Path -RepoRoot $RepoRoot 6>&1 | ForEach-Object {
        $text = [string]$_
        $bytes = [Text.UTF8Encoding]::new($false, $true).GetByteCount($text) + 1
        $totalBytes += $bytes
        if ($records.Count -ge $maximumBufferedReviewerRecords) {
            Fail-NxbWindowsAdmission "$Label emitted more than $maximumBufferedReviewerRecords buffered records"
        }
        if ($totalBytes -gt $maximumBufferedReviewerBytes) {
            Fail-NxbWindowsAdmission "$Label emitted more than $maximumBufferedReviewerBytes buffered UTF-8 bytes"
        }
        $records.Add($text)
    }
    return @($records)
}

if (-not $IsWindows) {
    Fail-NxbWindowsAdmission 'canonical Windows admission review must run on Windows'
}
if ($PSVersionTable.PSEdition -cne 'Core') {
    Fail-NxbWindowsAdmission 'canonical Windows admission review requires PowerShell Core'
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
    Fail-NxbWindowsAdmission ('ambient Git authority variables are not admitted before exact-head resolution: ' + ($orderedGitAuthority -join ', '))
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$canonicalScripts = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'scripts'))
if (-not [string]::Equals($canonicalScripts, [IO.Path]::GetFullPath($PSScriptRoot), [StringComparison]::OrdinalIgnoreCase)) {
    Fail-NxbWindowsAdmission 'admission wrapper must execute from the canonical repository scripts directory'
}

$namespaceHandles = [Collections.Generic.List[IDisposable]]::new()
$authorities = [Collections.Generic.List[object]]::new()
$toolVersionProbeOutput = @()
$processReviewOutput = @()
$mainReviewOutput = @()
$primaryFailure = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$gitAuthority = $null
$gitPath = $null
$headSha = $null
$originalPath = [string]$env:PATH
$pathWasRebound = $false
try {
    $git = Get-Command git -CommandType Application -ErrorAction Stop
    $gitAuthority = Open-NxbPinnedHostTool -Path ([string]$git.Source) -Label 'host Git'
    $gitPath = [string]$gitAuthority.Path

    if ([string]::IsNullOrEmpty($originalPath)) {
        $env:PATH = [string]$gitAuthority.Directory
    }
    else {
        $env:PATH = ([string]$gitAuthority.Directory) + [IO.Path]::PathSeparator + $originalPath
    }
    $pathWasRebound = $true

    $resolvedGit = Get-Command git -CommandType Application -ErrorAction Stop
    $resolvedGitPath = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath([string]$resolvedGit.Source))
    if (-not [string]::Equals($resolvedGitPath, $gitPath, [StringComparison]::OrdinalIgnoreCase)) {
        Fail-NxbWindowsAdmission "subordinate Git resolution differs from the pinned host Git: expected '$gitPath', resolved '$resolvedGitPath'"
    }

    $headSha = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'initial exact Git HEAD'
    if ($headSha -notmatch '^[0-9a-f]{40}$') {
        Fail-NxbWindowsAdmission 'exact Git HEAD is not canonical 40-hex SHA-1'
    }

    foreach ($entry in @(
        [pscustomobject]@{ Path = $RepoRoot; Label = 'repository root' },
        [pscustomobject]@{ Path = $canonicalScripts; Label = 'scripts directory' }
    )) {
        $namespaceHandles.Add((Open-NxbPinnedDirectory -Path $entry.Path -Label $entry.Label))
    }

    foreach ($relative in @(
        'scripts/review-nxb-153-windows-admission.ps1',
        'scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1',
        'scripts/review-nxb-153-evidence-windows.ps1',
        'scripts/nxb-153-windows-tool-version-output-probe.ps1',
        'scripts/prepare-and-validate-nxb-153-windows-inner.ps1'
    )) {
        $authorities.Add((Open-NxbPinnedExactHeadScript -GitPath $gitPath -HeadSha $headSha -RelativePath $relative))
    }

    $processReviewer = $authorities[1]
    $mainReviewer = $authorities[2]
    $toolVersionProbe = $authorities[3]

    # Tool-version output behavior is a mandatory canonical admission layer, not
    # an optional side probe. The probe itself exact-head binds and AST-loads the
    # production helper, while this wrapper keeps both probe and production
    # tool-preparation source pinned against write/delete for the whole review.
    $toolVersionProbeOutput = @(Invoke-NxbBufferedReviewer -Path ([string]$toolVersionProbe.Path) -Label 'tool-version output regression probe')
    foreach ($authority in $authorities) {
        Assert-NxbPinnedAuthority -GitPath $gitPath -Authority $authority
    }
    $postToolVersionHead = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'post-tool-version-probe Git HEAD'
    if ($postToolVersionHead -cne $headSha) {
        Fail-NxbWindowsAdmission 'Git HEAD changed after tool-version output regression probe'
    }

    $processReviewOutput = @(Invoke-NxbBufferedReviewer -Path ([string]$processReviewer.Path) -Label 'process-lifecycle evidence reviewer')
    foreach ($authority in $authorities) {
        Assert-NxbPinnedAuthority -GitPath $gitPath -Authority $authority
    }
    $middleHead = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'post-process-review Git HEAD'
    if ($middleHead -cne $headSha) {
        Fail-NxbWindowsAdmission 'Git HEAD changed after process-lifecycle evidence review'
    }

    $mainReviewOutput = @(Invoke-NxbBufferedReviewer -Path ([string]$mainReviewer.Path) -Label 'Windows schema-v2 closure reviewer')
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
    for ($index = $namespaceHandles.Count - 1; $index -ge 0; $index--) {
        try { $namespaceHandles[$index].Dispose() }
        catch { $cleanupErrors.Add("pinned admission namespace disposal failed at index ${index}: $($_.Exception.Message)") }
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

if ($null -ne $primaryFailure) {
    if ($cleanupErrors.Count -gt 0) {
        throw "NXB-153 Windows admission review failed: $($primaryFailure.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
    }
    throw $primaryFailure
}
if ($cleanupErrors.Count -gt 0) {
    Fail-NxbWindowsAdmission ("cleanup failed after otherwise successful admission review: " + ($cleanupErrors -join ' | '))
}

foreach ($line in $toolVersionProbeOutput) {
    Write-Host $line
}
foreach ($line in $processReviewOutput) {
    Write-Host $line
}
foreach ($line in $mainReviewOutput) {
    Write-Host $line
}
Write-Host "NXB-153 canonical Windows admission review passed for HEAD $headSha."
