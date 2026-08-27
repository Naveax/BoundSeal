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

$maximumTrackedFiles = 4096
$maximumTrackedBytes = 536870912
$maximumArchiveBytes = 1073741824

function Fail-Nxb {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 immutable Windows source runner failed: $Message"
}

function Assert-LowerSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ($Value -notmatch '^[0-9a-f]{64}$') {
        Fail-Nxb "$Label is not a lowercase SHA-256"
    }
}

function Invoke-NxbCargo {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )
    & rustup run $RustToolchain cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail-Nxb "$Label failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NxbTool {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )
    & $Path @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail-Nxb "$Label failed with exit code $LASTEXITCODE"
    }
}

function Get-NxbExactToolVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $value = (& $Path --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $value -notmatch ('(^|\s)' + [regex]::Escape($ExpectedVersion) + '($|\s)')) {
        Fail-Nxb "$Label version mismatch: expected $ExpectedVersion, found '$value'"
    }
    return $value
}

function ConvertTo-NxbHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NxbStreamSha256 {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        Fail-Nxb "$Label stream must be readable and seekable"
    }
    $savedPosition = $Stream.Position
    try {
        $Stream.Position = 0
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            return (ConvertTo-NxbHex -Bytes ($sha.ComputeHash($Stream)))
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $Stream.Position = $savedPosition
    }
}

function Get-NxbGitBlobOidFromStream {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        Fail-Nxb 'Git blob verification stream must be readable and seekable'
    }
    $savedPosition = $Stream.Position
    try {
        $Stream.Position = 0
        $header = [Text.Encoding]::UTF8.GetBytes("blob $($Stream.Length)`0")
        $incremental = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA1)
        try {
            $incremental.AppendData($header)
            $buffer = [byte[]]::new(1048576)
            while (($read = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $incremental.AppendData($buffer, 0, $read)
            }
            return (ConvertTo-NxbHex -Bytes ($incremental.GetHashAndReset()))
        }
        finally {
            $incremental.Dispose()
        }
    }
    finally {
        $Stream.Position = $savedPosition
    }
}

function Assert-NxbSafeTrackedPath {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    if ($RelativePath.Length -le 0 -or $RelativePath.Length -gt 512) {
        Fail-Nxb "tracked path length is outside the supported envelope: $RelativePath"
    }
    if ($RelativePath -notmatch '^[A-Za-z0-9._/-]+$') {
        Fail-Nxb "tracked path contains bytes outside the conservative Windows validation grammar: $RelativePath"
    }
    foreach ($part in $RelativePath.Split('/')) {
        if ([string]::IsNullOrEmpty($part) -or $part -eq '.' -or $part -eq '..') {
            Fail-Nxb "tracked path contains an empty/dot component: $RelativePath"
        }
        if ($part.EndsWith('.', [StringComparison]::Ordinal) -or $part.EndsWith(' ', [StringComparison]::Ordinal)) {
            Fail-Nxb "tracked path contains a trailing dot/space component: $RelativePath"
        }
        $stem = $part.Split('.')[0]
        if ($stem -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            Fail-Nxb "tracked path contains a reserved Win32 device name: $RelativePath"
        }
    }
}

function Test-NxbRuntimeRelativePath {
    param([Parameter(Mandatory = $true)][string]$RelativePath)
    foreach ($runtimeRoot in @('target', '.nxb-153-tmp', '.nxb-153-cargo-home')) {
        if ($RelativePath -ieq $runtimeRoot -or $RelativePath.StartsWith("$runtimeRoot/", [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-NxbTreeManifest {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$CommitSha
    )

    $lines = & git -C $RepositoryRoot -c core.quotePath=false ls-tree -rl --full-tree $CommitSha
    if ($LASTEXITCODE -ne 0) {
        Fail-Nxb 'git ls-tree failed for exact-head source manifest'
    }

    $manifest = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [Int64]$totalBytes = 0

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        $tab = $line.IndexOf("`t", [StringComparison]::Ordinal)
        if ($tab -le 0 -or $tab -ge ($line.Length - 1)) {
            Fail-Nxb "unparseable git ls-tree record: $line"
        }
        $prefix = $line.Substring(0, $tab)
        $relativePath = $line.Substring($tab + 1)
        $fields = $prefix -split '\s+'
        if ($fields.Count -ne 4) {
            Fail-Nxb "unexpected git ls-tree metadata: $prefix"
        }
        $mode = $fields[0]
        $type = $fields[1]
        $objectId = $fields[2]
        $sizeText = $fields[3]
        if ($mode -notin @('100644', '100755') -or $type -cne 'blob') {
            Fail-Nxb "unsupported exact-head tree entry mode/type for '$relativePath': $mode $type"
        }
        if ($objectId -notmatch '^[0-9a-f]{40}$') {
            Fail-Nxb "invalid Git blob object id for '$relativePath'"
        }
        [Int64]$size = 0
        if (-not [Int64]::TryParse($sizeText, [ref]$size) -or $size -lt 0) {
            Fail-Nxb "invalid Git blob size for '$relativePath'"
        }
        Assert-NxbSafeTrackedPath -RelativePath $relativePath
        if (-not $seen.Add($relativePath)) {
            Fail-Nxb "case-insensitive tracked path collision is unsupported on Windows: $relativePath"
        }
        $totalBytes += $size
        if ($manifest.Count + 1 -gt $maximumTrackedFiles) {
            Fail-Nxb "tracked file count exceeds $maximumTrackedFiles"
        }
        if ($totalBytes -gt $maximumTrackedBytes) {
            Fail-Nxb "tracked byte total exceeds $maximumTrackedBytes"
        }
        $manifest.Add([pscustomobject]@{
            Path = $relativePath
            Mode = $mode
            ObjectId = $objectId
            Size = $size
        })
    }

    if ($manifest.Count -le 0) {
        Fail-Nxb 'exact-head tree manifest is empty'
    }
    foreach ($reserved in @('target', '.nxb-153-tmp', '.nxb-153-cargo-home')) {
        foreach ($entry in $manifest) {
            if ($entry.Path -ieq $reserved -or $entry.Path.StartsWith("$reserved/", [StringComparison]::OrdinalIgnoreCase)) {
                Fail-Nxb "exact-head tree contains reserved runtime path: $reserved"
            }
        }
    }
    return $manifest
}

if ($null -eq ('Nxb153ImmutableWindowsNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Nxb153ImmutableWindowsNative
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

    public static SafeFileHandle OpenDirectory(string path)
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
            throw new Win32Exception(error, "CreateFileW failed for directory " + path);
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
    } elseif ($value.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
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
    $handle = [Nxb153ImmutableWindowsNative]::OpenDirectory($expected)
    try {
        $resolved = ConvertFrom-NxbFinalPath -Path ([Nxb153ImmutableWindowsNative]::GetFinalPath($handle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-Nxb "$Label resolved through a redirected/reparse path: expected '$expected', resolved '$resolved'"
        }
        return $handle
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Open-NxbPinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Fail-Nxb "$Label is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-Nxb "$Label must not be a reparse point: $Path"
    }
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $expected = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath($Path))
        $resolved = ConvertFrom-NxbFinalPath -Path ([Nxb153ImmutableWindowsNative]::GetFinalPath($stream.SafeFileHandle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-Nxb "$Label opened a different file object: expected '$expected', resolved '$resolved'"
        }
        return $stream
    }
    catch {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        throw "Could not pin $Label with write/delete sharing withheld: $($_.Exception.Message)"
    }
}

function New-NxbPinnedGitArchive {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$CommitSha
    )

    $stream = $null
    $process = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $expected = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath($Path))
        $resolved = ConvertFrom-NxbFinalPath -Path ([Nxb153ImmutableWindowsNative]::GetFinalPath($stream.SafeFileHandle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-Nxb "create-new Git archive opened a different object: expected '$expected', resolved '$resolved'"
        }

        $gitCommand = Get-Command git -CommandType Application -ErrorAction Stop
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $gitCommand.Source
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        [void]$startInfo.ArgumentList.Add('-C')
        [void]$startInfo.ArgumentList.Add($RepositoryRoot)
        [void]$startInfo.ArgumentList.Add('archive')
        [void]$startInfo.ArgumentList.Add('--format=tar')
        [void]$startInfo.ArgumentList.Add($CommitSha)

        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            Fail-Nxb 'could not start git archive process'
        }
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $buffer = [byte[]]::new(1048576)
        [Int64]$total = 0
        while (($read = $process.StandardOutput.BaseStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $read
            if ($total -gt $maximumArchiveBytes) {
                try { $process.Kill($true) } catch {}
                Fail-Nxb "exact-head Git archive exceeds $maximumArchiveBytes bytes"
            }
            $stream.Write($buffer, 0, $read)
        }
        $process.WaitForExit()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            Fail-Nxb "git archive failed for exact-head Windows source snapshot: $stderr"
        }
        if ($total -le 0) {
            Fail-Nxb 'exact-head Git archive is empty'
        }
        $stream.Flush($true)
        if ($stream.Length -ne $total) {
            Fail-Nxb 'create-new Git archive stream length differs from captured stdout bytes'
        }
        $stream.Position = 0
        return $stream
    }
    catch {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        throw
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Expand-NxbPinnedTarArchive {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        Fail-Nxb 'pinned Git archive stream must be readable and seekable for extraction'
    }
    $savedPosition = $Stream.Position
    $process = $null
    try {
        $Stream.Position = 0
        $tarCommand = Get-Command tar -CommandType Application -ErrorAction Stop
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $tarCommand.Source
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        [void]$startInfo.ArgumentList.Add('-x')
        [void]$startInfo.ArgumentList.Add('-f')
        [void]$startInfo.ArgumentList.Add('-')
        [void]$startInfo.ArgumentList.Add('-C')
        [void]$startInfo.ArgumentList.Add($Destination)

        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            Fail-Nxb 'could not start tar extraction process'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $Stream.CopyTo($process.StandardInput.BaseStream)
        $process.StandardInput.BaseStream.Flush()
        $process.StandardInput.Close()
        $process.WaitForExit()
        [void]$stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            Fail-Nxb "tar extraction failed for exact-head Windows source snapshot: $stderr"
        }
    }
    catch {
        if ($null -ne $process) {
            try {
                if (-not $process.HasExited) { $process.Kill($true) }
            }
            catch {}
        }
        throw
    }
    finally {
        $Stream.Position = $savedPosition
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Protect-NxbRuntimeDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $true)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-NxbSourceWriteDeny {
    param([Parameter(Mandatory = $true)][string]$Path)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $identity) {
        Fail-Nxb 'current Windows identity SID is unavailable'
    }
    $acl = Get-Acl -LiteralPath $Path
    $rights = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        $rights,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Deny
    )
    [void]$acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-NxbDirectoryCreateDenied {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fileProbe = Join-Path $Path ('.nxb-153-file-deny-probe-' + [Guid]::NewGuid().ToString('N'))
    $fileBlocked = $false
    try {
        [IO.File]::WriteAllText($fileProbe, 'blocked', [Text.UTF8Encoding]::new($false))
    }
    catch [UnauthorizedAccessException] {
        $fileBlocked = $true
    }
    if (-not $fileBlocked -or (Test-Path -LiteralPath $fileProbe)) {
        Fail-Nxb "$Label remained capable of creating a file after source deny ACL staging"
    }

    $directoryProbe = Join-Path $Path ('.nxb-153-dir-deny-probe-' + [Guid]::NewGuid().ToString('N'))
    $directoryBlocked = $false
    try {
        [void][IO.Directory]::CreateDirectory($directoryProbe)
    }
    catch [UnauthorizedAccessException] {
        $directoryBlocked = $true
    }
    if (-not $directoryBlocked -or (Test-Path -LiteralPath $directoryProbe)) {
        Fail-Nxb "$Label remained capable of creating a directory after source deny ACL staging"
    }
}

function Assert-NxbRuntimeWritable {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $probe = Join-Path $Path ('.nxb-153-runtime-probe-' + [Guid]::NewGuid().ToString('N'))
    [IO.File]::WriteAllText($probe, 'ok', [Text.UTF8Encoding]::new($false))
    if ((Get-Content -LiteralPath $probe -Raw) -cne 'ok') {
        Fail-Nxb "$Label did not preserve runtime probe bytes"
    }
    Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $probe) {
        Fail-Nxb "$Label runtime probe could not be removed"
    }
}

function Assert-NxbSnapshotNamespace {
    param(
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [Parameter(Mandatory = $true)][Collections.Generic.Dictionary[string,string]]$ExpectedFiles,
        [Parameter(Mandatory = $true)][Collections.Generic.Dictionary[string,bool]]$ExpectedDirectories,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $seenFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in Get-ChildItem -LiteralPath $SnapshotRoot -File -Force -Recurse) {
        $relative = [IO.Path]::GetRelativePath($SnapshotRoot, $item.FullName).Replace([IO.Path]::DirectorySeparatorChar, '/')
        if (Test-NxbRuntimeRelativePath -RelativePath $relative) {
            continue
        }
        Assert-NxbSafeTrackedPath -RelativePath $relative
        if (-not $ExpectedFiles.ContainsKey($relative) -or -not $seenFiles.Add($relative)) {
            Fail-Nxb "$Label observed an unexpected or duplicate source file: $relative"
        }
    }
    if ($seenFiles.Count -ne $ExpectedFiles.Count) {
        Fail-Nxb "$Label source file namespace count differs from the exact-head manifest"
    }
    foreach ($expectedPath in $ExpectedFiles.Keys) {
        if (-not $seenFiles.Contains($expectedPath)) {
            Fail-Nxb "$Label is missing expected source file: $expectedPath"
        }
    }

    $seenDirectories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in Get-ChildItem -LiteralPath $SnapshotRoot -Directory -Force -Recurse) {
        $relative = [IO.Path]::GetRelativePath($SnapshotRoot, $item.FullName).Replace([IO.Path]::DirectorySeparatorChar, '/')
        if (Test-NxbRuntimeRelativePath -RelativePath $relative) {
            continue
        }
        Assert-NxbSafeTrackedPath -RelativePath $relative
        if (-not $ExpectedDirectories.ContainsKey($relative) -or -not $seenDirectories.Add($relative)) {
            Fail-Nxb "$Label observed an unexpected or duplicate source directory: $relative"
        }
    }
    if ($seenDirectories.Count -ne $ExpectedDirectories.Count) {
        Fail-Nxb "$Label source directory namespace count differs from the exact-head manifest"
    }
    foreach ($expectedPath in $ExpectedDirectories.Keys) {
        if (-not $seenDirectories.Contains($expectedPath)) {
            Fail-Nxb "$Label is missing expected source directory: $expectedPath"
        }
    }
}

function Invoke-NxbSelfTest {
    if (-not $IsWindows) {
        Fail-Nxb 'self-test requires Windows'
    }

    $root = Join-Path ([IO.Path]::GetTempPath()) ("nxb-153-windows-source-selftest-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $root | Out-Null
    $originalAcl = Get-Acl -LiteralPath $root
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    $primaryFailure = $null
    try {
        $nested = Join-Path $root 'nested'
        New-Item -ItemType Directory -Path $nested | Out-Null
        $source = Join-Path $nested 'source.txt'
        [IO.File]::WriteAllText($source, 'trusted', [Text.UTF8Encoding]::new($false))
        $runtime = Join-Path $root 'target'
        Protect-NxbRuntimeDirectory -Path $runtime
        Set-NxbSourceWriteDeny -Path $root

        Assert-NxbDirectoryCreateDenied -Path $root -Label 'self-test source root'
        Assert-NxbDirectoryCreateDenied -Path $nested -Label 'self-test nested source directory'

        $existingWriteBlocked = $false
        try {
            [IO.File]::WriteAllText($source, 'changed', [Text.UTF8Encoding]::new($false))
        }
        catch [UnauthorizedAccessException] {
            $existingWriteBlocked = $true
        }
        if (-not $existingWriteBlocked -or (Get-Content -LiteralPath $source -Raw) -cne 'trusted') {
            Fail-Nxb 'write-deny ACL self-test did not preserve existing nested source bytes'
        }

        Assert-NxbRuntimeWritable -Path $runtime -Label 'self-test runtime directory'
    }
    catch {
        $primaryFailure = $_
    }
    finally {
        if (Test-Path -LiteralPath $root) {
            try { Set-Acl -LiteralPath $root -AclObject $originalAcl -ErrorAction Stop } catch { $cleanupErrors.Add("self-test ACL restore: $($_.Exception.Message)") }
            try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop } catch { $cleanupErrors.Add("self-test root removal: $($_.Exception.Message)") }
        }
    }

    if ($null -ne $primaryFailure -or $cleanupErrors.Count -gt 0) {
        $parts = [Collections.Generic.List[string]]::new()
        if ($null -ne $primaryFailure) { $parts.Add("primary: $($primaryFailure.Exception.Message)") }
        foreach ($errorText in $cleanupErrors) { $parts.Add("cleanup: $errorText") }
        Fail-Nxb ($parts -join ' | ')
    }
    Write-Host 'NXB-153 immutable Windows source ACL primitive self-test passed.'
}

if ($SelfTest) {
    Invoke-NxbSelfTest
    return
}

if (-not $IsWindows) {
    Fail-Nxb 'immutable Windows source validation must run on Windows'
}
foreach ($command in @('git', 'rustup', 'tar')) {
    if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
        Fail-Nxb "$command is unavailable"
    }
}
if ($HeadSha -notmatch '^[0-9a-f]{40}$') {
    Fail-Nxb 'exact head is not a canonical 40-hex SHA-1'
}
Assert-LowerSha256 -Value $AuditSha256 -Label 'cargo-audit SHA-256'
Assert-LowerSha256 -Value $DenySha256 -Label 'cargo-deny SHA-256'
Assert-LowerSha256 -Value $ExpectedCargoLockSha256 -Label 'Cargo.lock SHA-256'

$repoRootFull = [IO.Path]::GetFullPath($RepoRoot)
$validationRoot = [IO.Path]::GetFullPath($ValidationDirectory)
$snapshotRoot = Join-Path $validationRoot (".nxb-153-windows-source-$HeadSha-" + [Guid]::NewGuid().ToString('N'))
$archivePath = "$snapshotRoot.tar"
$directoryHandles = [Collections.Generic.List[IDisposable]]::new()
$fileStreams = [Collections.Generic.List[IO.FileStream]]::new()
$sourceDirectories = [Collections.Generic.List[string]]::new()
$archiveStream = $null
$validationRootHandle = $null
$repoRootHandle = $null
$originalRootAcl = $null
$primaryFailure = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$validationSucceeded = $false

try {
    $repoRootHandle = Open-NxbPinnedDirectory -Path $repoRootFull -Label 'repository root'
    $validationRootHandle = Open-NxbPinnedDirectory -Path $validationRoot -Label 'validation evidence directory'
    $manifest = @(Get-NxbTreeManifest -RepositoryRoot $repoRootFull -CommitSha $HeadSha)

    $expectedSourceDirectories = [Collections.Generic.Dictionary[string,bool]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $manifest) {
        $parent = $entry.Path
        while (($slash = $parent.LastIndexOf('/')) -gt 0) {
            $parent = $parent.Substring(0, $slash)
            if (-not $expectedSourceDirectories.ContainsKey($parent)) {
                $expectedSourceDirectories.Add($parent, $true)
            }
        }
    }

    New-Item -ItemType Directory -Path $snapshotRoot | Out-Null
    $directoryHandles.Add((Open-NxbPinnedDirectory -Path $snapshotRoot -Label 'immutable source snapshot root'))
    $sourceDirectories.Add($snapshotRoot)

    $archiveStream = New-NxbPinnedGitArchive -RepositoryRoot $repoRootFull -Path $archivePath -CommitSha $HeadSha
    Expand-NxbPinnedTarArchive -Stream $archiveStream -Destination $snapshotRoot

    $reparse = Get-ChildItem -LiteralPath $snapshotRoot -Force -Recurse | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    } | Select-Object -First 1
    if ($null -ne $reparse) {
        Fail-Nxb "exact-head snapshot unexpectedly contains a reparse point: $($reparse.FullName)"
    }

    $observedSourceDirectories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($directory in @(Get-ChildItem -LiteralPath $snapshotRoot -Directory -Force -Recurse | Sort-Object { $_.FullName.Length } | ForEach-Object { $_.FullName })) {
        $relativeDirectory = [IO.Path]::GetRelativePath($snapshotRoot, $directory).Replace([IO.Path]::DirectorySeparatorChar, '/')
        Assert-NxbSafeTrackedPath -RelativePath $relativeDirectory
        if (-not $expectedSourceDirectories.ContainsKey($relativeDirectory) -or -not $observedSourceDirectories.Add($relativeDirectory)) {
            Fail-Nxb "snapshot contains unexpected or duplicate source directory: $relativeDirectory"
        }
        $sourceDirectories.Add($directory)
        $directoryHandles.Add((Open-NxbPinnedDirectory -Path $directory -Label 'immutable source directory'))
    }
    if ($observedSourceDirectories.Count -ne $expectedSourceDirectories.Count) {
        Fail-Nxb 'snapshot source directory count differs from the exact-head manifest'
    }

    $actualFiles = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in Get-ChildItem -LiteralPath $snapshotRoot -File -Force -Recurse) {
        $relative = [IO.Path]::GetRelativePath($snapshotRoot, $item.FullName).Replace([IO.Path]::DirectorySeparatorChar, '/')
        Assert-NxbSafeTrackedPath -RelativePath $relative
        if ($actualFiles.ContainsKey($relative)) {
            Fail-Nxb "duplicate extracted path: $relative"
        }
        $actualFiles.Add($relative, $item.FullName)
    }
    if ($actualFiles.Count -ne $manifest.Count) {
        Fail-Nxb "snapshot file count differs from exact-head tree: expected $($manifest.Count), found $($actualFiles.Count)"
    }

    $cargoLockStream = $null
    for ($index = 0; $index -lt $manifest.Count; $index++) {
        $entry = $manifest[$index]
        if (-not $actualFiles.ContainsKey($entry.Path)) {
            Fail-Nxb "snapshot is missing exact-head tracked file: $($entry.Path)"
        }
        $path = $actualFiles[$entry.Path]
        $stream = Open-NxbPinnedFile -Path $path -Label "tracked source $($entry.Path)"
        if ($stream.Length -ne $entry.Size) {
            $stream.Dispose()
            Fail-Nxb "tracked file size mismatch for $($entry.Path): expected $($entry.Size), found $($stream.Length)"
        }
        $oid = Get-NxbGitBlobOidFromStream -Stream $stream
        if ($oid -cne $entry.ObjectId) {
            $stream.Dispose()
            Fail-Nxb "tracked file bytes do not match exact-head Git blob for $($entry.Path)"
        }
        $fileStreams.Add($stream)
        if ($entry.Path -ceq 'Cargo.lock') {
            $cargoLockStream = $stream
        }
    }
    if ($null -eq $cargoLockStream) {
        Fail-Nxb 'exact-head snapshot does not contain Cargo.lock'
    }
    $lockSha = Get-NxbStreamSha256 -Stream $cargoLockStream -Label 'snapshot Cargo.lock'
    if ($lockSha -cne $ExpectedCargoLockSha256) {
        Fail-Nxb "immutable snapshot Cargo.lock SHA-256 mismatch: expected $ExpectedCargoLockSha256, found $lockSha"
    }

    $auditPathSha = (Get-FileHash -LiteralPath $AuditPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $denyPathSha = (Get-FileHash -LiteralPath $DenyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($auditPathSha -cne $AuditSha256) {
        Fail-Nxb 'cargo-audit path does not name the receipt-admitted pinned bytes before immutable validation'
    }
    if ($denyPathSha -cne $DenySha256) {
        Fail-Nxb 'cargo-deny path does not name the receipt-admitted pinned bytes before immutable validation'
    }
    [void](Get-NxbExactToolVersion -Path $AuditPath -ExpectedVersion $CargoAuditVersion -Label 'cargo-audit')
    [void](Get-NxbExactToolVersion -Path $DenyPath -ExpectedVersion $CargoDenyVersion -Label 'cargo-deny')

    $runtimeTarget = Join-Path $snapshotRoot 'target'
    $runtimeTmp = Join-Path $snapshotRoot '.nxb-153-tmp'
    $runtimeCargoHome = Join-Path $snapshotRoot '.nxb-153-cargo-home'
    foreach ($runtime in @($runtimeTarget, $runtimeTmp, $runtimeCargoHome)) {
        Protect-NxbRuntimeDirectory -Path $runtime
    }

    $originalRootAcl = Get-Acl -LiteralPath $snapshotRoot
    Set-NxbSourceWriteDeny -Path $snapshotRoot

    foreach ($sourceDirectory in $sourceDirectories) {
        Assert-NxbDirectoryCreateDenied -Path $sourceDirectory -Label "source directory $sourceDirectory"
    }
    Assert-NxbRuntimeWritable -Path $runtimeTarget -Label 'Cargo target directory'
    Assert-NxbRuntimeWritable -Path $runtimeTmp -Label 'temporary directory'
    Assert-NxbRuntimeWritable -Path $runtimeCargoHome -Label 'Cargo home directory'
    Assert-NxbSnapshotNamespace -SnapshotRoot $snapshotRoot -ExpectedFiles $actualFiles -ExpectedDirectories $expectedSourceDirectories -Label 'pre-gate namespace check'

    $previousTarget = $env:CARGO_TARGET_DIR
    $previousCargoHome = $env:CARGO_HOME
    $previousTmp = $env:TMP
    $previousTemp = $env:TEMP
    $env:CARGO_TARGET_DIR = $runtimeTarget
    $env:CARGO_HOME = $runtimeCargoHome
    $env:TMP = $runtimeTmp
    $env:TEMP = $runtimeTmp

    Push-Location $snapshotRoot
    try {
        Invoke-NxbCargo -Arguments @('metadata', '--format-version', '1', '--locked', '--no-deps') -Label 'cargo metadata --locked'
        Invoke-NxbCargo -Arguments @('fmt', '--all', '--', '--check') -Label 'cargo fmt'

        Invoke-NxbCargo -Arguments @('check', '-p', 'nxb-policy', '--all-targets', '--locked') -Label 'nxb-policy cargo check'
        Invoke-NxbCargo -Arguments @('clippy', '-p', 'nxb-policy', '--all-targets', '--locked', '--', '-D', 'warnings') -Label 'nxb-policy cargo clippy'
        Invoke-NxbCargo -Arguments @('test', '-p', 'nxb-policy', '--locked', '--', '--test-threads=1') -Label 'nxb-policy cargo test'

        Invoke-NxbCargo -Arguments @('check', '-p', 'nxb-core', '--all-targets', '--locked') -Label 'nxb-core cargo check'
        Invoke-NxbCargo -Arguments @('clippy', '-p', 'nxb-core', '--all-targets', '--locked', '--', '-D', 'warnings') -Label 'nxb-core cargo clippy'
        Invoke-NxbCargo -Arguments @('test', '-p', 'nxb-core', '--lib', '--locked', '--', '--test-threads=1') -Label 'nxb-core unit tests'
        foreach ($testName in @(
            'target_setup_cli',
            'target_activation_cli',
            'target_activation_recovery_cli',
            'target_guided_artifact_cli',
            'target_import_cli',
            'target_import_failclosed_cli',
            'target_path_binding_cli',
            'target_scope_failclosed_cli',
            'target_subdomain_failclosed_cli',
            'target_persistence_envelope_cli',
            'target_unicode_path_failclosed_cli'
        )) {
            Invoke-NxbCargo -Arguments @('test', '-p', 'nxb-core', '--test', $testName, '--locked', '--', '--test-threads=1') -Label "focused test $testName"
        }

        Invoke-NxbCargo -Arguments @('check', '--workspace', '--all-targets', '--all-features', '--locked') -Label 'workspace cargo check'
        Invoke-NxbCargo -Arguments @('clippy', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings') -Label 'workspace cargo clippy'
        Invoke-NxbCargo -Arguments @('test', '--workspace', '--all-features', '--locked', '--', '--test-threads=1') -Label 'workspace cargo test'

        Invoke-NxbTool -Path $AuditPath -Arguments @('audit') -Label 'RustSec cargo audit'
        Invoke-NxbTool -Path $DenyPath -Arguments @('check') -Label 'cargo-deny checks'

        $finalLockSha = Get-NxbStreamSha256 -Stream $cargoLockStream -Label 'final snapshot Cargo.lock'
        if ($finalLockSha -cne $ExpectedCargoLockSha256) {
            Fail-Nxb 'immutable snapshot Cargo.lock changed during validation'
        }
        for ($index = 0; $index -lt $manifest.Count; $index++) {
            $entry = $manifest[$index]
            $stream = $fileStreams[$index]
            if ((Get-NxbGitBlobOidFromStream -Stream $stream) -cne $entry.ObjectId) {
                Fail-Nxb "pinned tracked source object changed during validation: $($entry.Path)"
            }
            $path = $actualFiles[$entry.Path]
            $item = Get-Item -LiteralPath $path -Force
            if ($item.Length -ne $entry.Size -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail-Nxb "tracked source pathname/object metadata changed during validation: $($entry.Path)"
            }
        }
        Assert-NxbSnapshotNamespace -SnapshotRoot $snapshotRoot -ExpectedFiles $actualFiles -ExpectedDirectories $expectedSourceDirectories -Label 'post-gate namespace check'
        $finalAuditPathSha = (Get-FileHash -LiteralPath $AuditPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $finalDenyPathSha = (Get-FileHash -LiteralPath $DenyPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($finalAuditPathSha -cne $AuditSha256 -or $finalDenyPathSha -cne $DenySha256) {
            Fail-Nxb 'security-tool canonical paths drifted during immutable source validation'
        }
        $validationSucceeded = $true
    }
    finally {
        Pop-Location
        $env:CARGO_TARGET_DIR = $previousTarget
        $env:CARGO_HOME = $previousCargoHome
        $env:TMP = $previousTmp
        $env:TEMP = $previousTemp
    }
}
catch {
    $primaryFailure = $_
}
finally {
    if ($null -ne $originalRootAcl -and (Test-Path -LiteralPath $snapshotRoot)) {
        try { Set-Acl -LiteralPath $snapshotRoot -AclObject $originalRootAcl -ErrorAction Stop } catch { $cleanupErrors.Add("snapshot ACL restore: $($_.Exception.Message)") }
    }
    for ($index = $fileStreams.Count - 1; $index -ge 0; $index--) {
        try { $fileStreams[$index].Dispose() } catch { $cleanupErrors.Add("tracked file handle disposal: $($_.Exception.Message)") }
    }
    for ($index = $directoryHandles.Count - 1; $index -ge 0; $index--) {
        try { $directoryHandles[$index].Dispose() } catch { $cleanupErrors.Add("source directory handle disposal: $($_.Exception.Message)") }
    }
    if ($null -ne $archiveStream) {
        try { $archiveStream.Dispose() } catch { $cleanupErrors.Add("archive handle disposal: $($_.Exception.Message)") }
    }
    if ($null -ne $validationRootHandle) {
        try { $validationRootHandle.Dispose() } catch { $cleanupErrors.Add("validation directory handle disposal: $($_.Exception.Message)") }
    }
    if ($null -ne $repoRootHandle) {
        try { $repoRootHandle.Dispose() } catch { $cleanupErrors.Add("repository handle disposal: $($_.Exception.Message)") }
    }
    if (Test-Path -LiteralPath $snapshotRoot) {
        try { Remove-Item -LiteralPath $snapshotRoot -Recurse -Force -ErrorAction Stop } catch { $cleanupErrors.Add("snapshot removal: $($_.Exception.Message)") }
    }
    if (Test-Path -LiteralPath $archivePath) {
        try { Remove-Item -LiteralPath $archivePath -Force -ErrorAction Stop } catch { $cleanupErrors.Add("archive removal: $($_.Exception.Message)") }
    }
}

if ($null -ne $primaryFailure -or $cleanupErrors.Count -gt 0 -or -not $validationSucceeded) {
    $parts = [Collections.Generic.List[string]]::new()
    if ($null -ne $primaryFailure) { $parts.Add("primary: $($primaryFailure.Exception.Message)") }
    if (-not $validationSucceeded -and $null -eq $primaryFailure) { $parts.Add('primary: validation did not reach the success boundary') }
    foreach ($errorText in $cleanupErrors) { $parts.Add("cleanup: $errorText") }
    Fail-Nxb ($parts -join ' | ')
}

Write-Host 'NXB-153 exact-head Windows gates passed inside a pinned write-denied source snapshot.'
