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

function Fail-NxbH2 {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows host Rust toolchain H2 wrapper failed: $Message"
}

function Resolve-NxbH2Python {
    foreach ($candidate in @('python3', 'python')) {
        $command = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            $version = (& $command.Source -I --version 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -eq 0 -and $version -match '^Python 3\.(1[1-9]|[2-9][0-9])(?:\.|$)') {
                return $command.Source
            }
        }
    }
    Fail-NxbH2 'Python 3.11 or newer with isolated-mode support is required'
}

function ConvertTo-NxbH2Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Open-NxbH2PinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2 "$Label must be a regular non-reparse file: $Path"
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
        Fail-NxbH2 "could not pin $Label with write/delete sharing withheld: $($_.Exception.Message)"
    }
}

function Get-NxbH2GitBlobOidFromStream {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $savedPosition = $Stream.Position
    try {
        $Stream.Position = 0
        $length = $Stream.Length
        if ($length -le 0 -or $length -gt 1048576) {
            Fail-NxbH2 "$Label size is outside the supported envelope"
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
                Fail-NxbH2 "$Label changed size while hashing"
            }
            [void]$sha1.TransformFinalBlock([byte[]]::new(0), 0, 0)
            return (ConvertTo-NxbH2Hex -Bytes $sha1.Hash)
        }
        finally {
            $sha1.Dispose()
        }
    }
    finally {
        $Stream.Position = $savedPosition
    }
}

function Assert-NxbH2CommittedFile {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $expected = (git rev-parse "${HeadSha}:$RelativePath").Trim()
    if ($LASTEXITCODE -ne 0 -or $expected -notmatch '^[0-9a-f]{40}$') {
        Fail-NxbH2 "exact-head $Label Git object could not be resolved"
    }
    $objectType = (git cat-file -t $expected).Trim()
    if ($LASTEXITCODE -ne 0 -or $objectType -cne 'blob') {
        Fail-NxbH2 "exact-head $Label authority is not a Git blob"
    }
    $actual = Get-NxbH2GitBlobOidFromStream -Stream $Stream -Label $Label
    if ($actual -cne $expected) {
        Fail-NxbH2 "pinned $Label bytes differ from the exact-head committed Git object"
    }
}

function Invoke-NxbH2Authority {
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
            Fail-NxbH2 "$Label failed with exit code $LASTEXITCODE"
        }
        return $output
    }
    & $PythonPath -I $HelperPath @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail-NxbH2 "$Label failed with exit code $LASTEXITCODE"
    }
}

function Get-NxbH2TreeSha256 {
    param([Parameter(Mandatory = $true)][string]$Payload)
    try {
        $record = $Payload | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Fail-NxbH2 "toolchain tree authority output is invalid JSON: $($_.Exception.Message)"
    }
    $value = [string]$record.tree_sha256
    if ($value -notmatch '^[0-9a-f]{64}$') {
        Fail-NxbH2 'toolchain tree authority output has invalid SHA-256'
    }
    return $value
}

if ($null -eq ('Nxb153H2Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Nxb153H2Native
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
            throw new Win32Exception(error, "CreateFileW failed for " + path);
        }
        return handle;
    }

    public static string GetFinalPath(SafeFileHandle handle)
    {
        var builder = new StringBuilder(32768);
        uint result = GetFinalPathNameByHandleW(handle, builder, (uint)builder.Capacity, 0);
        if (result == 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        if (result >= builder.Capacity)
        {
            throw new InvalidOperationException("Resolved path exceeds supported buffer.");
        }
        return builder.ToString();
    }
}
'@
}

function ConvertFrom-NxbH2FinalPath {
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

function Open-NxbH2PinnedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $expected = ConvertFrom-NxbH2FinalPath -Path ([IO.Path]::GetFullPath($Path))
    $handle = [Nxb153H2Native]::OpenDirectory($expected)
    try {
        $resolved = ConvertFrom-NxbH2FinalPath -Path ([Nxb153H2Native]::GetFinalPath($handle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbH2 "$Label resolved through redirected/reparse authority"
        }
        return $handle
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Assert-NxbH2NoReparseTree {
    param([Parameter(Mandatory = $true)][string]$Root)
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2 "snapshot root must be a normal directory: $Root"
    }
    foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-NxbH2 "snapshot contains a reparse point: $($item.FullName)"
        }
    }
}

if (-not $IsWindows) {
    Fail-NxbH2 'Windows H2 wrapper must run on Windows'
}
if ($HeadSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbH2 'exact head is not canonical 40-hex SHA-1'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ValidationDirectory = [IO.Path]::GetFullPath($ValidationDirectory)
$scriptsRoot = Join-Path $RepoRoot 'scripts'
$h1Relative = 'scripts/nxb-153-windows-immutable-source-h1-inner.ps1'
$authorityRelative = 'scripts/nxb-153-rust-toolchain-authority.py'
$h1Path = Join-Path $scriptsRoot 'nxb-153-windows-immutable-source-h1-inner.ps1'
$authorityPath = Join-Path $scriptsRoot 'nxb-153-rust-toolchain-authority.py'
$h1Stream = $null
$authorityStream = $null
$snapshotRoot = $null
$fileStreams = [Collections.Generic.List[IDisposable]]::new()
$directoryHandles = [Collections.Generic.List[IDisposable]]::new()
$aclBackups = [Collections.Generic.List[object]]::new()
$cleanupErrors = [Collections.Generic.List[string]]::new()
$primaryError = $null
$successMessage = $null

try {
    $h1Stream = Open-NxbH2PinnedFile -Path $h1Path -Label 'Windows H1 inner wrapper'
    $authorityStream = Open-NxbH2PinnedFile -Path $authorityPath -Label 'host Rust authority helper'
    Assert-NxbH2CommittedFile -Stream $h1Stream -RelativePath $h1Relative -Label 'Windows H1 inner wrapper'
    Assert-NxbH2CommittedFile -Stream $authorityStream -RelativePath $authorityRelative -Label 'host Rust authority helper'

    $pythonPath = Resolve-NxbH2Python
    Invoke-NxbH2Authority -PythonPath $pythonPath -HelperPath $authorityPath -Arguments @('self-test') -Label 'host Rust authority helper self-test'

    $innerParameters = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $innerParameters[$entry.Key] = $entry.Value
    }

    if ($SelfTest) {
        & $h1Path @innerParameters
        $successMessage = 'NXB-153 Windows H2 wrapper source self-test passed; real NTFS H2 validation remains required.'
    }
    else {
        $hostSysroot = (& rustup run $RustToolchain rustc --print sysroot | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($hostSysroot) -or -not (Test-Path -LiteralPath $hostSysroot -PathType Container)) {
            Fail-NxbH2 "could not resolve Rust $RustToolchain host sysroot"
        }
        $hostSysroot = [IO.Path]::GetFullPath($hostSysroot)

        $hostJson = Invoke-NxbH2Authority -PythonPath $pythonPath -HelperPath $authorityPath -Arguments @('digest', $hostSysroot, '--platform-model', 'windows') -Label 'host Rust tree identity' -Capture
        $hostSha256 = Get-NxbH2TreeSha256 -Payload $hostJson

        $snapshotName = ".nxb-153-rust-h2-windows-$HeadSha-$PID-$([Guid]::NewGuid().ToString('N'))"
        $snapshotRoot = Join-Path $ValidationDirectory $snapshotName
        [void](New-Item -ItemType Directory -Path $snapshotRoot -ErrorAction Stop)

        foreach ($item in Get-ChildItem -LiteralPath $hostSysroot -Force -ErrorAction Stop) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail-NxbH2 "host Rust sysroot contains a reparse point during copy: $($item.FullName)"
            }
            Copy-Item -LiteralPath $item.FullName -Destination $snapshotRoot -Recurse -Force -ErrorAction Stop
        }

        Assert-NxbH2NoReparseTree -Root $snapshotRoot
        Invoke-NxbH2Authority -PythonPath $pythonPath -HelperPath $authorityPath -Arguments @('verify', $snapshotRoot, $hostSha256, '--platform-model', 'windows') -Label 'copied Rust snapshot identity'

        $directoryPaths = [Collections.Generic.List[string]]::new()
        $directoryPaths.Add($snapshotRoot)
        foreach ($directory in Get-ChildItem -LiteralPath $snapshotRoot -Force -Recurse -Directory -ErrorAction Stop) {
            $directoryPaths.Add($directory.FullName)
        }
        $filePaths = [Collections.Generic.List[string]]::new()
        foreach ($file in Get-ChildItem -LiteralPath $snapshotRoot -Force -Recurse -File -ErrorAction Stop) {
            if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail-NxbH2 "snapshot file is a reparse point: $($file.FullName)"
            }
            $filePaths.Add($file.FullName)
        }

        foreach ($directoryPath in $directoryPaths) {
            $directoryHandles.Add((Open-NxbH2PinnedDirectory -Path $directoryPath -Label "Rust snapshot directory $directoryPath"))
        }
        foreach ($filePath in $filePaths) {
            $fileStreams.Add((Open-NxbH2PinnedFile -Path $filePath -Label "Rust snapshot file $filePath"))
        }

        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $denyRights = [IO.FileSystemRights]::WriteData -bor
            [IO.FileSystemRights]::AppendData -bor
            [IO.FileSystemRights]::CreateFiles -bor
            [IO.FileSystemRights]::CreateDirectories -bor
            [IO.FileSystemRights]::Delete -bor
            [IO.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [IO.FileSystemRights]::WriteAttributes -bor
            [IO.FileSystemRights]::WriteExtendedAttributes -bor
            [IO.FileSystemRights]::ChangePermissions -bor
            [IO.FileSystemRights]::TakeOwnership
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagation = [Security.AccessControl.PropagationFlags]::None

        foreach ($directoryPath in $directoryPaths) {
            $originalAcl = Get-Acl -LiteralPath $directoryPath -ErrorAction Stop
            $aclBackups.Add([pscustomobject]@{ Path = $directoryPath; Acl = $originalAcl })
            $newAcl = Get-Acl -LiteralPath $directoryPath -ErrorAction Stop
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $currentSid,
                $denyRights,
                $inheritance,
                $propagation,
                [Security.AccessControl.AccessControlType]::Deny
            )
            [void]$newAcl.AddAccessRule($rule)
            Set-Acl -LiteralPath $directoryPath -AclObject $newAcl -ErrorAction Stop

            $fileProbe = Join-Path $directoryPath ('.nxb-h2-file-probe-' + [Guid]::NewGuid().ToString('N'))
            $directoryProbe = Join-Path $directoryPath ('.nxb-h2-dir-probe-' + [Guid]::NewGuid().ToString('N'))
            $fileCreated = $false
            try {
                [IO.File]::WriteAllText($fileProbe, 'x')
                $fileCreated = $true
            }
            catch [UnauthorizedAccessException] {}
            catch [IO.IOException] {}
            if ($fileCreated -or (Test-Path -LiteralPath $fileProbe)) {
                Fail-NxbH2 "snapshot ACL did not deny file creation in $directoryPath"
            }
            $dirCreated = $false
            try {
                [IO.Directory]::CreateDirectory($directoryProbe) | Out-Null
                $dirCreated = $true
            }
            catch [UnauthorizedAccessException] {}
            catch [IO.IOException] {}
            if ($dirCreated -or (Test-Path -LiteralPath $directoryProbe)) {
                Fail-NxbH2 "snapshot ACL did not deny directory creation in $directoryPath"
            }
        }

        Invoke-NxbH2Authority -PythonPath $pythonPath -HelperPath $authorityPath -Arguments @('verify', $snapshotRoot, $hostSha256, '--platform-model', 'windows') -Label 'pinned Rust snapshot identity'

        $snapshotRustc = Join-Path $snapshotRoot 'bin\rustc.exe'
        $snapshotCargo = Join-Path $snapshotRoot 'bin\cargo.exe'
        $snapshotRustdoc = Join-Path $snapshotRoot 'bin\rustdoc.exe'
        foreach ($requiredBinary in @($snapshotRustc, $snapshotCargo, $snapshotRustdoc)) {
            if (-not (Test-Path -LiteralPath $requiredBinary -PathType Leaf)) {
                Fail-NxbH2 "required snapshot Rust binary is missing: $requiredBinary"
            }
        }

        $snapshotReportedSysroot = (& $snapshotRustc --print sysroot | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or -not [string]::Equals(
            [IO.Path]::GetFullPath($snapshotReportedSysroot),
            [IO.Path]::GetFullPath($snapshotRoot),
            [StringComparison]::OrdinalIgnoreCase
        )) {
            Fail-NxbH2 'relocated snapshot rustc did not report the H2 snapshot as its sysroot'
        }
        $snapshotVersion = (& $snapshotRustc --version | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $snapshotVersion.StartsWith('rustc 1.97.1 ')) {
            Fail-NxbH2 "snapshot rustc version is invalid: $snapshotVersion"
        }

        $hostPath = $env:PATH
        function rustup {
            param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CommandArguments)
            if ($CommandArguments.Count -lt 3 -or $CommandArguments[0] -cne 'run' -or $CommandArguments[1] -cne $RustToolchain) {
                Fail-NxbH2 'H2 rustup shim admits only rustup run <exact-toolchain> <tool> ...'
            }
            $tool = $CommandArguments[2]
            $remaining = if ($CommandArguments.Count -gt 3) {
                @($CommandArguments[3..($CommandArguments.Count - 1)])
            }
            else {
                @()
            }
            switch ($tool) {
                'rustc' {
                    & $snapshotRustc @remaining
                    return
                }
                'cargo' {
                    $savedRustc = $env:RUSTC
                    $savedRustdoc = $env:RUSTDOC
                    $savedPath = $env:PATH
                    try {
                        $env:RUSTC = $snapshotRustc
                        $env:RUSTDOC = $snapshotRustdoc
                        $env:PATH = "$(Join-Path $snapshotRoot 'bin');$hostPath"
                        & $snapshotCargo @remaining
                    }
                    finally {
                        $env:RUSTC = $savedRustc
                        $env:RUSTDOC = $savedRustdoc
                        $env:PATH = $savedPath
                    }
                    return
                }
                default {
                    $candidate = Join-Path (Join-Path $snapshotRoot 'bin') ($tool + '.exe')
                    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                        Fail-NxbH2 "H2 rustup shim tool is unavailable in snapshot: $tool"
                    }
                    & $candidate @remaining
                    return
                }
            }
        }

        & $h1Path @innerParameters

        Invoke-NxbH2Authority -PythonPath $pythonPath -HelperPath $authorityPath -Arguments @('verify', $snapshotRoot, $hostSha256, '--platform-model', 'windows') -Label 'post-gate Rust snapshot identity'

        if ($filePaths.Count -gt 0) {
            $writeSucceeded = $false
            try {
                $probeStream = [IO.File]::Open($filePaths[0], [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $probeStream.Dispose()
                $writeSucceeded = $true
            }
            catch [UnauthorizedAccessException] {}
            catch [IO.IOException] {}
            if ($writeSucceeded) {
                Fail-NxbH2 'snapshot file write probe unexpectedly succeeded after heavy gates'
            }
        }

        $successMessage = 'NXB-153 Windows H2 source-staged snapshot gate passed. Real supported Windows/NTFS execution remains required for admission.'
    }
}
catch {
    $primaryError = $_
}
finally {
    Remove-Item Function:\rustup -ErrorAction SilentlyContinue

    for ($index = $aclBackups.Count - 1; $index -ge 0; $index--) {
        try {
            Set-Acl -LiteralPath $aclBackups[$index].Path -AclObject $aclBackups[$index].Acl -ErrorAction Stop
        }
        catch {
            $cleanupErrors.Add("ACL restore failed for $($aclBackups[$index].Path): $($_.Exception.Message)")
        }
    }

    for ($index = $fileStreams.Count - 1; $index -ge 0; $index--) {
        try { $fileStreams[$index].Dispose() }
        catch { $cleanupErrors.Add("file handle disposal failed: $($_.Exception.Message)") }
    }
    for ($index = $directoryHandles.Count - 1; $index -ge 0; $index--) {
        try { $directoryHandles[$index].Dispose() }
        catch { $cleanupErrors.Add("directory handle disposal failed: $($_.Exception.Message)") }
    }

    if ($null -ne $authorityStream) {
        try { $authorityStream.Dispose() }
        catch { $cleanupErrors.Add("authority helper handle disposal failed: $($_.Exception.Message)") }
    }
    if ($null -ne $h1Stream) {
        try { $h1Stream.Dispose() }
        catch { $cleanupErrors.Add("H1 wrapper handle disposal failed: $($_.Exception.Message)") }
    }

    if ($null -ne $snapshotRoot -and (Test-Path -LiteralPath $snapshotRoot)) {
        try {
            Remove-Item -LiteralPath $snapshotRoot -Recurse -Force -ErrorAction Stop
        }
        catch {
            $cleanupErrors.Add("snapshot cleanup failed: $($_.Exception.Message)")
        }
    }
}

if ($null -ne $primaryError) {
    if ($cleanupErrors.Count -gt 0) {
        throw "NXB-153 Windows H2 failed: $($primaryError.Exception.Message); cleanup errors: $($cleanupErrors -join ' | ')"
    }
    throw $primaryError
}
if ($cleanupErrors.Count -gt 0) {
    Fail-NxbH2 ("cleanup failed after otherwise successful validation: " + ($cleanupErrors -join ' | '))
}
if (-not [string]::IsNullOrWhiteSpace($successMessage)) {
    Write-Host $successMessage
}
