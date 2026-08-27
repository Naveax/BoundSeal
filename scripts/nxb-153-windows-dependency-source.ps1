[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SnapshotRoot,
    [Parameter(Mandatory = $true)][string]$RuntimeTarget,
    [Parameter(Mandatory = $true)][string]$RuntimeTmp,
    [Parameter(Mandatory = $true)][string]$RuntimeCargoHome,
    [Parameter(Mandatory = $true)][string]$RustToolchain,
    [Parameter(Mandatory = $true)][string]$CargoAuditVersion,
    [Parameter(Mandatory = $true)][string]$CargoDenyVersion,
    [Parameter(Mandatory = $true)][string]$AuditSha256,
    [Parameter(Mandatory = $true)][string]$DenySha256,
    [Parameter(Mandatory = $true)][string]$AuditPath,
    [Parameter(Mandatory = $true)][string]$DenyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$maximumVendorFiles = 200000
$maximumVendorBytes = [Int64]4294967296

function Fail-NxbDependency {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows dependency source authority failed: $Message"
}

function ConvertTo-NxbDependencyHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NxbDependencyStreamSha256 {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        Fail-NxbDependency "$Label stream must be readable and seekable"
    }
    $position = $Stream.Position
    try {
        $Stream.Position = 0
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            return (ConvertTo-NxbDependencyHex -Bytes ($sha.ComputeHash($Stream)))
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $Stream.Position = $position
    }
}

function Resolve-NxbPython {
    foreach ($candidate in @('python3', 'python')) {
        $command = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            $version = (& $command.Source --version 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -eq 0 -and $version -match '^Python 3\.(1[1-9]|[2-9][0-9])(?:\.|$)') {
                return $command.Source
            }
        }
    }
    Fail-NxbDependency 'Python 3.11 or newer is required for registry source authority verification'
}

function Invoke-NxbDependencyCargo {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )
    & rustup run $RustToolchain cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail-NxbDependency "$Label failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NxbDependencyTool {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )
    & $Path @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail-NxbDependency "$Label failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NxbRegistryVerifier {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$HelperPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )
    & $PythonPath $HelperPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail-NxbDependency "$Label failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NxbRegistryVerifierWithInput {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$HelperPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$InputText,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $process = $null
    try {
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $PythonPath
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        [void]$startInfo.ArgumentList.Add($HelperPath)
        foreach ($argument in $Arguments) {
            [void]$startInfo.ArgumentList.Add($argument)
        }

        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            Fail-NxbDependency "could not start registry verifier for $Label"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Write($InputText)
        $process.StandardInput.Close()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            Fail-NxbDependency "$Label failed: $stderr"
        }
        return $stdout.Trim()
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function ConvertTo-NxbTomlBasicString {
    param([Parameter(Mandatory = $true)][string]$Value)
    foreach ($character in $Value.ToCharArray()) {
        if ([char]::IsControl($character)) {
            Fail-NxbDependency 'Cargo source replacement path contains a control character'
        }
    }
    return $Value.Replace('\', '\\').Replace('"', '\"')
}

if ($null -eq ('Nxb153DependencyWindowsNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Nxb153DependencyWindowsNative
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

function ConvertFrom-NxbDependencyFinalPath {
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

function Open-NxbDependencyDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $expected = ConvertFrom-NxbDependencyFinalPath -Path ([IO.Path]::GetFullPath($Path))
    $handle = [Nxb153DependencyWindowsNative]::OpenDirectory($expected)
    try {
        $resolved = ConvertFrom-NxbDependencyFinalPath -Path ([Nxb153DependencyWindowsNative]::GetFinalPath($handle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbDependency "$Label resolved through a redirected path: expected '$expected', resolved '$resolved'"
        }
        return $handle
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Open-NxbDependencyFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        $stream = $null
        try {
            $stream = [IO.File]::Open(
                $Path,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read
            )
            $expected = ConvertFrom-NxbDependencyFinalPath -Path ([IO.Path]::GetFullPath($Path))
            $resolved = ConvertFrom-NxbDependencyFinalPath -Path ([Nxb153DependencyWindowsNative]::GetFinalPath($stream.SafeFileHandle))
            if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
                Fail-NxbDependency "$Label opened a different object: expected '$expected', resolved '$resolved'"
            }
            return $stream
        }
        catch {
            if ($null -ne $stream) { $stream.Dispose() }
            throw
        }
    }
    Fail-NxbDependency "$Label must be a regular non-reparse file: $Path"
}

function Set-NxbDependencyWriteDeny {
    param([Parameter(Mandatory = $true)][string]$Path)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $identity) {
        Fail-NxbDependency 'current Windows identity SID is unavailable'
    }
    $acl = Get-Acl -LiteralPath $Path
    $rights = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        $rights,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Deny
    )
    [void]$acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Assert-NxbDependencyDirectoryDenied {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fileProbe = Join-Path $Path ('.nxb-153-dependency-file-probe-' + [Guid]::NewGuid().ToString('N'))
    $fileBlocked = $false
    try {
        [IO.File]::WriteAllText($fileProbe, 'blocked', [Text.UTF8Encoding]::new($false))
    }
    catch [UnauthorizedAccessException] {
        $fileBlocked = $true
    }
    if (-not $fileBlocked -or (Test-Path -LiteralPath $fileProbe)) {
        Fail-NxbDependency "dependency directory remained capable of creating a file: $Path"
    }

    $directoryProbe = Join-Path $Path ('.nxb-153-dependency-dir-probe-' + [Guid]::NewGuid().ToString('N'))
    $directoryBlocked = $false
    try {
        [void][IO.Directory]::CreateDirectory($directoryProbe)
    }
    catch [UnauthorizedAccessException] {
        $directoryBlocked = $true
    }
    if (-not $directoryBlocked -or (Test-Path -LiteralPath $directoryProbe)) {
        Fail-NxbDependency "dependency directory remained capable of creating a subdirectory: $Path"
    }
}

$SnapshotRoot = [IO.Path]::GetFullPath($SnapshotRoot)
$RuntimeTarget = [IO.Path]::GetFullPath($RuntimeTarget)
$RuntimeTmp = [IO.Path]::GetFullPath($RuntimeTmp)
$RuntimeCargoHome = [IO.Path]::GetFullPath($RuntimeCargoHome)
$registryHelper = Join-Path $SnapshotRoot 'scripts\nxb-153-registry-source.py'
$lockPath = Join-Path $SnapshotRoot 'Cargo.lock'
$pythonPath = Resolve-NxbPython

foreach ($path in @($SnapshotRoot, $RuntimeTarget, $RuntimeTmp, $RuntimeCargoHome)) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        Fail-NxbDependency "required dependency authority directory is missing: $path"
    }
}
if (-not (Test-Path -LiteralPath $registryHelper -PathType Leaf)) {
    Fail-NxbDependency "registry source helper is missing from immutable snapshot: $registryHelper"
}

Invoke-NxbRegistryVerifier `
    -PythonPath $pythonPath `
    -HelperPath $registryHelper `
    -Arguments @('self-test') `
    -Label 'registry source authority primitive self-test'
Invoke-NxbRegistryVerifier `
    -PythonPath $pythonPath `
    -HelperPath $registryHelper `
    -Arguments @('validate-lock', $lockPath) `
    -Label 'Cargo.lock registry source admission'

$fetchHome = Join-Path $RuntimeCargoHome 'fetch'
$vendorRoot = Join-Path $RuntimeCargoHome 'vendor'
$gateHome = Join-Path $RuntimeCargoHome 'gate'
foreach ($path in @($fetchHome, $vendorRoot, $gateHome)) {
    if (Test-Path -LiteralPath $path) {
        Fail-NxbDependency "dependency runtime path unexpectedly already exists: $path"
    }
    New-Item -ItemType Directory -Path $path | Out-Null
}

$vendorDirectoryHandles = [Collections.Generic.List[IDisposable]]::new()
$vendorFileStreams = [Collections.Generic.List[IO.FileStream]]::new()
$runtimeCargoHomeHandle = $null
$fetchHomeHandle = $null
$vendorRootHandle = $null
$gateHomeHandle = $null
$configStream = $null
$vendorOriginalAcl = $null
$primaryFailure = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()

$oldTarget = $env:CARGO_TARGET_DIR
$oldCargoHome = $env:CARGO_HOME
$oldTmp = $env:TMP
$oldTemp = $env:TEMP
$oldOffline = $env:CARGO_NET_OFFLINE

try {
    $runtimeCargoHomeHandle = Open-NxbDependencyDirectory -Path $RuntimeCargoHome -Label 'dependency runtime root'
    $fetchHomeHandle = Open-NxbDependencyDirectory -Path $fetchHome -Label 'fetch CARGO_HOME'
    $vendorRootHandle = Open-NxbDependencyDirectory -Path $vendorRoot -Label 'vendor root'
    $gateHomeHandle = Open-NxbDependencyDirectory -Path $gateHome -Label 'gate CARGO_HOME'

    $env:CARGO_TARGET_DIR = $RuntimeTarget
    $env:TMP = $RuntimeTmp
    $env:TEMP = $RuntimeTmp
    $env:CARGO_HOME = $fetchHome
    Remove-Item Env:CARGO_NET_OFFLINE -ErrorAction SilentlyContinue

    Push-Location $SnapshotRoot
    try {
        Invoke-NxbDependencyCargo -Arguments @('fetch', '--locked') -Label 'cargo fetch --locked'

        $metadataText = (& rustup run $RustToolchain cargo metadata --format-version 1 --locked | Out-String)
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($metadataText)) {
            Fail-NxbDependency 'cargo metadata --locked failed before dependency freeze'
        }
        [void](Invoke-NxbRegistryVerifierWithInput `
            -PythonPath $pythonPath `
            -HelperPath $registryHelper `
            -Arguments @('validate-metadata', $SnapshotRoot) `
            -InputText $metadataText `
            -Label 'Cargo metadata source locality')

        $env:CARGO_NET_OFFLINE = 'true'
        Invoke-NxbDependencyCargo `
            -Arguments @('vendor', '--locked', '--versioned-dirs', $vendorRoot) `
            -Label 'offline cargo vendor'
        Invoke-NxbRegistryVerifier `
            -PythonPath $pythonPath `
            -HelperPath $registryHelper `
            -Arguments @('validate-vendor', $lockPath, $vendorRoot) `
            -Label 'vendored registry dependency authority'

        $vendorOriginalAcl = Get-Acl -LiteralPath $vendorRoot
        Set-NxbDependencyWriteDeny -Path $vendorRoot

        [Int64]$pinnedBytes = 0
        $pinnedFiles = 0
        foreach ($directory in @(Get-ChildItem -LiteralPath $vendorRoot -Directory -Force -Recurse | Sort-Object { $_.FullName.Length } | ForEach-Object { $_.FullName })) {
            Assert-NxbDependencyDirectoryDenied -Path $directory
            $vendorDirectoryHandles.Add((Open-NxbDependencyDirectory -Path $directory -Label 'vendored dependency directory'))
        }
        Assert-NxbDependencyDirectoryDenied -Path $vendorRoot
        foreach ($file in Get-ChildItem -LiteralPath $vendorRoot -File -Force -Recurse) {
            $pinnedFiles++
            $pinnedBytes += $file.Length
            if ($pinnedFiles -gt $maximumVendorFiles -or $pinnedBytes -gt $maximumVendorBytes) {
                Fail-NxbDependency 'vendored dependency snapshot exceeds pinned file/byte envelope'
            }
            $vendorFileStreams.Add((Open-NxbDependencyFile -Path $file.FullName -Label 'vendored dependency file'))
        }
        Invoke-NxbRegistryVerifier `
            -PythonPath $pythonPath `
            -HelperPath $registryHelper `
            -Arguments @('validate-vendor', $lockPath, $vendorRoot) `
            -Label 'pinned vendored registry dependency authority'

        $configPath = Join-Path $gateHome 'config.toml'
        $vendorForToml = ConvertTo-NxbTomlBasicString -Value $vendorRoot
        $configText = @"
[source.crates-io]
replace-with = "nxb-vendored-sources"

[source.nxb-vendored-sources]
directory = "$vendorForToml"
"@
        $configBytes = [Text.UTF8Encoding]::new($false).GetBytes($configText)
        $configWrite = [IO.File]::Open(
            $configPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
        try {
            $configWrite.Write($configBytes, 0, $configBytes.Length)
            $configWrite.Flush($true)
        }
        finally {
            $configWrite.Dispose()
        }
        $configStream = Open-NxbDependencyFile -Path $configPath -Label 'gate Cargo config'
        $configSha256 = Get-NxbDependencyStreamSha256 -Stream $configStream -Label 'gate Cargo config'

        $gateProbe = Join-Path $gateHome '.nxb-153-gate-home-probe'
        [IO.File]::WriteAllText($gateProbe, 'writable', [Text.UTF8Encoding]::new($false))
        Remove-Item -LiteralPath $gateProbe -Force -ErrorAction Stop
        $configWriteBlocked = $false
        try {
            [IO.File]::WriteAllText($configPath, 'changed', [Text.UTF8Encoding]::new($false))
        }
        catch [IO.IOException] {
            $configWriteBlocked = $true
        }
        catch [UnauthorizedAccessException] {
            $configWriteBlocked = $true
        }
        if (-not $configWriteBlocked) {
            Fail-NxbDependency 'gate Cargo config remained writable while pinned'
        }

        $env:CARGO_HOME = $gateHome
        $env:CARGO_NET_OFFLINE = 'true'

        Invoke-NxbDependencyCargo -Arguments @('metadata', '--format-version', '1', '--locked') -Label 'offline cargo metadata'
        Invoke-NxbDependencyCargo -Arguments @('fmt', '--all', '--', '--check') -Label 'cargo fmt'

        Invoke-NxbDependencyCargo -Arguments @('check', '-p', 'nxb-policy', '--all-targets', '--locked') -Label 'nxb-policy cargo check'
        Invoke-NxbDependencyCargo -Arguments @('clippy', '-p', 'nxb-policy', '--all-targets', '--locked', '--', '-D', 'warnings') -Label 'nxb-policy cargo clippy'
        Invoke-NxbDependencyCargo -Arguments @('test', '-p', 'nxb-policy', '--locked', '--', '--test-threads=1') -Label 'nxb-policy cargo test'

        Invoke-NxbDependencyCargo -Arguments @('check', '-p', 'nxb-core', '--all-targets', '--locked') -Label 'nxb-core cargo check'
        Invoke-NxbDependencyCargo -Arguments @('clippy', '-p', 'nxb-core', '--all-targets', '--locked', '--', '-D', 'warnings') -Label 'nxb-core cargo clippy'
        Invoke-NxbDependencyCargo -Arguments @('test', '-p', 'nxb-core', '--lib', '--locked', '--', '--test-threads=1') -Label 'nxb-core unit tests'
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
            Invoke-NxbDependencyCargo `
                -Arguments @('test', '-p', 'nxb-core', '--test', $testName, '--locked', '--', '--test-threads=1') `
                -Label "focused test $testName"
        }

        Invoke-NxbDependencyCargo -Arguments @('check', '--workspace', '--all-targets', '--all-features', '--locked') -Label 'workspace cargo check'
        Invoke-NxbDependencyCargo -Arguments @('clippy', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings') -Label 'workspace cargo clippy'
        Invoke-NxbDependencyCargo -Arguments @('test', '--workspace', '--all-features', '--locked', '--', '--test-threads=1') -Label 'workspace cargo test'

        Remove-Item Env:CARGO_NET_OFFLINE -ErrorAction SilentlyContinue
        Invoke-NxbDependencyTool -Path $AuditPath -Arguments @('audit') -Label 'RustSec cargo audit'
        Invoke-NxbDependencyTool -Path $DenyPath -Arguments @('check') -Label 'cargo-deny checks'
        $env:CARGO_NET_OFFLINE = 'true'

        if ((Get-NxbDependencyStreamSha256 -Stream $configStream -Label 'final gate Cargo config') -cne $configSha256) {
            Fail-NxbDependency 'gate Cargo source-replacement config changed during validation'
        }
        Invoke-NxbRegistryVerifier `
            -PythonPath $pythonPath `
            -HelperPath $registryHelper `
            -Arguments @('validate-vendor', $lockPath, $vendorRoot) `
            -Label 'final vendored registry dependency authority'
    }
    finally {
        Pop-Location
    }
}
catch {
    $primaryFailure = $_
}
finally {
    $env:CARGO_TARGET_DIR = $oldTarget
    $env:CARGO_HOME = $oldCargoHome
    $env:TMP = $oldTmp
    $env:TEMP = $oldTemp
    if ($null -eq $oldOffline) {
        Remove-Item Env:CARGO_NET_OFFLINE -ErrorAction SilentlyContinue
    } else {
        $env:CARGO_NET_OFFLINE = $oldOffline
    }

    if ($null -ne $configStream) {
        try { $configStream.Dispose() } catch { $cleanupErrors.Add("config stream dispose: $($_.Exception.Message)") }
    }
    for ($index = $vendorFileStreams.Count - 1; $index -ge 0; $index--) {
        try { $vendorFileStreams[$index].Dispose() } catch { $cleanupErrors.Add("vendor file stream dispose: $($_.Exception.Message)") }
    }
    for ($index = $vendorDirectoryHandles.Count - 1; $index -ge 0; $index--) {
        try { $vendorDirectoryHandles[$index].Dispose() } catch { $cleanupErrors.Add("vendor directory handle dispose: $($_.Exception.Message)") }
    }
    if ($null -ne $vendorOriginalAcl -and (Test-Path -LiteralPath $vendorRoot)) {
        try { Set-Acl -LiteralPath $vendorRoot -AclObject $vendorOriginalAcl -ErrorAction Stop } catch { $cleanupErrors.Add("vendor ACL restore: $($_.Exception.Message)") }
    }
    foreach ($handleInfo in @(
        [pscustomobject]@{ Handle = $gateHomeHandle; Label = 'gate-home' },
        [pscustomobject]@{ Handle = $vendorRootHandle; Label = 'vendor-root' },
        [pscustomobject]@{ Handle = $fetchHomeHandle; Label = 'fetch-home' },
        [pscustomobject]@{ Handle = $runtimeCargoHomeHandle; Label = 'dependency-runtime-root' }
    )) {
        if ($null -ne $handleInfo.Handle) {
            try { $handleInfo.Handle.Dispose() } catch { $cleanupErrors.Add("$($handleInfo.Label) handle dispose: $($_.Exception.Message)") }
        }
    }
    foreach ($path in @($gateHome, $vendorRoot, $fetchHome)) {
        if (Test-Path -LiteralPath $path) {
            try { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop } catch { $cleanupErrors.Add("dependency runtime removal $path`: $($_.Exception.Message)") }
        }
    }
}

if ($null -ne $primaryFailure -or $cleanupErrors.Count -gt 0) {
    $parts = [Collections.Generic.List[string]]::new()
    if ($null -ne $primaryFailure) {
        $parts.Add("primary: $($primaryFailure.Exception.Message)")
    }
    foreach ($cleanupError in $cleanupErrors) {
        $parts.Add("cleanup: $cleanupError")
    }
    Fail-NxbDependency ($parts -join ' | ')
}

Write-Host 'NXB-153 Windows Cargo gates passed against pinned checksum-verified vendored dependencies.'
