[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [switch]$PrepareOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rustToolchain = '1.97.1'
$cargoAuditVersion = '0.22.2'
$cargoDenyVersion = '0.20.2'
$maximumEvidenceBytes = 65536

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

function Get-ToolVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    $value = (& $Path --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $value -notmatch ('(^|\s)' + [regex]::Escape($ExpectedVersion) + '($|\s)')) {
        return $null
    }
    return $value
}

function Assert-LowerSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value -notmatch '^[0-9a-f]{64}$') {
        throw "$Label is not a lowercase SHA-256."
    }
}

function Open-NxbPinnedToolStream {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a reparse point."
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
        throw "Could not pin $Label with write/delete sharing withheld: $($_.Exception.Message)"
    }
}

function Get-NxbStreamSha256 {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw "$Label pinned stream must be readable and seekable."
    }
    $savedPosition = $Stream.Position
    try {
        $Stream.Position = 0
        $hash = (Get-FileHash -InputStream $Stream -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    finally {
        $Stream.Position = $savedPosition
    }
    Assert-LowerSha256 -Value $hash -Label "$Label pinned SHA-256"
    return $hash
}

if ($null -eq ('Nxb153NativeToolPath' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Nxb153NativeToolPath
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
        uint result = GetFinalPathNameByHandleW(
            handle,
            builder,
            (uint)builder.Capacity,
            0);
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

function ConvertFrom-NxbToolFinalPath {
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

function Open-NxbPinnedToolDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expected = ConvertFrom-NxbToolFinalPath -Path ([IO.Path]::GetFullPath($Path))
    $handle = [Nxb153NativeToolPath]::OpenDirectory($expected)
    try {
        $resolved = ConvertFrom-NxbToolFinalPath -Path ([Nxb153NativeToolPath]::GetFinalPath($handle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label resolved through a reparse/redirected path: expected '$expected', resolved '$resolved'."
        }
        return $handle
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Assert-ExactStreamBytes {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][byte[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $Stream.Position = 0
    $persisted = [byte[]]::new($Expected.Length)
    $offset = 0
    while ($offset -lt $persisted.Length) {
        $read = $Stream.Read($persisted, $offset, $persisted.Length - $offset)
        if ($read -le 0) {
            throw "$Label could not be read back completely from its create-new handle."
        }
        $offset += $read
    }
    if ($Stream.ReadByte() -ne -1) {
        throw "$Label contains trailing bytes beyond the deterministic representation."
    }
    if ([Convert]::ToBase64String($persisted) -cne [Convert]::ToBase64String($Expected)) {
        throw "$Label read-back bytes differ from the deterministic representation."
    }
}

function Assert-NxbAmbientEnvironment {
    $forbiddenExact = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @(
        'CARGO',
        'CARGO_ENCODED_RUSTFLAGS',
        'CARGO_ENCODED_RUSTDOCFLAGS',
        'CARGO_HOME',
        'CARGO_INCREMENTAL',
        'CARGO_NET_OFFLINE',
        'CARGO_TARGET_DIR',
        'PYTHONHOME',
        'PYTHONINSPECT',
        'PYTHONPATH',
        'PYTHONSTARTUP',
        'RUSTC',
        'RUSTC_BOOTSTRAP',
        'RUSTC_WORKSPACE_WRAPPER',
        'RUSTC_WRAPPER',
        'RUSTDOC',
        'RUSTDOCFLAGS',
        'RUSTFLAGS'
    )) {
        [void]$forbiddenExact.Add($name)
    }
    $forbiddenPrefixes = @(
        'CARGO_ALIAS_',
        'CARGO_BUILD_',
        'CARGO_NET_',
        'CARGO_PROFILE_',
        'CARGO_REGISTRIES_',
        'CARGO_REGISTRY_',
        'CARGO_SOURCE_',
        'CARGO_TARGET_',
        'RUSTC_',
        'RUSTDOC_',
        'RUSTUP_'
    )
    $collisions = [Collections.Generic.List[string]]::new()
    foreach ($entry in [Environment]::GetEnvironmentVariables().Keys) {
        $name = [string]$entry
        $blocked = $forbiddenExact.Contains($name)
        if (-not $blocked) {
            foreach ($prefix in $forbiddenPrefixes) {
                if ($name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    $blocked = $true
                    break
                }
            }
        }
        if ($blocked) {
            $collisions.Add($name)
        }
    }
    if ($collisions.Count -gt 0) {
        $ordered = @($collisions | Sort-Object { $_.ToUpperInvariant() })
        throw ('Ambient Rust/Cargo/Python authority variables are not admitted: ' + ($ordered -join ', '))
    }
}

if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'git is unavailable.'
}
if ($null -eq (Get-Command rustup -ErrorAction SilentlyContinue)) {
    throw 'rustup is unavailable. Install rustup from the official Rust distribution before running this script.'
}
if (-not $IsWindows) {
    throw 'The Windows NXB-153 tool preparation script must run on Windows.'
}
Assert-NxbAmbientEnvironment

$prepLockStream = $null
$prepLockPath = $null
$auditToolStream = $null
$denyToolStream = $null
$namespaceHandles = [Collections.Generic.List[IDisposable]]::new()

Push-Location $RepoRoot
try {
    $repoHandle = Open-NxbPinnedToolDirectory -Path $RepoRoot -Label 'repository root'
    $namespaceHandles.Add($repoHandle)

    $headSha = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $headSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Exact Git HEAD could not be resolved.'
    }
    $status = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $status) {
        throw 'Working tree must be clean before tool preparation.'
    }

    $targetDirectory = Join-Path $RepoRoot 'target'
    $receiptDirectory = Join-Path $targetDirectory 'nxb-validation'
    New-Item -ItemType Directory -Path $receiptDirectory -Force | Out-Null

    $targetHandle = Open-NxbPinnedToolDirectory -Path $targetDirectory -Label 'target directory'
    $namespaceHandles.Add($targetHandle)
    $receiptDirectoryHandle = Open-NxbPinnedToolDirectory -Path $receiptDirectory -Label 'validation evidence directory'
    $namespaceHandles.Add($receiptDirectoryHandle)

    $receiptPath = Join-Path $receiptDirectory "nxb-153-tooling-windows-$headSha.json"
    if (Test-Path -LiteralPath $receiptPath) {
        throw "Exact-head tooling receipt already exists; tool bytes were not mutated: $receiptPath. Run the validator directly with the existing receipt, or review/remove it explicitly before preparing again."
    }

    $prepLockPath = Join-Path $receiptDirectory ".nxb-153-tool-prep-$headSha.lock"
    try {
        $prepLockStream = [IO.FileStream]::new(
            $prepLockPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::DeleteOnClose
        )
    }
    catch [IO.IOException] {
        if (Test-Path -LiteralPath $receiptPath) {
            throw "Exact-head tooling receipt appeared before preparation-lock acquisition; tool bytes were not mutated: $receiptPath"
        }
        if (Test-Path -LiteralPath $prepLockPath) {
            throw "Exact-head tool preparation is already in progress: $prepLockPath"
        }
        throw
    }
    $lockBytes = [Text.UTF8Encoding]::new($false).GetBytes("$headSha`n")
    $prepLockStream.Write($lockBytes, 0, $lockBytes.Length)
    $prepLockStream.Flush($true)
    Assert-ExactStreamBytes -Stream $prepLockStream -Expected $lockBytes -Label 'Tool-preparation lock'

    if (Test-Path -LiteralPath $receiptPath) {
        throw "Exact-head tooling receipt appeared while claiming the preparation lock; tool bytes were not mutated: $receiptPath"
    }

    $toolsRelative = "target/nxb-tools/windows/$headSha"
    $toolsRoot = Join-Path $RepoRoot ($toolsRelative -replace '/', [IO.Path]::DirectorySeparatorChar)
    $toolsBin = Join-Path $toolsRoot 'bin'
    if (Test-Path -LiteralPath $toolsRoot) {
        throw "Exact-head Windows tools root already exists without an admitted tooling receipt; explicit recovery is required: $toolsRoot"
    }

    Invoke-NativeChecked -FilePath 'rustup' -Label 'Rust 1.97.1 toolchain installation' -Arguments @(
        'toolchain', 'install', $rustToolchain,
        '--profile', 'minimal',
        '--component', 'rustfmt',
        '--component', 'clippy'
    )

    $auditPath = Join-Path $toolsBin 'cargo-audit.exe'
    $denyPath = Join-Path $toolsBin 'cargo-deny.exe'

    $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) (
        'nxb-153-tool-bootstrap-' + [Guid]::NewGuid().ToString('N')
    )
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    try {
        Push-Location $temporaryDirectory
        try {
            Invoke-NativeChecked -FilePath 'rustup' -Label 'fresh cargo-audit installation' -Arguments @(
                'run', $rustToolchain, 'cargo', 'install',
                '--locked', '--force', '--version', $cargoAuditVersion,
                '--root', $toolsRoot, 'cargo-audit'
            )
            Invoke-NativeChecked -FilePath 'rustup' -Label 'fresh cargo-deny installation' -Arguments @(
                'run', $rustToolchain, 'cargo', 'install',
                '--locked', '--force', '--version', $cargoDenyVersion,
                '--root', $toolsRoot, 'cargo-deny'
            )
        }
        finally {
            Pop-Location
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Pin every directory component used to resolve the tool executables. The
    # directory handles omit delete sharing, so a later rename/delete of any
    # pinned namespace component cannot redirect $auditPath/$denyPath execution.
    $nxbToolsDirectory = Join-Path $targetDirectory 'nxb-tools'
    $windowsToolsDirectory = Join-Path $nxbToolsDirectory 'windows'

    $nxbToolsHandle = Open-NxbPinnedToolDirectory -Path $nxbToolsDirectory -Label 'nxb-tools directory'
    $namespaceHandles.Add($nxbToolsHandle)
    $windowsToolsHandle = Open-NxbPinnedToolDirectory -Path $windowsToolsDirectory -Label 'Windows tools platform directory'
    $namespaceHandles.Add($windowsToolsHandle)
    $toolsRootHandle = Open-NxbPinnedToolDirectory -Path $toolsRoot -Label 'exact-head Windows tools directory'
    $namespaceHandles.Add($toolsRootHandle)
    $toolsBinHandle = Open-NxbPinnedToolDirectory -Path $toolsBin -Label 'exact-head Windows tools bin directory'
    $namespaceHandles.Add($toolsBinHandle)

    # Pin the exact files produced by cargo install before version/hash inspection.
    # Receipt identity is derived from these handles and write/delete sharing stays
    # withheld until the create-new receipt has been published and read back.
    $auditToolStream = Open-NxbPinnedToolStream -Path $auditPath -Label 'fresh cargo-audit'
    $denyToolStream = Open-NxbPinnedToolStream -Path $denyPath -Label 'fresh cargo-deny'

    $auditVersion = Get-ToolVersion -Path $auditPath -ExpectedVersion $cargoAuditVersion
    $denyVersion = Get-ToolVersion -Path $denyPath -ExpectedVersion $cargoDenyVersion
    if ($null -eq $auditVersion -or $null -eq $denyVersion) {
        throw 'Fresh validation tools were not installed correctly.'
    }

    $auditSha256 = Get-NxbStreamSha256 -Stream $auditToolStream -Label 'fresh cargo-audit'
    $denySha256 = Get-NxbStreamSha256 -Stream $denyToolStream -Label 'fresh cargo-deny'
    $auditPathSha256 = (Get-FileHash -LiteralPath $auditPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $denyPathSha256 = (Get-FileHash -LiteralPath $denyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($auditPathSha256 -cne $auditSha256) {
        throw 'cargo-audit pathname drifted before tooling receipt publication.'
    }
    if ($denyPathSha256 -cne $denySha256) {
        throw 'cargo-deny pathname drifted before tooling receipt publication.'
    }

    $finalHead = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $finalHead -ne $headSha) {
        throw 'Git HEAD changed during tool preparation.'
    }
    $finalStatus = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $finalStatus) {
        throw 'Working tree changed during tool preparation.'
    }

    $receipt = [ordered]@{
        schema_version = 1
        milestone = 'NXB-153'
        gate = 'validation_tool_bootstrap'
        platform = 'windows'
        head_sha = $headSha
        rust_toolchain = (& rustup run $rustToolchain rustc --version | Out-String).Trim()
        cargo_audit = $auditVersion
        cargo_audit_sha256 = $auditSha256
        cargo_deny = $denyVersion
        cargo_deny_sha256 = $denySha256
        tools_root = $toolsRelative
        network_activity = 'rustup_and_crates_io_tool_installation_only'
        prepared_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    $receiptText = (($receipt | ConvertTo-Json -Depth 8) + [Environment]::NewLine)
    $receiptBytes = [Text.UTF8Encoding]::new($false).GetBytes($receiptText)
    if ($receiptBytes.Length -le 0 -or $receiptBytes.Length -gt $maximumEvidenceBytes) {
        throw 'Tooling receipt size is invalid.'
    }

    $receiptStream = $null
    try {
        try {
            $receiptStream = [IO.File]::Open(
                $receiptPath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
        }
        catch [IO.IOException] {
            if (Test-Path -LiteralPath $receiptPath) {
                throw "Exact-head tooling receipt was claimed by another process and will not be overwritten: $receiptPath"
            }
            throw
        }

        $receiptStream.Write($receiptBytes, 0, $receiptBytes.Length)
        $receiptStream.Flush($true)
        Assert-ExactStreamBytes -Stream $receiptStream -Expected $receiptBytes -Label 'Tooling receipt'
    }
    finally {
        if ($null -ne $receiptStream) {
            $receiptStream.Dispose()
        }
    }

    $denyToolStream.Dispose()
    $denyToolStream = $null
    $auditToolStream.Dispose()
    $auditToolStream = $null

    $prepLockStream.Dispose()
    $prepLockStream = $null

    Write-Host 'NXB-153 fresh pinned Windows validation tools are ready.'
    Write-Host "HEAD: $headSha"
    Write-Host "Tool root: $toolsRelative"
    Write-Host "Tooling receipt: $receiptPath"

    if (-not $PrepareOnly) {
        & (Join-Path $PSScriptRoot 'validate-nxb-153-windows.ps1') -RepoRoot $RepoRoot
    }
}
finally {
    if ($null -ne $denyToolStream) {
        $denyToolStream.Dispose()
    }
    if ($null -ne $auditToolStream) {
        $auditToolStream.Dispose()
    }
    if ($null -ne $prepLockStream) {
        $prepLockStream.Dispose()
    }
    for ($index = $namespaceHandles.Count - 1; $index -ge 0; $index--) {
        $namespaceHandles[$index].Dispose()
    }
    Pop-Location
}
