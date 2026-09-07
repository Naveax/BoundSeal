[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rustToolchain = '1.97.1'
$cargoAuditVersion = '0.22.2'
$cargoDenyVersion = '0.20.2'
$maximumEvidenceBytes = 65536
$maximumImplementationBytes = 1048576
$expectedCargoLockSha256 = 'f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff'

function Get-NxbToolVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is unavailable at $Path. Run scripts/prepare-and-validate-nxb-153-windows.ps1 first."
    }
    $value = (& $Path --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $value -notmatch ('(^|\s)' + [regex]::Escape($ExpectedVersion) + '($|\s)')) {
        throw "$Label version mismatch: expected $ExpectedVersion, found '$value'."
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

function Open-NxbPinnedStream {
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

function ConvertTo-NxbHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NxbGitBlobOidFromStream {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw "$Label pinned stream must be readable and seekable for Git blob verification."
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
        uint result = GetFinalPathNameByHandleW(handle, builder, (uint)builder.Capacity, 0);
        if (result == 0)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (result >= builder.Capacity)
            throw new InvalidOperationException("Resolved path exceeds the supported buffer.");
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
    $handle = [Nxb153NativeToolPath]::OpenDirectory($expected)
    try {
        $resolved = ConvertFrom-NxbFinalPath -Path ([Nxb153NativeToolPath]::GetFinalPath($handle))
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
        'AR',
        'BINDGEN_EXTRA_CLANG_ARGS',
        'CARGO',
        'CARGO_ENCODED_RUSTFLAGS',
        'CARGO_ENCODED_RUSTDOCFLAGS',
        'CARGO_HOME',
        'CARGO_INCREMENTAL',
        'CARGO_NET_OFFLINE',
        'CARGO_TARGET_DIR',
        'CC',
        'CC_ENABLE_DEBUG_OUTPUT',
        'CFLAGS',
        'CL',
        'CPP',
        'CPPFLAGS',
        'CRATE_CC_NO_DEFAULTS',
        'CXX',
        'CXXFLAGS',
        'LD',
        'LDFLAGS',
        'PYTHONHOME',
        'PYTHONINSPECT',
        'PYTHONPATH',
        'PYTHONSTARTUP',
        'RANLIB',
        'RANLIBFLAGS',
        'RUSTC',
        'RUSTC_BOOTSTRAP',
        'RUSTC_WORKSPACE_WRAPPER',
        'RUSTC_WRAPPER',
        'RUSTDOC',
        'RUSTDOCFLAGS',
        'RUSTFLAGS',
        '_CL_'
    )) {
        [void]$forbiddenExact.Add($name)
    }
    $forbiddenPrefixes = @(
        'AR_',
        'BINDGEN_EXTRA_CLANG_ARGS_',
        'CARGO_ALIAS_',
        'CARGO_BUILD_',
        'CARGO_NET_',
        'CARGO_PROFILE_',
        'CARGO_REGISTRIES_',
        'CARGO_REGISTRY_',
        'CARGO_SOURCE_',
        'CARGO_TARGET_',
        'CC_',
        'CFLAGS_',
        'CPPFLAGS_',
        'CXX_',
        'CXXFLAGS_',
        'LD_',
        'LDFLAGS_',
        'RANLIB_',
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
        throw ('Ambient compiler/Cargo/Python authority variables are not admitted: ' + ($ordered -join ', '))
    }
}

function Assert-ToolingReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$HeadSha,
        [Parameter(Mandatory = $true)][string]$ExpectedToolsRoot,
        [Parameter(Mandatory = $true)][string]$RustcVersion,
        [Parameter(Mandatory = $true)][string]$AuditVersion,
        [Parameter(Mandatory = $true)][string]$AuditSha256,
        [Parameter(Mandatory = $true)][string]$DenyVersion,
        [Parameter(Mandatory = $true)][string]$DenySha256
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Exact-head tooling receipt is missing. Run scripts/prepare-and-validate-nxb-153-windows.ps1 first.'
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Tooling receipt must not be a reparse point.'
    }
    if ($item.Length -le 0 -or $item.Length -gt $maximumEvidenceBytes) {
        throw 'Tooling receipt size is invalid.'
    }

    try {
        $receipt = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "Tooling receipt is invalid JSON: $($_.Exception.Message)"
    }

    $expectedFields = @(
        'schema_version', 'milestone', 'gate', 'platform', 'head_sha',
        'rust_toolchain', 'cargo_audit', 'cargo_audit_sha256',
        'cargo_deny', 'cargo_deny_sha256', 'tools_root',
        'network_activity', 'prepared_at'
    )
    $actualFields = @($receipt.PSObject.Properties.Name | Sort-Object)
    $sortedExpected = @($expectedFields | Sort-Object)
    if (($actualFields -join "`n") -cne ($sortedExpected -join "`n")) {
        throw 'Tooling receipt fields do not match the NXB-153 bootstrap contract.'
    }

    if (
        $receipt.schema_version -ne 1 -or
        $receipt.milestone -cne 'NXB-153' -or
        $receipt.gate -cne 'validation_tool_bootstrap' -or
        $receipt.platform -cne 'windows' -or
        $receipt.head_sha -cne $HeadSha -or
        $receipt.rust_toolchain -cne $RustcVersion -or
        $receipt.cargo_audit -cne $AuditVersion -or
        $receipt.cargo_audit_sha256 -cne $AuditSha256 -or
        $receipt.cargo_deny -cne $DenyVersion -or
        $receipt.cargo_deny_sha256 -cne $DenySha256 -or
        $receipt.tools_root -cne $ExpectedToolsRoot -or
        $receipt.network_activity -cne 'rustup_and_crates_io_tool_installation_only'
    ) {
        throw 'Tooling receipt does not match the current exact-head validation tools.'
    }

    Assert-LowerSha256 -Value $receipt.cargo_audit_sha256 -Label 'Receipt cargo-audit SHA-256'
    Assert-LowerSha256 -Value $receipt.cargo_deny_sha256 -Label 'Receipt cargo-deny SHA-256'

    $parsedPreparedAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
        [string]$receipt.prepared_at,
        'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$parsedPreparedAt
    )) {
        throw 'Tooling receipt prepared_at is not canonical UTC.'
    }
    if ($parsedPreparedAt -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        throw 'Tooling receipt prepared_at is unreasonably in the future.'
    }
}

$validationLockStream = $null
$auditToolStream = $null
$denyToolStream = $null
$receiptStream = $null
$cargoLockStream = $null
$immutableSourceStream = $null
$namespaceHandles = [Collections.Generic.List[IDisposable]]::new()

Push-Location $RepoRoot
try {
    foreach ($command in @('git', 'rustup', 'tar')) {
        if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "$command is unavailable."
        }
    }
    if (-not $IsWindows) {
        throw 'The Windows NXB-153 validator must run on Windows.'
    }
    Assert-NxbAmbientEnvironment

    $repoHandle = Open-NxbPinnedDirectory -Path $RepoRoot -Label 'repository root'
    $namespaceHandles.Add($repoHandle)

    $headSha = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $headSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Exact Git HEAD could not be resolved.'
    }
    $status = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $status) {
        throw 'Working tree must be clean.'
    }

    $targetDirectory = Join-Path $RepoRoot 'target'
    $validationDirectory = Join-Path $targetDirectory 'nxb-validation'
    New-Item -ItemType Directory -Path $validationDirectory -Force | Out-Null

    $targetHandle = Open-NxbPinnedDirectory -Path $targetDirectory -Label 'target directory'
    $namespaceHandles.Add($targetHandle)
    $validationDirectoryHandle = Open-NxbPinnedDirectory -Path $validationDirectory -Label 'validation evidence directory'
    $namespaceHandles.Add($validationDirectoryHandle)

    $evidencePath = Join-Path $validationDirectory "nxb-153-windows-$headSha.json"
    if (Test-Path -LiteralPath $evidencePath) {
        throw "Exact-head Windows validation evidence already exists; validation gates were not rerun: $evidencePath. Use the evidence reviewer or perform explicit recovery."
    }

    $validationLockPath = Join-Path $validationDirectory ".nxb-153-validation-windows-$headSha.lock"
    try {
        $validationLockStream = [IO.FileStream]::new(
            $validationLockPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::DeleteOnClose
        )
    }
    catch [IO.IOException] {
        if (Test-Path -LiteralPath $evidencePath) {
            throw "Exact-head Windows validation evidence appeared before lock acquisition; validation gates were not rerun: $evidencePath"
        }
        if (Test-Path -LiteralPath $validationLockPath) {
            throw "Exact-head Windows validation is already in progress or requires explicit stale-lock recovery: $validationLockPath"
        }
        throw
    }
    $validationLockBytes = [Text.UTF8Encoding]::new($false).GetBytes("$headSha`n")
    $validationLockStream.Write($validationLockBytes, 0, $validationLockBytes.Length)
    $validationLockStream.Flush($true)
    Assert-ExactStreamBytes -Stream $validationLockStream -Expected $validationLockBytes -Label 'Validation lock'

    if (Test-Path -LiteralPath $evidencePath) {
        throw "Exact-head Windows validation evidence appeared while claiming the validation lock; heavy validation was not started: $evidencePath"
    }

    $toolsRelative = "target/nxb-tools/windows/$headSha"
    $toolsRoot = Join-Path $RepoRoot ($toolsRelative -replace '/', [IO.Path]::DirectorySeparatorChar)
    $toolsBin = Join-Path $toolsRoot 'bin'
    $auditPath = Join-Path $toolsBin 'cargo-audit.exe'
    $denyPath = Join-Path $toolsBin 'cargo-deny.exe'
    if (-not (Test-Path -LiteralPath $toolsRoot -PathType Container)) {
        throw "Exact-head Windows tools root is missing: $toolsRoot. Run scripts/prepare-and-validate-nxb-153-windows.ps1 first."
    }

    $nxbToolsDirectory = Join-Path $targetDirectory 'nxb-tools'
    $windowsToolsDirectory = Join-Path $nxbToolsDirectory 'windows'
    $nxbToolsHandle = Open-NxbPinnedDirectory -Path $nxbToolsDirectory -Label 'nxb-tools directory'
    $namespaceHandles.Add($nxbToolsHandle)
    $windowsToolsHandle = Open-NxbPinnedDirectory -Path $windowsToolsDirectory -Label 'Windows tools platform directory'
    $namespaceHandles.Add($windowsToolsHandle)
    $toolsRootHandle = Open-NxbPinnedDirectory -Path $toolsRoot -Label 'exact-head Windows tools directory'
    $namespaceHandles.Add($toolsRootHandle)
    $toolsBinHandle = Open-NxbPinnedDirectory -Path $toolsBin -Label 'exact-head Windows tools bin directory'
    $namespaceHandles.Add($toolsBinHandle)

    $auditToolStream = Open-NxbPinnedStream -Path $auditPath -Label 'cargo-audit'
    $denyToolStream = Open-NxbPinnedStream -Path $denyPath -Label 'cargo-deny'

    $rustcVersion = (& rustup run $rustToolchain rustc --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $rustcVersion.StartsWith('rustc 1.97.1 ')) {
        throw "Expected rustc 1.97.1, found '$rustcVersion'."
    }
    $cargoVersion = (& rustup run $rustToolchain cargo --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not resolve pinned Cargo version.'
    }
    $auditVersion = Get-NxbToolVersion -Path $auditPath -ExpectedVersion $cargoAuditVersion -Label 'cargo-audit'
    $denyVersion = Get-NxbToolVersion -Path $denyPath -ExpectedVersion $cargoDenyVersion -Label 'cargo-deny'
    $auditSha256 = Get-NxbStreamSha256 -Stream $auditToolStream -Label 'cargo-audit'
    $denySha256 = Get-NxbStreamSha256 -Stream $denyToolStream -Label 'cargo-deny'

    $receiptPath = Join-Path $validationDirectory "nxb-153-tooling-windows-$headSha.json"
    $receiptStream = Open-NxbPinnedStream -Path $receiptPath -Label 'tooling receipt'
    Assert-ToolingReceipt `
        -Path $receiptPath `
        -HeadSha $headSha `
        -ExpectedToolsRoot $toolsRelative `
        -RustcVersion $rustcVersion `
        -AuditVersion $auditVersion `
        -AuditSha256 $auditSha256 `
        -DenyVersion $denyVersion `
        -DenySha256 $denySha256
    $receiptSha256 = Get-NxbStreamSha256 -Stream $receiptStream -Label 'tooling receipt'

    $lockPath = Join-Path $RepoRoot 'Cargo.lock'
    $cargoLockStream = Open-NxbPinnedStream -Path $lockPath -Label 'Cargo.lock'
    $lockSha256 = Get-NxbStreamSha256 -Stream $cargoLockStream -Label 'Cargo.lock'
    if ($lockSha256 -cne $expectedCargoLockSha256) {
        throw "Cargo.lock SHA-256 mismatch: expected $expectedCargoLockSha256, found $lockSha256"
    }
    git diff --exit-code -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        throw 'Committed Cargo.lock differs before locked validation.'
    }

    $scriptsDirectory = Join-Path $RepoRoot 'scripts'
    $scriptsHandle = Open-NxbPinnedDirectory -Path $scriptsDirectory -Label 'scripts directory'
    $namespaceHandles.Add($scriptsHandle)
    $immutableSourcePath = Join-Path $scriptsDirectory 'nxb-153-windows-immutable-source.ps1'
    $immutableSourceStream = Open-NxbPinnedStream -Path $immutableSourcePath -Label 'immutable Windows source runner'
    if ($immutableSourceStream.Length -le 0 -or $immutableSourceStream.Length -gt $maximumImplementationBytes) {
        throw 'Immutable Windows source runner size is outside the supported implementation envelope.'
    }
    $expectedImmutableObject = (git rev-parse "${headSha}:scripts/nxb-153-windows-immutable-source.ps1").Trim()
    if ($LASTEXITCODE -ne 0 -or $expectedImmutableObject -notmatch '^[0-9a-f]{40}$') {
        throw 'Exact-head immutable Windows source runner object could not be resolved.'
    }
    $immutableObjectType = (git cat-file -t $expectedImmutableObject).Trim()
    if ($LASTEXITCODE -ne 0 -or $immutableObjectType -cne 'blob') {
        throw 'Exact-head immutable Windows source runner authority is not a Git blob.'
    }
    $actualImmutableObject = Get-NxbGitBlobOidFromStream -Stream $immutableSourceStream -Label 'immutable Windows source runner'
    if ($actualImmutableObject -cne $expectedImmutableObject) {
        throw 'Pinned immutable Windows source runner bytes differ from the exact-head committed Git object.'
    }

    & $immutableSourcePath `
        -RepoRoot $RepoRoot `
        -ValidationDirectory $validationDirectory `
        -HeadSha $headSha `
        -RustToolchain $rustToolchain `
        -CargoAuditVersion $cargoAuditVersion `
        -CargoDenyVersion $cargoDenyVersion `
        -AuditSha256 $auditSha256 `
        -DenySha256 $denySha256 `
        -ExpectedCargoLockSha256 $lockSha256 `
        -AuditPath $auditPath `
        -DenyPath $denyPath `
        -SelfTest

    & $immutableSourcePath `
        -RepoRoot $RepoRoot `
        -ValidationDirectory $validationDirectory `
        -HeadSha $headSha `
        -RustToolchain $rustToolchain `
        -CargoAuditVersion $cargoAuditVersion `
        -CargoDenyVersion $cargoDenyVersion `
        -AuditSha256 $auditSha256 `
        -DenySha256 $denySha256 `
        -ExpectedCargoLockSha256 $lockSha256 `
        -AuditPath $auditPath `
        -DenyPath $denyPath

    $finalPinnedLockSha256 = Get-NxbStreamSha256 -Stream $cargoLockStream -Label 'Cargo.lock final pinned object'
    if ($finalPinnedLockSha256 -cne $lockSha256) {
        throw 'Pinned Cargo.lock bytes changed during validation.'
    }
    $finalLockPathSha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($finalLockPathSha256 -cne $lockSha256) {
        throw 'Cargo.lock pathname no longer names the pinned bytes used to authorize the immutable snapshot.'
    }
    git diff --exit-code -- Cargo.lock
    if ($LASTEXITCODE -ne 0) {
        throw 'Cargo.lock Git diff appeared during validation.'
    }

    $finalHead = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $finalHead -cne $headSha) {
        throw 'Git HEAD changed during validation.'
    }
    $finalStatus = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $finalStatus) {
        throw 'Working tree changed during validation.'
    }

    $finalImmutableObject = Get-NxbGitBlobOidFromStream -Stream $immutableSourceStream -Label 'immutable Windows source runner final pinned object'
    if ($finalImmutableObject -cne $expectedImmutableObject) {
        throw 'Pinned immutable Windows source runner bytes changed during validation.'
    }
    $finalPinnedAuditSha256 = Get-NxbStreamSha256 -Stream $auditToolStream -Label 'cargo-audit final pinned object'
    $finalPinnedDenySha256 = Get-NxbStreamSha256 -Stream $denyToolStream -Label 'cargo-deny final pinned object'
    if ($finalPinnedAuditSha256 -cne $auditSha256 -or $finalPinnedDenySha256 -cne $denySha256) {
        throw 'Pinned security-tool bytes changed during validation.'
    }
    $finalAuditPathSha256 = (Get-FileHash -LiteralPath $auditPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $finalDenyPathSha256 = (Get-FileHash -LiteralPath $denyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($finalAuditPathSha256 -cne $auditSha256 -or $finalDenyPathSha256 -cne $denySha256) {
        throw 'Security-tool canonical paths no longer name the validated pinned bytes.'
    }

    $finalPinnedReceiptSha256 = Get-NxbStreamSha256 -Stream $receiptStream -Label 'tooling receipt final pinned object'
    if ($finalPinnedReceiptSha256 -cne $receiptSha256) {
        throw 'Pinned tooling receipt bytes changed during validation.'
    }
    $finalReceiptPathSha256 = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($finalReceiptPathSha256 -cne $receiptSha256) {
        throw 'Tooling receipt pathname no longer names the semantically verified pinned bytes.'
    }

    $evidence = [ordered]@{
        schema_version = 2
        milestone = 'NXB-153'
        gate = 'guided_target_authorization_setup'
        platform = 'windows'
        head_sha = $headSha
        rustc = $rustcVersion
        cargo = $cargoVersion
        cargo_audit = $auditVersion
        cargo_audit_sha256 = $auditSha256
        cargo_deny = $denyVersion
        cargo_deny_sha256 = $denySha256
        tooling_receipt = "target/nxb-validation/nxb-153-tooling-windows-$headSha.json"
        tooling_receipt_sha256 = $receiptSha256
        tooling_receipt_verified = $true
        cargo_lock_sha256 = $lockSha256
        cargo_lock_expected_sha256 = $expectedCargoLockSha256
        lockfile_pinned_and_unchanged = $true
        validation_environment_policy = 'nxb-153-compiler-cargo-python-authority-v2'
        validation_environment_authority = 'passed'
        python_isolated_helper_authority = 'passed'
        workspace_namespace_authority = 'passed'
        workspace_git_object_authority = 'passed'
        dependency_source_authority = 'passed'
        security_tool_object_authority = 'passed'
        host_rust_toolchain_identity = 'version_pinned_object_identity_pending'
        fmt = 'passed'
        nxb_policy_check_clippy_tests = 'passed'
        nxb_core_check_clippy_unit_tests = 'passed'
        focused_target_tests = 'passed'
        workspace_check_clippy_tests_all_features = 'passed'
        rustsec = 'passed'
        cargo_deny_checks = 'passed'
        test_threads = 1
        network_activity = 'cargo_dependency_and_advisory_sources_only'
        validated_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    $evidenceText = (($evidence | ConvertTo-Json -Depth 8) + [Environment]::NewLine)
    $evidenceBytes = [Text.UTF8Encoding]::new($false).GetBytes($evidenceText)
    if ($evidenceBytes.Length -le 0 -or $evidenceBytes.Length -gt $maximumEvidenceBytes) {
        throw 'Windows validation evidence size is invalid.'
    }

    $evidenceStream = $null
    try {
        try {
            $evidenceStream = [IO.File]::Open(
                $evidencePath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
        }
        catch [IO.IOException] {
            if (Test-Path -LiteralPath $evidencePath) {
                throw "Exact-head Windows validation evidence already exists and will not be overwritten: $evidencePath. Review/remove it explicitly before validating again."
            }
            throw
        }
        $evidenceStream.Write($evidenceBytes, 0, $evidenceBytes.Length)
        $evidenceStream.Flush($true)
        Assert-ExactStreamBytes -Stream $evidenceStream -Expected $evidenceBytes -Label 'Windows validation evidence'
    }
    finally {
        if ($null -ne $evidenceStream) {
            $evidenceStream.Dispose()
        }
    }

    Write-Host 'NXB-153 Windows validation passed from an exact-head pinned write-denied source snapshot.'
    Write-Host "HEAD: $headSha"
    Write-Host "Tool root: $toolsRelative"
    Write-Host "Cargo.lock SHA-256: $lockSha256"
    Write-Host "Tooling receipt SHA-256: $receiptSha256"
    Write-Host "Evidence: $evidencePath"
}
finally {
    if ($null -ne $immutableSourceStream) {
        $immutableSourceStream.Dispose()
    }
    if ($null -ne $cargoLockStream) {
        $cargoLockStream.Dispose()
    }
    if ($null -ne $receiptStream) {
        $receiptStream.Dispose()
    }
    if ($null -ne $denyToolStream) {
        $denyToolStream.Dispose()
    }
    if ($null -ne $auditToolStream) {
        $auditToolStream.Dispose()
    }
    if ($null -ne $validationLockStream) {
        $validationLockStream.Dispose()
    }
    for ($index = $namespaceHandles.Count - 1; $index -ge 0; $index--) {
        $namespaceHandles[$index].Dispose()
    }
    Pop-Location
}
