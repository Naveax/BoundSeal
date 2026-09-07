[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$EvidenceDirectory = (Join-Path $RepoRoot 'target\nxb-validation')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedLockSha256 = 'f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff'

if ($null -eq ('Nxb153NativeEvidence' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Nxb153NativeEvidence
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
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
        return OpenChecked(
            path,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_FLAG_BACKUP_SEMANTICS);
    }

    public static SafeFileHandle OpenReadOnlyFile(string path)
    {
        return OpenChecked(path, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL);
    }

    private static SafeFileHandle OpenChecked(string path, uint share, uint flags)
    {
        SafeFileHandle handle = CreateFileW(
            path,
            GENERIC_READ,
            share,
            IntPtr.Zero,
            OPEN_EXISTING,
            flags,
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
            throw new InvalidOperationException("Resolved path exceeds the supported buffer.");
        }
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

function Open-NxbPinnedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$Directory
    )

    $expected = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath($Path))
    $handle = if ($Directory) {
        [Nxb153NativeEvidence]::OpenDirectory($expected)
    } else {
        [Nxb153NativeEvidence]::OpenReadOnlyFile($expected)
    }

    try {
        $resolved = ConvertFrom-NxbFinalPath -Path ([Nxb153NativeEvidence]::GetFinalPath($handle))
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

if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'git is unavailable.'
}
if (-not $IsWindows) {
    throw 'The Windows guarded evidence reviewer must run on Windows.'
}

$pinnedHandles = [Collections.Generic.List[IDisposable]]::new()
Push-Location $RepoRoot
try {
    $repoHandle = Open-NxbPinnedPath -Path $RepoRoot -Label 'repository root' -Directory
    $pinnedHandles.Add($repoHandle)

    $initialHead = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $initialHead -notmatch '^[0-9a-f]{40}$') {
        throw 'Exact Git HEAD could not be resolved before evidence review.'
    }

    $initialStatus = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $initialStatus) {
        throw 'Working tree must be clean before evidence review.'
    }

    $lockPath = Join-Path $RepoRoot 'Cargo.lock'
    $lockHandle = Open-NxbPinnedPath -Path $lockPath -Label 'Cargo.lock'
    $pinnedHandles.Add($lockHandle)

    $reviewScript = Join-Path $PSScriptRoot 'review-nxb-153-evidence.ps1'
    $reviewScriptHandle = Open-NxbPinnedPath -Path $reviewScript -Label 'semantic evidence reviewer'
    $pinnedHandles.Add($reviewScriptHandle)

    $EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
    $evidenceDirectoryHandle = Open-NxbPinnedPath `
        -Path $EvidenceDirectory `
        -Label 'evidence directory' `
        -Directory
    $pinnedHandles.Add($evidenceDirectoryHandle)

    foreach ($path in @(
        (Join-Path $EvidenceDirectory "nxb-153-windows-$initialHead.json"),
        (Join-Path $EvidenceDirectory "nxb-153-linux-$initialHead.json"),
        (Join-Path $EvidenceDirectory "nxb-153-tooling-windows-$initialHead.json"),
        (Join-Path $EvidenceDirectory "nxb-153-tooling-linux-$initialHead.json")
    )) {
        $handle = Open-NxbPinnedPath -Path $path -Label "evidence input $path"
        $pinnedHandles.Add($handle)
    }

    $initialLockSha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($initialLockSha256 -cne $expectedLockSha256) {
        throw "Cargo.lock SHA-256 mismatch before evidence review: expected $expectedLockSha256, found $initialLockSha256"
    }

    $closurePath = Join-Path $EvidenceDirectory "nxb-153-closure-$initialHead.json"
    $closureHandle = $null
    if (Test-Path -LiteralPath $closurePath -PathType Leaf) {
        $closureHandle = Open-NxbPinnedPath -Path $closurePath -Label 'existing closure evidence'
        $pinnedHandles.Add($closureHandle)
    }

    $reviewOutput = (& $reviewScript `
        -RepoRoot $RepoRoot `
        -EvidenceDirectory $EvidenceDirectory `
        6>&1 | Out-String)

    if ($null -eq $closureHandle) {
        $closureHandle = Open-NxbPinnedPath -Path $closurePath -Label 'published closure evidence'
        $pinnedHandles.Add($closureHandle)
    }

    # Re-run the inexpensive semantic closure review while the canonical closure is pinned.
    # If another process substituted the path between inner publication and this open, this
    # pass validates the exact object that remains locked through the final authority checks.
    $null = (& $reviewScript `
        -RepoRoot $RepoRoot `
        -EvidenceDirectory $EvidenceDirectory `
        6>&1 | Out-String)

    $finalHead = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $finalHead -cne $initialHead) {
        throw "Git HEAD changed during evidence review: initial=$initialHead final=$finalHead. Any newly published closure requires explicit recovery/review."
    }

    $finalStatus = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $finalStatus) {
        throw 'Working tree changed during evidence review. Any newly published closure requires explicit recovery/review.'
    }

    $finalLockSha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($finalLockSha256 -cne $initialLockSha256) {
        throw 'Cargo.lock bytes changed during evidence review. Any newly published closure requires explicit recovery/review.'
    }

    if (-not [string]::IsNullOrWhiteSpace($reviewOutput)) {
        Write-Host $reviewOutput.TrimEnd()
    }
    Write-Host 'NXB-153 guarded Windows closure authority and pinned evidence inputs remained stable.'
    Write-Host "HEAD: $initialHead"
    Write-Host "Cargo.lock SHA-256: $initialLockSha256"
}
finally {
    for ($index = $pinnedHandles.Count - 1; $index -ge 0; $index--) {
        $pinnedHandles[$index].Dispose()
    }
    Pop-Location
}
