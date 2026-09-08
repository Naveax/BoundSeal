[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$policy = 'nxb-153-windows-host-git-lifetime-probe-v1'
$maximumGitValueBytes = 4096
$gitReadTimeoutMilliseconds = 30000
$gitExitTimeoutMilliseconds = 30000

function Fail-NxbHostGitLifetimeProbe {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows host-Git lifetime probe failed: $Message"
}

function Fail-NxbWindowsAdmission {
    param([Parameter(Mandatory = $true)][string]$Message)
    Fail-NxbHostGitLifetimeProbe $Message
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

function Invoke-NxbBoundedGitValue {
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
            Fail-NxbHostGitLifetimeProbe "$Label Git process could not be started"
        }
        $buffer = [byte[]]::new(1024)
        [Int64]$total = 0
        while ($true) {
            $readTask = $process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $readTask.Wait($gitReadTimeoutMilliseconds)) {
                Fail-NxbHostGitLifetimeProbe "$Label Git stdout made no progress for $gitReadTimeoutMilliseconds ms"
            }
            $read = $readTask.Result
            if ($read -le 0) { break }
            $total += $read
            if ($total -gt $maximumGitValueBytes) {
                Fail-NxbHostGitLifetimeProbe "$Label Git stdout exceeds the $maximumGitValueBytes-byte control-plane envelope"
            }
            $memory.Write($buffer, 0, $read)
        }
        if (-not $process.WaitForExit($gitExitTimeoutMilliseconds)) {
            Fail-NxbHostGitLifetimeProbe "$Label Git process did not exit after stdout closed"
        }
        if ($process.ExitCode -ne 0) {
            Fail-NxbHostGitLifetimeProbe "$Label Git command failed with exit code $($process.ExitCode)"
        }
        $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
        try {
            $value = $strictUtf8.GetString($memory.ToArray()).Trim()
        }
        catch {
            Fail-NxbHostGitLifetimeProbe "$Label Git stdout is not strict UTF-8: $($_.Exception.Message)"
        }
        if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256) {
            Fail-NxbHostGitLifetimeProbe "$Label did not return one bounded value"
        }
        return $value
    }
    finally {
        try {
            if (-not $process.HasExited) {
                $process.Kill($true)
                [void]$process.WaitForExit($gitExitTimeoutMilliseconds)
            }
        }
        catch {}
        $memory.Dispose()
        $process.Dispose()
    }
}

function Get-NxbFunctionText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -ne 0) {
        Fail-NxbHostGitLifetimeProbe "PowerShell parser rejected $Path"
    }
    $matches = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name
    }, $true))
    if ($matches.Count -ne 1) {
        Fail-NxbHostGitLifetimeProbe "expected one function '$Name' in $Path, found $($matches.Count)"
    }
    return $matches[0].Extent.Text
}

function Assert-NxbContains {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Needle,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ($Text.IndexOf($Needle, [StringComparison]::Ordinal) -lt 0) {
        Fail-NxbHostGitLifetimeProbe "$Label is missing required source pattern '$Needle'"
    }
}

function Assert-NxbExpectedFailure {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $failed = $false
    try {
        & $Action
    }
    catch {
        $failed = $true
    }
    if (-not $failed) {
        Fail-NxbHostGitLifetimeProbe "$Label unexpectedly succeeded"
    }
}

if (-not $IsWindows) {
    Fail-NxbHostGitLifetimeProbe 'probe requires supported Windows filesystem and PowerShell semantics'
}
if ($PSVersionTable.PSEdition -cne 'Core') {
    Fail-NxbHostGitLifetimeProbe 'probe requires PowerShell Core'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$admissionPath = Join-Path $RepoRoot 'scripts\review-nxb-153-windows-admission.ps1'
$selfPath = Join-Path $RepoRoot 'scripts\nxb-153-windows-host-git-lifetime-probe.ps1'
foreach ($required in @($admissionPath, $selfPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Fail-NxbHostGitLifetimeProbe "required exact-head source is missing: $required"
    }
}

$git = Get-Command git -CommandType Application -ErrorAction Stop
$gitPath = [IO.Path]::GetFullPath([string]$git.Source)
$headSha = Invoke-NxbBoundedGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'exact Git HEAD'
if ($headSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbHostGitLifetimeProbe 'exact Git HEAD is not canonical 40-hex SHA-1'
}

$admissionObject = Invoke-NxbBoundedGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', "${headSha}:scripts/review-nxb-153-windows-admission.ps1") -Label 'admission wrapper Git object'
$admissionWorking = Invoke-NxbBoundedGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $admissionPath) -Label 'admission wrapper working-tree object'
$selfObject = Invoke-NxbBoundedGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', "${headSha}:scripts/nxb-153-windows-host-git-lifetime-probe.ps1") -Label 'host-Git probe Git object'
$selfWorking = Invoke-NxbBoundedGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $selfPath) -Label 'host-Git probe working-tree object'
if ($admissionObject -notmatch '^[0-9a-f]{40}$' -or $admissionWorking -cne $admissionObject) {
    Fail-NxbHostGitLifetimeProbe 'admission wrapper bytes differ from exact-head Git authority'
}
if ($selfObject -notmatch '^[0-9a-f]{40}$' -or $selfWorking -cne $selfObject) {
    Fail-NxbHostGitLifetimeProbe 'probe bytes differ from exact-head Git authority'
}

$admissionInfo = Get-Item -LiteralPath $admissionPath -Force -ErrorAction Stop
if ($admissionInfo.Length -le 0 -or $admissionInfo.Length -gt 1048576) {
    Fail-NxbHostGitLifetimeProbe 'admission wrapper is outside the supported 1 MiB source envelope'
}
$admissionText = [IO.File]::ReadAllText($admissionPath, [Text.UTF8Encoding]::new($false, $true))
foreach ($needle in @(
    "Open-NxbPinnedHostTool -Path ([string]`$git.Source) -Label 'host Git'",
    '$env:PATH = ([string]$gitAuthority.Directory) + [IO.Path]::PathSeparator + $originalPath',
    'Get-Command git -CommandType Application -ErrorAction Stop',
    'subordinate Git resolution differs from the pinned host Git',
    '$env:PATH = $originalPath',
    'pinned host Git file disposal failed',
    'pinned host Git directory disposal failed'
)) {
    Assert-NxbContains -Text $admissionText -Needle $needle -Label 'canonical admission host-Git lifetime source'
}

$convertText = Get-NxbFunctionText -Path $admissionPath -Name 'ConvertFrom-NxbFinalPath'
$directoryText = Get-NxbFunctionText -Path $admissionPath -Name 'Open-NxbPinnedDirectory'
$hostToolText = Get-NxbFunctionText -Path $admissionPath -Name 'Open-NxbPinnedHostTool'
foreach ($needle in @(
    '[IO.FileShare]::Read',
    '[Nxb153WindowsAdmissionNative]::GetFinalPath($stream.SafeFileHandle)',
    'Open-NxbPinnedDirectory -Path $directory',
    'executable resolved through redirected authority'
)) {
    Assert-NxbContains -Text $hostToolText -Needle $needle -Label 'production Open-NxbPinnedHostTool'
}
foreach ($needle in @(
    'OpenDirectoryNoDeleteShare($expected)',
    '[Nxb153WindowsAdmissionNative]::GetFinalPath($handle)',
    'must not be a reparse point'
)) {
    Assert-NxbContains -Text $directoryText -Needle $needle -Label 'production Open-NxbPinnedDirectory'
}

. ([scriptblock]::Create($convertText))
. ([scriptblock]::Create($directoryText))
. ([scriptblock]::Create($hostToolText))

$results = [Collections.Generic.List[string]]::new()
$results.Add('exact-head admission host-Git source/AST contract')

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('nxb-153-host-git-lifetime-' + [Guid]::NewGuid().ToString('N'))
$trustedDirectory = Join-Path $temporaryRoot 'trusted'
$hostileDirectory = Join-Path $temporaryRoot 'hostile'
$gitAuthority = $null
$originalPath = [string]$env:PATH
$pathChanged = $false
$primaryFailure = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()

try {
    [IO.Directory]::CreateDirectory($trustedDirectory) | Out-Null
    [IO.Directory]::CreateDirectory($hostileDirectory) | Out-Null

    $shellPath = (Get-Process -Id $PID -ErrorAction Stop).Path
    if ([string]::IsNullOrWhiteSpace($shellPath) -or -not (Test-Path -LiteralPath $shellPath -PathType Leaf)) {
        Fail-NxbHostGitLifetimeProbe 'current PowerShell executable path is unavailable'
    }

    $trustedGit = Join-Path $trustedDirectory 'git.exe'
    $hostileGit = Join-Path $hostileDirectory 'git.exe'
    [IO.File]::Copy($shellPath, $trustedGit, $false)
    [IO.File]::Copy($shellPath, $hostileGit, $false)

    $baselineWrite = [IO.File]::Open($trustedGit, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    $baselineWrite.Dispose()
    $results.Add('temporary host-tool baseline writable before pin')

    $gitAuthority = Open-NxbPinnedHostTool -Path $trustedGit -Label 'probe host Git'
    $expectedTrusted = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath($trustedGit))
    if (-not [string]::Equals([string]$gitAuthority.Path, $expectedTrusted, [StringComparison]::OrdinalIgnoreCase)) {
        Fail-NxbHostGitLifetimeProbe 'production pin returned an unexpected canonical executable path'
    }
    $results.Add('production host-tool final-path identity primitive')

    Assert-NxbExpectedFailure -Label 'pinned host-tool write sharing rejection primitive' -Action {
        $candidate = [IO.File]::Open($trustedGit, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $candidate.Dispose()
    }
    $results.Add('pinned host-tool write sharing rejection primitive')

    Assert-NxbExpectedFailure -Label 'pinned host-tool delete rejection primitive' -Action {
        Remove-Item -LiteralPath $trustedGit -Force -ErrorAction Stop
    }
    $results.Add('pinned host-tool delete rejection primitive')

    $renamedGit = Join-Path $trustedDirectory 'git-renamed.exe'
    Assert-NxbExpectedFailure -Label 'pinned host-tool rename rejection primitive' -Action {
        Move-Item -LiteralPath $trustedGit -Destination $renamedGit -ErrorAction Stop
    }
    $results.Add('pinned host-tool rename rejection primitive')

    $renamedTrustedDirectory = Join-Path $temporaryRoot 'trusted-renamed'
    Assert-NxbExpectedFailure -Label 'pinned host-tool directory rename rejection primitive' -Action {
        Move-Item -LiteralPath $trustedDirectory -Destination $renamedTrustedDirectory -ErrorAction Stop
    }
    $results.Add('pinned host-tool directory rename rejection primitive')

    $hostileFirstPath = $hostileDirectory
    if (-not [string]::IsNullOrEmpty($originalPath)) {
        $hostileFirstPath += [IO.Path]::PathSeparator + $originalPath
    }
    $env:PATH = $hostileFirstPath
    $pathChanged = $true
    $before = Get-Command git -CommandType Application -ErrorAction Stop
    $beforePath = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath([string]$before.Source))
    if (-not [string]::Equals($beforePath, (ConvertFrom-NxbFinalPath -Path $hostileGit), [StringComparison]::OrdinalIgnoreCase)) {
        Fail-NxbHostGitLifetimeProbe 'hostile PATH candidate did not control application resolution before canonical rebinding'
    }

    $env:PATH = ([string]$gitAuthority.Directory) + [IO.Path]::PathSeparator + $hostileFirstPath
    $after = Get-Command git -CommandType Application -ErrorAction Stop
    $afterPath = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath([string]$after.Source))
    if (-not [string]::Equals($afterPath, [string]$gitAuthority.Path, [StringComparison]::OrdinalIgnoreCase)) {
        Fail-NxbHostGitLifetimeProbe 'canonical PATH rebinding did not force nested Git resolution to the pinned executable'
    }
    $results.Add('hostile PATH overridden by pinned Git directory primitive')

    $env:PATH = $hostileFirstPath
    if (-not [string]::Equals([string]$env:PATH, $hostileFirstPath, [StringComparison]::Ordinal)) {
        Fail-NxbHostGitLifetimeProbe 'PATH did not restore byte-for-byte after successful rebinding primitive'
    }
    $results.Add('PATH success restoration primitive')

    try {
        $env:PATH = ([string]$gitAuthority.Directory) + [IO.Path]::PathSeparator + $hostileFirstPath
        throw 'nxb-153 deliberate PATH restoration probe failure'
    }
    catch {
        if ($_.Exception.Message -cne 'nxb-153 deliberate PATH restoration probe failure') {
            throw
        }
    }
    finally {
        $env:PATH = $hostileFirstPath
    }
    if (-not [string]::Equals([string]$env:PATH, $hostileFirstPath, [StringComparison]::Ordinal)) {
        Fail-NxbHostGitLifetimeProbe 'PATH did not restore byte-for-byte after deliberate failure primitive'
    }
    $results.Add('PATH failure restoration primitive')

    $env:PATH = $originalPath
    $pathChanged = $false
    $gitAuthority.Stream.Dispose()
    $gitAuthority.DirectoryHandle.Dispose()
    $gitAuthority = $null
    $results.Add('production host-tool pin cleanup primitive')

    $releasedGit = Join-Path $trustedDirectory 'git-released.exe'
    Move-Item -LiteralPath $trustedGit -Destination $releasedGit -ErrorAction Stop
    Move-Item -LiteralPath $releasedGit -Destination $trustedGit -ErrorAction Stop
    $results.Add('host-tool rename succeeds after pin cleanup primitive')

    $releasedDirectory = Join-Path $temporaryRoot 'trusted-released'
    Move-Item -LiteralPath $trustedDirectory -Destination $releasedDirectory -ErrorAction Stop
    Move-Item -LiteralPath $releasedDirectory -Destination $trustedDirectory -ErrorAction Stop
    $results.Add('host-tool directory rename succeeds after pin cleanup primitive')

    $finalHead = Invoke-NxbBoundedGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'final exact Git HEAD'
    $finalAdmission = Invoke-NxbBoundedGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $admissionPath) -Label 'final admission wrapper object'
    $finalSelf = Invoke-NxbBoundedGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $selfPath) -Label 'final host-Git probe object'
    if ($finalHead -cne $headSha -or $finalAdmission -cne $admissionObject -or $finalSelf -cne $selfObject) {
        Fail-NxbHostGitLifetimeProbe 'exact-head source authority changed during host-Git lifetime probe'
    }
    $results.Add('final exact-head authority recheck')
}
catch {
    $primaryFailure = $_
}
finally {
    if ($pathChanged) {
        try { $env:PATH = $originalPath }
        catch { $cleanupErrors.Add("PATH restoration failed: $($_.Exception.Message)") }
    }
    if ($null -ne $gitAuthority) {
        try { $gitAuthority.Stream.Dispose() }
        catch { $cleanupErrors.Add("pinned host-tool file disposal failed: $($_.Exception.Message)") }
        try { $gitAuthority.DirectoryHandle.Dispose() }
        catch { $cleanupErrors.Add("pinned host-tool directory disposal failed: $($_.Exception.Message)") }
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        try { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction Stop }
        catch { $cleanupErrors.Add("temporary probe cleanup failed: $($_.Exception.Message)") }
    }
}

if ($null -ne $primaryFailure) {
    if ($cleanupErrors.Count -gt 0) {
        throw "NXB-153 Windows host-Git lifetime probe failed: $($primaryFailure.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
    }
    throw $primaryFailure
}
if ($cleanupErrors.Count -gt 0) {
    Fail-NxbHostGitLifetimeProbe ("cleanup failed after otherwise successful probe: " + ($cleanupErrors -join ' | '))
}

Write-Host "NXB-153 Windows host-Git lifetime probe passed for HEAD $headSha."
Write-Host "Policy: $policy"
Write-Host "Admission object: $admissionObject"
Write-Host "Probe object: $selfObject"
Write-Host "Tests: $($results.Count)"
foreach ($result in $results) {
    Write-Host "- $result"
}
