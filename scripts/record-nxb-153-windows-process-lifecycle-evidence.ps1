[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [ValidateRange(50, 10000)][int]$ProbeIoTimeoutMilliseconds = 1000,
    [ValidateRange(50, 10000)][int]$ProbeExitTimeoutMilliseconds = 1500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$policy = 'nxb-153-windows-process-lifecycle-evidence-v1'
$probePolicy = 'nxb-153-windows-process-lifecycle-probe-v1'
$maximumEvidenceBytes = 65536
$expectedTests = @(
    'exact-head source/AST contract',
    'registry-style text stdin success primitive',
    'registry-style stalled stdin timeout primitive',
    'registry-style post-stdin exit timeout primitive',
    'tar-style binary stdin success primitive',
    'tar-style stalled stdin timeout primitive',
    'tar-style post-stdin exit timeout primitive',
    'Git-archive-style stdout success primitive',
    'Git-archive-style stalled stdout timeout primitive',
    'Git-archive-style nonzero exit primitive',
    'broker-control bounded CRLF success primitive',
    'broker-control missing-newline rejection primitive',
    'broker-control invalid-UTF8 rejection primitive',
    'broker-control stalled-output timeout primitive',
    'post-I/O exit timeout primitive',
    'recursive process-tree termination primitive'
)

function Fail-NxbProcessEvidence {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows process lifecycle evidence failed: $Message"
}

if ($null -eq ('Nxb153ProcessEvidenceWriterNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Nxb153ProcessEvidenceWriterNative
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
        Fail-NxbProcessEvidence "$Label is missing: $expected"
    }
    $item = Get-Item -LiteralPath $expected -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbProcessEvidence "$Label must not be a reparse point"
    }
    $handle = [Nxb153ProcessEvidenceWriterNative]::OpenDirectoryNoDeleteShare($expected)
    try {
        $resolved = ConvertFrom-NxbFinalPath -Path ([Nxb153ProcessEvidenceWriterNative]::GetFinalPath($handle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbProcessEvidence "$Label resolved through redirected authority: expected '$expected', resolved '$resolved'"
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
        Fail-NxbProcessEvidence "$Label executable is missing: $expected"
    }
    $item = Get-Item -LiteralPath $expected -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbProcessEvidence "$Label executable must be a regular non-reparse file"
    }

    $directory = [IO.Path]::GetDirectoryName($expected)
    if ([string]::IsNullOrWhiteSpace($directory)) {
        Fail-NxbProcessEvidence "$Label executable parent directory is unavailable"
    }

    $directoryHandle = $null
    $stream = $null
    try {
        $directoryHandle = Open-NxbPinnedDirectory -Path $directory -Label "$Label executable directory"
        $stream = [IO.File]::Open($expected, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $resolved = ConvertFrom-NxbFinalPath -Path ([Nxb153ProcessEvidenceWriterNative]::GetFinalPath($stream.SafeFileHandle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbProcessEvidence "$Label executable resolved through redirected authority: expected '$expected', resolved '$resolved'"
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

function Invoke-NxbBoundedProcessOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][ValidateRange(1, 1048576)][int]$MaximumBytes,
        [Parameter(Mandatory = $true)][ValidateRange(1, 600000)][int]$ReadTimeoutMilliseconds,
        [Parameter(Mandatory = $true)][ValidateRange(1, 600000)][int]$ExitTimeoutMilliseconds
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
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
            Fail-NxbProcessEvidence "$Label process could not be started"
        }

        $buffer = [byte[]]::new(4096)
        [Int64]$total = 0
        while ($true) {
            $readTask = $process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $readTask.Wait($ReadTimeoutMilliseconds)) {
                Fail-NxbProcessEvidence "$Label stdout made no progress for $ReadTimeoutMilliseconds ms"
            }
            $read = $readTask.Result
            if ($read -le 0) { break }
            $total += $read
            if ($total -gt $MaximumBytes) {
                Fail-NxbProcessEvidence "$Label stdout exceeds the $MaximumBytes-byte envelope"
            }
            $memory.Write($buffer, 0, $read)
        }

        if (-not $process.WaitForExit($ExitTimeoutMilliseconds)) {
            Fail-NxbProcessEvidence "$Label process did not exit after stdout closed"
        }
        if ($process.ExitCode -ne 0) {
            Fail-NxbProcessEvidence "$Label failed with exit code $($process.ExitCode)"
        }

        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        try {
            return $utf8.GetString($memory.ToArray())
        }
        catch {
            Fail-NxbProcessEvidence "$Label stdout is not strict UTF-8: $($_.Exception.Message)"
        }
    }
    finally {
        try {
            if (-not $process.HasExited) {
                $process.Kill($true)
                [void]$process.WaitForExit($ExitTimeoutMilliseconds)
            }
        }
        catch {}
        $memory.Dispose()
        $process.Dispose()
    }
}

function Get-NxbGitValue {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $value = (Invoke-NxbBoundedProcessOutput `
        -Executable $GitPath `
        -Arguments $Arguments `
        -Label $Label `
        -MaximumBytes 4096 `
        -ReadTimeoutMilliseconds 30000 `
        -ExitTimeoutMilliseconds 30000).Trim()
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256) {
        Fail-NxbProcessEvidence "$Label did not return one bounded value"
    }
    return $value
}

function Get-NxbExactHeadObject {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$HeadSha,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    $full = Join-Path $RepoRoot ($RelativePath -replace '/', [IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Fail-NxbProcessEvidence "required exact-head file is missing: $RelativePath"
    }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbProcessEvidence "required exact-head file is a reparse point: $RelativePath"
    }
    $stream = $null
    try {
        $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $expectedPath = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath($full))
        $resolvedPath = ConvertFrom-NxbFinalPath -Path ([Nxb153ProcessEvidenceWriterNative]::GetFinalPath($stream.SafeFileHandle))
        if (-not [string]::Equals($resolvedPath, $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbProcessEvidence "required exact-head file resolved through redirected authority: expected '$expectedPath', resolved '$resolvedPath'"
        }
        $expected = Get-NxbGitValue -GitPath $GitPath -Arguments @('-C', $RepoRoot, 'rev-parse', "${HeadSha}:$RelativePath") -Label "Git object for $RelativePath"
        $actual = Get-NxbGitValue -GitPath $GitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $full) -Label "working-tree object for $RelativePath"
        if ($expected -notmatch '^[0-9a-f]{40}$' -or $actual -cne $expected) {
            Fail-NxbProcessEvidence "working-tree bytes differ from exact-head Git authority: $RelativePath"
        }
        return [pscustomobject]@{ Path = $full; ObjectId = $expected; Stream = $stream }
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Assert-NxbCanonicalUtc {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
        $Value,
        'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$parsed
    )) {
        Fail-NxbProcessEvidence "$Label is not canonical UTC"
    }
    if ($parsed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        Fail-NxbProcessEvidence "$Label is unreasonably in the future"
    }
}

function Assert-NxbExactTests {
    param([Parameter(Mandatory = $true)]$Actual)
    $values = @($Actual | ForEach-Object { [string]$_ })
    if ($values.Count -ne $expectedTests.Count) {
        Fail-NxbProcessEvidence "probe returned $($values.Count) tests; expected $($expectedTests.Count)"
    }
    for ($index = 0; $index -lt $expectedTests.Count; $index++) {
        if ($values[$index] -cne $expectedTests[$index]) {
            Fail-NxbProcessEvidence "probe test sequence differs at index $index"
        }
    }
    return $values
}

if (-not $IsWindows) {
    Fail-NxbProcessEvidence 'evidence recording requires supported Windows runtime semantics'
}
if ($PSVersionTable.PSEdition -cne 'Core') {
    Fail-NxbProcessEvidence 'evidence recording requires PowerShell Core'
}
if ($ProbeIoTimeoutMilliseconds -ne 1000 -or $ProbeExitTimeoutMilliseconds -ne 1500) {
    Fail-NxbProcessEvidence 'admission evidence requires canonical probe deadlines: 1000 ms I/O and 1500 ms exit'
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
    Fail-NxbProcessEvidence ('ambient Git authority variables are not admitted before exact-head resolution: ' + ($orderedGitAuthority -join ', '))
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$namespaceHandles = [Collections.Generic.List[IDisposable]]::new()
$sourceAuthorities = [Collections.Generic.List[object]]::new()
$cleanupErrors = [Collections.Generic.List[string]]::new()
$primaryFailure = $null
$evidencePath = $null
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
        Fail-NxbProcessEvidence "probe Git resolution differs from the pinned host Git: expected '$gitPath', resolved '$resolvedGitPath'"
    }

    $headSha = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'exact Git HEAD'
    if ($headSha -notmatch '^[0-9a-f]{40}$') {
        Fail-NxbProcessEvidence 'exact Git HEAD is not canonical 40-hex SHA-1'
    }

    $scriptsDirectory = Join-Path $RepoRoot 'scripts'
    $targetDirectory = Join-Path $RepoRoot 'target'
    $validationDirectory = Join-Path $targetDirectory 'nxb-validation'

    foreach ($entry in @(
        [pscustomobject]@{ Path = $RepoRoot; Label = 'repository root' },
        [pscustomobject]@{ Path = $scriptsDirectory; Label = 'scripts directory' },
        [pscustomobject]@{ Path = $targetDirectory; Label = 'target directory' },
        [pscustomobject]@{ Path = $validationDirectory; Label = 'validation evidence directory' }
    )) {
        $namespaceHandles.Add((Open-NxbPinnedDirectory -Path $entry.Path -Label $entry.Label))
    }

    $probe = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-process-lifecycle-probe.ps1'
    $sourceAuthorities.Add($probe)
    $writer = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1'
    $sourceAuthorities.Add($writer)
    $dependency = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-dependency-source.ps1'
    $sourceAuthorities.Add($dependency)
    $immutable = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-immutable-source-inner.ps1'
    $sourceAuthorities.Add($immutable)
    $bounded = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-immutable-source-bounded-inner.ps1'
    $sourceAuthorities.Add($bounded)

    $shellPath = (Get-Process -Id $PID -ErrorAction Stop).Path
    if ([string]::IsNullOrWhiteSpace($shellPath) -or -not (Test-Path -LiteralPath $shellPath -PathType Leaf)) {
        Fail-NxbProcessEvidence 'current PowerShell executable path is unavailable for probe execution'
    }
    $probeOutput = Invoke-NxbBoundedProcessOutput `
        -Executable $shellPath `
        -Arguments @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', $probe.Path,
            '-RepoRoot', $RepoRoot,
            '-ProbeIoTimeoutMilliseconds', [string]$ProbeIoTimeoutMilliseconds,
            '-ProbeExitTimeoutMilliseconds', [string]$ProbeExitTimeoutMilliseconds,
            '-Json'
        ) `
        -Label 'process lifecycle probe' `
        -MaximumBytes $maximumEvidenceBytes `
        -ReadTimeoutMilliseconds 300000 `
        -ExitTimeoutMilliseconds 30000
    $probeBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($probeOutput)
    if ($probeBytes.Length -le 0 -or $probeBytes.Length -gt $maximumEvidenceBytes) {
        Fail-NxbProcessEvidence 'probe JSON output is outside the supported evidence envelope'
    }
    try {
        $probeRecord = $probeOutput | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Fail-NxbProcessEvidence "probe output is invalid JSON: $($_.Exception.Message)"
    }

    $expectedProbeFields = @(
        'schema_version', 'policy', 'milestone', 'platform', 'head_sha',
        'dependency_source_object', 'immutable_source_object', 'bounded_source_object',
        'production_io_timeout_milliseconds', 'production_exit_timeout_milliseconds',
        'probe_io_timeout_milliseconds', 'probe_exit_timeout_milliseconds',
        'powershell_version', 'tests', 'status', 'probed_at'
    )
    $actualProbeFields = @($probeRecord.PSObject.Properties.Name | Sort-Object)
    $sortedExpectedProbeFields = @($expectedProbeFields | Sort-Object)
    if (($actualProbeFields -join "`n") -cne ($sortedExpectedProbeFields -join "`n")) {
        Fail-NxbProcessEvidence 'probe JSON fields do not match the canonical contract'
    }

    if (
        [int]$probeRecord.schema_version -ne 1 -or
        [string]$probeRecord.policy -cne $probePolicy -or
        [string]$probeRecord.milestone -cne 'NXB-153' -or
        [string]$probeRecord.platform -cne 'windows' -or
        [string]$probeRecord.head_sha -cne $headSha -or
        [string]$probeRecord.dependency_source_object -cne $dependency.ObjectId -or
        [string]$probeRecord.immutable_source_object -cne $immutable.ObjectId -or
        [string]$probeRecord.bounded_source_object -cne $bounded.ObjectId -or
        [int]$probeRecord.production_io_timeout_milliseconds -ne 300000 -or
        [int]$probeRecord.production_exit_timeout_milliseconds -ne 30000 -or
        [int]$probeRecord.probe_io_timeout_milliseconds -ne $ProbeIoTimeoutMilliseconds -or
        [int]$probeRecord.probe_exit_timeout_milliseconds -ne $ProbeExitTimeoutMilliseconds -or
        [string]$probeRecord.status -cne 'passed'
    ) {
        Fail-NxbProcessEvidence 'probe JSON does not match exact-head process-lifecycle authority'
    }
    if ([string]::IsNullOrWhiteSpace([string]$probeRecord.powershell_version) -or ([string]$probeRecord.powershell_version).Length -gt 64) {
        Fail-NxbProcessEvidence 'probe PowerShell version is outside the supported envelope'
    }
    Assert-NxbCanonicalUtc -Value ([string]$probeRecord.probed_at) -Label 'probe probed_at'
    $tests = @(Assert-NxbExactTests -Actual $probeRecord.tests)

    $evidencePath = Join-Path $validationDirectory "nxb-153-windows-process-lifecycle-$headSha.json"
    $record = [ordered]@{
        schema_version = 1
        policy = $policy
        milestone = 'NXB-153'
        platform = 'windows'
        head_sha = $headSha
        probe_policy = $probePolicy
        probe_script_object = $probe.ObjectId
        evidence_writer_object = $writer.ObjectId
        dependency_source_object = $dependency.ObjectId
        immutable_source_object = $immutable.ObjectId
        bounded_source_object = $bounded.ObjectId
        production_io_timeout_milliseconds = 300000
        production_exit_timeout_milliseconds = 30000
        probe_io_timeout_milliseconds = $ProbeIoTimeoutMilliseconds
        probe_exit_timeout_milliseconds = $ProbeExitTimeoutMilliseconds
        powershell_version = [string]$probeRecord.powershell_version
        tests = $tests
        status = 'passed'
        probed_at = [string]$probeRecord.probed_at
        recorded_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    $evidenceText = (($record | ConvertTo-Json -Depth 5) + [Environment]::NewLine)
    $evidenceBytes = [Text.UTF8Encoding]::new($false).GetBytes($evidenceText)
    if ($evidenceBytes.Length -le 0 -or $evidenceBytes.Length -gt $maximumEvidenceBytes) {
        Fail-NxbProcessEvidence 'process-lifecycle evidence is outside the supported evidence envelope'
    }

    $stream = $null
    try {
        try {
            $stream = [IO.File]::Open(
                $evidencePath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
        }
        catch [IO.IOException] {
            if (Test-Path -LiteralPath $evidencePath) {
                Fail-NxbProcessEvidence "exact-head process-lifecycle evidence already exists and will not be overwritten: $evidencePath"
            }
            throw
        }
        $stream.Write($evidenceBytes, 0, $evidenceBytes.Length)
        $stream.Flush($true)
        $stream.Position = 0
        $persisted = [byte[]]::new($evidenceBytes.Length)
        $offset = 0
        while ($offset -lt $persisted.Length) {
            $read = $stream.Read($persisted, $offset, $persisted.Length - $offset)
            if ($read -le 0) {
                Fail-NxbProcessEvidence 'process-lifecycle evidence could not be read back completely'
            }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1 -or [Convert]::ToBase64String($persisted) -cne [Convert]::ToBase64String($evidenceBytes)) {
            Fail-NxbProcessEvidence 'process-lifecycle evidence read-back bytes differ from the deterministic record'
        }
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }

    $finalHead = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'final exact Git HEAD'
    if ($finalHead -cne $headSha) {
        Fail-NxbProcessEvidence 'Git HEAD changed during process-lifecycle evidence recording'
    }
    foreach ($authority in $sourceAuthorities) {
        $actual = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $authority.Path) -Label "final object for $($authority.Path)"
        if ($actual -cne $authority.ObjectId) {
            Fail-NxbProcessEvidence "exact-head source authority changed during evidence recording: $($authority.Path)"
        }
    }
}
catch {
    $primaryFailure = $_
}
finally {
    for ($index = $sourceAuthorities.Count - 1; $index -ge 0; $index--) {
        try { $sourceAuthorities[$index].Stream.Dispose() }
        catch { $cleanupErrors.Add("source authority handle disposal failed: $($sourceAuthorities[$index].Path): $($_.Exception.Message)") }
    }
    for ($index = $namespaceHandles.Count - 1; $index -ge 0; $index--) {
        try { $namespaceHandles[$index].Dispose() }
        catch { $cleanupErrors.Add("namespace handle disposal failed at index $index: $($_.Exception.Message)") }
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
        throw "NXB-153 Windows process lifecycle evidence failed: $($primaryFailure.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
    }
    throw $primaryFailure
}
if ($cleanupErrors.Count -gt 0) {
    Fail-NxbProcessEvidence ("cleanup failed after otherwise successful evidence recording: " + ($cleanupErrors -join ' | '))
}
if ([string]::IsNullOrWhiteSpace($evidencePath)) {
    Fail-NxbProcessEvidence 'evidence path was not established after otherwise successful recording'
}

Write-Host "NXB-153 Windows process-lifecycle evidence recorded for HEAD $headSha."
Write-Host "Evidence: $evidencePath"
