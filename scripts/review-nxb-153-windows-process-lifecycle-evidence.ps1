[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$EvidencePath
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
    'post-I/O exit timeout primitive',
    'recursive process-tree termination primitive'
)

function Fail-NxbProcessReview {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows process lifecycle evidence review failed: $Message"
}

function Get-NxbGitValue {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $value = (& $GitPath @Arguments | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256) {
        Fail-NxbProcessReview "$Label did not return one bounded value"
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
        Fail-NxbProcessReview "required exact-head file is missing: $RelativePath"
    }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbProcessReview "required exact-head file is a reparse point: $RelativePath"
    }
    $expected = Get-NxbGitValue -GitPath $GitPath -Arguments @('-C', $RepoRoot, 'rev-parse', "${HeadSha}:$RelativePath") -Label "Git object for $RelativePath"
    $actual = Get-NxbGitValue -GitPath $GitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $full) -Label "working-tree object for $RelativePath"
    if ($expected -notmatch '^[0-9a-f]{40}$' -or $actual -cne $expected) {
        Fail-NxbProcessReview "working-tree bytes differ from exact-head Git authority: $RelativePath"
    }
    return [pscustomobject]@{ Path = $full; ObjectId = $expected }
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
    return [IO.Path]::GetFullPath($value)
}

if ($null -eq ('Nxb153ProcessEvidenceNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Nxb153ProcessEvidenceNative
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle hFile,
        StringBuilder lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

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

function Open-NxbPinnedEvidence {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Fail-NxbProcessReview "process-lifecycle evidence is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbProcessReview 'process-lifecycle evidence must not be a reparse point'
    }
    if ($item.Length -le 0 -or $item.Length -gt $maximumEvidenceBytes) {
        Fail-NxbProcessReview 'process-lifecycle evidence size is outside the supported envelope'
    }
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $expected = ConvertFrom-NxbFinalPath -Path ([IO.Path]::GetFullPath($Path))
        $resolved = ConvertFrom-NxbFinalPath -Path ([Nxb153ProcessEvidenceNative]::GetFinalPath($stream.SafeFileHandle))
        if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-NxbProcessReview "evidence path resolved through redirected authority: expected '$expected', resolved '$resolved'"
        }
        return $stream
    }
    catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Read-NxbPinnedEvidenceText {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        Fail-NxbProcessReview 'evidence stream must be readable and seekable'
    }
    if ($Stream.Length -le 0 -or $Stream.Length -gt $maximumEvidenceBytes) {
        Fail-NxbProcessReview 'pinned evidence length is outside the supported envelope'
    }
    $Stream.Position = 0
    $bytes = [byte[]]::new([int]$Stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $Stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -le 0) {
            Fail-NxbProcessReview 'pinned evidence could not be read completely'
        }
        $offset += $read
    }
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    try {
        return $strictUtf8.GetString($bytes)
    }
    catch {
        Fail-NxbProcessReview "pinned evidence is not strict UTF-8: $($_.Exception.Message)"
    }
}

function Get-NxbStreamSha256 {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)
    $saved = $Stream.Position
    try {
        $Stream.Position = 0
        return (Get-FileHash -InputStream $Stream -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    finally {
        $Stream.Position = $saved
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
        Fail-NxbProcessReview "$Label is not canonical UTC"
    }
    if ($parsed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        Fail-NxbProcessReview "$Label is unreasonably in the future"
    }
    return $parsed
}

if (-not $IsWindows) {
    Fail-NxbProcessReview 'review requires supported Windows file/process semantics'
}
if ($PSVersionTable.PSEdition -cne 'Core') {
    Fail-NxbProcessReview 'review requires PowerShell Core'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$git = Get-Command git -CommandType Application -ErrorAction Stop
$gitPath = $git.Source
$headSha = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'exact Git HEAD'
if ($headSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbProcessReview 'exact Git HEAD is not canonical 40-hex SHA-1'
}

$probe = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-process-lifecycle-probe.ps1'
$writer = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1'
$reviewer = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/review-nxb-153-windows-process-lifecycle-evidence.ps1'
$dependency = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-dependency-source.ps1'
$immutable = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-immutable-source-inner.ps1'

if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $RepoRoot "target\nxb-validation\nxb-153-windows-process-lifecycle-$headSha.json"
}
$EvidencePath = [IO.Path]::GetFullPath($EvidencePath)
$expectedEvidencePath = [IO.Path]::GetFullPath((Join-Path $RepoRoot "target\nxb-validation\nxb-153-windows-process-lifecycle-$headSha.json"))
if (-not [string]::Equals($EvidencePath, $expectedEvidencePath, [StringComparison]::OrdinalIgnoreCase)) {
    Fail-NxbProcessReview 'reviewed evidence path is not the canonical exact-head process-lifecycle evidence path'
}

$stream = Open-NxbPinnedEvidence -Path $EvidencePath
try {
    $text = Read-NxbPinnedEvidenceText -Stream $stream
    $sha256 = Get-NxbStreamSha256 -Stream $stream
    try {
        $record = $text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Fail-NxbProcessReview "process-lifecycle evidence is invalid JSON: $($_.Exception.Message)"
    }

    $expectedFields = @(
        'schema_version', 'policy', 'milestone', 'platform', 'head_sha',
        'probe_policy', 'probe_script_object', 'evidence_writer_object',
        'dependency_source_object', 'immutable_source_object',
        'production_io_timeout_milliseconds', 'production_exit_timeout_milliseconds',
        'probe_io_timeout_milliseconds', 'probe_exit_timeout_milliseconds',
        'powershell_version', 'tests', 'status', 'probed_at', 'recorded_at'
    )
    $actualFields = @($record.PSObject.Properties.Name | Sort-Object)
    $sortedExpectedFields = @($expectedFields | Sort-Object)
    if (($actualFields -join "`n") -cne ($sortedExpectedFields -join "`n")) {
        Fail-NxbProcessReview 'evidence fields do not match the canonical process-lifecycle schema'
    }

    if (
        [int]$record.schema_version -ne 1 -or
        [string]$record.policy -cne $policy -or
        [string]$record.milestone -cne 'NXB-153' -or
        [string]$record.platform -cne 'windows' -or
        [string]$record.head_sha -cne $headSha -or
        [string]$record.probe_policy -cne $probePolicy -or
        [string]$record.probe_script_object -cne $probe.ObjectId -or
        [string]$record.evidence_writer_object -cne $writer.ObjectId -or
        [string]$record.dependency_source_object -cne $dependency.ObjectId -or
        [string]$record.immutable_source_object -cne $immutable.ObjectId -or
        [int]$record.production_io_timeout_milliseconds -ne 300000 -or
        [int]$record.production_exit_timeout_milliseconds -ne 30000 -or
        [int]$record.probe_io_timeout_milliseconds -ne 1000 -or
        [int]$record.probe_exit_timeout_milliseconds -ne 1500 -or
        [string]$record.status -cne 'passed'
    ) {
        Fail-NxbProcessReview 'evidence values do not match exact-head process-lifecycle authority'
    }

    if ([string]::IsNullOrWhiteSpace([string]$record.powershell_version) -or ([string]$record.powershell_version).Length -gt 64) {
        Fail-NxbProcessReview 'evidence PowerShell version is outside the supported envelope'
    }
    $tests = @($record.tests | ForEach-Object { [string]$_ })
    if ($tests.Count -ne $expectedTests.Count) {
        Fail-NxbProcessReview 'evidence test count differs from the canonical probe contract'
    }
    for ($index = 0; $index -lt $expectedTests.Count; $index++) {
        if ($tests[$index] -cne $expectedTests[$index]) {
            Fail-NxbProcessReview "evidence test sequence differs at index $index"
        }
    }
    $probedAt = Assert-NxbCanonicalUtc -Value ([string]$record.probed_at) -Label 'probed_at'
    $recordedAt = Assert-NxbCanonicalUtc -Value ([string]$record.recorded_at) -Label 'recorded_at'
    if ($recordedAt -lt $probedAt -or $recordedAt -gt $probedAt.AddMinutes(5)) {
        Fail-NxbProcessReview 'recorded_at is outside the admitted probe-to-evidence interval'
    }

    $finalHead = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'final exact Git HEAD'
    if ($finalHead -cne $headSha) {
        Fail-NxbProcessReview 'Git HEAD changed during process-lifecycle evidence review'
    }
    foreach ($authority in @($probe, $writer, $reviewer, $dependency, $immutable)) {
        $actual = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $authority.Path) -Label "final object for $($authority.Path)"
        if ($actual -cne $authority.ObjectId) {
            Fail-NxbProcessReview "exact-head authority bytes changed during review: $($authority.Path)"
        }
    }

    Write-Host 'NXB-153 Windows process-lifecycle evidence review passed.'
    Write-Host "HEAD: $headSha"
    Write-Host "Evidence SHA-256: $sha256"
    Write-Host "Reviewer object: $($reviewer.ObjectId)"
}
finally {
    $stream.Dispose()
}
