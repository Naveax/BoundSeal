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
    'post-I/O exit timeout primitive',
    'recursive process-tree termination primitive'
)

function Fail-NxbProcessEvidence {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows process lifecycle evidence failed: $Message"
}

function Get-NxbGitValue {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $value = (& $GitPath @Arguments | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256) {
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
    $expected = Get-NxbGitValue -GitPath $GitPath -Arguments @('-C', $RepoRoot, 'rev-parse', "${HeadSha}:$RelativePath") -Label "Git object for $RelativePath"
    $actual = Get-NxbGitValue -GitPath $GitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $full) -Label "working-tree object for $RelativePath"
    if ($expected -notmatch '^[0-9a-f]{40}$' -or $actual -cne $expected) {
        Fail-NxbProcessEvidence "working-tree bytes differ from exact-head Git authority: $RelativePath"
    }
    return [pscustomobject]@{ Path = $full; ObjectId = $expected }
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

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$git = Get-Command git -CommandType Application -ErrorAction Stop
$gitPath = $git.Source
$headSha = Get-NxbGitValue -GitPath $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'exact Git HEAD'
if ($headSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbProcessEvidence 'exact Git HEAD is not canonical 40-hex SHA-1'
}

$probe = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-process-lifecycle-probe.ps1'
$writer = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1'
$dependency = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-dependency-source.ps1'
$immutable = Get-NxbExactHeadObject -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-immutable-source-inner.ps1'

$probeOutput = (& $probe.Path `
    -RepoRoot $RepoRoot `
    -ProbeIoTimeoutMilliseconds $ProbeIoTimeoutMilliseconds `
    -ProbeExitTimeoutMilliseconds $ProbeExitTimeoutMilliseconds `
    -Json | Out-String)
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
    'dependency_source_object', 'immutable_source_object',
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

$validationDirectory = Join-Path $RepoRoot 'target\nxb-validation'
New-Item -ItemType Directory -Path $validationDirectory -Force | Out-Null
$validationItem = Get-Item -LiteralPath $validationDirectory -Force
if (-not $validationItem.PSIsContainer -or ($validationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail-NxbProcessEvidence 'validation evidence directory must be a normal non-reparse directory'
}

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

Write-Host "NXB-153 Windows process-lifecycle evidence recorded for HEAD $headSha."
Write-Host "Evidence: $evidencePath"
