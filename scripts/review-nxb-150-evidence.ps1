[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$EvidenceDirectory = (Join-Path $RepoRoot 'target\nxb-validation')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedLockSha256 = 'f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff'
$expectedAuditVersion = '0.22.2'
$expectedDenyVersion = '0.20.2'
$maximumEvidenceBytes = 65536
$expectedFields = @(
    'schema_version', 'milestone', 'gate', 'platform', 'head_sha', 'rustc', 'cargo',
    'cargo_audit', 'cargo_audit_sha256', 'cargo_deny', 'cargo_deny_sha256',
    'cargo_lock_sha256', 'lockfile_reproduced_without_diff',
    'package_fmt_check_clippy_tests', 'vault_provider_regressions',
    'workspace_check_clippy_tests', 'rustsec', 'cargo_deny_checks',
    'process_fixture_serial', 'network_activity', 'validated_at'
)
$stringFields = @(
    'milestone', 'gate', 'platform', 'head_sha', 'rustc', 'cargo', 'cargo_audit',
    'cargo_audit_sha256', 'cargo_deny', 'cargo_deny_sha256', 'cargo_lock_sha256',
    'package_fmt_check_clippy_tests', 'vault_provider_regressions',
    'workspace_check_clippy_tests', 'rustsec', 'cargo_deny_checks',
    'network_activity', 'validated_at'
)
$booleanFields = @('lockfile_reproduced_without_diff', 'process_fixture_serial')

function Test-LowerSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    return $Value -match '^[0-9a-f]{64}$'
}

function Assert-NoReparseComponents {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $absolute = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($absolute)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label path has no filesystem root."
    }
    $current = $root
    $relative = $absolute.Substring($root.Length)
    foreach ($segment in $relative.Split(
        [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar),
        [StringSplitOptions]::RemoveEmptyEntries
    )) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            break
        }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a symbolic-link or reparse-point component: $current"
        }
    }
}

function Assert-ExactFields {
    param(
        [Parameter(Mandatory = $true)]$Evidence,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $actual = @($Evidence.PSObject.Properties.Name)
    foreach ($field in $expectedFields) {
        if ($field -notin $actual) {
            throw "$Label is missing required field '$field'."
        }
    }
    foreach ($field in $actual) {
        if ($field -notin $expectedFields) {
            throw "$Label contains unsupported field '$field'."
        }
    }
}

function Assert-ExactTypes {
    param(
        [Parameter(Mandatory = $true)]$Evidence,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (($Evidence.schema_version -isnot [int]) -and
        ($Evidence.schema_version -isnot [long])) {
        throw "$Label field 'schema_version' must be an integer."
    }
    foreach ($field in $stringFields) {
        if ($Evidence.$field -isnot [string]) {
            throw "$Label field '$field' must be a string."
        }
    }
    foreach ($field in $booleanFields) {
        if ($Evidence.$field -isnot [bool]) {
            throw "$Label field '$field' must be a boolean."
        }
    }
}

function Read-Evidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedPlatform,
        [Parameter(Mandatory = $true)][string]$ExpectedHead
    )

    Assert-NoReparseComponents -Path $Path -Label "$ExpectedPlatform evidence"
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing $ExpectedPlatform evidence: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$ExpectedPlatform evidence must not be a symbolic link or reparse point."
    }
    if ($item.Length -le 0 -or $item.Length -gt $maximumEvidenceBytes) {
        throw "$ExpectedPlatform evidence size is invalid."
    }

    $raw = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true))
    $evidence = $raw | ConvertFrom-Json -Depth 16
    Assert-ExactFields -Evidence $evidence -Label "$ExpectedPlatform evidence"
    Assert-ExactTypes -Evidence $evidence -Label "$ExpectedPlatform evidence"

    if ($evidence.schema_version -ne 2 -or
        $evidence.milestone -cne 'NXB-150' -or
        $evidence.gate -cne 'pinned_process_evidence_key_provider' -or
        $evidence.platform -cne $ExpectedPlatform -or
        $evidence.head_sha -cne $ExpectedHead) {
        throw "$ExpectedPlatform evidence identity does not match the closure contract."
    }
    if ($evidence.rustc -notmatch '^rustc 1\.97\.1\s' -or
        $evidence.cargo -notmatch '^cargo\s' -or
        $evidence.cargo_audit -notmatch ('(^|\s)' + [regex]::Escape($expectedAuditVersion) + '($|\s)') -or
        $evidence.cargo_deny -notmatch ('(^|\s)' + [regex]::Escape($expectedDenyVersion) + '($|\s)')) {
        throw "$ExpectedPlatform evidence reports an unsupported toolchain."
    }
    foreach ($field in @('cargo_audit_sha256', 'cargo_deny_sha256', 'cargo_lock_sha256')) {
        if (-not (Test-LowerSha256 -Value ([string]$evidence.$field))) {
            throw "$ExpectedPlatform evidence field '$field' is not a lowercase SHA-256."
        }
    }
    if ($evidence.cargo_lock_sha256 -cne $expectedLockSha256 -or
        $evidence.lockfile_reproduced_without_diff -ne $true -or
        $evidence.package_fmt_check_clippy_tests -cne 'passed' -or
        $evidence.vault_provider_regressions -cne 'passed' -or
        $evidence.workspace_check_clippy_tests -cne 'passed' -or
        $evidence.rustsec -cne 'passed' -or
        $evidence.cargo_deny_checks -cne 'passed' -or
        $evidence.process_fixture_serial -ne $true -or
        $evidence.network_activity -cne 'dependency_and_advisory_sources_only') {
        throw "$ExpectedPlatform evidence contains a failed or unsupported gate value."
    }

    $timestamp = [DateTimeOffset]::MinValue
    $dateStyles = [Globalization.DateTimeStyles]::AssumeUniversal -bor `
        [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTimeOffset]::TryParseExact(
        [string]$evidence.validated_at,
        'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture,
        $dateStyles,
        [ref]$timestamp
    )) {
        throw "$ExpectedPlatform evidence validated_at is not canonical UTC."
    }
    if ($timestamp -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        throw "$ExpectedPlatform evidence validated_at is unreasonably in the future."
    }

    return [ordered]@{
        platform = $ExpectedPlatform
        file_name = [IO.Path]::GetFileName($Path)
        evidence_sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        validated_at = [string]$evidence.validated_at
        rustc = [string]$evidence.rustc
        cargo = [string]$evidence.cargo
        cargo_audit = [string]$evidence.cargo_audit
        cargo_audit_sha256 = [string]$evidence.cargo_audit_sha256
        cargo_deny = [string]$evidence.cargo_deny
        cargo_deny_sha256 = [string]$evidence.cargo_deny_sha256
        cargo_lock_sha256 = [string]$evidence.cargo_lock_sha256
    }
}

Push-Location $RepoRoot
try {
    if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
        throw 'git is unavailable.'
    }

    $headSha = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $headSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Exact Git HEAD could not be resolved.'
    }
    $status = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $status) {
        throw 'Working tree must be clean before evidence review.'
    }

    $lockPath = Join-Path $RepoRoot 'Cargo.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'Cargo.lock is missing.'
    }
    $lockSha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($lockSha256 -cne $expectedLockSha256) {
        throw "Repository Cargo.lock SHA-256 mismatch: expected $expectedLockSha256, found $lockSha256"
    }

    $EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
    Assert-NoReparseComponents -Path $EvidenceDirectory -Label 'evidence directory'
    if (Test-Path -LiteralPath $EvidenceDirectory) {
        $directoryItem = Get-Item -LiteralPath $EvidenceDirectory -Force
        if (-not $directoryItem.PSIsContainer -or
            ($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Evidence directory must be a normal non-reparse directory.'
        }
    } else {
        New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
        Assert-NoReparseComponents -Path $EvidenceDirectory -Label 'evidence directory'
    }

    $windowsPath = Join-Path $EvidenceDirectory "nxb-150-windows-$headSha.json"
    $linuxPath = Join-Path $EvidenceDirectory "nxb-150-linux-$headSha.json"
    $windows = Read-Evidence -Path $windowsPath -ExpectedPlatform 'windows' -ExpectedHead $headSha
    $linux = Read-Evidence -Path $linuxPath -ExpectedPlatform 'linux' -ExpectedHead $headSha

    foreach ($field in @('rustc', 'cargo', 'cargo_audit', 'cargo_deny', 'cargo_lock_sha256')) {
        if ($windows[$field] -cne $linux[$field]) {
            throw "Linux and Windows evidence disagree on '$field'."
        }
    }

    $closure = [ordered]@{
        schema_version = 1
        milestone = 'NXB-150'
        gate = 'dual_platform_evidence_closure'
        status = 'ready_for_manual_pr_review'
        head_sha = $headSha
        cargo_lock_sha256 = $lockSha256
        rustc = $windows['rustc']
        cargo = $windows['cargo']
        cargo_audit = $windows['cargo_audit']
        cargo_deny = $windows['cargo_deny']
        platforms = @('linux', 'windows')
        evidence = @($linux, $windows)
        requirements = [ordered]@{
            same_exact_head = 'passed'
            canonical_lockfile = 'passed'
            package_and_workspace_gates = 'passed'
            rustsec = 'passed'
            cargo_deny = 'passed'
            serial_process_fixture = 'passed'
        }
        network_activity = 'none'
    }

    $closurePath = Join-Path $EvidenceDirectory "nxb-150-closure-$headSha.json"
    $pendingPath = "$closurePath.pending"
    Assert-NoReparseComponents -Path $closurePath -Label 'closure evidence'
    if (Test-Path -LiteralPath $closurePath) {
        if (-not (Test-Path -LiteralPath $closurePath -PathType Leaf)) {
            throw 'Existing closure evidence must be a regular file.'
        }
        $closureItem = Get-Item -LiteralPath $closurePath -Force
        if (($closureItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Existing closure evidence must not be a symbolic link or reparse point.'
        }
        if ($closureItem.Length -le 0 -or $closureItem.Length -gt $maximumEvidenceBytes) {
            throw 'Existing closure evidence size is invalid.'
        }
        $existing = [IO.File]::ReadAllText(
            $closurePath,
            [Text.UTF8Encoding]::new($false, $true)
        ) | ConvertFrom-Json -Depth 16
        $existingCanonical = $existing | ConvertTo-Json -Depth 16 -Compress
        $expectedCanonical = $closure | ConvertTo-Json -Depth 16 -Compress
        if ($existingCanonical -cne $expectedCanonical) {
            throw 'Existing closure evidence differs from the deterministic review result.'
        }
    } else {
        Assert-NoReparseComponents -Path $pendingPath -Label 'pending closure evidence'
        if (Test-Path -LiteralPath $pendingPath) {
            throw 'Pending closure evidence already exists; manual recovery is required.'
        }
        $json = $closure | ConvertTo-Json -Depth 16
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
        $stream = [IO.File]::Open(
            $pendingPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        Move-Item -LiteralPath $pendingPath -Destination $closurePath
    }

    Write-Host 'NXB-150 dual-platform evidence closure passed.'
    Write-Host "HEAD: $headSha"
    Write-Host "Cargo.lock SHA-256: $lockSha256"
    Write-Host "Closure: $closurePath"
}
finally {
    Pop-Location
}
