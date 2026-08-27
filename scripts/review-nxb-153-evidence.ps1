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
$expectedEnvironmentPolicy = 'nxb-153-compiler-cargo-python-authority-v2'
$expectedHostRustIdentity = 'version_pinned_object_identity_pending'
$maximumEvidenceBytes = 65536
$expectedEvidenceFields = @(
    'schema_version', 'milestone', 'gate', 'platform', 'head_sha', 'rustc', 'cargo',
    'cargo_audit', 'cargo_audit_sha256', 'cargo_deny', 'cargo_deny_sha256',
    'tooling_receipt', 'tooling_receipt_sha256', 'tooling_receipt_verified',
    'cargo_lock_sha256', 'cargo_lock_expected_sha256', 'lockfile_pinned_and_unchanged',
    'validation_environment_policy', 'validation_environment_authority',
    'python_isolated_helper_authority', 'workspace_namespace_authority',
    'workspace_git_object_authority', 'dependency_source_authority',
    'security_tool_object_authority', 'host_rust_toolchain_identity',
    'fmt', 'nxb_policy_check_clippy_tests', 'nxb_core_check_clippy_unit_tests',
    'focused_target_tests', 'workspace_check_clippy_tests_all_features',
    'rustsec', 'cargo_deny_checks', 'test_threads', 'network_activity', 'validated_at'
)
$expectedReceiptFields = @(
    'schema_version', 'milestone', 'gate', 'platform', 'head_sha', 'rust_toolchain',
    'cargo_audit', 'cargo_audit_sha256', 'cargo_deny', 'cargo_deny_sha256',
    'tools_root', 'network_activity', 'prepared_at'
)

$convertFromJsonCommand = Get-Command ConvertFrom-Json -ErrorAction Stop
if (-not $convertFromJsonCommand.Parameters.ContainsKey('DateKind')) {
    throw 'PowerShell 7.5 or newer is required so JSON timestamp fields remain strings.'
}

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
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expectedSorted = @($Expected | Sort-Object)
    if (($actual -join "`n") -cne ($expectedSorted -join "`n")) {
        throw "$Label fields do not match the closure contract."
    }
}

function Read-StrictJsonRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-NoReparseComponents -Path $Path -Label $Label
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing $Label: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a symbolic link or reparse point."
    }
    if ($item.Length -le 0 -or $item.Length -gt $maximumEvidenceBytes) {
        throw "$Label size is invalid."
    }
    $raw = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true))
    return $raw | ConvertFrom-Json -Depth 24 -DateKind String
}

function Assert-CanonicalUtc {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $timestamp = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor `
        [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTimeOffset]::TryParseExact(
        $Value,
        'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture,
        $styles,
        [ref]$timestamp
    )) {
        throw "$Label is not canonical UTC."
    }
    if ($timestamp -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        throw "$Label is unreasonably in the future."
    }
}

function Read-ToolingReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedPlatform,
        [Parameter(Mandatory = $true)][string]$ExpectedHead,
        [Parameter(Mandatory = $true)]$Evidence
    )

    $receipt = Read-StrictJsonRecord -Path $Path -Label "$ExpectedPlatform tooling receipt"
    Assert-ExactFields -Value $receipt -Expected $expectedReceiptFields -Label "$ExpectedPlatform tooling receipt"
    $expectedToolsRoot = "target/nxb-tools/$ExpectedPlatform/$ExpectedHead"

    if (
        $receipt.schema_version -ne 1 -or
        $receipt.milestone -cne 'NXB-153' -or
        $receipt.gate -cne 'validation_tool_bootstrap' -or
        $receipt.platform -cne $ExpectedPlatform -or
        $receipt.head_sha -cne $ExpectedHead -or
        $receipt.tools_root -cne $expectedToolsRoot -or
        $receipt.network_activity -cne 'rustup_and_crates_io_tool_installation_only'
    ) {
        throw "$ExpectedPlatform tooling receipt identity is invalid."
    }
    if (
        $receipt.rust_toolchain -cne $Evidence.rustc -or
        $receipt.cargo_audit -cne $Evidence.cargo_audit -or
        $receipt.cargo_audit_sha256 -cne $Evidence.cargo_audit_sha256 -or
        $receipt.cargo_deny -cne $Evidence.cargo_deny -or
        $receipt.cargo_deny_sha256 -cne $Evidence.cargo_deny_sha256
    ) {
        throw "$ExpectedPlatform tooling receipt differs from validation evidence."
    }
    foreach ($field in @('cargo_audit_sha256', 'cargo_deny_sha256')) {
        if (-not (Test-LowerSha256 -Value ([string]$receipt.$field))) {
            throw "$ExpectedPlatform tooling receipt field '$field' is not a lowercase SHA-256."
        }
    }
    Assert-CanonicalUtc -Value ([string]$receipt.prepared_at) -Label "$ExpectedPlatform tooling receipt prepared_at"

    $receiptSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($receiptSha256 -cne $Evidence.tooling_receipt_sha256) {
        throw "$ExpectedPlatform tooling receipt SHA-256 does not match validation evidence."
    }
}

function Read-Evidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedPlatform,
        [Parameter(Mandatory = $true)][string]$ExpectedHead
    )

    $evidence = Read-StrictJsonRecord -Path $Path -Label "$ExpectedPlatform validation evidence"
    Assert-ExactFields -Value $evidence -Expected $expectedEvidenceFields -Label "$ExpectedPlatform validation evidence"

    if (
        $evidence.schema_version -ne 2 -or
        $evidence.milestone -cne 'NXB-153' -or
        $evidence.gate -cne 'guided_target_authorization_setup' -or
        $evidence.platform -cne $ExpectedPlatform -or
        $evidence.head_sha -cne $ExpectedHead -or
        $evidence.test_threads -ne 1
    ) {
        throw "$ExpectedPlatform evidence identity does not match NXB-153 closure."
    }
    if (
        $evidence.rustc -notmatch '^rustc 1\.97\.1\s' -or
        $evidence.cargo -notmatch '^cargo\s' -or
        $evidence.cargo_audit -notmatch ('(^|\s)' + [regex]::Escape($expectedAuditVersion) + '($|\s)') -or
        $evidence.cargo_deny -notmatch ('(^|\s)' + [regex]::Escape($expectedDenyVersion) + '($|\s)')
    ) {
        throw "$ExpectedPlatform evidence reports an unsupported toolchain."
    }
    foreach ($field in @(
        'cargo_audit_sha256', 'cargo_deny_sha256', 'tooling_receipt_sha256',
        'cargo_lock_sha256', 'cargo_lock_expected_sha256'
    )) {
        if (-not (Test-LowerSha256 -Value ([string]$evidence.$field))) {
            throw "$ExpectedPlatform evidence field '$field' is not a lowercase SHA-256."
        }
    }
    if (
        $evidence.cargo_lock_sha256 -cne $expectedLockSha256 -or
        $evidence.cargo_lock_expected_sha256 -cne $expectedLockSha256 -or
        $evidence.tooling_receipt_verified -ne $true -or
        $evidence.lockfile_pinned_and_unchanged -ne $true -or
        $evidence.validation_environment_policy -cne $expectedEnvironmentPolicy -or
        $evidence.validation_environment_authority -cne 'passed' -or
        $evidence.python_isolated_helper_authority -cne 'passed' -or
        $evidence.workspace_namespace_authority -cne 'passed' -or
        $evidence.workspace_git_object_authority -cne 'passed' -or
        $evidence.dependency_source_authority -cne 'passed' -or
        $evidence.security_tool_object_authority -cne 'passed' -or
        $evidence.host_rust_toolchain_identity -cne $expectedHostRustIdentity -or
        $evidence.fmt -cne 'passed' -or
        $evidence.nxb_policy_check_clippy_tests -cne 'passed' -or
        $evidence.nxb_core_check_clippy_unit_tests -cne 'passed' -or
        $evidence.focused_target_tests -cne 'passed' -or
        $evidence.workspace_check_clippy_tests_all_features -cne 'passed' -or
        $evidence.rustsec -cne 'passed' -or
        $evidence.cargo_deny_checks -cne 'passed' -or
        $evidence.network_activity -cne 'cargo_dependency_and_advisory_sources_only'
    ) {
        throw "$ExpectedPlatform evidence contains a failed or unsupported gate value."
    }

    Assert-CanonicalUtc -Value ([string]$evidence.validated_at) -Label "$ExpectedPlatform validated_at"
    $expectedReceiptRelative = "target/nxb-validation/nxb-153-tooling-$ExpectedPlatform-$ExpectedHead.json"
    if ($evidence.tooling_receipt -cne $expectedReceiptRelative) {
        throw "$ExpectedPlatform evidence tooling receipt path is not canonical."
    }
    $receiptPath = Join-Path $EvidenceDirectory "nxb-153-tooling-$ExpectedPlatform-$ExpectedHead.json"
    Read-ToolingReceipt `
        -Path $receiptPath `
        -ExpectedPlatform $ExpectedPlatform `
        -ExpectedHead $ExpectedHead `
        -Evidence $evidence

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
        tooling_receipt_sha256 = [string]$evidence.tooling_receipt_sha256
        cargo_lock_sha256 = [string]$evidence.cargo_lock_sha256
        validation_environment_policy = [string]$evidence.validation_environment_policy
        validation_environment_authority = [string]$evidence.validation_environment_authority
        python_isolated_helper_authority = [string]$evidence.python_isolated_helper_authority
        workspace_namespace_authority = [string]$evidence.workspace_namespace_authority
        workspace_git_object_authority = [string]$evidence.workspace_git_object_authority
        dependency_source_authority = [string]$evidence.dependency_source_authority
        security_tool_object_authority = [string]$evidence.security_tool_object_authority
        host_rust_toolchain_identity = [string]$evidence.host_rust_toolchain_identity
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

    $windowsPath = Join-Path $EvidenceDirectory "nxb-153-windows-$headSha.json"
    $linuxPath = Join-Path $EvidenceDirectory "nxb-153-linux-$headSha.json"
    $windows = Read-Evidence -Path $windowsPath -ExpectedPlatform 'windows' -ExpectedHead $headSha
    $linux = Read-Evidence -Path $linuxPath -ExpectedPlatform 'linux' -ExpectedHead $headSha

    foreach ($field in @(
        'rustc', 'cargo', 'cargo_audit', 'cargo_deny', 'cargo_lock_sha256',
        'validation_environment_policy', 'host_rust_toolchain_identity'
    )) {
        if ($windows[$field] -cne $linux[$field]) {
            throw "Linux and Windows evidence disagree on '$field'."
        }
    }

    $closure = [ordered]@{
        schema_version = 2
        milestone = 'NXB-153'
        gate = 'dual_platform_evidence_closure'
        status = 'dual_platform_validation_passed'
        admission = 'blocker_review_required'
        head_sha = $headSha
        cargo_lock_sha256 = $lockSha256
        rustc = $windows['rustc']
        cargo = $windows['cargo']
        cargo_audit = $windows['cargo_audit']
        cargo_deny = $windows['cargo_deny']
        validation_environment_policy = $windows['validation_environment_policy']
        host_rust_toolchain_identity = $windows['host_rust_toolchain_identity']
        platforms = @('linux', 'windows')
        evidence = @($linux, $windows)
        requirements = [ordered]@{
            same_exact_head = 'passed'
            canonical_lockfile = 'passed'
            fresh_tool_bootstrap_receipts = 'passed'
            validation_environment_authority = 'passed'
            python_isolated_helper_authority = 'passed'
            workspace_namespace_authority = 'passed'
            workspace_git_object_authority = 'passed'
            dependency_source_authority = 'passed'
            security_tool_object_authority = 'passed'
            package_and_workspace_gates = 'passed'
            focused_nxb153_tests = 'passed'
            rustsec = 'passed'
            cargo_deny = 'passed'
            host_rust_toolchain_identity = 'blocker_pending'
        }
        network_activity = 'none'
    }

    $closurePath = Join-Path $EvidenceDirectory "nxb-153-closure-$headSha.json"
    Assert-NoReparseComponents -Path $closurePath -Label 'closure evidence'
    if (Test-Path -LiteralPath $closurePath) {
        $existing = Read-StrictJsonRecord -Path $closurePath -Label 'existing closure evidence'
        $existingCanonical = $existing | ConvertTo-Json -Depth 24 -Compress
        $expectedCanonical = $closure | ConvertTo-Json -Depth 24 -Compress
        if ($existingCanonical -cne $expectedCanonical) {
            throw 'Existing closure evidence differs from deterministic review result.'
        }
    } else {
        $json = $closure | ConvertTo-Json -Depth 24
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
        if ($bytes.Length -le 0 -or $bytes.Length -gt $maximumEvidenceBytes) {
            throw 'Canonical closure evidence size is invalid.'
        }

        $stream = [IO.File]::Open(
            $closurePath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
            $stream.Position = 0

            $persisted = [byte[]]::new($bytes.Length)
            $offset = 0
            while ($offset -lt $persisted.Length) {
                $read = $stream.Read($persisted, $offset, $persisted.Length - $offset)
                if ($read -le 0) {
                    throw 'Published closure evidence could not be read back completely from its create-new handle.'
                }
                $offset += $read
            }
            if ($stream.ReadByte() -ne -1) {
                throw 'Published closure evidence grew beyond the deterministic canonical bytes.'
            }
            if ([Convert]::ToBase64String($persisted) -cne [Convert]::ToBase64String($bytes)) {
                throw 'Published closure evidence bytes differ from the deterministic canonical review result.'
            }
        }
        finally {
            # Once FileMode.CreateNew succeeds the canonical destination is visible. Never
            # path-delete it after a write/flush/read-back failure; explicit recovery owns
            # any partial state.
            $stream.Dispose()
        }
    }

    Write-Host 'NXB-153 dual-platform evidence closure passed.'
    Write-Host 'Admission remains blocker_review_required.'
    Write-Host "HEAD: $headSha"
    Write-Host "Cargo.lock SHA-256: $lockSha256"
    Write-Host "Closure: $closurePath"
}
finally {
    Pop-Location
}
