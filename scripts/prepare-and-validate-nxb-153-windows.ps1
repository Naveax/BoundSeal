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
$toolsRoot = Join-Path $RepoRoot 'target\nxb-tools'
$toolsBin = Join-Path $toolsRoot 'bin'

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

if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'git is unavailable.'
}
if ($null -eq (Get-Command rustup -ErrorAction SilentlyContinue)) {
    throw 'rustup is unavailable. Install rustup from the official Rust distribution before running this script.'
}

Push-Location $RepoRoot
try {
    $headSha = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $headSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Exact Git HEAD could not be resolved.'
    }
    $status = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $status) {
        throw 'Working tree must be clean before tool preparation.'
    }

    Invoke-NativeChecked -FilePath 'rustup' -Label 'Rust 1.97.1 toolchain installation' -Arguments @(
        'toolchain', 'install', $rustToolchain,
        '--profile', 'minimal',
        '--component', 'rustfmt',
        '--component', 'clippy'
    )

    New-Item -ItemType Directory -Path $toolsRoot -Force | Out-Null
    $auditPath = Join-Path $toolsBin 'cargo-audit.exe'
    $denyPath = Join-Path $toolsBin 'cargo-deny.exe'

    $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) (
        'nxb-153-tool-bootstrap-' + [Guid]::NewGuid().ToString('N')
    )
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    try {
        Push-Location $temporaryDirectory
        try {
            if ($null -eq (Get-ToolVersion -Path $auditPath -ExpectedVersion $cargoAuditVersion)) {
                Invoke-NativeChecked -FilePath 'rustup' -Label 'cargo-audit installation' -Arguments @(
                    'run', $rustToolchain, 'cargo', 'install',
                    '--locked', '--force', '--version', $cargoAuditVersion,
                    '--root', $toolsRoot, 'cargo-audit'
                )
            }
            if ($null -eq (Get-ToolVersion -Path $denyPath -ExpectedVersion $cargoDenyVersion)) {
                Invoke-NativeChecked -FilePath 'rustup' -Label 'cargo-deny installation' -Arguments @(
                    'run', $rustToolchain, 'cargo', 'install',
                    '--locked', '--force', '--version', $cargoDenyVersion,
                    '--root', $toolsRoot, 'cargo-deny'
                )
            }
        }
        finally {
            Pop-Location
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }

    $auditVersion = Get-ToolVersion -Path $auditPath -ExpectedVersion $cargoAuditVersion
    $denyVersion = Get-ToolVersion -Path $denyPath -ExpectedVersion $cargoDenyVersion
    if ($null -eq $auditVersion -or $null -eq $denyVersion) {
        throw 'Pinned validation tools were not installed correctly.'
    }

    $finalHead = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $finalHead -ne $headSha) {
        throw 'Git HEAD changed during tool preparation.'
    }
    $finalStatus = git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $finalStatus) {
        throw 'Working tree changed during tool preparation.'
    }

    $receiptDirectory = Join-Path $RepoRoot 'target\nxb-validation'
    New-Item -ItemType Directory -Path $receiptDirectory -Force | Out-Null
    $receiptPath = Join-Path $receiptDirectory "nxb-153-tooling-windows-$headSha.json"
    $receipt = [ordered]@{
        schema_version = 1
        milestone = 'NXB-153'
        gate = 'validation_tool_bootstrap'
        platform = 'windows'
        head_sha = $headSha
        rust_toolchain = (& rustup run $rustToolchain rustc --version | Out-String).Trim()
        cargo_audit = $auditVersion
        cargo_audit_sha256 = (Get-FileHash -LiteralPath $auditPath -Algorithm SHA256).Hash.ToLowerInvariant()
        cargo_deny = $denyVersion
        cargo_deny_sha256 = (Get-FileHash -LiteralPath $denyPath -Algorithm SHA256).Hash.ToLowerInvariant()
        tools_root = 'target/nxb-tools'
        network_activity = 'rustup_and_crates_io_tool_installation_only'
        prepared_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    [IO.File]::WriteAllText(
        $receiptPath,
        (($receipt | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host 'NXB-153 pinned Windows validation tools are ready.'
    Write-Host "HEAD: $headSha"
    Write-Host "Tooling receipt: $receiptPath"

    if (-not $PrepareOnly) {
        & (Join-Path $PSScriptRoot 'validate-nxb-153-windows.ps1') -RepoRoot $RepoRoot
        if ($LASTEXITCODE -ne 0) {
            throw "NXB-153 Windows validation failed with exit code $LASTEXITCODE."
        }
    }
}
finally {
    Pop-Location
}
