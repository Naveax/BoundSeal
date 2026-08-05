[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$legacy = $null
$orphan = $null

function Invoke-NativeGate {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter()] [string[]]$Arguments = @()
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Gate '$Name' failed with exit code $LASTEXITCODE."
    }
}

Push-Location $RepoRoot
try {
    $head = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
        throw "Could not resolve an exact Git HEAD."
    }
    $status = git status --porcelain=v1
    if ($LASTEXITCODE -ne 0 -or $status) {
        throw "Working tree must be clean before validation."
    }
    $rustcVersion = (& rustc --version).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $rustcVersion.StartsWith("rustc 1.97.1 ")) {
        throw "Rust 1.97.1 is required."
    }

    Invoke-NativeGate cargo_fmt cargo @("fmt", "--all", "--", "--check")
    Invoke-NativeGate cargo_check cargo @("check", "-p", "nxb-core", "--bin", "nxb-workspace-migrate", "--all-features", "--locked")
    Invoke-NativeGate cargo_clippy cargo @("clippy", "-p", "nxb-core", "--bin", "nxb-workspace-migrate", "--all-features", "--locked", "--", "-D", "warnings")
    Invoke-NativeGate cargo_test cargo @("test", "-p", "nxb-core", "--bin", "nxb-workspace-migrate", "--all-features", "--locked", "--", "--test-threads=1")
    Invoke-NativeGate cargo_build cargo @("build", "-p", "nxb-core", "--bin", "nxb-product", "--bin", "nxb-workspace-migrate", "--all-features", "--locked")

    $product = Join-Path $RepoRoot "target\debug\nxb-product.exe"
    $migrate = Join-Path $RepoRoot "target\debug\nxb-workspace-migrate.exe"
    $fixture = Join-Path $RepoRoot "fixtures\nxb-151\workspace-v0.json"
    foreach ($path in @($product, $migrate, $fixture)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required migration acceptance input is missing: $path"
        }
    }

    $nonce = [Guid]::NewGuid().ToString("N")
    $legacy = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-migrate-$nonce"
    $orphan = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-orphan-$nonce"
    $fixtureBytes = [IO.File]::ReadAllBytes($fixture)

    Invoke-NativeGate product_init $product @("init", "--workspace", $legacy, "--name", "Legacy Migration Acceptance", "--json")
    [IO.File]::WriteAllBytes((Join-Path $legacy "workspace.json"), $fixtureBytes)
    Invoke-NativeGate migration_status_before $migrate @("status", "--workspace", $legacy, "--json")
    Invoke-NativeGate migration_apply $migrate @("apply", "--workspace", $legacy, "--json")
    Invoke-NativeGate migration_status_after $migrate @("status", "--workspace", $legacy, "--json")

    $manifest = Get-Content -LiteralPath (Join-Path $legacy "workspace.json") -Raw | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or $manifest.secret_storage -ne "external_provider_only") {
        throw "Schema-0 workspace did not migrate to the canonical schema-1 manifest."
    }
    $receipts = @(Get-ChildItem -LiteralPath (Join-Path $legacy "state\migrations") -File -Filter "nxb-migration-*.json")
    if ($receipts.Count -ne 1) {
        throw "Expected exactly one immutable migration receipt."
    }
    foreach ($name in @("migration-active.json", "migration-source.json", "migration-applied.json")) {
        if (Test-Path -LiteralPath (Join-Path $legacy "state\$name")) {
            throw "Transient migration file remained after commit: $name"
        }
    }

    Invoke-NativeGate product_init_orphan $product @("init", "--workspace", $orphan, "--name", "Orphan Recovery Acceptance", "--json")
    [IO.File]::WriteAllBytes((Join-Path $orphan "workspace.json"), $fixtureBytes)
    [IO.File]::WriteAllBytes((Join-Path $orphan "state\migration-source.json"), $fixtureBytes)
    Invoke-NativeGate migration_recover_orphan $migrate @("recover", "--workspace", $orphan, "--json")
    Invoke-NativeGate migration_status_orphan $migrate @("status", "--workspace", $orphan, "--json")

    $orphanManifest = Get-Content -LiteralPath (Join-Path $orphan "workspace.json") -Raw | ConvertFrom-Json
    if ($orphanManifest.schema_version -ne 1) {
        throw "Orphan backup recovery did not publish schema 1."
    }

    $outputDirectory = Join-Path $RepoRoot "target\nxb-validation"
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    $output = Join-Path $outputDirectory "nxb-151-migration-windows-$head.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = "NXB-151-migration"
        platform = "windows"
        head_sha = $head
        rustc = $rustcVersion
        product_binary_sha256 = (Get-FileHash -LiteralPath $product -Algorithm SHA256).Hash.ToLowerInvariant()
        migration_binary_sha256 = (Get-FileHash -LiteralPath $migrate -Algorithm SHA256).Hash.ToLowerInvariant()
        gates = @("fmt", "check", "clippy", "tests", "schema_0_to_1", "orphan_backup_recovery", "receipt_cleanup")
    }
    [IO.File]::WriteAllText(
        $output,
        ($evidence | ConvertTo-Json -Depth 6) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host "NXB-151 migration Windows validation passed."
    Write-Host "HEAD: $head"
    Write-Host "Evidence: $output"
}
finally {
    Pop-Location
    foreach ($path in @($legacy, $orphan)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
