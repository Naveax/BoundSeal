[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$results = [System.Collections.Generic.List[object]]::new()
$workspace = $null
$nonEmptyWorkspace = $null
$brokenWorkspace = $null

function Invoke-Gate {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter()] [string[]]$Arguments = @()
    )

    $started = [DateTimeOffset]::UtcNow
    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    $finished = [DateTimeOffset]::UtcNow

    $results.Add([ordered]@{
        name = $Name
        command = (($FilePath, $Arguments) -join " ")
        exit_code = $exitCode
        started_at = $started.ToString("O")
        finished_at = $finished.ToString("O")
        passed = ($exitCode -eq 0)
    })

    if ($exitCode -ne 0) {
        throw "Gate '$Name' failed with exit code $exitCode."
    }
}

function Invoke-ExpectedFailure {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [int]$ExpectedExitCode
    )

    $started = [DateTimeOffset]::UtcNow
    & $FilePath @Arguments 2>$null | Out-Null
    $exitCode = $LASTEXITCODE
    $finished = [DateTimeOffset]::UtcNow

    $results.Add([ordered]@{
        name = $Name
        command = (($FilePath, $Arguments) -join " ")
        exit_code = $exitCode
        expected_exit_code = $ExpectedExitCode
        started_at = $started.ToString("O")
        finished_at = $finished.ToString("O")
        passed = ($exitCode -eq $ExpectedExitCode)
    })

    if ($exitCode -ne $ExpectedExitCode) {
        throw "Gate '$Name' returned $exitCode; expected $ExpectedExitCode."
    }
}

Push-Location $RepoRoot
try {
    $head = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
        throw "Could not resolve an exact Git HEAD."
    }

    $status = git status --porcelain=v1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect repository status."
    }
    if ($status) {
        throw "Working tree must be clean before validation."
    }

    $rustcVersion = (& rustc --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "rustc is unavailable."
    }
    if (-not $rustcVersion.StartsWith("rustc 1.97.1 ")) {
        throw "Expected rustc 1.97.1, found '$rustcVersion'."
    }

    $cargoVersion = (& cargo --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo is unavailable."
    }
    $rustfmtVersion = (& rustfmt --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "rustfmt is unavailable."
    }
    $clippyVersion = (& cargo clippy --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Clippy is unavailable."
    }

    Invoke-Gate -Name "cargo_fmt" -FilePath "cargo" -Arguments @(
        "fmt", "--all", "--", "--check"
    )
    Invoke-Gate -Name "cargo_check" -FilePath "cargo" -Arguments @(
        "check", "-p", "nxb-core", "--all-targets", "--all-features", "--locked"
    )
    Invoke-Gate -Name "cargo_clippy" -FilePath "cargo" -Arguments @(
        "clippy", "-p", "nxb-core", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings"
    )
    Invoke-Gate -Name "cargo_test" -FilePath "cargo" -Arguments @(
        "test", "-p", "nxb-core", "--all-features", "--locked", "--", "--test-threads=1"
    )
    Invoke-Gate -Name "cargo_build_product" -FilePath "cargo" -Arguments @(
        "build", "-p", "nxb-core", "--bin", "nxb-product", "--all-features", "--locked"
    )

    $binary = Join-Path $RepoRoot "target\debug\nxb-product.exe"
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "Product binary was not created at '$binary'."
    }

    $nonce = [Guid]::NewGuid().ToString("N")
    $workspace = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-$nonce"
    $nonEmptyWorkspace = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-nonempty-$nonce"
    $brokenWorkspace = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-broken-$nonce"

    Invoke-Gate -Name "product_init" -FilePath $binary -Arguments @(
        "init", "--workspace", $workspace, "--name", "Windows Acceptance", "--json"
    )
    Invoke-Gate -Name "product_doctor" -FilePath $binary -Arguments @(
        "doctor", "--workspace", $workspace, "--json"
    )
    Invoke-Gate -Name "product_status" -FilePath $binary -Arguments @(
        "status", "--workspace", $workspace, "--json"
    )

    New-Item -ItemType Directory -Path $nonEmptyWorkspace | Out-Null
    Set-Content -LiteralPath (Join-Path $nonEmptyWorkspace "existing.txt") -Value "occupied" -NoNewline
    Invoke-ExpectedFailure -Name "init_rejects_nonempty" -FilePath $binary -Arguments @(
        "init", "--workspace", $nonEmptyWorkspace, "--json"
    ) -ExpectedExitCode 10

    Copy-Item -LiteralPath $workspace -Destination $brokenWorkspace -Recurse
    Remove-Item -LiteralPath (Join-Path $brokenWorkspace "evidence") -Recurse -Force
    Invoke-ExpectedFailure -Name "doctor_detects_missing_directory" -FilePath $binary -Arguments @(
        "doctor", "--workspace", $brokenWorkspace, "--json"
    ) -ExpectedExitCode 20

    $evidenceDirectory = Join-Path $RepoRoot "target\nxb-validation"
    New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
    $evidencePath = Join-Path $evidenceDirectory "nxb-151-windows-$head.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = "NXB-151"
        platform = "windows"
        head_sha = $head
        generated_at = [DateTimeOffset]::UtcNow.ToString("O")
        toolchain = [ordered]@{
            rustc = $rustcVersion
            cargo = $cargoVersion
            rustfmt = $rustfmtVersion
            clippy = $clippyVersion
        }
        product_binary_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        results = $results
    }
    $json = $evidence | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($evidencePath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))

    Write-Host "NXB-151 Windows validation passed."
    Write-Host "HEAD: $head"
    Write-Host "Evidence: $evidencePath"
}
finally {
    Pop-Location
    foreach ($path in @($workspace, $nonEmptyWorkspace, $brokenWorkspace)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
