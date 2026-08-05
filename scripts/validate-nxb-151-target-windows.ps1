[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$workspace = $null
$outputDirectory = $null

function Invoke-NativeJson {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [string]$Name
    )

    $errorPath = Join-Path $outputDirectory "$Name.err"
    $raw = (& $FilePath @Arguments 2>$errorPath | Out-String)
    $exitCode = $LASTEXITCODE
    [IO.File]::WriteAllText(
        (Join-Path $outputDirectory "$Name.json"),
        $raw,
        [Text.UTF8Encoding]::new($false)
    )
    if ($exitCode -ne 0) {
        $errorText = if (Test-Path -LiteralPath $errorPath) {
            Get-Content -LiteralPath $errorPath -Raw
        } else {
            ""
        }
        throw "Command '$FilePath $($Arguments -join ' ')' returned $exitCode. $errorText"
    }
    return ($raw | ConvertFrom-Json -Depth 32)
}

function Assert-NativeExit {
    param(
        [Parameter(Mandatory)] [int]$Expected,
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [string]$Name
    )

    $stdoutPath = Join-Path $outputDirectory "$Name.out"
    $stderrPath = Join-Path $outputDirectory "$Name.err"
    & $FilePath @Arguments 1>$stdoutPath 2>$stderrPath
    $actual = $LASTEXITCODE
    if ($actual -ne $Expected) {
        $errorText = if (Test-Path -LiteralPath $stderrPath) {
            Get-Content -LiteralPath $stderrPath -Raw
        } else {
            ""
        }
        throw "Command '$Name' returned $actual; expected $Expected. $errorText"
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
        throw "Expected rustc 1.97.1, found '$rustcVersion'."
    }

    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt failed." }
    & cargo check -p nxb-core --all-targets --all-features --locked
    if ($LASTEXITCODE -ne 0) { throw "cargo check failed." }
    & cargo clippy -p nxb-core --all-targets --all-features --locked -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed." }
    & cargo test -p nxb-core --all-features --locked -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw "cargo test failed." }
    & cargo build -p nxb-core --bin nxb --all-features --locked
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed." }

    $nxb = Join-Path $RepoRoot "target\debug\nxb.exe"
    if (-not (Test-Path -LiteralPath $nxb -PathType Leaf)) {
        throw "nxb.exe is missing."
    }

    $nonce = [Guid]::NewGuid().ToString("N")
    $workspace = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-target-$nonce"
    $outputDirectory = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-target-output-$nonce"
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null

    $initialized = Invoke-NativeJson -FilePath $nxb -Name "init" -Arguments @(
        "workspace", "init", "--workspace", $workspace,
        "--name", "Target Windows Acceptance", "--json"
    )
    if ($initialized.status -ne "initialized") { throw "Workspace initialization failed." }

    $created = Invoke-NativeJson -FilePath $nxb -Name "create" -Arguments @(
        "target", "create", "--workspace", $workspace,
        "--id", "example-app", "--name", "Example App",
        "--origin", "https://example.org",
        "--include-path", "/api",
        "--exclude-path", "/api/logout",
        "--json"
    )
    if ($created.status -ne "active" -or $created.origin -ne "https://example.org") {
        throw "Created target output is invalid."
    }
    if (($created.allowed_methods -join ',') -ne "GET,HEAD,OPTIONS") {
        throw "Created target methods exceed or differ from the read-only boundary."
    }

    $listed = Invoke-NativeJson -FilePath $nxb -Name "list" -Arguments @(
        "target", "list", "--workspace", $workspace, "--json"
    )
    if ($listed.count -ne 1 -or $listed.network_activity -ne "none") {
        throw "Target list output is invalid."
    }

    $shown = Invoke-NativeJson -FilePath $nxb -Name "show" -Arguments @(
        "target", "show", "--workspace", $workspace,
        "--id", "example-app", "--json"
    )
    if ($shown.target_id -ne "example-app" -or
        ($shown.include_paths -join ',') -ne "/api" -or
        ($shown.exclude_paths -join ',') -ne "/api/logout") {
        throw "Target show output is invalid."
    }

    $invalidOrigins = @(
        "http://example.org",
        "https://user@example.org",
        "https://127.0.0.1",
        "https://service.internal",
        "https://*.example.org"
    )
    for ($index = 0; $index -lt $invalidOrigins.Count; $index++) {
        Assert-NativeExit -Expected 50 -FilePath $nxb -Name "invalid-origin-$index" -Arguments @(
            "target", "create", "--workspace", $workspace,
            "--id", "invalid-$index", "--name", "Invalid Origin",
            "--origin", $invalidOrigins[$index], "--json"
        )
    }
    Assert-NativeExit -Expected 50 -FilePath $nxb -Name "invalid-path" -Arguments @(
        "target", "create", "--workspace", $workspace,
        "--id", "invalid-path", "--name", "Invalid Path",
        "--origin", "https://example.org",
        "--include-path", "/api%2fadmin", "--json"
    )

    $profile = Join-Path $workspace "targets\example-app.json"
    $profileBackup = Join-Path $outputDirectory "profile.original"
    [IO.File]::WriteAllBytes($profileBackup, [IO.File]::ReadAllBytes($profile))
    $profileValue = Get-Content -LiteralPath $profile -Raw | ConvertFrom-Json -Depth 32
    $profileValue.origin = "https://attacker.invalid"
    [IO.File]::WriteAllText(
        $profile,
        ($profileValue | ConvertTo-Json -Depth 32) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    Assert-NativeExit -Expected 52 -FilePath $nxb -Name "profile-tamper" -Arguments @(
        "target", "show", "--workspace", $workspace,
        "--id", "example-app", "--json"
    )
    [IO.File]::WriteAllBytes($profile, [IO.File]::ReadAllBytes($profileBackup))

    $disabled = Invoke-NativeJson -FilePath $nxb -Name "disable" -Arguments @(
        "target", "disable", "--workspace", $workspace,
        "--id", "example-app", "--reason", "operator-hold", "--json"
    )
    if ($disabled.status -ne "disabled" -or $disabled.disabled_reason -ne "operator_hold") {
        throw "Target disable output is invalid."
    }
    $active = Invoke-NativeJson -FilePath $nxb -Name "active" -Arguments @(
        "target", "list", "--workspace", $workspace, "--json"
    )
    $all = Invoke-NativeJson -FilePath $nxb -Name "all" -Arguments @(
        "target", "list", "--workspace", $workspace,
        "--include-disabled", "--json"
    )
    if ($active.count -ne 0 -or $all.count -ne 1 -or $all.targets[0].status -ne "disabled") {
        throw "Disabled-target list behavior is invalid."
    }

    $receipt = Join-Path $workspace "targets\example-app.disabled.json"
    $receiptBackup = Join-Path $outputDirectory "receipt.original"
    [IO.File]::WriteAllBytes($receiptBackup, [IO.File]::ReadAllBytes($receipt))
    $receiptValue = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json -Depth 32
    $receiptValue.profile_sha256 = "0" * 64
    [IO.File]::WriteAllText(
        $receipt,
        ($receiptValue | ConvertTo-Json -Depth 32) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    Assert-NativeExit -Expected 52 -FilePath $nxb -Name "receipt-tamper" -Arguments @(
        "target", "show", "--workspace", $workspace,
        "--id", "example-app", "--json"
    )
    [IO.File]::WriteAllBytes($receipt, [IO.File]::ReadAllBytes($receiptBackup))

    $systemRoot = [Environment]::GetEnvironmentVariable("SystemRoot")
    if ([string]::IsNullOrWhiteSpace($systemRoot)) { throw "SystemRoot is unavailable." }
    $icacls = Join-Path $systemRoot "System32\icacls.exe"
    if (-not (Test-Path -LiteralPath $icacls -PathType Leaf)) { throw "icacls.exe is missing." }
    & $icacls $profile "/grant" "*S-1-1-0:(R)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not inject broad target-profile ACL." }
    Assert-NativeExit -Expected 52 -FilePath $nxb -Name "profile-acl-tamper" -Arguments @(
        "target", "show", "--workspace", $workspace,
        "--id", "example-app", "--json"
    )
    & $icacls $profile "/remove:g" "*S-1-1-0" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not remove broad target-profile ACL." }

    $migrationActive = Join-Path $workspace "state\migration-active.json"
    [IO.File]::WriteAllText($migrationActive, "{}`n", [Text.UTF8Encoding]::new($false))
    Assert-NativeExit -Expected 51 -FilePath $nxb -Name "pending-migration" -Arguments @(
        "target", "list", "--workspace", $workspace, "--json"
    )
    Remove-Item -LiteralPath $migrationActive -Force
    [void](Invoke-NativeJson -FilePath $nxb -Name "restored" -Arguments @(
        "target", "show", "--workspace", $workspace,
        "--id", "example-app", "--json"
    ))

    $validationDirectory = Join-Path $RepoRoot "target\nxb-validation"
    New-Item -ItemType Directory -Path $validationDirectory -Force | Out-Null
    $evidencePath = Join-Path $validationDirectory "nxb-151-target-windows-$head.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = "NXB-151"
        gate = "target_profiles"
        platform = "windows"
        head_sha = $head
        rustc = $rustcVersion
        binary_sha256 = (Get-FileHash -LiteralPath $nxb -Algorithm SHA256).Hash.ToLowerInvariant()
        checks = [ordered]@{
            create_list_show_disable = "passed"
            origin_and_path_rejection = "passed"
            profile_tamper_rejection = "passed"
            receipt_tamper_rejection = "passed"
            broad_acl_rejection = "passed"
            pending_migration_exit_51 = "passed"
            network_activity = "none"
        }
    }
    [IO.File]::WriteAllText(
        $evidencePath,
        ($evidence | ConvertTo-Json -Depth 8) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host "NXB-151 target Windows validation passed."
    Write-Host "HEAD: $head"
    Write-Host "Evidence: $evidencePath"
}
finally {
    Pop-Location
    foreach ($path in @($workspace, $outputDirectory)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
