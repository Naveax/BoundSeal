[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$temporaryRoot = $null
$certificate = $null
$rootStore = $null
$publisherStore = $null

function Get-OpenSslPath {
    $command = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) { return $command.Source }
    $candidates = @(
        (Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'),
        (Join-Path $env:ProgramFiles 'OpenSSL-Win64\bin\openssl.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'OpenSSL-Win32\bin\openssl.exe')
    )
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and
            (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }
    throw 'OpenSSL with Ed25519 support is required for installer validation.'
}

function Convert-BytesToHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

function Convert-HexToBytes {
    param([Parameter(Mandatory = $true)][string]$Hex)
    if ($Hex.Length % 2 -ne 0 -or $Hex -notmatch '^[0-9a-f]+$') {
        throw 'Hexadecimal value is invalid.'
    }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return $bytes
}

function Assert-PowerShellScriptParses {
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$tokens,
        [ref]$errors
    )
    if ($errors.Count -ne 0) {
        $messages = ($errors | ForEach-Object { $_.Message }) -join '; '
        throw "PowerShell parser rejected $Path: $messages"
    }
}

function Invoke-InstallerJson {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][hashtable]$Arguments
    )

    $raw = (& $ScriptPath @Arguments | Out-String)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Installer script returned no JSON: $ScriptPath"
    }
    return $raw | ConvertFrom-Json
}

function Expect-InstallerFailure {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][hashtable]$Arguments
    )

    $failed = $false
    try {
        [void](& $ScriptPath @Arguments | Out-String)
    }
    catch {
        $failed = $true
    }
    if (-not $failed) {
        throw "Expected installer failure was not observed: $ScriptPath"
    }
}

Push-Location $RepoRoot
try {
    $head = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
        throw 'Could not resolve exact Git HEAD.'
    }
    $status = git status --porcelain=v1
    if ($LASTEXITCODE -ne 0 -or $status) {
        throw 'Working tree must be clean before installer validation.'
    }
    $rustcVersion = (& rustc --version).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $rustcVersion.StartsWith('rustc 1.97.1 ')) {
        throw "Expected rustc 1.97.1, found '$rustcVersion'."
    }

    $scripts = @(
        (Join-Path $RepoRoot 'scripts\nxb-installer-common.ps1'),
        (Join-Path $RepoRoot 'scripts\install-nxb-windows.ps1'),
        (Join-Path $RepoRoot 'scripts\rollback-nxb-windows.ps1'),
        (Join-Path $RepoRoot 'scripts\uninstall-nxb-windows.ps1'),
        (Join-Path $RepoRoot 'scripts\validate-nxb-151-installer-windows.ps1')
    )
    foreach ($script in $scripts) {
        Assert-PowerShellScriptParses $script
    }

    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'cargo fmt failed.' }
    & cargo check -p nxb-core --all-targets --all-features --locked
    if ($LASTEXITCODE -ne 0) { throw 'cargo check failed.' }
    & cargo clippy -p nxb-core --all-targets --all-features --locked -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'cargo clippy failed.' }
    & cargo test -p nxb-core --all-features --locked -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'cargo test failed.' }
    & cargo build -p nxb-core --bin nxb --release --all-features --locked
    if ($LASTEXITCODE -ne 0) { throw 'release build failed.' }

    $sourceBinary = Join-Path $RepoRoot 'target\release\nxb.exe'
    if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) {
        throw 'Release nxb.exe is missing.'
    }
    $openssl = Get-OpenSslPath
    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('nxb-installer-validation-' + [Guid]::NewGuid().ToString('N'))
    $packageRoot = Join-Path $temporaryRoot 'package'
    $tamperedPackageRoot = Join-Path $temporaryRoot 'tampered-package'
    $installRoot = Join-Path $temporaryRoot 'install\NXBounty'
    $dataRoot = Join-Path $temporaryRoot 'data\NXBounty'
    New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null

    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=NXBounty Installer Validation' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddDays(2)
    $rootStore = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
    $publisherStore = New-Object Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'CurrentUser')
    $rootStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $publisherStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $rootStore.Add($certificate)
    $publisherStore.Add($certificate)

    $candidateBinary = Join-Path $packageRoot 'nxb.exe'
    Copy-Item -LiteralPath $sourceBinary -Destination $candidateBinary
    $signature = Set-AuthenticodeSignature `
        -LiteralPath $candidateBinary `
        -Certificate $certificate `
        -HashAlgorithm SHA256
    if ($signature.Status.ToString() -ne 'Valid') {
        throw "Could not create a valid Authenticode test signature: $($signature.Status)"
    }

    $sbomPath = Join-Path $packageRoot 'nxb.cdx.json'
    [IO.File]::WriteAllText(
        $sbomPath,
        '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    $checksumsPath = Join-Path $packageRoot 'SHA256SUMS'
    $binarySha = (Get-FileHash -LiteralPath $candidateBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    $sbomSha = (Get-FileHash -LiteralPath $sbomPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        $checksumsPath,
        "$binarySha  nxb.exe`n$sbomSha  nxb.cdx.json`n",
        [Text.UTF8Encoding]::new($false)
    )

    $privateKey = Join-Path $temporaryRoot 'release-private-key.pem'
    $publicDer = Join-Path $temporaryRoot 'release-public-key.der'
    & $openssl genpkey -algorithm ED25519 -out $privateKey
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL Ed25519 private-key generation failed.' }
    & $openssl pkey -in $privateKey -pubout -outform DER -out $publicDer
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL Ed25519 public-key export failed.' }
    $derBytes = [IO.File]::ReadAllBytes($publicDer)
    if ($derBytes.Length -lt 32) { throw 'Ed25519 SPKI output is too short.' }
    $rawPublicKey = New-Object byte[] 32
    [Array]::Copy($derBytes, $derBytes.Length - 32, $rawPublicKey, 0, 32)
    $publicKeyPath = Join-Path $packageRoot 'release-public-key.hex'
    [IO.File]::WriteAllText(
        $publicKeyPath,
        (Convert-BytesToHex $rawPublicKey) + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    $manifestPath = Join-Path $packageRoot 'nxb-release-manifest.json'
    $generatedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    & $candidateBinary release manifest-template `
        --release-id 'v0.1.0-installer-validation' `
        --source-commit $head `
        --platform windows `
        --architecture x86-64 `
        --binary $candidateBinary `
        --sbom $sbomPath `
        --checksums $checksumsPath `
        --generated-at $generatedAt `
        --output $manifestPath `
        --json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Release manifest template generation failed.' }

    $manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    $payloadBytes = Convert-HexToBytes $manifest.signing_payload_hex
    $payloadPath = Join-Path $temporaryRoot 'signing-payload.bin'
    $signaturePath = Join-Path $temporaryRoot 'release-signature.bin'
    [IO.File]::WriteAllBytes($payloadPath, $payloadBytes)
    & $openssl pkeyutl -sign -inkey $privateKey -rawin -in $payloadPath -out $signaturePath
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL Ed25519 signing failed.' }
    $signatureBytes = [IO.File]::ReadAllBytes($signaturePath)
    if ($signatureBytes.Length -ne 64) { throw 'Ed25519 signature length is invalid.' }
    $manifestText = [IO.File]::ReadAllText($manifestPath)
    $manifestText = $manifestText.Replace(
        '"signature_hex": ""',
        ('"signature_hex": "' + (Convert-BytesToHex $signatureBytes) + '"')
    )
    [IO.File]::WriteAllText(
        $manifestPath,
        $manifestText,
        [Text.UTF8Encoding]::new($false)
    )

    & $candidateBinary release verify-manifest `
        --document $manifestPath `
        --public-key $publicKeyPath `
        --binary $candidateBinary `
        --sbom $sbomPath `
        --checksums $checksumsPath `
        --json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Pre-install signed release verification failed.' }

    $publisherThumbprint = $certificate.Thumbprint.ToLowerInvariant()
    $publicKeySha = (Get-FileHash -LiteralPath $publicKeyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $installScript = Join-Path $RepoRoot 'scripts\install-nxb-windows.ps1'
    $installArguments = @{
        PackageDirectory = $packageRoot
        InstallRoot = $installRoot
        DataRoot = $dataRoot
        ExpectedPublisherThumbprint = $publisherThumbprint
        ExpectedReleasePublicKeySha256 = $publicKeySha
        AddToUserPath = $false
        CreateStartMenuShortcut = $false
    }
    $installed = Invoke-InstallerJson $installScript $installArguments
    if ($installed.status -ne 'installed' -or
        $installed.network_activity -ne 'none' -or
        -not (Test-Path -LiteralPath (Join-Path $installRoot 'nxb.exe') -PathType Leaf)) {
        throw 'Clean installation result is invalid.'
    }

    $idempotent = Invoke-InstallerJson $installScript $installArguments
    if ($idempotent.status -ne 'already_installed') {
        throw 'Idempotent install did not return already_installed.'
    }

    New-Item -ItemType Directory -Path $tamperedPackageRoot | Out-Null
    foreach ($name in @('nxb.exe', 'nxb.cdx.json', 'SHA256SUMS', 'nxb-release-manifest.json', 'release-public-key.hex')) {
        Copy-Item -LiteralPath (Join-Path $packageRoot $name) -Destination (Join-Path $tamperedPackageRoot $name)
    }
    $tamperedBinary = Join-Path $tamperedPackageRoot 'nxb.exe'
    $tamperedBytes = [IO.File]::ReadAllBytes($tamperedBinary)
    $tamperedBytes[$tamperedBytes.Length - 1] = $tamperedBytes[$tamperedBytes.Length - 1] -bxor 1
    [IO.File]::WriteAllBytes($tamperedBinary, $tamperedBytes)
    $tamperedArguments = $installArguments.Clone()
    $tamperedArguments.PackageDirectory = $tamperedPackageRoot
    Expect-InstallerFailure $installScript $tamperedArguments

    $sentinel = Join-Path $dataRoot 'workspace-data-sentinel.txt'
    [IO.File]::WriteAllText($sentinel, 'preserve-me', [Text.UTF8Encoding]::new($false))
    $uninstallScript = Join-Path $dataRoot 'installer\uninstall-nxb-windows.ps1'
    $uninstalled = Invoke-InstallerJson $uninstallScript @{
        InstallRoot = $installRoot
        DataRoot = $dataRoot
        ExpectedPublisherThumbprint = $publisherThumbprint
        ExpectedReleasePublicKeySha256 = $publicKeySha
    }
    if ($uninstalled.status -ne 'uninstalled' -or
        $uninstalled.data_preserved -ne $true -or
        (Test-Path -LiteralPath $installRoot) -or
        -not (Test-Path -LiteralPath $sentinel -PathType Leaf)) {
        throw 'Data-preserving uninstall result is invalid.'
    }

    $validationDirectory = Join-Path $RepoRoot 'target\nxb-validation'
    New-Item -ItemType Directory -Path $validationDirectory -Force | Out-Null
    $evidencePath = Join-Path $validationDirectory "nxb-151-installer-windows-$head.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = 'NXB-151'
        gate = 'windows_installer_lifecycle'
        platform = 'windows'
        head_sha = $head
        rustc = $rustcVersion
        release_binary_sha256 = $binarySha
        publisher_thumbprint = $publisherThumbprint
        release_public_key_sha256 = $publicKeySha
        checks = [ordered]@{
            powershell_parser = 'passed'
            authenticode_bootstrap = 'passed'
            ed25519_manifest_verification = 'passed'
            clean_install = 'passed'
            idempotent_install = 'passed'
            tampered_binary_rejection = 'passed'
            data_preserving_uninstall = 'passed'
            upgrade_transaction_source = 'present'
            rollback_transaction_source = 'present'
            version_pair_upgrade_and_rollback = 'pending_distinct_signed_versions'
            network_activity = 'none'
        }
    }
    [IO.File]::WriteAllText(
        $evidencePath,
        ($evidence | ConvertTo-Json -Depth 8) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host 'NXB-151 Windows installer validation passed for clean install and uninstall.'
    Write-Host "HEAD: $head"
    Write-Host "Evidence: $evidencePath"
}
finally {
    Pop-Location
    if ($null -ne $publisherStore) {
        if ($null -ne $certificate) { $publisherStore.Remove($certificate) }
        $publisherStore.Close()
    }
    if ($null -ne $rootStore) {
        if ($null -ne $certificate) { $rootStore.Remove($certificate) }
        $rootStore.Close()
    }
    if ($null -ne $certificate) {
        Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $certificate.Thumbprint) -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
