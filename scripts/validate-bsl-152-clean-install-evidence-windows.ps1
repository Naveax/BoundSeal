[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$expectedParent = '92915afbb7a92ff4c591028017686d9b7e6fdb89'
$expectedLockSha256 = 'f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff'
$branch = 'bsl-152-windows-credential-helper'
$helperFileName = 'bsl-windows-credential-evidence-key-helper.exe'
$storeId = 'bsl152-d3-validation'
$keyId = 'temporary-key'
$credentialTarget = "Naveax_BoundSeal_EvidenceKey::${storeId}::${keyId}"

$temporaryRoot = $null
$certificate = $null
$rootStore = $null
$publisherStore = $null
$cleanupHelper = $null
$credentialMayExist = $false

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
    throw 'OpenSSL with Ed25519 support is required.'
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

function Get-TextSha256 {
    param([Parameter(Mandatory = $true)][string]$Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return Convert-BytesToHex $hash
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
        throw "PowerShell parser rejected ${Path}: $messages"
    }
}

function Invoke-NativeCaptured {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$WorkingDirectory = ''
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $startInfo.WorkingDirectory = $WorkingDirectory
    }
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Could not start process: $FilePath"
    }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    $process.Dispose()

    return [pscustomobject]@{
        ExitCode = $exitCode
        Stdout = $stdout
        Stderr = $stderr
    }
}

function Invoke-Cargo {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$TargetDirectory,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $previousTarget = $env:CARGO_TARGET_DIR
    try {
        $env:CARGO_TARGET_DIR = $TargetDirectory
        Push-Location $WorkingDirectory
        try {
            & rustup run 1.97.1 cargo @Arguments
            if ($LASTEXITCODE -ne 0) {
                throw "$Label failed with exit code $LASTEXITCODE."
            }
        }
        finally {
            Pop-Location
        }
    }
    finally {
        $env:CARGO_TARGET_DIR = $previousTarget
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

function Invoke-Lifecycle {
    param(
        [Parameter(Mandatory = $true)][string]$HelperPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$ExpectedOperation
    )

    $result = Invoke-NativeCaptured $HelperPath $Arguments
    if ($result.ExitCode -ne 0) {
        throw "Lifecycle $ExpectedOperation failed. stderr=$($result.Stderr.Trim())"
    }
    if (-not [string]::IsNullOrWhiteSpace($result.Stderr)) {
        throw "Lifecycle $ExpectedOperation emitted unexpected stderr."
    }
    $value = $result.Stdout.Trim() | ConvertFrom-Json
    $allowed = @('key_bytes', 'operation', 'persistence', 'present', 'target', 'version_id') | Sort-Object
    $actual = @($value.PSObject.Properties.Name) | Sort-Object
    if (@(Compare-Object $allowed $actual).Count -ne 0) {
        throw "Lifecycle $ExpectedOperation emitted unexpected metadata fields."
    }
    if ($value.operation -ne $ExpectedOperation -or $value.target -ne $credentialTarget) {
        throw "Lifecycle $ExpectedOperation metadata binding is invalid."
    }
    return $value
}

function New-SignedPackage {
    param(
        [Parameter(Mandatory = $true)][string]$SourceBinary,
        [Parameter(Mandatory = $true)][string]$SourceHelper,
        [Parameter(Mandatory = $true)][string]$SourceCommit,
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$OpenSsl,
        [Parameter(Mandatory = $true)][string]$PrivateKey,
        [Parameter(Mandatory = $true)][string]$RawPublicKeyHex
    )

    New-Item -ItemType Directory -Path $PackageRoot | Out-Null
    $binary = Join-Path $PackageRoot 'bsl.exe'
    $helper = Join-Path $PackageRoot $helperFileName
    Copy-Item -LiteralPath $SourceBinary -Destination $binary
    Copy-Item -LiteralPath $SourceHelper -Destination $helper

    foreach ($path in @($binary, $helper)) {
        $signature = Set-AuthenticodeSignature -LiteralPath $path -Certificate $Certificate -HashAlgorithm SHA256
        if ($signature.Status.ToString() -ne 'Valid') {
            throw "Could not create a valid Authenticode signature for $path"
        }
    }

    $sbomPath = Join-Path $PackageRoot 'bsl.cdx.json'
    $sbom = [ordered]@{
        bomFormat = 'CycloneDX'
        specVersion = '1.6'
        components = @()
        metadata = [ordered]@{
            component = [ordered]@{
                type = 'application'
                name = 'BoundSeal'
                version = '0.1.0'
                properties = @(
                    [ordered]@{ name = 'bsl:source_commit'; value = $SourceCommit },
                    [ordered]@{ name = 'bsl:release_sequence'; value = '3' },
                    [ordered]@{ name = 'bsl:bundled_windows_credential_helper'; value = 'true' }
                )
            }
        }
    }
    [IO.File]::WriteAllText(
        $sbomPath,
        ($sbom | ConvertTo-Json -Depth 12 -Compress) + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    $binarySha = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    $helperSha = (Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToLowerInvariant()
    $sbomSha = (Get-FileHash -LiteralPath $sbomPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksumsPath = Join-Path $PackageRoot 'SHA256SUMS'
    [IO.File]::WriteAllText(
        $checksumsPath,
        "$binarySha  bsl.exe`n$sbomSha  bsl.cdx.json`n$helperSha  $helperFileName`n",
        [Text.UTF8Encoding]::new($false)
    )

    $publicKeyPath = Join-Path $PackageRoot 'release-public-key.hex'
    [IO.File]::WriteAllText(
        $publicKeyPath,
        $RawPublicKeyHex + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    $manifestPath = Join-Path $PackageRoot 'bsl-release-manifest.json'
    $generatedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    & $binary release manifest-template `
        --release-id 'v0.1.0-r3-bsl152-d3' `
        --release-sequence 3 `
        --source-commit $SourceCommit `
        --platform windows `
        --architecture x86-64 `
        --binary $binary `
        --sbom $sbomPath `
        --checksums $checksumsPath `
        --generated-at $generatedAt `
        --output $manifestPath `
        --json | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Release manifest template generation failed.'
    }

    $manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    $payloadPath = Join-Path $PackageRoot 'signing-payload.bin'
    $signaturePath = Join-Path $PackageRoot 'release-signature.bin'
    [IO.File]::WriteAllBytes($payloadPath, (Convert-HexToBytes $manifest.signing_payload_hex))
    & $OpenSsl pkeyutl -sign -inkey $PrivateKey -rawin -in $payloadPath -out $signaturePath
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL Ed25519 signing failed.' }
    $signatureBytes = [IO.File]::ReadAllBytes($signaturePath)
    if ($signatureBytes.Length -ne 64) { throw 'Ed25519 signature length is invalid.' }
    $manifestText = [IO.File]::ReadAllText($manifestPath).Replace(
        '"signature_hex": ""',
        ('"signature_hex": "' + (Convert-BytesToHex $signatureBytes) + '"')
    )
    [IO.File]::WriteAllText($manifestPath, $manifestText, [Text.UTF8Encoding]::new($false))
    Remove-Item -LiteralPath $payloadPath, $signaturePath -Force

    $verifiedRaw = (& $binary release verify-manifest `
        --document $manifestPath `
        --public-key $publicKeyPath `
        --binary $binary `
        --sbom $sbomPath `
        --checksums $checksumsPath `
        --json | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Pre-install signed release verification failed.' }
    $verified = $verifiedRaw | ConvertFrom-Json
    if ($verified.status -ne 'valid' -or $verified.source_commit -ne $SourceCommit) {
        throw 'Signed package source binding is invalid.'
    }

    return [pscustomobject]@{
        Root = $PackageRoot
        BinarySha256 = $binarySha
        HelperSha256 = $helperSha
        PublicKey = $publicKeyPath
        ManifestSha256 = $verified.manifest_sha256
    }
}

function New-D3Harness {
    param([Parameter(Mandatory = $true)][string]$HarnessRoot)

    $src = Join-Path $HarnessRoot 'src'
    New-Item -ItemType Directory -Path $src -Force | Out-Null
    $repo = $RepoRoot.Replace('\', '/')
    $manifest = @"
[package]
name = "bsl152-d3-harness"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
bsl-evidence-key-provider = { path = "$repo/crates/bsl-evidence-key-provider" }
bsl-evidence-key-provider-process = { path = "$repo/crates/bsl-evidence-key-provider-process" }
bsl-evidence-sealer = { path = "$repo/crates/bsl-evidence-sealer" }
bsl-knowledge-reporting = { path = "$repo/crates/bsl-knowledge-reporting" }
ring = "0.17"
serde_json = "1.0"
sha2 = "0.10"
"@
    [IO.File]::WriteAllText(
        (Join-Path $HarnessRoot 'Cargo.toml'),
        $manifest,
        [Text.UTF8Encoding]::new($false)
    )

    $source = @'
use std::{collections::BTreeMap, env, path::PathBuf, process, time::{Duration, SystemTime, UNIX_EPOCH}};

use bsl_evidence_key_provider::{
    acquire_evidence_sealer, EvidenceKeyActivation, EvidenceKeyPlan, EvidenceKeyPlanInput,
    EvidenceKeyProviderError,
};
use bsl_evidence_key_provider_process::{
    bundled_windows_credential_config, ProcessEvidenceKeyProvider,
};
use bsl_evidence_sealer::{EncryptedEvidenceStore, ProductionEvidenceSealer};
use bsl_knowledge_reporting::{EvidenceClass, EvidenceInput, EvidenceStore};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use sha2::{Digest, Sha256};

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn now_epoch_seconds() -> Result<i64, String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system_time_before_epoch".to_string())?
        .as_secs();
    i64::try_from(seconds).map_err(|_| "system_time_overflow".to_string())
}

fn acquire(
    install_root: &PathBuf,
    helper_sha256: &str,
    store_id: &str,
    key_id: &str,
    version_id: &str,
) -> Result<(ProductionEvidenceSealer, String), EvidenceKeyProviderError> {
    let now = now_epoch_seconds().map_err(|_| EvidenceKeyProviderError::InvalidPlan)?;
    let required_version_sha256 = lower_hex(&Sha256::digest(version_id.as_bytes()));
    let config = bundled_windows_credential_config(
        install_root,
        helper_sha256,
        store_id,
        key_id,
        Some(required_version_sha256),
        now + 300,
        Duration::from_secs(5),
    )
    .map_err(|_| EvidenceKeyProviderError::InvalidPlan)?;
    let identity = config
        .evidence_identity()
        .map_err(|_| EvidenceKeyProviderError::InvalidPlan)?;
    let mut provider = ProcessEvidenceKeyProvider::new(config)
        .map_err(|_| EvidenceKeyProviderError::InvalidPlan)?;

    let random = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random)
        .map_err(|_| EvidenceKeyProviderError::InvalidActivation)?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| EvidenceKeyProviderError::InvalidActivation)?;
    let policy = "b".repeat(64);
    let plan = EvidenceKeyPlan::create(EvidenceKeyPlanInput {
        provider_identity: identity,
        key_id: key_id.to_owned(),
        store_id: store_id.to_owned(),
        policy_snapshot_sha256: policy,
        activation_public_key_hex: lower_hex(pair.public_key().as_ref()),
        issued_at_epoch_seconds: now - 1,
        expires_at_epoch_seconds: now + 120,
    })?;
    let message = EvidenceKeyActivation::signing_message(&plan.plan_sha256)?;
    let activation = EvidenceKeyActivation::from_signature(
        plan.plan_sha256.clone(),
        pair.sign(&message).as_ref(),
    )?;
    let (sealer, receipt) = acquire_evidence_sealer(plan, activation, &mut provider, now)?;
    if receipt.key_version_id != version_id {
        return Err(EvidenceKeyProviderError::InvalidKeyMaterial);
    }
    Ok((sealer, receipt.key_version_id))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 10 {
        return Err("invalid_argument_count".into());
    }
    let mode = args[1].as_str();
    let install_root = PathBuf::from(&args[2]);
    let helper_sha256 = &args[3];
    let store_id = &args[4];
    let key_id = &args[5];
    let version_id = &args[6];
    let store_directory = PathBuf::from(&args[7]);
    let evidence_id = &args[8];
    let expected_content_sha256 = &args[9];

    if mode == "expect-stale" {
        match acquire(&install_root, helper_sha256, store_id, key_id, version_id) {
            Err(EvidenceKeyProviderError::ProviderFetchFailure(code))
                if code == "windows_credential_version_mismatch" =>
            {
                println!("{}", serde_json::json!({
                    "status": "stale_version_rejected",
                    "failure_code": code,
                }));
                return Ok(());
            }
            Err(error) => return Err(format!("unexpected_stale_result:{error}")),
            Ok(_) => return Err("stale_version_was_accepted".into()),
        }
    }

    let (sealer, acquired_version) = acquire(
        &install_root,
        helper_sha256,
        store_id,
        key_id,
        version_id,
    )
    .map_err(|error| error.to_string())?;
    let policy = "b".repeat(64);

    match mode {
        "seal" => {
            let mut logical = EvidenceStore::new(policy.clone(), "a".repeat(64))
                .map_err(|error| error.to_string())?;
            let record = logical
                .insert(EvidenceInput {
                    class: EvidenceClass::Observation,
                    subject_id: "bsl152-d3-subject".into(),
                    summary: "BSL-152 D3 clean-install evidence round trip".into(),
                    metadata: BTreeMap::from([("gate".into(), "pass-d3".into())]),
                    provenance_sha256: "c".repeat(64),
                    policy_snapshot_sha256: policy.clone(),
                    redaction_count: 0,
                    redaction_verified: true,
                })
                .map_err(|error| error.to_string())?
                .clone();
            let encrypted = EncryptedEvidenceStore::initialize(
                store_directory,
                policy,
                16 * 1024 * 1024,
                sealer,
            )
            .map_err(|error| error.to_string())?;
            let receipt = encrypted.seal(&record).map_err(|error| error.to_string())?;
            println!("{}", serde_json::json!({
                "status": "sealed",
                "key_version_id": acquired_version,
                "evidence_id": record.evidence_id,
                "content_sha256": record.content_sha256,
                "envelope_sha256": receipt.envelope_sha256,
            }));
        }
        "recover" => {
            if !evidence_id.starts_with("evidence-") || expected_content_sha256.len() != 64 {
                return Err("invalid_recovery_binding".into());
            }
            let encrypted = EncryptedEvidenceStore::open_existing(
                store_directory,
                policy,
                16 * 1024 * 1024,
                sealer,
            )
            .map_err(|error| error.to_string())?;
            let recovered = encrypted.open(evidence_id).map_err(|error| error.to_string())?;
            if recovered.content_sha256 != *expected_content_sha256
                || recovered.summary != "BSL-152 D3 clean-install evidence round trip"
            {
                return Err("recovered_evidence_binding_mismatch".into());
            }
            let manifest = encrypted.verify_all().map_err(|error| error.to_string())?;
            if manifest.entries.len() != 1 {
                return Err("unexpected_manifest_entry_count".into());
            }
            println!("{}", serde_json::json!({
                "status": "recovered",
                "key_version_id": acquired_version,
                "evidence_id": recovered.evidence_id,
                "content_sha256": recovered.content_sha256,
                "manifest_sha256": manifest.manifest_sha256,
            }));
        }
        _ => return Err("invalid_mode".into()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("D3_HARNESS_ERROR={error}");
        process::exit(1);
    }
}
'@
    [IO.File]::WriteAllText(
        (Join-Path $src 'main.rs'),
        $source,
        [Text.UTF8Encoding]::new($false)
    )

    Push-Location $HarnessRoot
    try {
        & rustup run 1.97.1 cargo generate-lockfile --offline
        if ($LASTEXITCODE -ne 0) { throw 'D3 harness offline lock generation failed.' }
    }
    finally {
        Pop-Location
    }
}

function Invoke-D3Harness {
    param(
        [Parameter(Mandatory = $true)][string]$HarnessRoot,
        [Parameter(Mandatory = $true)][string]$HarnessTarget,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$HelperSha256,
        [Parameter(Mandatory = $true)][string]$VersionId,
        [Parameter(Mandatory = $true)][string]$StoreDirectory,
        [string]$EvidenceId = '-',
        [string]$ExpectedContentSha256 = '-'
    )

    $previousTarget = $env:CARGO_TARGET_DIR
    try {
        $env:CARGO_TARGET_DIR = $HarnessTarget
        $raw = (& rustup run 1.97.1 cargo run `
            --offline `
            --locked `
            --quiet `
            --manifest-path (Join-Path $HarnessRoot 'Cargo.toml') `
            -- `
            $Mode `
            $InstallRoot `
            $HelperSha256 `
            $storeId `
            $keyId `
            $VersionId `
            $StoreDirectory `
            $EvidenceId `
            $ExpectedContentSha256 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "D3 harness mode '$Mode' failed."
        }
        if ([string]::IsNullOrWhiteSpace($raw)) {
            throw "D3 harness mode '$Mode' returned no JSON."
        }
        return $raw | ConvertFrom-Json
    }
    finally {
        $env:CARGO_TARGET_DIR = $previousTarget
    }
}

Push-Location $RepoRoot
try {
    $head = (git rev-parse HEAD).Trim()
    $parent = (git rev-parse "$head^").Trim()
    $currentBranch = (git branch --show-current).Trim()
    $dirty = @(git status --porcelain=v1 --untracked-files=all)
    if ($currentBranch -ne $branch -or $head -notmatch '^[0-9a-f]{40}$' -or
        $parent -ne $expectedParent -or $dirty.Count -ne 0) {
        throw 'D3 exact-head/branch/clean-tree authority check failed.'
    }

    $lockSha = (Get-FileHash -LiteralPath (Join-Path $RepoRoot 'Cargo.lock') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($lockSha -ne $expectedLockSha256) {
        throw 'D3 root Cargo.lock identity changed.'
    }
    $rustcVersion = (& rustup run 1.97.1 rustc --version).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $rustcVersion.StartsWith('rustc 1.97.1 ')) {
        throw "Expected rustc 1.97.1, found '$rustcVersion'."
    }

    foreach ($script in @(
        (Join-Path $RepoRoot 'scripts\bsl-installer-common.ps1'),
        (Join-Path $RepoRoot 'scripts\install-bsl-windows.ps1'),
        (Join-Path $RepoRoot 'scripts\uninstall-bsl-windows.ps1'),
        (Join-Path $RepoRoot 'scripts\validate-bsl-152-clean-install-evidence-windows.ps1')
    )) {
        Assert-PowerShellScriptParses $script
    }

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('bsl152-d3-' + [Guid]::NewGuid().ToString('N'))
    $buildTarget = Join-Path $temporaryRoot 'build-target'
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

    Invoke-Cargo $RepoRoot $buildTarget @('fmt', '--all', '--', '--check') 'cargo fmt'
    foreach ($package in @('bsl-evidence-sealer', 'bsl-evidence-key-provider', 'bsl-evidence-key-provider-process')) {
        Invoke-Cargo $RepoRoot $buildTarget @('check', '-p', $package, '--all-targets', '--all-features', '--locked') "$package check"
        Invoke-Cargo $RepoRoot $buildTarget @('clippy', '-p', $package, '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings') "$package clippy"
        Invoke-Cargo $RepoRoot $buildTarget @('test', '-p', $package, '--all-features', '--locked', '--', '--test-threads=1') "$package tests"
    }
    Invoke-Cargo $RepoRoot $buildTarget @('build', '-p', 'bsl-core', '--bin', 'bsl', '--release', '--all-features', '--locked') 'bsl release build'
    Invoke-Cargo $RepoRoot $buildTarget @('build', '-p', 'bsl-evidence-key-provider-process', '--bin', 'bsl-windows-credential-evidence-key-helper', '--release', '--locked') 'helper release build'

    $sourceBinary = Join-Path $buildTarget 'release\bsl.exe'
    $sourceHelper = Join-Path $buildTarget "release\$helperFileName"
    if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf) -or
        -not (Test-Path -LiteralPath $sourceHelper -PathType Leaf)) {
        throw 'D3 release build artifacts are missing.'
    }

    $openssl = Get-OpenSslPath
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=BoundSeal D3 Validation' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddDays(2)
    $rootStore = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
    $publisherStore = New-Object Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'CurrentUser')
    $rootStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $publisherStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $rootStore.Add($certificate)
    $publisherStore.Add($certificate)

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
    $rawPublicKeyHex = Convert-BytesToHex $rawPublicKey

    $package = New-SignedPackage `
        $sourceBinary `
        $sourceHelper `
        $head `
        (Join-Path $temporaryRoot 'package') `
        $certificate `
        $openssl `
        $privateKey `
        $rawPublicKeyHex

    $publisherThumbprint = $certificate.Thumbprint.ToLowerInvariant()
    $publicKeySha = (Get-FileHash -LiteralPath $package.PublicKey -Algorithm SHA256).Hash.ToLowerInvariant()
    $installRoot = Join-Path $temporaryRoot 'install\BoundSeal'
    $dataRoot = Join-Path $temporaryRoot 'data\BoundSeal'
    $installScript = Join-Path $RepoRoot 'scripts\install-bsl-windows.ps1'
    $installed = Invoke-InstallerJson $installScript @{
        PackageDirectory = $package.Root
        InstallRoot = $installRoot
        DataRoot = $dataRoot
        ExpectedPublisherThumbprint = $publisherThumbprint
        ExpectedReleasePublicKeySha256 = $publicKeySha
        AddToUserPath = $false
        CreateStartMenuShortcut = $false
    }
    if ($installed.status -ne 'installed' -or [uint32]$installed.schema_version -ne 3 -or
        $installed.helper_sha256 -ne $package.HelperSha256 -or
        (Test-Path -LiteralPath ($installRoot + '.previous'))) {
        throw 'D3 clean bundled installation failed.'
    }

    $installedHelper = Join-Path $installRoot $helperFileName
    $preservedHelperRoot = Join-Path $temporaryRoot 'preserved-helper'
    New-Item -ItemType Directory -Path $preservedHelperRoot | Out-Null
    $preservedHelper = Join-Path $preservedHelperRoot $helperFileName
    Copy-Item -LiteralPath $installedHelper -Destination $preservedHelper
    if ((Get-FileHash -LiteralPath $preservedHelper -Algorithm SHA256).Hash.ToLowerInvariant() -ne $package.HelperSha256) {
        throw 'Preserved helper digest mismatch.'
    }
    $cleanupHelper = $preservedHelper

    $initial = Invoke-Lifecycle $installedHelper @('status', '--store-id', $storeId, '--key-id', $keyId) 'status'
    if ($initial.present) {
        [void](Invoke-Lifecycle $installedHelper @('delete', '--store-id', $storeId, '--key-id', $keyId, '--confirm-target', $credentialTarget) 'delete')
    }
    $create = Invoke-Lifecycle $installedHelper @('create', '--store-id', $storeId, '--key-id', $keyId, '--confirm-target', $credentialTarget) 'create'
    $credentialMayExist = $true
    if (-not $create.present -or [int]$create.key_bytes -ne 32 -or $create.persistence -ne 'local_machine' -or
        [string]$create.version_id -notmatch '^v1-[0-9a-f]{32}$') {
        throw 'D3 credential create metadata is invalid.'
    }
    $version1 = [string]$create.version_id

    $harnessRoot = Join-Path $temporaryRoot 'harness'
    $harnessTarget = Join-Path $temporaryRoot 'harness-target'
    New-D3Harness $harnessRoot
    $storeV1 = Join-Path $temporaryRoot 'sealed-v1'
    $sealedV1 = Invoke-D3Harness $harnessRoot $harnessTarget 'seal' $installRoot $package.HelperSha256 $version1 $storeV1
    if ($sealedV1.status -ne 'sealed' -or $sealedV1.key_version_id -ne $version1) {
        throw 'D3 first sealed-evidence acquisition failed.'
    }
    $recoveredV1 = Invoke-D3Harness `
        $harnessRoot $harnessTarget 'recover' $installRoot $package.HelperSha256 $version1 $storeV1 `
        ([string]$sealedV1.evidence_id) ([string]$sealedV1.content_sha256)
    if ($recoveredV1.status -ne 'recovered' -or $recoveredV1.key_version_id -ne $version1 -or
        $recoveredV1.evidence_id -ne $sealedV1.evidence_id -or
        $recoveredV1.content_sha256 -ne $sealedV1.content_sha256) {
        throw 'D3 later evidence recovery failed.'
    }

    $rotate = Invoke-Lifecycle $installedHelper @('rotate', '--store-id', $storeId, '--key-id', $keyId, '--confirm-target', $credentialTarget) 'rotate'
    if (-not $rotate.present -or [int]$rotate.key_bytes -ne 32 -or $rotate.persistence -ne 'local_machine' -or
        [string]$rotate.version_id -notmatch '^v1-[0-9a-f]{32}$' -or $rotate.version_id -eq $version1) {
        throw 'D3 credential rotation metadata is invalid.'
    }
    $version2 = [string]$rotate.version_id

    $stale = Invoke-D3Harness $harnessRoot $harnessTarget 'expect-stale' $installRoot $package.HelperSha256 $version1 (Join-Path $temporaryRoot 'unused-stale')
    if ($stale.status -ne 'stale_version_rejected' -or $stale.failure_code -ne 'windows_credential_version_mismatch') {
        throw 'D3 stale required-version binding did not fail closed.'
    }

    $statusV2 = Invoke-Lifecycle $installedHelper @('status', '--store-id', $storeId, '--key-id', $keyId) 'status'
    if (-not $statusV2.present -or $statusV2.version_id -ne $version2 -or [int]$statusV2.key_bytes -ne 32) {
        throw 'D3 post-rotation metadata status is invalid.'
    }

    $storeV2 = Join-Path $temporaryRoot 'sealed-v2'
    $sealedV2 = Invoke-D3Harness $harnessRoot $harnessTarget 'seal' $installRoot $package.HelperSha256 $version2 $storeV2
    $recoveredV2 = Invoke-D3Harness `
        $harnessRoot $harnessTarget 'recover' $installRoot $package.HelperSha256 $version2 $storeV2 `
        ([string]$sealedV2.evidence_id) ([string]$sealedV2.content_sha256)
    if ($sealedV2.status -ne 'sealed' -or $recoveredV2.status -ne 'recovered' -or
        $sealedV2.key_version_id -ne $version2 -or $recoveredV2.key_version_id -ne $version2) {
        throw 'D3 rotated-key seal/recover failed.'
    }

    $sentinel = Join-Path $dataRoot 'd3-data-sentinel.txt'
    [IO.File]::WriteAllText($sentinel, 'preserve-data', [Text.UTF8Encoding]::new($false))
    $uninstallScript = Join-Path $dataRoot 'installer\uninstall-bsl-windows.ps1'
    $uninstalled = Invoke-InstallerJson $uninstallScript @{
        InstallRoot = $installRoot
        DataRoot = $dataRoot
        ExpectedPublisherThumbprint = $publisherThumbprint
        ExpectedReleasePublicKeySha256 = $publicKeySha
    }
    if ($uninstalled.status -ne 'uninstalled' -or -not $uninstalled.cleanup_complete -or
        (Test-Path -LiteralPath $installRoot) -or -not (Test-Path -LiteralPath $sentinel -PathType Leaf)) {
        throw 'D3 data-preserving uninstall failed.'
    }

    $afterUninstall = Invoke-Lifecycle $preservedHelper @('status', '--store-id', $storeId, '--key-id', $keyId) 'status'
    if (-not $afterUninstall.present -or $afterUninstall.version_id -ne $version2) {
        throw 'BSL uninstall destroyed or changed the Credential Manager evidence key.'
    }

    $deleted = Invoke-Lifecycle $preservedHelper @('delete', '--store-id', $storeId, '--key-id', $keyId, '--confirm-target', $credentialTarget) 'delete'
    if ($deleted.present) { throw 'D3 explicit credential cleanup did not delete the key.' }
    $credentialMayExist = $false
    $finalStatus = Invoke-Lifecycle $preservedHelper @('status', '--store-id', $storeId, '--key-id', $keyId) 'status'
    if ($finalStatus.present) { throw 'D3 final credential status is not absent.' }

    $finalLockSha = (Get-FileHash -LiteralPath (Join-Path $RepoRoot 'Cargo.lock') -Algorithm SHA256).Hash.ToLowerInvariant()
    $finalDirty = @(git status --porcelain=v1 --untracked-files=all)
    if ($finalLockSha -ne $expectedLockSha256 -or $finalDirty.Count -ne 0) {
        throw 'D3 changed repository authority or the canonical lockfile.'
    }

    $evidenceDirectory = Join-Path $RepoRoot 'target\bsl-validation'
    New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
    $evidencePath = Join-Path $evidenceDirectory "bsl-152-pass-d3-windows-$head.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = 'BSL-152'
        gate = 'pass_d3_clean_install_seal_recover'
        platform = 'windows'
        head_sha = $head
        parent_sha = $parent
        rustc = $rustcVersion
        cargo_lock_sha256 = $finalLockSha
        package_helper_sha256 = $package.HelperSha256
        credential_target_sha256 = Get-TextSha256 $credentialTarget
        version_1_sha256 = Get-TextSha256 $version1
        version_2_sha256 = Get-TextSha256 $version2
        version_changed = ($version1 -ne $version2)
        evidence_id = [string]$sealedV1.evidence_id
        evidence_content_sha256 = [string]$sealedV1.content_sha256
        evidence_envelope_sha256 = [string]$sealedV1.envelope_sha256
        checks = [ordered]@{
            clean_schema3_install = 'passed'
            lifecycle_metadata_only = 'passed'
            credential_create = 'passed'
            bundled_pinned_process_acquisition = 'passed'
            sealed_evidence_persistence = 'passed'
            later_evidence_recovery = 'passed'
            deliberate_rotation = 'passed'
            stale_required_version_rejection = 'passed'
            rotated_key_seal_recover = 'passed'
            uninstall_preserved_credential = 'passed'
            explicit_key_deletion = 'passed'
            final_credential_absent = 'passed'
            root_lockfile_unchanged = 'passed'
            raw_key_observed_by_shell = $false
            network_activity = 'none'
        }
    }
    [IO.File]::WriteAllText(
        $evidencePath,
        ($evidence | ConvertTo-Json -Depth 12) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host 'BSL-152 Pass D3 clean-install evidence validation passed.'
    Write-Host "HEAD: $head"
    Write-Host "HELPER SHA256: $($package.HelperSha256)"
    Write-Host "EVIDENCE: $evidencePath"
}
finally {
    if ($credentialMayExist -and $null -ne $cleanupHelper -and
        (Test-Path -LiteralPath $cleanupHelper -PathType Leaf)) {
        try {
            $status = Invoke-Lifecycle $cleanupHelper @('status', '--store-id', $storeId, '--key-id', $keyId) 'status'
            if ($status.present) {
                [void](Invoke-Lifecycle $cleanupHelper @('delete', '--store-id', $storeId, '--key-id', $keyId, '--confirm-target', $credentialTarget) 'delete')
            }
        }
        catch {
            Write-Warning "D3 emergency credential cleanup failed: $($_.Exception.Message)"
        }
    }

    Pop-Location
    if ($null -ne $publisherStore -and $null -ne $certificate) {
        try { $publisherStore.Remove($certificate) } catch { }
    }
    if ($null -ne $rootStore -and $null -ne $certificate) {
        try { $rootStore.Remove($certificate) } catch { }
    }
    if ($null -ne $publisherStore) { $publisherStore.Dispose() }
    if ($null -ne $rootStore) { $rootStore.Dispose() }
    if ($null -ne $certificate) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\{0}" -f $certificate.Thumbprint) -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
