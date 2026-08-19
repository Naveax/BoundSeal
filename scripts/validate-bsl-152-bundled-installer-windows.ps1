[CmdletBinding()]
param(
    [string]$RepoRoot =
        (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,

    [string]$LegacySourceCommit =
        'a43d0777339d74b86ef03730f53bc0c35c4301fb'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$temporaryRoot = $null
$legacyWorktree = $null
$certificate = $null
$rootStore = $null
$publisherStore = $null

$helperFileName =
    'nxb-windows-credential-evidence-key-helper.exe'

function Get-OpenSslPath {
    $command =
        Get-Command openssl.exe `
            -ErrorAction SilentlyContinue

    if ($null -ne $command) {
        return $command.Source
    }

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
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    return -join (
        $Bytes |
        ForEach-Object {
            $_.ToString('x2')
        }
    )
}

function Convert-HexToBytes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hex
    )

    if ($Hex.Length % 2 -ne 0 -or
        $Hex -notmatch '^[0-9a-f]+$') {
        throw 'Hexadecimal value is invalid.'
    }

    $bytes =
        New-Object byte[] ($Hex.Length / 2)

    for (
        $index = 0;
        $index -lt $bytes.Length;
        $index++
    ) {
        $bytes[$index] =
            [Convert]::ToByte(
                $Hex.Substring(
                    $index * 2,
                    2
                ),
                16
            )
    }

    return $bytes
}

function Assert-PowerShellScriptParses {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $tokens = $null
    $errors = $null

    [void][Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$tokens,
        [ref]$errors
    )

    if ($errors.Count -ne 0) {
        $messages =
            (
                $errors |
                ForEach-Object {
                    $_.Message
                }
            ) -join '; '

        throw (
            "PowerShell parser rejected ${Path}: " +
            $messages
        )
    }
}

function Invoke-InstallerJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Arguments
    )

    $raw =
        (
            & $ScriptPath @Arguments |
            Out-String
        )

    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw (
            'Installer script returned no JSON: ' +
            $ScriptPath
        )
    }

    return $raw | ConvertFrom-Json
}

function Expect-InstallerFailure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Arguments
    )

    $failed = $false

    try {
        [void](
            & $ScriptPath @Arguments |
            Out-String
        )
    }
    catch {
        $failed = $true
    }

    if (-not $failed) {
        throw (
            'Expected installer failure was not observed: ' +
            $ScriptPath
        )
    }
}

function Invoke-Cargo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [string]$TargetDirectory,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $previousTarget =
        $env:CARGO_TARGET_DIR

    try {
        $env:CARGO_TARGET_DIR =
            $TargetDirectory

        Push-Location $WorkingDirectory

        try {
            rustup run 1.97.1 cargo @Arguments

            if ($LASTEXITCODE -ne 0) {
                throw (
                    "$Label failed with exit code " +
                    $LASTEXITCODE
                )
            }
        }
        finally {
            Pop-Location
        }
    }
    finally {
        $env:CARGO_TARGET_DIR =
            $previousTarget
    }
}

function Assert-NoInstallerResidue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallRoot
    )

    $parent =
        Split-Path -Parent $InstallRoot

    $leaf =
        Split-Path -Leaf $InstallRoot

    $patterns = @(
        "$leaf.stage.*",
        "$leaf.previous.backup.*",
        "$leaf.rollback-failed.*",
        "$leaf.rollback-restore.*",
        "$leaf.uninstall.*"
    )

    foreach ($pattern in $patterns) {
        $matches = @(
            Get-ChildItem `
                -LiteralPath $parent `
                -Force `
                -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -like $pattern
            }
        )

        if ($matches.Count -ne 0) {
            throw (
                "Installer left transaction residue matching " +
                "'$pattern'."
            )
        }
    }
}

function Assert-InstalledLayout {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [uint32]$ExpectedSchema,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedCommit,

        [string]$ExpectedHelperSha256 = ''
    )

    $statePath =
        Join-Path $Root 'install-state.json'

    if (-not (
        Test-Path `
            -LiteralPath $statePath `
            -PathType Leaf
    )) {
        throw "Installed state is missing: $statePath"
    }

    $state =
        [IO.File]::ReadAllText($statePath) |
        ConvertFrom-Json

    if ([uint32]$state.schema_version -ne
            $ExpectedSchema -or
        $state.source_commit -ne
            $ExpectedCommit) {
        throw 'Installed layout state binding is invalid.'
    }

    $helperPath =
        Join-Path $Root $helperFileName

    if ([string]::IsNullOrWhiteSpace(
        $ExpectedHelperSha256
    )) {
        if (Test-Path -LiteralPath $helperPath) {
            throw (
                'Legacy layout unexpectedly contains ' +
                'the bundled helper.'
            )
        }

        return
    }

    if (-not (
        Test-Path `
            -LiteralPath $helperPath `
            -PathType Leaf
    )) {
        throw 'Bundled layout helper is missing.'
    }

    $actual = (
        Get-FileHash `
            -LiteralPath $helperPath `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()

    if ($actual -ne $ExpectedHelperSha256) {
        throw 'Installed helper SHA-256 is invalid.'
    }

    if ($state.helper_sha256 -ne
        $ExpectedHelperSha256) {
        throw (
            'Installed state helper SHA-256 ' +
            'does not match the helper.'
        )
    }
}

function New-SignedReleasePackage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceBinary,

        [Parameter(Mandatory = $true)]
        [string]$SourceCommit,

        [Parameter(Mandatory = $true)]
        [uint64]$ReleaseSequence,

        [Parameter(Mandatory = $true)]
        [string]$PackageRoot,

        [Parameter(Mandatory = $true)]
        $Certificate,

        [Parameter(Mandatory = $true)]
        [string]$OpenSsl,

        [Parameter(Mandatory = $true)]
        [string]$PrivateKey,

        [Parameter(Mandatory = $true)]
        [string]$RawPublicKeyHex,

        [string]$SourceHelper = ''
    )

    if (Test-Path -LiteralPath $PackageRoot) {
        Remove-Item `
            -LiteralPath $PackageRoot `
            -Recurse `
            -Force
    }

    New-Item `
        -ItemType Directory `
        -Path $PackageRoot |
        Out-Null

    $candidateBinary =
        Join-Path $PackageRoot 'nxb.exe'

    Copy-Item `
        -LiteralPath $SourceBinary `
        -Destination $candidateBinary

    $authenticode =
        Set-AuthenticodeSignature `
            -LiteralPath $candidateBinary `
            -Certificate $Certificate `
            -HashAlgorithm SHA256

    if ($authenticode.Status.ToString() -ne 'Valid') {
        throw (
            'Could not create a valid nxb.exe ' +
            'Authenticode signature.'
        )
    }

    $bundled =
        -not [string]::IsNullOrWhiteSpace(
            $SourceHelper
        )

    $candidateHelper = $null
    $helperSha = $null

    if ($bundled) {
        if (-not (
            Test-Path `
                -LiteralPath $SourceHelper `
                -PathType Leaf
        )) {
            throw 'Source helper is missing.'
        }

        $candidateHelper =
            Join-Path `
                $PackageRoot `
                $helperFileName

        Copy-Item `
            -LiteralPath $SourceHelper `
            -Destination $candidateHelper

        $helperAuthenticode =
            Set-AuthenticodeSignature `
                -LiteralPath $candidateHelper `
                -Certificate $Certificate `
                -HashAlgorithm SHA256

        if ($helperAuthenticode.Status.ToString() -ne 'Valid') {
            throw (
                'Could not create a valid helper ' +
                'Authenticode signature.'
            )
        }

        $helperSha = (
            Get-FileHash `
                -LiteralPath $candidateHelper `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }

    $sbomPath =
        Join-Path $PackageRoot 'nxb.cdx.json'

    $sbom = [ordered]@{
        bomFormat = 'CycloneDX'
        specVersion = '1.6'
        components = @()
        metadata = [ordered]@{
            component = [ordered]@{
                type = 'application'
                name = 'NXBounty'
                version = '0.1.0'
                properties = @(
                    [ordered]@{
                        name = 'nxb:source_commit'
                        value = $SourceCommit
                    },
                    [ordered]@{
                        name = 'nxb:release_sequence'
                        value = [string]$ReleaseSequence
                    },
                    [ordered]@{
                        name = 'nxb:bundled_windows_credential_helper'
                        value = [string]$bundled
                    }
                )
            }
        }
    }

    [IO.File]::WriteAllText(
        $sbomPath,
        (
            $sbom |
            ConvertTo-Json `
                -Depth 12 `
                -Compress
        ) + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    $binarySha = (
        Get-FileHash `
            -LiteralPath $candidateBinary `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()

    $sbomSha = (
        Get-FileHash `
            -LiteralPath $sbomPath `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()

    $checksumLines = @(
        "$binarySha  nxb.exe",
        "$sbomSha  nxb.cdx.json"
    )

    if ($bundled) {
        $checksumLines +=
            "$helperSha  $helperFileName"
    }

    $checksumsPath =
        Join-Path $PackageRoot 'SHA256SUMS'

    [IO.File]::WriteAllText(
        $checksumsPath,
        ($checksumLines -join "`n") + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    $publicKeyPath =
        Join-Path `
            $PackageRoot `
            'release-public-key.hex'

    [IO.File]::WriteAllText(
        $publicKeyPath,
        $RawPublicKeyHex + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    $manifestPath =
        Join-Path `
            $PackageRoot `
            'nxb-release-manifest.json'

    $generatedAt =
        [DateTime]::UtcNow.ToString(
            'yyyy-MM-ddTHH:mm:ssZ'
        )

    $sequenceText =
        [string]$ReleaseSequence

    & $candidateBinary `
        release `
        manifest-template `
        --release-id `
            "v0.1.0-r$sequenceText-nxb152-d2" `
        --release-sequence `
            $sequenceText `
        --source-commit `
            $SourceCommit `
        --platform `
            windows `
        --architecture `
            x86-64 `
        --binary `
            $candidateBinary `
        --sbom `
            $sbomPath `
        --checksums `
            $checksumsPath `
        --generated-at `
            $generatedAt `
        --output `
            $manifestPath `
        --json |
        Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw (
            'Release manifest template generation failed.'
        )
    }

    $manifest =
        [IO.File]::ReadAllText($manifestPath) |
        ConvertFrom-Json

    if ([uint64]$manifest.manifest.release_sequence -ne
            $ReleaseSequence -or
        $manifest.manifest.source_commit -ne
            $SourceCommit) {
        throw (
            'Generated manifest does not bind ' +
            'the requested revision.'
        )
    }

    $payloadPath =
        Join-Path `
            $PackageRoot `
            'signing-payload.bin'

    $signaturePath =
        Join-Path `
            $PackageRoot `
            'release-signature.bin'

    [IO.File]::WriteAllBytes(
        $payloadPath,
        (
            Convert-HexToBytes `
                $manifest.signing_payload_hex
        )
    )

    & $OpenSsl `
        pkeyutl `
        -sign `
        -inkey $PrivateKey `
        -rawin `
        -in $payloadPath `
        -out $signaturePath

    if ($LASTEXITCODE -ne 0) {
        throw 'OpenSSL Ed25519 signing failed.'
    }

    $signatureBytes =
        [IO.File]::ReadAllBytes(
            $signaturePath
        )

    if ($signatureBytes.Length -ne 64) {
        throw 'Ed25519 signature length is invalid.'
    }

    $manifestText =
        [IO.File]::ReadAllText(
            $manifestPath
        )

    $manifestText =
        $manifestText.Replace(
            '"signature_hex": ""',
            (
                '"signature_hex": "' +
                (
                    Convert-BytesToHex `
                        $signatureBytes
                ) +
                '"'
            )
        )

    [IO.File]::WriteAllText(
        $manifestPath,
        $manifestText,
        [Text.UTF8Encoding]::new($false)
    )

    Remove-Item `
        -LiteralPath $payloadPath, $signaturePath `
        -Force

    $verifiedRaw = (
        & $candidateBinary `
            release `
            verify-manifest `
            --document $manifestPath `
            --public-key $publicKeyPath `
            --binary $candidateBinary `
            --sbom $sbomPath `
            --checksums $checksumsPath `
            --json |
        Out-String
    )

    if ($LASTEXITCODE -ne 0) {
        throw (
            'Pre-install signed release ' +
            'verification failed.'
        )
    }

    $verified =
        $verifiedRaw |
        ConvertFrom-Json

    if ($verified.status -ne 'valid' -or
        [uint64]$verified.release_sequence -ne
            $ReleaseSequence -or
        $verified.source_commit -ne
            $SourceCommit) {
        throw (
            'Pre-install verifier returned ' +
            'an invalid revision binding.'
        )
    }

    return [pscustomobject]@{
        Root = $PackageRoot
        BinarySha256 = $binarySha
        HelperSha256 = $helperSha
        ManifestSha256 =
            $verified.manifest_sha256
        SourceCommit = $SourceCommit
        ReleaseSequence = $ReleaseSequence
        BundledHelper = $bundled
    }
}

Push-Location $RepoRoot

try {
    $head =
        (git rev-parse HEAD).Trim()

    if ($LASTEXITCODE -ne 0 -or
        $head -notmatch '^[0-9a-f]{40}$') {
        throw 'Could not resolve exact Git HEAD.'
    }

    $legacy =
        (git rev-parse $LegacySourceCommit).Trim()

    if ($LASTEXITCODE -ne 0 -or
        $legacy -notmatch '^[0-9a-f]{40}$' -or
        $legacy -eq $head) {
        throw (
            'LegacySourceCommit must resolve ' +
            'to a distinct exact commit.'
        )
    }

    git merge-base `
        --is-ancestor `
        $legacy `
        $head

    if ($LASTEXITCODE -ne 0) {
        throw (
            'LegacySourceCommit must be ' +
            'an ancestor of validation HEAD.'
        )
    }

    $status =
        @(git status --porcelain=v1)

    if ($status.Count -ne 0) {
        throw (
            'Working tree must be clean ' +
            'before D2 validation.'
        )
    }

    $rustcVersion =
        (
            rustup run 1.97.1 rustc --version
        ).Trim()

    if ($LASTEXITCODE -ne 0 -or
        -not $rustcVersion.StartsWith(
            'rustc 1.97.1 '
        )) {
        throw (
            "Expected rustc 1.97.1, found " +
            "'$rustcVersion'."
        )
    }

    $scripts = @(
        (
            Join-Path `
                $RepoRoot `
                'scripts\nxb-installer-common.ps1'
        ),
        (
            Join-Path `
                $RepoRoot `
                'scripts\install-nxb-windows.ps1'
        ),
        (
            Join-Path `
                $RepoRoot `
                'scripts\rollback-nxb-windows.ps1'
        ),
        (
            Join-Path `
                $RepoRoot `
                'scripts\uninstall-nxb-windows.ps1'
        ),
        (
            Join-Path `
                $RepoRoot `
                'scripts\validate-nxb-152-bundled-installer-windows.ps1'
        )
    )

    foreach ($script in $scripts) {
        Assert-PowerShellScriptParses $script
    }

    $temporaryRoot =
        Join-Path `
            ([IO.Path]::GetTempPath()) `
            (
                'nxb152-d2-' +
                [Guid]::NewGuid().ToString('N')
            )

    $legacyWorktree =
        Join-Path `
            $temporaryRoot `
            'legacy-source'

    $currentTarget =
        Join-Path `
            $temporaryRoot `
            'current-target'

    $legacyTarget =
        Join-Path `
            $temporaryRoot `
            'legacy-target'

    New-Item `
        -ItemType Directory `
        -Path $temporaryRoot |
        Out-Null

    Invoke-Cargo `
        $RepoRoot `
        $currentTarget `
        @(
            'fmt',
            '--all',
            '--',
            '--check'
        ) `
        'cargo fmt'

    Invoke-Cargo `
        $RepoRoot `
        $currentTarget `
        @(
            'check',
            '-p',
            'nxb-evidence-key-provider-process',
            '--all-features',
            '--all-targets',
            '--locked'
        ) `
        'process provider check'

    Invoke-Cargo `
        $RepoRoot `
        $currentTarget `
        @(
            'clippy',
            '-p',
            'nxb-evidence-key-provider-process',
            '--all-features',
            '--all-targets',
            '--locked',
            '--',
            '-D',
            'warnings'
        ) `
        'process provider clippy'

    Invoke-Cargo `
        $RepoRoot `
        $currentTarget `
        @(
            'test',
            '-p',
            'nxb-evidence-key-provider-process',
            '--all-features',
            '--locked',
            '--',
            '--test-threads=1'
        ) `
        'process provider tests'

    Invoke-Cargo `
        $RepoRoot `
        $currentTarget `
        @(
            'check',
            '-p',
            'nxb-core',
            '--all-targets',
            '--all-features',
            '--locked'
        ) `
        'nxb-core check'

    Invoke-Cargo `
        $RepoRoot `
        $currentTarget `
        @(
            'clippy',
            '-p',
            'nxb-core',
            '--all-targets',
            '--all-features',
            '--locked',
            '--',
            '-D',
            'warnings'
        ) `
        'nxb-core clippy'

    Invoke-Cargo `
        $RepoRoot `
        $currentTarget `
        @(
            'test',
            '-p',
            'nxb-core',
            '--all-features',
            '--locked',
            '--',
            '--test-threads=1'
        ) `
        'nxb-core tests'

    Invoke-Cargo `
        $RepoRoot `
        $currentTarget `
        @(
            'build',
            '-p',
            'nxb-core',
            '--bin',
            'nxb',
            '--release',
            '--all-features',
            '--locked'
        ) `
        'current nxb release build'

    Invoke-Cargo `
        $RepoRoot `
        $currentTarget `
        @(
            'build',
            '-p',
            'nxb-evidence-key-provider-process',
            '--bin',
            'nxb-windows-credential-evidence-key-helper',
            '--release',
            '--locked'
        ) `
        'current helper release build'

    git worktree add `
        --detach `
        $legacyWorktree `
        $legacy

    if ($LASTEXITCODE -ne 0) {
        throw 'Could not create legacy worktree.'
    }

    Invoke-Cargo `
        $legacyWorktree `
        $legacyTarget `
        @(
            'build',
            '-p',
            'nxb-core',
            '--bin',
            'nxb',
            '--release',
            '--all-features',
            '--locked'
        ) `
        'legacy nxb release build'

    $currentBinary =
        Join-Path `
            $currentTarget `
            'release\nxb.exe'

    $currentHelper =
        Join-Path `
            $currentTarget `
            'release\nxb-windows-credential-evidence-key-helper.exe'

    $legacyBinary =
        Join-Path `
            $legacyTarget `
            'release\nxb.exe'

    foreach ($binary in @(
        $currentBinary,
        $currentHelper,
        $legacyBinary
    )) {
        if (-not (
            Test-Path `
                -LiteralPath $binary `
                -PathType Leaf
        )) {
            throw "Release artifact is missing: $binary"
        }
    }

    $openssl =
        Get-OpenSslPath

    $certificate =
        New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject 'CN=NXBounty D2 Validation' `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -KeyExportPolicy Exportable `
            -NotAfter (Get-Date).AddDays(2)

    $rootStore =
        New-Object `
            Security.Cryptography.X509Certificates.X509Store(
                'Root',
                'CurrentUser'
            )

    $publisherStore =
        New-Object `
            Security.Cryptography.X509Certificates.X509Store(
                'TrustedPublisher',
                'CurrentUser'
            )

    $rootStore.Open(
        [Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite
    )

    $publisherStore.Open(
        [Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite
    )

    $rootStore.Add($certificate)
    $publisherStore.Add($certificate)

    $privateKey =
        Join-Path `
            $temporaryRoot `
            'release-private-key.pem'

    $publicDer =
        Join-Path `
            $temporaryRoot `
            'release-public-key.der'

    & $openssl `
        genpkey `
        -algorithm ED25519 `
        -out $privateKey

    if ($LASTEXITCODE -ne 0) {
        throw (
            'OpenSSL Ed25519 private-key ' +
            'generation failed.'
        )
    }

    & $openssl `
        pkey `
        -in $privateKey `
        -pubout `
        -outform DER `
        -out $publicDer

    if ($LASTEXITCODE -ne 0) {
        throw (
            'OpenSSL Ed25519 public-key ' +
            'export failed.'
        )
    }

    $derBytes =
        [IO.File]::ReadAllBytes(
            $publicDer
        )

    if ($derBytes.Length -lt 32) {
        throw 'Ed25519 SPKI output is too short.'
    }

    $rawPublicKey =
        New-Object byte[] 32

    [Array]::Copy(
        $derBytes,
        $derBytes.Length - 32,
        $rawPublicKey,
        0,
        32
    )

    $rawPublicKeyHex =
        Convert-BytesToHex `
            $rawPublicKey

    $legacyPackage =
        New-SignedReleasePackage `
            -SourceBinary $legacyBinary `
            -SourceCommit $legacy `
            -ReleaseSequence 1 `
            -PackageRoot (
                Join-Path `
                    $temporaryRoot `
                    'package-r1-legacy'
            ) `
            -Certificate $certificate `
            -OpenSsl $openssl `
            -PrivateKey $privateKey `
            -RawPublicKeyHex $rawPublicKeyHex

    $currentPackage =
        New-SignedReleasePackage `
            -SourceBinary $currentBinary `
            -SourceCommit $head `
            -ReleaseSequence 2 `
            -PackageRoot (
                Join-Path `
                    $temporaryRoot `
                    'package-r2-bundled'
            ) `
            -Certificate $certificate `
            -OpenSsl $openssl `
            -PrivateKey $privateKey `
            -RawPublicKeyHex $rawPublicKeyHex `
            -SourceHelper $currentHelper

    if ([string]::IsNullOrWhiteSpace(
        $currentPackage.HelperSha256
    )) {
        throw (
            'Bundled package did not produce ' +
            'a helper SHA-256.'
        )
    }

    $publisherThumbprint =
        $certificate.Thumbprint.ToLowerInvariant()

    $publicKeyPath =
        Join-Path `
            $currentPackage.Root `
            'release-public-key.hex'

    $publicKeySha = (
        Get-FileHash `
            -LiteralPath $publicKeyPath `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()

    $installRoot =
        Join-Path `
            $temporaryRoot `
            'install\NXBounty'

    $previousRoot =
        $installRoot + '.previous'

    $dataRoot =
        Join-Path `
            $temporaryRoot `
            'data\NXBounty'

    $legacyInstallScript =
        Join-Path `
            $legacyWorktree `
            'scripts\install-nxb-windows.ps1'

    $currentInstallScript =
        Join-Path `
            $RepoRoot `
            'scripts\install-nxb-windows.ps1'

    $rollbackScript =
        Join-Path `
            $RepoRoot `
            'scripts\rollback-nxb-windows.ps1'

    #
    # First establish a real legacy NXB-151 installation
    # using the legacy installer itself.
    #

    $legacyArguments = @{
        PackageDirectory =
            $legacyPackage.Root
        InstallRoot =
            $installRoot
        DataRoot =
            $dataRoot
        ExpectedPublisherThumbprint =
            $publisherThumbprint
        ExpectedReleasePublicKeySha256 =
            $publicKeySha
        AddToUserPath =
            $false
        CreateStartMenuShortcut =
            $false
    }

    $legacyInstalled =
        Invoke-InstallerJson `
            $legacyInstallScript `
            $legacyArguments

    if ($legacyInstalled.status -ne 'installed' -or
        [uint64]$legacyInstalled.release_sequence -ne 1) {
        throw 'Legacy clean installation failed.'
    }

    Assert-InstalledLayout `
        $installRoot `
        2 `
        $legacy

    #
    # Upgrade legacy layout -> schema 3 bundled layout.
    #

    $currentArguments = @{
        PackageDirectory =
            $currentPackage.Root
        InstallRoot =
            $installRoot
        DataRoot =
            $dataRoot
        ExpectedPublisherThumbprint =
            $publisherThumbprint
        ExpectedReleasePublicKeySha256 =
            $publicKeySha
        AddToUserPath =
            $false
        CreateStartMenuShortcut =
            $false
    }

    $upgraded =
        Invoke-InstallerJson `
            $currentInstallScript `
            $currentArguments

    if ($upgraded.status -ne 'upgraded' -or
        [uint64]$upgraded.release_sequence -ne 2 -or
        $upgraded.rollback_available -ne $true -or
        $upgraded.helper_sha256 -ne
            $currentPackage.HelperSha256) {
        throw (
            'Legacy-to-bundled signed ' +
            'revision upgrade failed.'
        )
    }

    Assert-InstalledLayout `
        $installRoot `
        3 `
        $head `
        $currentPackage.HelperSha256

    Assert-InstalledLayout `
        $previousRoot `
        2 `
        $legacy

    #
    # Current bundled release must be idempotent.
    #

    $idempotent =
        Invoke-InstallerJson `
            $currentInstallScript `
            $currentArguments

    if ($idempotent.status -ne
            'already_installed' -or
        [uint64]$idempotent.release_sequence -ne 2 -or
        $idempotent.helper_sha256 -ne
            $currentPackage.HelperSha256) {
        throw (
            'Bundled idempotent installation failed.'
        )
    }

    #
    # Tampered candidate helper must fail even though
    # nxb.exe + manifest themselves remain untouched.
    #

    $tamperedPackageRoot =
        Join-Path `
            $temporaryRoot `
            'tampered-helper-package'

    Copy-Item `
        -LiteralPath $currentPackage.Root `
        -Destination $tamperedPackageRoot `
        -Recurse

    $tamperedHelper =
        Join-Path `
            $tamperedPackageRoot `
            $helperFileName

    $tamperedBytes =
        [IO.File]::ReadAllBytes(
            $tamperedHelper
        )

    $tamperedBytes[
        $tamperedBytes.Length - 1
    ] =
        $tamperedBytes[
            $tamperedBytes.Length - 1
        ] -bxor 1

    [IO.File]::WriteAllBytes(
        $tamperedHelper,
        $tamperedBytes
    )

    $tamperedArguments =
        $currentArguments.Clone()

    $tamperedArguments.PackageDirectory =
        $tamperedPackageRoot

    Expect-InstallerFailure `
        $currentInstallScript `
        $tamperedArguments

    #
    # Tampering the installed helper must also make the
    # installed-root verifier fail closed.
    #

    $installedHelper =
        Join-Path `
            $installRoot `
            $helperFileName

    $originalInstalledHelper =
        [IO.File]::ReadAllBytes(
            $installedHelper
        )

    try {
        $mutatedInstalledHelper =
            [byte[]]$originalInstalledHelper.Clone()

        $mutatedInstalledHelper[
            $mutatedInstalledHelper.Length - 1
        ] =
            $mutatedInstalledHelper[
                $mutatedInstalledHelper.Length - 1
            ] -bxor 1

        [IO.File]::WriteAllBytes(
            $installedHelper,
            $mutatedInstalledHelper
        )

        Expect-InstallerFailure `
            $currentInstallScript `
            $currentArguments
    }
    finally {
        [IO.File]::WriteAllBytes(
            $installedHelper,
            $originalInstalledHelper
        )
    }

    Assert-InstalledLayout `
        $installRoot `
        3 `
        $head `
        $currentPackage.HelperSha256

    #
    # Rollback bundled -> legacy. The new common verifier
    # must deliberately accept the signed schema-2 slot.
    #

    $rolledBack =
        Invoke-InstallerJson `
            $rollbackScript `
            @{
                InstallRoot =
                    $installRoot
                DataRoot =
                    $dataRoot
                ExpectedPublisherThumbprint =
                    $publisherThumbprint
                ExpectedReleasePublicKeySha256 =
                    $publicKeySha
            }

    if ($rolledBack.status -ne 'rolled_back' -or
        [uint64]$rolledBack.from_release_sequence -ne 2 -or
        [uint64]$rolledBack.to_release_sequence -ne 1) {
        throw (
            'Bundled-to-legacy rollback failed.'
        )
    }

    Assert-InstalledLayout `
        $installRoot `
        2 `
        $legacy

    Assert-InstalledLayout `
        $previousRoot `
        3 `
        $head `
        $currentPackage.HelperSha256

    #
    # Upgrade back to the bundled revision.
    #

    $upgradedAgain =
        Invoke-InstallerJson `
            $currentInstallScript `
            $currentArguments

    if ($upgradedAgain.status -ne 'upgraded' -or
        [uint64]$upgradedAgain.release_sequence -ne 2 -or
        $upgradedAgain.helper_sha256 -ne
            $currentPackage.HelperSha256) {
        throw (
            'Post-rollback bundled upgrade failed.'
        )
    }

    Assert-InstalledLayout `
        $installRoot `
        3 `
        $head `
        $currentPackage.HelperSha256

    Assert-InstalledLayout `
        $previousRoot `
        2 `
        $legacy

    Assert-NoInstallerResidue `
        $installRoot

    #
    # Data-preserving uninstall. Credential Manager is
    # intentionally outside the filesystem uninstall transaction.
    #

    $sentinel =
        Join-Path `
            $dataRoot `
            'workspace-data-sentinel.txt'

    [IO.File]::WriteAllText(
        $sentinel,
        'preserve-me',
        [Text.UTF8Encoding]::new($false)
    )

    $uninstallScript =
        Join-Path `
            $dataRoot `
            'installer\uninstall-nxb-windows.ps1'

    $uninstalled =
        Invoke-InstallerJson `
            $uninstallScript `
            @{
                InstallRoot =
                    $installRoot
                DataRoot =
                    $dataRoot
                ExpectedPublisherThumbprint =
                    $publisherThumbprint
                ExpectedReleasePublicKeySha256 =
                    $publicKeySha
            }

    if ($uninstalled.status -ne 'uninstalled' -or
        $uninstalled.cleanup_complete -ne $true -or
        @($uninstalled.cleanup_warnings).Count -ne 0 -or
        $uninstalled.rollback_slot_deactivated -ne $true -or
        $uninstalled.data_preserved -ne $true -or
        (Test-Path -LiteralPath $installRoot) -or
        (Test-Path -LiteralPath $previousRoot) -or
        -not (
            Test-Path `
                -LiteralPath $sentinel `
                -PathType Leaf
        )) {
        throw (
            'Bundled data-preserving uninstall result ' +
            'is invalid.'
        )
    }

    Assert-NoInstallerResidue `
        $installRoot

    #
    # Evidence.
    #

    $validationDirectory =
        Join-Path `
            $RepoRoot `
            'target\nxb-validation'

    New-Item `
        -ItemType Directory `
        -Path $validationDirectory `
        -Force |
        Out-Null

    $evidencePath =
        Join-Path `
            $validationDirectory `
            "nxb-152-pass-d2-installer-windows-$head.json"

    $evidence = [ordered]@{
        schema_version = 1
        milestone = 'NXB-152'
        gate = 'pass_d2_bundled_windows_installer'
        platform = 'windows'
        head_sha = $head
        legacy_source_commit = $legacy
        rustc = $rustcVersion
        publisher_thumbprint =
            $publisherThumbprint
        release_public_key_sha256 =
            $publicKeySha
        releases = @(
            [ordered]@{
                layout = 'legacy'
                schema_version = 2
                source_commit =
                    $legacyPackage.SourceCommit
                release_sequence =
                    $legacyPackage.ReleaseSequence
                binary_sha256 =
                    $legacyPackage.BinarySha256
                helper_sha256 = $null
                manifest_sha256 =
                    $legacyPackage.ManifestSha256
            },
            [ordered]@{
                layout = 'bundled'
                schema_version = 3
                source_commit =
                    $currentPackage.SourceCommit
                release_sequence =
                    $currentPackage.ReleaseSequence
                binary_sha256 =
                    $currentPackage.BinarySha256
                helper_sha256 =
                    $currentPackage.HelperSha256
                manifest_sha256 =
                    $currentPackage.ManifestSha256
            }
        )
        checks = [ordered]@{
            powershell_parser = 'passed'
            rust_fmt = 'passed'
            process_provider_check = 'passed'
            process_provider_clippy = 'passed'
            process_provider_tests = 'passed'
            nxb_core_check = 'passed'
            nxb_core_clippy = 'passed'
            nxb_core_tests = 'passed'
            legacy_clean_install = 'passed'
            legacy_to_bundled_upgrade = 'passed'
            bundled_idempotent_install = 'passed'
            signed_helper_checksum_binding = 'passed'
            tampered_candidate_helper_rejection = 'passed'
            tampered_installed_helper_rejection = 'passed'
            bundled_to_legacy_rollback = 'passed'
            post_rollback_bundled_upgrade = 'passed'
            data_preserving_uninstall = 'passed'
            transaction_residue_cleanup = 'passed'
            network_activity = 'none'
        }
    }

    [IO.File]::WriteAllText(
        $evidencePath,
        (
            $evidence |
            ConvertTo-Json `
                -Depth 12
        ) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host ""
    Write-Host "NXB-152 Pass D2 Windows validation passed."
    Write-Host "HEAD: $head"
    Write-Host "LEGACY: $legacy"
    Write-Host (
        "BUNDLED HELPER SHA256: " +
        $currentPackage.HelperSha256
    )
    Write-Host "EVIDENCE: $evidencePath"
}
finally {
    Pop-Location

    if ($null -ne $publisherStore -and
        $null -ne $certificate) {
        try {
            $publisherStore.Remove(
                $certificate
            )
        }
        catch { }
    }

    if ($null -ne $rootStore -and
        $null -ne $certificate) {
        try {
            $rootStore.Remove(
                $certificate
            )
        }
        catch { }
    }

    if ($null -ne $publisherStore) {
        $publisherStore.Dispose()
    }

    if ($null -ne $rootStore) {
        $rootStore.Dispose()
    }

    if ($null -ne $certificate) {
        Remove-Item `
            -LiteralPath (
                'Cert:\CurrentUser\My\{0}' -f
                $certificate.Thumbprint
            ) `
            -Force `
            -ErrorAction SilentlyContinue
    }

    if ($null -ne $legacyWorktree -and
        (Test-Path -LiteralPath $legacyWorktree)) {
        git -C $RepoRoot `
            worktree `
            remove `
            --force `
            $legacyWorktree `
            2>$null

        if ($LASTEXITCODE -ne 0) {
            Remove-Item `
                -LiteralPath $legacyWorktree `
                -Recurse `
                -Force `
                -ErrorAction SilentlyContinue

            git -C $RepoRoot `
                worktree `
                prune `
                2>$null
        }
    }

    if ($null -ne $temporaryRoot -and
        (Test-Path -LiteralPath $temporaryRoot)) {
        Remove-Item `
            -LiteralPath $temporaryRoot `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue
    }
}