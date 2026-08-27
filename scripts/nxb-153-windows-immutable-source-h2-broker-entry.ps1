[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$ValidationDirectory,
    [Parameter(Mandatory = $true)][string]$HeadSha,
    [Parameter(Mandatory = $true)][string]$RustToolchain,
    [Parameter(Mandatory = $true)][string]$CargoAuditVersion,
    [Parameter(Mandatory = $true)][string]$CargoDenyVersion,
    [Parameter(Mandatory = $true)][string]$AuditSha256,
    [Parameter(Mandatory = $true)][string]$DenySha256,
    [Parameter(Mandatory = $true)][string]$ExpectedCargoLockSha256,
    [Parameter(Mandatory = $true)][string]$AuditPath,
    [Parameter(Mandatory = $true)][string]$DenyPath,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail-NxbH2BrokerEntry {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows H2 broker entry failed: $Message"
}

function ConvertTo-NxbH2BrokerEntryHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Open-NxbH2BrokerEntryPinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2BrokerEntry "$Label must be a regular non-reparse file: $Path"
    }
    return [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
}

function Get-NxbH2BrokerEntryGitBlobOid {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $saved = $Stream.Position
    try {
        $Stream.Position = 0
        $length = $Stream.Length
        if ($length -le 0 -or $length -gt 2097152) {
            Fail-NxbH2BrokerEntry "$Label size is outside the supported implementation envelope"
        }
        $sha1 = [Security.Cryptography.SHA1]::Create()
        try {
            $header = [Text.Encoding]::ASCII.GetBytes("blob $length`0")
            [void]$sha1.TransformBlock($header, 0, $header.Length, $null, 0)
            $buffer = [byte[]]::new(65536)
            [Int64]$total = 0
            while (($read = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $total += $read
                [void]$sha1.TransformBlock($buffer, 0, $read, $null, 0)
            }
            if ($total -ne $length) {
                Fail-NxbH2BrokerEntry "$Label changed size while hashing"
            }
            [void]$sha1.TransformFinalBlock([byte[]]::new(0), 0, 0)
            return (ConvertTo-NxbH2BrokerEntryHex -Bytes $sha1.Hash)
        }
        finally {
            $sha1.Dispose()
        }
    }
    finally {
        $Stream.Position = $saved
    }
}

function Assert-NxbH2BrokerEntryCommittedFile {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $expected = (git -C $RepoRoot rev-parse "${HeadSha}:$RelativePath").Trim()
    if ($LASTEXITCODE -ne 0 -or $expected -notmatch '^[0-9a-f]{40}$') {
        Fail-NxbH2BrokerEntry "exact-head $Label Git object could not be resolved"
    }
    $type = (git -C $RepoRoot cat-file -t $expected).Trim()
    if ($LASTEXITCODE -ne 0 -or $type -cne 'blob') {
        Fail-NxbH2BrokerEntry "exact-head $Label is not a Git blob"
    }
    $actual = Get-NxbH2BrokerEntryGitBlobOid -Stream $Stream -Label $Label
    if ($actual -cne $expected) {
        Fail-NxbH2BrokerEntry "pinned $Label bytes differ from exact-head Git authority"
    }
    return $expected
}

if (-not $IsWindows) {
    Fail-NxbH2BrokerEntry 'Windows H2 broker entry must run on Windows'
}
if ($HeadSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbH2BrokerEntry 'exact head is not canonical 40-hex SHA-1'
}
if ($null -eq (Get-Command Assert-NxbH2DestinationBroker -CommandType Function -ErrorAction SilentlyContinue)) {
    Fail-NxbH2BrokerEntry 'destination broker health function is unavailable'
}
if ($null -eq (Get-Command Stop-NxbH2DestinationBroker -CommandType Function -ErrorAction SilentlyContinue)) {
    Fail-NxbH2BrokerEntry 'destination broker stop function is unavailable'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ValidationDirectory = [IO.Path]::GetFullPath($ValidationDirectory)
$h2EntryRelative = 'scripts/nxb-153-windows-immutable-source-h2-entry-inner.ps1'
$h2EntryPath = Join-Path (Join-Path $RepoRoot 'scripts') 'nxb-153-windows-immutable-source-h2-entry-inner.ps1'
$h2EntryStream = $null
$script:NxbH2DeferredSnapshotRoot = $null
$script:NxbH2BrokerHandoffComplete = $false
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()

function Test-NxbH2BrokerSnapshotPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [string]::Equals(
        [IO.Path]::GetDirectoryName($full),
        $ValidationDirectory,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        return $false
    }
    $leaf = [IO.Path]::GetFileName($full)
    $pattern = '^\.nxb-153-rust-h2-windows-' + [Regex]::Escape($HeadSha) + '-[0-9]+-[0-9a-f]{32}$'
    return ($leaf -cmatch $pattern)
}

try {
    $h2EntryStream = Open-NxbH2BrokerEntryPinnedFile -Path $h2EntryPath -Label 'Windows H2 entry inner runner'
    [void](Assert-NxbH2BrokerEntryCommittedFile -Stream $h2EntryStream -RelativePath $h2EntryRelative -Label 'Windows H2 entry inner runner')

    if (-not $SelfTest) {
        function New-Item {
            [CmdletBinding()]
            param(
                [string]$Path,
                [string]$ItemType,
                [object]$Value,
                [switch]$Force
            )
            if (
                $ItemType -ceq 'Directory' -and
                -not [string]::IsNullOrWhiteSpace($Path) -and
                (Test-NxbH2BrokerSnapshotPath -Path $Path)
            ) {
                $full = [IO.Path]::GetFullPath($Path)
                if ($null -ne $script:NxbH2DeferredSnapshotRoot) {
                    Fail-NxbH2BrokerEntry 'H2 snapshot root creation was requested more than once'
                }
                if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $full) {
                    Fail-NxbH2BrokerEntry 'deferred H2 snapshot root already exists'
                }
                $script:NxbH2DeferredSnapshotRoot = $full
                return
            }
            Microsoft.PowerShell.Management\New-Item @PSBoundParameters
        }

        function Test-Path {
            [CmdletBinding(DefaultParameterSetName = 'Path')]
            param(
                [Parameter(ParameterSetName = 'Path', Position = 0)][string[]]$Path,
                [Parameter(ParameterSetName = 'LiteralPath')][string[]]$LiteralPath,
                [Microsoft.PowerShell.Commands.TestPathType]$PathType = [Microsoft.PowerShell.Commands.TestPathType]::Any
            )
            $candidate = $null
            if ($PSCmdlet.ParameterSetName -eq 'LiteralPath' -and $LiteralPath.Count -eq 1) {
                $candidate = [string]$LiteralPath[0]
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'Path' -and $Path.Count -eq 1) {
                $candidate = [string]$Path[0]
            }

            if (
                -not $script:NxbH2BrokerHandoffComplete -and
                $null -ne $script:NxbH2DeferredSnapshotRoot -and
                -not [string]::IsNullOrWhiteSpace($candidate)
            ) {
                $fullCandidate = [IO.Path]::GetFullPath($candidate)
                $expectedRustc = Join-Path $script:NxbH2DeferredSnapshotRoot 'bin\rustc.exe'
                if ([string]::Equals(
                    $fullCandidate,
                    [IO.Path]::GetFullPath($expectedRustc),
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                    Assert-NxbH2DestinationBroker -SnapshotRoot $script:NxbH2DeferredSnapshotRoot
                    Stop-NxbH2DestinationBroker -SnapshotRoot $script:NxbH2DeferredSnapshotRoot
                    $script:NxbH2BrokerHandoffComplete = $true
                }
            }

            return Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
        }

        function Remove-Item {
            [CmdletBinding(DefaultParameterSetName = 'Path')]
            param(
                [Parameter(ParameterSetName = 'Path', Position = 0)][string[]]$Path,
                [Parameter(ParameterSetName = 'LiteralPath')][string[]]$LiteralPath,
                [switch]$Recurse,
                [switch]$Force
            )
            $candidate = $null
            if ($PSCmdlet.ParameterSetName -eq 'LiteralPath' -and $LiteralPath.Count -eq 1) {
                $candidate = [string]$LiteralPath[0]
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'Path' -and $Path.Count -eq 1) {
                $candidate = [string]$Path[0]
            }

            if (
                -not $script:NxbH2BrokerHandoffComplete -and
                $null -ne $script:NxbH2DeferredSnapshotRoot -and
                -not [string]::IsNullOrWhiteSpace($candidate)
            ) {
                $fullCandidate = $null
                try { $fullCandidate = [IO.Path]::GetFullPath($candidate) } catch {}
                if (
                    $null -ne $fullCandidate -and
                    [string]::Equals(
                        $fullCandidate,
                        $script:NxbH2DeferredSnapshotRoot,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                ) {
                    Stop-NxbH2DestinationBroker -SnapshotRoot $script:NxbH2DeferredSnapshotRoot -AllowMissing
                    $script:NxbH2BrokerHandoffComplete = $true
                }
            }

            Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters
        }
    }

    $innerParameters = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $innerParameters[$entry.Key] = $entry.Value
    }
    & $h2EntryPath @innerParameters

    if (-not $SelfTest) {
        if ($null -eq $script:NxbH2DeferredSnapshotRoot) {
            Fail-NxbH2BrokerEntry 'H2 validation returned without requesting the broker-owned snapshot root'
        }
        if (-not $script:NxbH2BrokerHandoffComplete) {
            Fail-NxbH2BrokerEntry 'H2 validation returned without completing creator-to-PowerShell authority handoff'
        }
    }

    $finalOid = Get-NxbH2BrokerEntryGitBlobOid -Stream $h2EntryStream -Label 'Windows H2 entry inner runner final pinned object'
    $expectedOid = (git -C $RepoRoot rev-parse "${HeadSha}:$h2EntryRelative").Trim()
    if ($LASTEXITCODE -ne 0 -or $finalOid -cne $expectedOid) {
        Fail-NxbH2BrokerEntry 'Windows H2 entry inner runner authority changed during execution'
    }
}
catch {
    $primaryError = $_
}
finally {
    if (
        -not $script:NxbH2BrokerHandoffComplete -and
        $null -ne $script:NxbH2DeferredSnapshotRoot
    ) {
        try {
            Stop-NxbH2DestinationBroker -SnapshotRoot $script:NxbH2DeferredSnapshotRoot -AllowMissing
            $script:NxbH2BrokerHandoffComplete = $true
        }
        catch {
            $cleanupErrors.Add("destination broker final cleanup failed: $($_.Exception.Message)")
        }
    }

    Microsoft.PowerShell.Management\Remove-Item Function:\New-Item -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Management\Remove-Item Function:\Test-Path -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Management\Remove-Item Function:\Remove-Item -ErrorAction SilentlyContinue

    if ($null -ne $h2EntryStream) {
        try { $h2EntryStream.Dispose() }
        catch { $cleanupErrors.Add("H2 entry inner handle disposal failed: $($_.Exception.Message)") }
    }
}

if ($null -ne $primaryError) {
    if ($cleanupErrors.Count -gt 0) {
        throw "NXB-153 Windows H2 broker entry failed: $($primaryError.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
    }
    throw $primaryError
}
if ($cleanupErrors.Count -gt 0) {
    Fail-NxbH2BrokerEntry ("cleanup failed after otherwise successful handoff: " + ($cleanupErrors -join ' | '))
}
if ($SelfTest) {
    Write-Host 'NXB-153 Windows H2 broker-entry source self-test chain passed.'
}
