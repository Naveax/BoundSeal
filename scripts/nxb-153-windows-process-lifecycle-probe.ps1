[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [ValidateRange(50, 10000)][int]$ProbeIoTimeoutMilliseconds = 1000,
    [ValidateRange(50, 10000)][int]$ProbeExitTimeoutMilliseconds = 1500,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$policy = 'nxb-153-windows-process-lifecycle-probe-v1'
$productionIoTimeoutMilliseconds = 300000
$productionExitTimeoutMilliseconds = 30000
$largeProbeBytes = 8 * 1024 * 1024

function Fail-NxbProcessProbe {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows process lifecycle probe failed: $Message"
}

function Get-NxbSmallCommandOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $value = (& $Executable @Arguments | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256) {
        Fail-NxbProcessProbe "$Label did not return one bounded value"
    }
    return $value
}

function Assert-NxbExactHeadFile {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$HeadSha,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    $full = Join-Path $RepoRoot ($RelativePath -replace '/', [IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Fail-NxbProcessProbe "required source file is missing: $RelativePath"
    }
    $expected = Get-NxbSmallCommandOutput -Executable $GitPath -Arguments @('-C', $RepoRoot, 'rev-parse', "${HeadSha}:$RelativePath") -Label "Git object for $RelativePath"
    $actual = Get-NxbSmallCommandOutput -Executable $GitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $full) -Label "working-tree object for $RelativePath"
    if ($expected -notmatch '^[0-9a-f]{40}$' -or $actual -cne $expected) {
        Fail-NxbProcessProbe "working-tree bytes differ from exact-head Git authority: $RelativePath"
    }
    return [pscustomobject]@{ Path = $full; ObjectId = $expected }
}

function Get-NxbFunctionText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -ne 0) {
        Fail-NxbProcessProbe "PowerShell parser rejected $Path"
    }
    $matches = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name
    }, $true))
    if ($matches.Count -ne 1) {
        Fail-NxbProcessProbe "expected one function '$Name' in $Path, found $($matches.Count)"
    }
    return $matches[0].Extent.Text
}

function Assert-NxbContains {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Needle,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ($Text.IndexOf($Needle, [StringComparison]::Ordinal) -lt 0) {
        Fail-NxbProcessProbe "$Label is missing required source pattern '$Needle'"
    }
}

function Assert-NxbAbsent {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Needle,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ($Text.IndexOf($Needle, [StringComparison]::Ordinal) -ge 0) {
        Fail-NxbProcessProbe "$Label retains forbidden source pattern '$Needle'"
    }
}

function Assert-NxbProductionSourceContract {
    param(
        [Parameter(Mandatory = $true)][string]$DependencyPath,
        [Parameter(Mandatory = $true)][string]$ImmutablePath,
        [Parameter(Mandatory = $true)][string]$BoundedPath
    )
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $dependencyText = [IO.File]::ReadAllText($DependencyPath, $strictUtf8)
    $immutableText = [IO.File]::ReadAllText($ImmutablePath, $strictUtf8)

    foreach ($pair in @(
        [pscustomobject]@{ Text = $dependencyText; Label = 'dependency source' },
        [pscustomobject]@{ Text = $immutableText; Label = 'immutable source' }
    )) {
        if (-not [regex]::IsMatch($pair.Text, '(?m)^\$childIoInactivityTimeoutMilliseconds\s*=\s*300000\s*$')) {
            Fail-NxbProcessProbe "$($pair.Label) does not retain the 300000 ms production I/O timeout"
        }
        if (-not [regex]::IsMatch($pair.Text, '(?m)^\$childExitTimeoutMilliseconds\s*=\s*30000\s*$')) {
            Fail-NxbProcessProbe "$($pair.Label) does not retain the 30000 ms production exit timeout"
        }
        if ($pair.Text.Contains('ReadToEndAsync()')) {
            Fail-NxbProcessProbe "$($pair.Label) reintroduced direct ReadToEndAsync retention"
        }
    }
    if (-not [regex]::IsMatch($immutableText, '(?m)^\$maximumArchiveBytes\s*=\s*1073741824\s*$')) {
        Fail-NxbProcessProbe 'immutable source does not retain the 1 GiB Git archive ceiling'
    }

    $registry = Get-NxbFunctionText -Path $DependencyPath -Name 'Invoke-NxbRegistryVerifierWithInput'
    Assert-NxbContains -Text $registry -Needle 'WriteAsync(' -Label 'registry verifier'
    Assert-NxbContains -Text $registry -Needle 'FlushAsync()' -Label 'registry verifier'
    Assert-NxbContains -Text $registry -Needle 'WaitForExit($childExitTimeoutMilliseconds)' -Label 'registry verifier'
    Assert-NxbContains -Text $registry -Needle 'Kill($true)' -Label 'registry verifier'
    Assert-NxbAbsent -Text $registry -Needle 'StandardInput.Write(' -Label 'registry verifier'
    Assert-NxbAbsent -Text $registry -Needle 'WaitForExit()' -Label 'registry verifier'

    $archive = Get-NxbFunctionText -Path $ImmutablePath -Name 'New-NxbPinnedGitArchive'
    Assert-NxbContains -Text $archive -Needle 'ReadAsync(' -Label 'Git archive'
    Assert-NxbContains -Text $archive -Needle 'WaitForExit($childExitTimeoutMilliseconds)' -Label 'Git archive'
    Assert-NxbContains -Text $archive -Needle 'Kill($true)' -Label 'Git archive'
    Assert-NxbAbsent -Text $archive -Needle 'BaseStream.Read(' -Label 'Git archive'
    Assert-NxbAbsent -Text $archive -Needle 'WaitForExit()' -Label 'Git archive'

    $tar = Get-NxbFunctionText -Path $ImmutablePath -Name 'Expand-NxbPinnedTarArchive'
    Assert-NxbContains -Text $tar -Needle 'WriteAsync(' -Label 'tar extraction'
    Assert-NxbContains -Text $tar -Needle 'FlushAsync()' -Label 'tar extraction'
    Assert-NxbContains -Text $tar -Needle 'WaitForExit($childExitTimeoutMilliseconds)' -Label 'tar extraction'
    Assert-NxbContains -Text $tar -Needle 'Kill($true)' -Label 'tar extraction'
    Assert-NxbAbsent -Text $tar -Needle 'CopyTo(' -Label 'tar extraction'
    Assert-NxbAbsent -Text $tar -Needle 'WaitForExit()' -Label 'tar extraction'

    $brokerReader = Get-NxbFunctionText -Path $BoundedPath -Name 'Read-NxbH2BrokerLine'
    Assert-NxbContains -Text $brokerReader -Needle 'StandardOutput.BaseStream' -Label 'broker control reader'
    Assert-NxbContains -Text $brokerReader -Needle 'ReadAsync(' -Label 'broker control reader'
    Assert-NxbContains -Text $brokerReader -Needle '$memory.Length -ge 65537' -Label 'broker control reader'
    Assert-NxbContains -Text $brokerReader -Needle '$length -gt 65536' -Label 'broker control reader'
    Assert-NxbContains -Text $brokerReader -Needle 'Kill($true)' -Label 'broker control reader'
    Assert-NxbContains -Text $brokerReader -Needle 'WaitForExit(30000)' -Label 'broker control reader'
    Assert-NxbContains -Text $brokerReader -Needle 'GetString($raw, 0, $length)' -Label 'broker control reader'
    Assert-NxbAbsent -Text $brokerReader -Needle 'ReadLineAsync(' -Label 'broker control reader'
    Assert-NxbAbsent -Text $brokerReader -Needle 'ReadToEndAsync(' -Label 'broker control reader'
    return $brokerReader
}

function New-NxbProbeProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [switch]$RedirectInput,
        [switch]$RedirectOutput,
        [string]$PidPath
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $script:ShellPath
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $RedirectInput.IsPresent
    $start.RedirectStandardOutput = $RedirectOutput.IsPresent
    $start.RedirectStandardError = $false
    foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:HelperPath, '-Mode', $Mode)) {
        [void]$start.ArgumentList.Add([string]$argument)
    }
    if (-not [string]::IsNullOrEmpty($PidPath)) {
        [void]$start.ArgumentList.Add('-PidPath')
        [void]$start.ArgumentList.Add($PidPath)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        $process.Dispose()
        Fail-NxbProcessProbe "could not start probe child mode $Mode"
    }
    return $process
}

function Stop-NxbProbeProcess {
    param([Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) {
            try {
                $Process.Kill($true)
            }
            catch {
                if (-not $Process.HasExited) { throw }
            }
            if (-not $Process.HasExited -and -not $Process.WaitForExit($ProbeExitTimeoutMilliseconds * 4)) {
                Fail-NxbProcessProbe 'probe child could not be reaped after recursive termination'
            }
        }
    }
    finally {
        $Process.Dispose()
    }
}

function Assert-NxbExpectedFailure {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$ExpectedFragment,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $failure = $null
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
    }
    catch {
        $failure = $_
    }
    finally {
        $watch.Stop()
    }
    if ($null -eq $failure) {
        Fail-NxbProcessProbe "$Label unexpectedly succeeded"
    }
    if ($failure.Exception.Message.IndexOf($ExpectedFragment, [StringComparison]::Ordinal) -lt 0) {
        Fail-NxbProcessProbe "$Label failed for the wrong reason: $($failure.Exception.Message)"
    }
    if ($watch.Elapsed.TotalSeconds -gt 10) {
        Fail-NxbProcessProbe "$Label exceeded the bounded probe wall-clock envelope"
    }
    $script:Results.Add($Label)
}

function Invoke-NxbTextInputProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$Text
    )
    $process = $null
    try {
        $process = New-NxbProbeProcess -Mode $Mode -RedirectInput
        $writeTask = $process.StandardInput.WriteAsync($Text)
        if (-not $writeTask.Wait($ProbeIoTimeoutMilliseconds)) {
            throw 'probe-io-timeout'
        }
        $flushTask = $process.StandardInput.FlushAsync()
        if (-not $flushTask.Wait($ProbeIoTimeoutMilliseconds)) {
            throw 'probe-flush-timeout'
        }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit($ProbeExitTimeoutMilliseconds)) {
            throw 'probe-exit-timeout'
        }
        if ($process.ExitCode -ne 0) {
            throw "probe-exit-code:$($process.ExitCode)"
        }
    }
    finally {
        Stop-NxbProbeProcess -Process $process
    }
}

function Invoke-NxbBinaryInputProbe {
    param([Parameter(Mandatory = $true)][string]$Mode)
    $process = $null
    try {
        $process = New-NxbProbeProcess -Mode $Mode -RedirectInput
        $buffer = [byte[]]::new(1048576)
        for ($index = 0; $index -lt 16; $index++) {
            $writeTask = $process.StandardInput.BaseStream.WriteAsync($buffer, 0, $buffer.Length)
            if (-not $writeTask.Wait($ProbeIoTimeoutMilliseconds)) {
                throw 'probe-io-timeout'
            }
        }
        $flushTask = $process.StandardInput.BaseStream.FlushAsync()
        if (-not $flushTask.Wait($ProbeIoTimeoutMilliseconds)) {
            throw 'probe-flush-timeout'
        }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit($ProbeExitTimeoutMilliseconds)) {
            throw 'probe-exit-timeout'
        }
        if ($process.ExitCode -ne 0) {
            throw "probe-exit-code:$($process.ExitCode)"
        }
    }
    finally {
        Stop-NxbProbeProcess -Process $process
    }
}

function Invoke-NxbOutputProbe {
    param([Parameter(Mandatory = $true)][string]$Mode)
    $process = $null
    try {
        $process = New-NxbProbeProcess -Mode $Mode -RedirectOutput
        $buffer = [byte[]]::new(4096)
        [Int64]$total = 0
        while ($true) {
            $readTask = $process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $readTask.Wait($ProbeIoTimeoutMilliseconds)) {
                throw 'probe-io-timeout'
            }
            $read = $readTask.Result
            if ($read -le 0) { break }
            $total += $read
            if ($total -gt 65536) {
                throw 'probe-output-limit'
            }
        }
        if (-not $process.WaitForExit($ProbeExitTimeoutMilliseconds)) {
            throw 'probe-exit-timeout'
        }
        if ($process.ExitCode -ne 0) {
            throw "probe-exit-code:$($process.ExitCode)"
        }
        if ($total -le 0) {
            throw 'probe-empty-output'
        }
    }
    finally {
        Stop-NxbProbeProcess -Process $process
    }
}

function Invoke-NxbBrokerReaderProbe {
    param([Parameter(Mandatory = $true)][string]$Mode)
    $process = $null
    try {
        $process = New-NxbProbeProcess -Mode $Mode -RedirectOutput
        $line = Read-NxbH2BrokerLine -Process $process -Label "broker reader $Mode" -TimeoutMilliseconds $ProbeIoTimeoutMilliseconds
        if (-not $process.WaitForExit($ProbeExitTimeoutMilliseconds)) {
            throw 'probe-broker-exit-timeout'
        }
        if ($process.ExitCode -ne 0) {
            throw "probe-broker-exit-code:$($process.ExitCode)"
        }
        return $line
    }
    finally {
        Stop-NxbProbeProcess -Process $process
    }
}

function Invoke-NxbExitTimeoutProbe {
    $process = $null
    try {
        $process = New-NxbProbeProcess -Mode 'leaf-stall'
        if ($process.WaitForExit($ProbeExitTimeoutMilliseconds)) {
            Fail-NxbProcessProbe 'sleeping child exited before exit-timeout probe fired'
        }
        $script:Results.Add('post-I/O exit timeout primitive')
    }
    finally {
        Stop-NxbProbeProcess -Process $process
    }
}

function Invoke-NxbRecursiveKillProbe {
    $pidPath = Join-Path $script:TemporaryRoot 'descendant.pid'
    $process = $null
    $descendantId = 0
    try {
        $process = New-NxbProbeProcess -Mode 'spawn-descendant' -PidPath $pidPath
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        while (-not (Test-Path -LiteralPath $pidPath -PathType Leaf) -and [DateTime]::UtcNow -lt $deadline) {
            if ($process.HasExited) {
                Fail-NxbProcessProbe "recursive-kill parent exited early with $($process.ExitCode)"
            }
            Start-Sleep -Milliseconds 20
        }
        if (-not (Test-Path -LiteralPath $pidPath -PathType Leaf)) {
            Fail-NxbProcessProbe 'recursive-kill child did not publish descendant PID'
        }
        $pidText = [IO.File]::ReadAllText($pidPath).Trim()
        if (-not [Int32]::TryParse($pidText, [ref]$descendantId) -or $descendantId -le 0) {
            Fail-NxbProcessProbe 'recursive-kill descendant PID is invalid'
        }
        $process.Kill($true)
        if (-not $process.WaitForExit($ProbeExitTimeoutMilliseconds * 4)) {
            Fail-NxbProcessProbe 'recursive-kill parent could not be reaped'
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(2)
        do {
            $descendant = Get-Process -Id $descendantId -ErrorAction SilentlyContinue
            if ($null -eq $descendant) { break }
            Start-Sleep -Milliseconds 20
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($null -ne (Get-Process -Id $descendantId -ErrorAction SilentlyContinue)) {
            try { Stop-Process -Id $descendantId -Force -ErrorAction SilentlyContinue } catch {}
            Fail-NxbProcessProbe 'Process.Kill(true) did not terminate the descendant process tree'
        }
        $script:Results.Add('recursive process-tree termination primitive')
    }
    finally {
        Stop-NxbProbeProcess -Process $process
    }
}

if (-not $IsWindows) {
    Fail-NxbProcessProbe 'probe requires supported Windows PowerShell/.NET process semantics'
}
if ($PSVersionTable.PSEdition -cne 'Core') {
    Fail-NxbProcessProbe 'probe requires PowerShell Core because production uses ProcessStartInfo.ArgumentList and Process.Kill(true)'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$gitCommand = Get-Command git -CommandType Application -ErrorAction Stop
$gitPath = $gitCommand.Source
$headSha = Get-NxbSmallCommandOutput -Executable $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'exact Git HEAD'
if ($headSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbProcessProbe 'exact Git HEAD is not canonical 40-hex SHA-1'
}

$dependency = Assert-NxbExactHeadFile -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-dependency-source.ps1'
$immutable = Assert-NxbExactHeadFile -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-immutable-source-inner.ps1'
$bounded = Assert-NxbExactHeadFile -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-immutable-source-bounded-inner.ps1'
[void](Assert-NxbExactHeadFile -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-process-lifecycle-probe.ps1')
$brokerReaderText = Assert-NxbProductionSourceContract -DependencyPath $dependency.Path -ImmutablePath $immutable.Path -BoundedPath $bounded.Path

function Fail-NxbH2CopyEntry {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "broker-reader:$Message"
}
. ([scriptblock]::Create($brokerReaderText))

$script:Results = [Collections.Generic.List[string]]::new()
$script:Results.Add('exact-head source/AST contract')
$script:TemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('nxb-153-process-probe-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($script:TemporaryRoot) | Out-Null
$script:HelperPath = Join-Path $script:TemporaryRoot 'child.ps1'
$script:ShellPath = (Get-Process -Id $PID -ErrorAction Stop).Path
if ([string]::IsNullOrWhiteSpace($script:ShellPath) -or -not (Test-Path -LiteralPath $script:ShellPath -PathType Leaf)) {
    Fail-NxbProcessProbe 'current PowerShell executable path is unavailable'
}

$helperText = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Mode,
    [string]$PidPath
)
$ErrorActionPreference = 'Stop'
switch -CaseSensitive ($Mode) {
    'consume-stdin' {
        [Console]::OpenStandardInput().CopyTo([IO.Stream]::Null)
        exit 0
    }
    'consume-stdin-then-stall' {
        [Console]::OpenStandardInput().CopyTo([IO.Stream]::Null)
        Start-Sleep -Seconds 30
        exit 0
    }
    'stall-no-read' {
        Start-Sleep -Seconds 30
        exit 0
    }
    'write-stdout' {
        $bytes = [Text.Encoding]::ASCII.GetBytes('12345678')
        $stream = [Console]::OpenStandardOutput()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        exit 0
    }
    'write-stdout-nonzero' {
        $bytes = [Text.Encoding]::ASCII.GetBytes('12345678')
        $stream = [Console]::OpenStandardOutput()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        exit 17
    }
    'write-broker-line' {
        $bytes = [Text.Encoding]::UTF8.GetBytes("{`"status`":`"healthy`"}`r`n")
        $stream = [Console]::OpenStandardOutput()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        exit 0
    }
    'write-broker-no-newline' {
        $bytes = [Text.Encoding]::UTF8.GetBytes("{`"status`":`"healthy`"}")
        $stream = [Console]::OpenStandardOutput()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        exit 0
    }
    'write-broker-invalid-utf8' {
        $bytes = [byte[]](123, 255, 125, 10)
        $stream = [Console]::OpenStandardOutput()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        exit 0
    }
    'stall-no-output' {
        Start-Sleep -Seconds 30
        exit 0
    }
    'leaf-stall' {
        Start-Sleep -Seconds 30
        exit 0
    }
    'spawn-descendant' {
        if ([string]::IsNullOrWhiteSpace($PidPath)) { exit 23 }
        $shell = (Get-Process -Id $PID -ErrorAction Stop).Path
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $shell
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Mode', 'leaf-stall')) {
            [void]$start.ArgumentList.Add([string]$argument)
        }
        $child = [Diagnostics.Process]::Start($start)
        if ($null -eq $child) { exit 24 }
        [IO.File]::WriteAllText($PidPath, [string]$child.Id, [Text.UTF8Encoding]::new($false))
        Start-Sleep -Seconds 30
        exit 0
    }
    default { exit 25 }
}
'@
[IO.File]::WriteAllText($script:HelperPath, $helperText, [Text.UTF8Encoding]::new($false))

try {
    Invoke-NxbTextInputProbe -Mode 'consume-stdin' -Text 'ok'
    $script:Results.Add('registry-style text stdin success primitive')

    $largeText = [string]::new([char]'x', $largeProbeBytes)
    Assert-NxbExpectedFailure -Label 'registry-style stalled stdin timeout primitive' -ExpectedFragment 'probe-io-timeout' -Action {
        Invoke-NxbTextInputProbe -Mode 'stall-no-read' -Text $largeText
    }
    Assert-NxbExpectedFailure -Label 'registry-style post-stdin exit timeout primitive' -ExpectedFragment 'probe-exit-timeout' -Action {
        Invoke-NxbTextInputProbe -Mode 'consume-stdin-then-stall' -Text 'ok'
    }

    Invoke-NxbBinaryInputProbe -Mode 'consume-stdin'
    $script:Results.Add('tar-style binary stdin success primitive')
    Assert-NxbExpectedFailure -Label 'tar-style stalled stdin timeout primitive' -ExpectedFragment 'probe-io-timeout' -Action {
        Invoke-NxbBinaryInputProbe -Mode 'stall-no-read'
    }
    Assert-NxbExpectedFailure -Label 'tar-style post-stdin exit timeout primitive' -ExpectedFragment 'probe-exit-timeout' -Action {
        Invoke-NxbBinaryInputProbe -Mode 'consume-stdin-then-stall'
    }

    Invoke-NxbOutputProbe -Mode 'write-stdout'
    $script:Results.Add('Git-archive-style stdout success primitive')
    Assert-NxbExpectedFailure -Label 'Git-archive-style stalled stdout timeout primitive' -ExpectedFragment 'probe-io-timeout' -Action {
        Invoke-NxbOutputProbe -Mode 'stall-no-output'
    }
    Assert-NxbExpectedFailure -Label 'Git-archive-style nonzero exit primitive' -ExpectedFragment 'probe-exit-code:17' -Action {
        Invoke-NxbOutputProbe -Mode 'write-stdout-nonzero'
    }

    $brokerLine = Invoke-NxbBrokerReaderProbe -Mode 'write-broker-line'
    if ($brokerLine -cne '{"status":"healthy"}') {
        Fail-NxbProcessProbe "broker control reader changed CRLF payload: $brokerLine"
    }
    $script:Results.Add('broker-control bounded CRLF success primitive')
    Assert-NxbExpectedFailure -Label 'broker-control missing-newline rejection primitive' -ExpectedFragment 'control stream closed before newline' -Action {
        Invoke-NxbBrokerReaderProbe -Mode 'write-broker-no-newline'
    }
    Assert-NxbExpectedFailure -Label 'broker-control invalid-UTF8 rejection primitive' -ExpectedFragment 'response is not strict UTF-8' -Action {
        Invoke-NxbBrokerReaderProbe -Mode 'write-broker-invalid-utf8'
    }
    Assert-NxbExpectedFailure -Label 'broker-control stalled-output timeout primitive' -ExpectedFragment 'timed out' -Action {
        Invoke-NxbBrokerReaderProbe -Mode 'stall-no-output'
    }

    Invoke-NxbExitTimeoutProbe
    Invoke-NxbRecursiveKillProbe

    $record = [ordered]@{
        schema_version = 1
        policy = $policy
        milestone = 'NXB-153'
        platform = 'windows'
        head_sha = $headSha
        dependency_source_object = $dependency.ObjectId
        immutable_source_object = $immutable.ObjectId
        bounded_source_object = $bounded.ObjectId
        production_io_timeout_milliseconds = $productionIoTimeoutMilliseconds
        production_exit_timeout_milliseconds = $productionExitTimeoutMilliseconds
        probe_io_timeout_milliseconds = $ProbeIoTimeoutMilliseconds
        probe_exit_timeout_milliseconds = $ProbeExitTimeoutMilliseconds
        powershell_version = $PSVersionTable.PSVersion.ToString()
        tests = @($script:Results)
        status = 'passed'
        probed_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    if ($Json) {
        $record | ConvertTo-Json -Depth 5
    }
    else {
        Write-Host "NXB-153 Windows process lifecycle probe passed for HEAD $headSha."
        Write-Host "Dependency source object: $($dependency.ObjectId)"
        Write-Host "Immutable source object: $($immutable.ObjectId)"
        Write-Host "Bounded H2 source object: $($bounded.ObjectId)"
        Write-Host "Probe tests: $($script:Results.Count)"
    }
}
finally {
    Remove-Item Function:\Read-NxbH2BrokerLine -ErrorAction SilentlyContinue
    Remove-Item Function:\Fail-NxbH2CopyEntry -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $script:TemporaryRoot) {
        Remove-Item -LiteralPath $script:TemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
