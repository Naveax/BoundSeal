[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [ValidateRange(50, 10000)][int]$ProbeReadTimeoutMilliseconds = 1500,
    [ValidateRange(50, 10000)][int]$ProbeExitTimeoutMilliseconds = 2000,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$policy = 'nxb-153-windows-tool-version-output-probe-v1'
$productionByteLimit = 4096
$productionReadTimeoutMilliseconds = 30000
$productionExitTimeoutMilliseconds = 30000
$productionCharacterLimit = 256

function Fail-NxbToolVersionProbe {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows tool-version output probe failed: $Message"
}

function Get-NxbSmallCommandOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $false
    $start.CreateNoWindow = $true
    foreach ($argument in $Arguments) {
        [void]$start.ArgumentList.Add([string]$argument)
    }

    $process = [Diagnostics.Process]::new()
    $memory = [IO.MemoryStream]::new()
    try {
        $process.StartInfo = $start
        if (-not $process.Start()) {
            Fail-NxbToolVersionProbe "$Label process could not be started"
        }
        $buffer = [byte[]]::new(1024)
        [Int64]$total = 0
        while ($true) {
            $readTask = $process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $readTask.Wait(30000)) {
                Fail-NxbToolVersionProbe "$Label stdout made no progress for 30000 ms"
            }
            $read = $readTask.Result
            if ($read -le 0) { break }
            $total += $read
            if ($total -gt 4096) {
                Fail-NxbToolVersionProbe "$Label stdout exceeds the 4096-byte control-plane envelope"
            }
            $memory.Write($buffer, 0, $read)
        }
        if (-not $process.WaitForExit(30000)) {
            Fail-NxbToolVersionProbe "$Label process did not exit after stdout closed"
        }
        if ($process.ExitCode -ne 0) {
            Fail-NxbToolVersionProbe "$Label failed with exit code $($process.ExitCode)"
        }
        $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
        try {
            $value = $strictUtf8.GetString($memory.ToArray()).Trim()
        }
        catch {
            Fail-NxbToolVersionProbe "$Label stdout is not strict UTF-8: $($_.Exception.Message)"
        }
        if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256) {
            Fail-NxbToolVersionProbe "$Label did not return one bounded value"
        }
        return $value
    }
    finally {
        try {
            if (-not $process.HasExited) {
                $process.Kill($true)
                [void]$process.WaitForExit(30000)
            }
        }
        catch {}
        $memory.Dispose()
        $process.Dispose()
    }
}

function Assert-NxbExactHeadFile {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$HeadSha,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $full = Join-Path $RepoRoot ($RelativePath -replace '/', [IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Fail-NxbToolVersionProbe "required source file is missing: $RelativePath"
    }
    $expected = Get-NxbSmallCommandOutput -Executable $GitPath -Arguments @('-C', $RepoRoot, 'rev-parse', "${HeadSha}:$RelativePath") -Label "Git object for $RelativePath"
    $actual = Get-NxbSmallCommandOutput -Executable $GitPath -Arguments @('-C', $RepoRoot, 'hash-object', '--', $full) -Label "working-tree object for $RelativePath"
    if ($expected -notmatch '^[0-9a-f]{40}$' -or $actual -cne $expected) {
        Fail-NxbToolVersionProbe "working-tree bytes differ from exact-head Git authority: $RelativePath"
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
        Fail-NxbToolVersionProbe "PowerShell parser rejected $Path"
    }
    $matches = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name
    }, $true))
    if ($matches.Count -ne 1) {
        Fail-NxbToolVersionProbe "expected one function '$Name' in $Path, found $($matches.Count)"
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
        Fail-NxbToolVersionProbe "$Label is missing required source pattern '$Needle'"
    }
}

function Assert-NxbAbsent {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Needle,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ($Text.IndexOf($Needle, [StringComparison]::Ordinal) -ge 0) {
        Fail-NxbToolVersionProbe "$Label retains forbidden source pattern '$Needle'"
    }
}

function Assert-NxbToolPreparationSourceContract {
    param([Parameter(Mandatory = $true)][string]$Path)

    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $text = [IO.File]::ReadAllText($Path, $strictUtf8)
    foreach ($requirement in @(
        '(?m)^\$fixedOutputByteLimit\s*=\s*4096\s*$',
        '(?m)^\$fixedOutputReadTimeoutMilliseconds\s*=\s*30000\s*$',
        '(?m)^\$fixedOutputExitTimeoutMilliseconds\s*=\s*30000\s*$'
    )) {
        if (-not [regex]::IsMatch($text, $requirement)) {
            Fail-NxbToolVersionProbe "tool-preparation source no longer retains fixed-output production constant: $requirement"
        }
    }
    Assert-NxbContains -Text $text -Needle "'RUSTC_WRAPPER'" -Label 'tool-preparation ambient authority'
    Assert-NxbAbsent -Text $text -Needle 'Out-String' -Label 'tool-preparation fixed-output source'

    $bounded = Get-NxbFunctionText -Path $Path -Name 'Invoke-NxbBoundedFixedOutput'
    foreach ($needle in @(
        'RedirectStandardOutput = $true',
        'RedirectStandardError = $false',
        'StandardOutput.BaseStream.ReadAsync(',
        '$readTask.Wait($fixedOutputReadTimeoutMilliseconds)',
        '$total -gt $fixedOutputByteLimit',
        'WaitForExit($fixedOutputExitTimeoutMilliseconds)',
        '[Text.UTF8Encoding]::new($false, $true)',
        '$value.Length -gt 256',
        'Kill($true)'
    )) {
        Assert-NxbContains -Text $bounded -Needle $needle -Label 'bounded tool-version helper'
    }
    Assert-NxbAbsent -Text $bounded -Needle 'ReadToEndAsync(' -Label 'bounded tool-version helper'
    Assert-NxbAbsent -Text $bounded -Needle 'ReadLineAsync(' -Label 'bounded tool-version helper'
    Assert-NxbAbsent -Text $bounded -Needle 'WaitForExit()' -Label 'bounded tool-version helper'

    $toolVersion = Get-NxbFunctionText -Path $Path -Name 'Get-ToolVersion'
    Assert-NxbContains -Text $toolVersion -Needle 'Invoke-NxbBoundedFixedOutput' -Label 'Get-ToolVersion'
    Assert-NxbContains -Text $toolVersion -Needle "@('--version')" -Label 'Get-ToolVersion'
    Assert-NxbAbsent -Text $toolVersion -Needle 'Out-String' -Label 'Get-ToolVersion'

    Assert-NxbContains -Text $text -Needle "@('run', `$rustToolchain, 'rustc', '--version')" -Label 'tooling receipt rustc version'
    Assert-NxbContains -Text $text -Needle "-Label 'Rust 1.97.1 receipt version'" -Label 'tooling receipt rustc version'
    return $bounded
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
        Fail-NxbToolVersionProbe "$Label unexpectedly succeeded"
    }
    if ($failure.Exception.Message.IndexOf($ExpectedFragment, [StringComparison]::Ordinal) -lt 0) {
        Fail-NxbToolVersionProbe "$Label failed for the wrong reason: $($failure.Exception.Message)"
    }
    if ($watch.Elapsed.TotalSeconds -gt 10) {
        Fail-NxbToolVersionProbe "$Label exceeded the bounded probe wall-clock envelope"
    }
    $script:Results.Add($Label)
}

if (-not $IsWindows) {
    Fail-NxbToolVersionProbe 'probe requires supported Windows PowerShell/.NET process semantics'
}
if ($PSVersionTable.PSEdition -cne 'Core') {
    Fail-NxbToolVersionProbe 'probe requires PowerShell Core because production uses ProcessStartInfo.ArgumentList and Process.Kill(true)'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$gitCommand = Get-Command git -CommandType Application -ErrorAction Stop
$gitPath = $gitCommand.Source
$headSha = Get-NxbSmallCommandOutput -Executable $gitPath -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -Label 'exact Git HEAD'
if ($headSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbToolVersionProbe 'exact Git HEAD is not canonical 40-hex SHA-1'
}

$toolPreparation = Assert-NxbExactHeadFile -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/prepare-and-validate-nxb-153-windows-inner.ps1'
$self = Assert-NxbExactHeadFile -GitPath $gitPath -HeadSha $headSha -RelativePath 'scripts/nxb-153-windows-tool-version-output-probe.ps1'
$boundedFunctionText = Assert-NxbToolPreparationSourceContract -Path $toolPreparation.Path

# Load only the exact production helper body from the exact-head AST. Dynamic
# tests intentionally shorten timeout constants; the static contract above
# separately pins the production 4096 / 30000 / 30000 values.
$fixedOutputByteLimit = $productionByteLimit
$fixedOutputReadTimeoutMilliseconds = $ProbeReadTimeoutMilliseconds
$fixedOutputExitTimeoutMilliseconds = $ProbeExitTimeoutMilliseconds
. ([scriptblock]::Create($boundedFunctionText))

$script:Results = [Collections.Generic.List[string]]::new()
$script:Results.Add('exact-head tool-preparation source/AST contract')
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('nxb-153-tool-version-probe-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
$helperPath = Join-Path $temporaryRoot 'child.ps1'
$descendantPidPath = Join-Path $temporaryRoot 'descendant.pid'
$shellPath = (Get-Process -Id $PID -ErrorAction Stop).Path
if ([string]::IsNullOrWhiteSpace($shellPath) -or -not (Test-Path -LiteralPath $shellPath -PathType Leaf)) {
    Fail-NxbToolVersionProbe 'current PowerShell executable path is unavailable'
}

$helperText = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Mode,
    [string]$PidPath
)
$ErrorActionPreference = 'Stop'
switch -CaseSensitive ($Mode) {
    'normal' {
        [Console]::Out.WriteLine('cargo-audit 0.22.2')
        exit 0
    }
    'oversize' {
        $bytes = [Text.Encoding]::ASCII.GetBytes(('x' * 4097))
        $stream = [Console]::OpenStandardOutput()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        exit 0
    }
    'invalid-utf8' {
        $bytes = [byte[]](255, 10)
        $stream = [Console]::OpenStandardOutput()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        exit 0
    }
    'nonzero' {
        [Console]::Out.WriteLine('cargo-audit 0.22.2')
        exit 17
    }
    'stall-no-output' {
        Start-Sleep -Seconds 30
        exit 0
    }
    'output-then-stall' {
        [Console]::Out.WriteLine('cargo-audit 0.22.2')
        [Console]::Out.Flush()
        Start-Sleep -Seconds 30
        exit 0
    }
    'close-stdout-then-stall' {
        Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class Nxb153ProbeStdout
{
    private const uint STD_OUTPUT_HANDLE = unchecked((uint)-11);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(uint nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static void CloseRedirectedStdout()
    {
        IntPtr handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetStdHandle(STD_OUTPUT_HANDLE) failed");
        }
        if (!CloseHandle(handle))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle(STD_OUTPUT_HANDLE) failed");
        }
    }
}
"@
        [Nxb153ProbeStdout]::CloseRedirectedStdout()
        Start-Sleep -Seconds 30
        exit 0
    }
    'spawn-descendant-stall' {
        if ([string]::IsNullOrWhiteSpace($PidPath)) { exit 23 }
        $shell = (Get-Process -Id $PID -ErrorAction Stop).Path
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $shell
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Mode', 'stall-no-output')) {
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
[IO.File]::WriteAllText($helperPath, $helperText, [Text.UTF8Encoding]::new($false))

function Invoke-NxbProductionHelperProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [string]$PidPath
    )
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $helperPath, '-Mode', $Mode)) {
        $arguments.Add([string]$argument)
    }
    if (-not [string]::IsNullOrWhiteSpace($PidPath)) {
        $arguments.Add('-PidPath')
        $arguments.Add($PidPath)
    }
    return Invoke-NxbBoundedFixedOutput -FilePath $shellPath -Arguments @($arguments) -Label "production helper $Mode"
}

try {
    $normal = Invoke-NxbProductionHelperProbe -Mode 'normal'
    if ($normal -cne 'cargo-audit 0.22.2') {
        Fail-NxbToolVersionProbe "production helper changed normal output: $normal"
    }
    $script:Results.Add('production helper normal fixed-output primitive')

    Assert-NxbExpectedFailure -Label 'production helper oversize rejection primitive' -ExpectedFragment 'fixed-output envelope' -Action {
        [void](Invoke-NxbProductionHelperProbe -Mode 'oversize')
    }
    Assert-NxbExpectedFailure -Label 'production helper invalid-UTF8 rejection primitive' -ExpectedFragment 'not strict UTF-8' -Action {
        [void](Invoke-NxbProductionHelperProbe -Mode 'invalid-utf8')
    }
    Assert-NxbExpectedFailure -Label 'production helper nonzero-exit primitive' -ExpectedFragment 'exit code 17' -Action {
        [void](Invoke-NxbProductionHelperProbe -Mode 'nonzero')
    }
    Assert-NxbExpectedFailure -Label 'production helper stalled-output timeout primitive' -ExpectedFragment 'made no progress' -Action {
        [void](Invoke-NxbProductionHelperProbe -Mode 'stall-no-output')
    }
    Assert-NxbExpectedFailure -Label 'production helper output-then-stall read-timeout primitive' -ExpectedFragment 'made no progress' -Action {
        [void](Invoke-NxbProductionHelperProbe -Mode 'output-then-stall')
    }
    Assert-NxbExpectedFailure -Label 'production helper post-stdout exit-timeout primitive' -ExpectedFragment 'did not exit within' -Action {
        [void](Invoke-NxbProductionHelperProbe -Mode 'close-stdout-then-stall')
    }

    Assert-NxbExpectedFailure -Label 'production helper recursive-cleanup timeout primitive' -ExpectedFragment 'made no progress' -Action {
        [void](Invoke-NxbProductionHelperProbe -Mode 'spawn-descendant-stall' -PidPath $descendantPidPath)
    }
    if (-not (Test-Path -LiteralPath $descendantPidPath -PathType Leaf)) {
        Fail-NxbToolVersionProbe 'recursive-cleanup child did not publish descendant PID'
    }
    $descendantText = [IO.File]::ReadAllText($descendantPidPath).Trim()
    [int]$descendantId = 0
    if (-not [Int32]::TryParse($descendantText, [ref]$descendantId) -or $descendantId -le 0) {
        Fail-NxbToolVersionProbe 'recursive-cleanup descendant PID is invalid'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(2)
    do {
        $descendant = Get-Process -Id $descendantId -ErrorAction SilentlyContinue
        if ($null -eq $descendant) { break }
        Start-Sleep -Milliseconds 20
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -ne (Get-Process -Id $descendantId -ErrorAction SilentlyContinue)) {
        try { Stop-Process -Id $descendantId -Force -ErrorAction SilentlyContinue } catch {}
        Fail-NxbToolVersionProbe 'production helper recursive cleanup did not terminate the descendant process tree'
    }
    $script:Results.Add('production helper recursive process-tree cleanup primitive')

    $record = [ordered]@{
        schema_version = 1
        policy = $policy
        milestone = 'NXB-153'
        platform = 'windows'
        head_sha = $headSha
        tool_preparation_source_object = $toolPreparation.ObjectId
        probe_source_object = $self.ObjectId
        production_output_byte_limit = $productionByteLimit
        production_read_timeout_milliseconds = $productionReadTimeoutMilliseconds
        production_exit_timeout_milliseconds = $productionExitTimeoutMilliseconds
        production_character_limit = $productionCharacterLimit
        probe_read_timeout_milliseconds = $ProbeReadTimeoutMilliseconds
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
        Write-Host "NXB-153 Windows tool-version output probe passed for HEAD $headSha."
        Write-Host "Tool-preparation source object: $($toolPreparation.ObjectId)"
        Write-Host "Probe source object: $($self.ObjectId)"
        Write-Host "Probe tests: $($script:Results.Count)"
    }
}
finally {
    Remove-Item Function:\Invoke-NxbBoundedFixedOutput -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
