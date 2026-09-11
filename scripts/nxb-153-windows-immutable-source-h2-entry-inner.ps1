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

function Fail-NxbH2Entry {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "NXB-153 Windows H2 entrypoint failed: $Message"
}

function ConvertTo-NxbH2EntryHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Open-NxbH2EntryPinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-NxbH2Entry "$Label must be a regular non-reparse file: $Path"
    }
    try {
        return [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
    }
    catch {
        Fail-NxbH2Entry "could not pin $Label with write/delete sharing withheld: $($_.Exception.Message)"
    }
}

function Get-NxbH2EntryGitBlobOid {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        Fail-NxbH2Entry "$Label stream must be readable and seekable"
    }
    $saved = $Stream.Position
    try {
        $Stream.Position = 0
        $length = $Stream.Length
        if ($length -le 0 -or $length -gt 2097152) {
            Fail-NxbH2Entry "$Label size is outside the supported implementation envelope"
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
                Fail-NxbH2Entry "$Label changed size while hashing"
            }
            [void]$sha1.TransformFinalBlock([byte[]]::new(0), 0, 0)
            return (ConvertTo-NxbH2EntryHex -Bytes $sha1.Hash)
        }
        finally {
            $sha1.Dispose()
        }
    }
    finally {
        $Stream.Position = $saved
    }
}

function Assert-NxbH2EntryCommittedFile {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $expected = (git rev-parse "${HeadSha}:$RelativePath").Trim()
    if ($LASTEXITCODE -ne 0 -or $expected -notmatch '^[0-9a-f]{40}$') {
        Fail-NxbH2Entry "exact-head $Label Git object could not be resolved"
    }
    $type = (git cat-file -t $expected).Trim()
    if ($LASTEXITCODE -ne 0 -or $type -cne 'blob') {
        Fail-NxbH2Entry "exact-head $Label is not a Git blob"
    }
    $actual = Get-NxbH2EntryGitBlobOid -Stream $Stream -Label $Label
    if ($actual -cne $expected) {
        Fail-NxbH2Entry "pinned $Label bytes differ from exact-head Git authority"
    }
}

if ($null -eq ('Nxb153H2SelfTestNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class Nxb153H2SelfTestNative
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    public static SafeFileHandle OpenDirectoryNoDeleteShare(string path)
    {
        SafeFileHandle handle = CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "CreateFileW failed for " + path);
        }
        return handle;
    }
}
'@
}

function Invoke-NxbH2EntryPrimitiveSelfTest {
    param([Parameter(Mandatory = $true)][string]$Root)

    $testRoot = Join-Path $Root ('.nxb-153-h2-selftest-' + [Guid]::NewGuid().ToString('N'))
    $guardedDirectory = Join-Path $testRoot 'guarded'
    $renameTarget = Join-Path $testRoot 'renamed'
    $guardedFile = Join-Path $guardedDirectory 'trusted.txt'
    $executableProbe = Join-Path $guardedDirectory 'cmd-probe.exe'
    $fileStream = $null
    $directoryHandle = $null
    $originalAcl = $null
    $aclApplied = $false
    $primaryError = $null
    $cleanupErrors = [Collections.Generic.List[string]]::new()

    try {
        [void](New-Item -ItemType Directory -Path $guardedDirectory -Force -ErrorAction Stop)
        [IO.File]::WriteAllText($guardedFile, 'trusted')

        $comSpec = [Environment]::GetEnvironmentVariable('ComSpec')
        if ([string]::IsNullOrWhiteSpace($comSpec) -or -not (Test-Path -LiteralPath $comSpec -PathType Leaf)) {
            Fail-NxbH2Entry 'ComSpec is unavailable for H2 process-launch self-test'
        }
        Copy-Item -LiteralPath $comSpec -Destination $executableProbe -ErrorAction Stop

        $fileStream = [IO.File]::Open(
            $guardedFile,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $writeOpened = $false
        try {
            $probe = [IO.File]::Open($guardedFile, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $probe.Dispose()
            $writeOpened = $true
        }
        catch [UnauthorizedAccessException] {}
        catch [IO.IOException] {}
        if ($writeOpened) {
            Fail-NxbH2Entry 'FileShare.Read self-test allowed concurrent write access'
        }

        $deleteSucceeded = $false
        try {
            [IO.File]::Delete($guardedFile)
            $deleteSucceeded = $true
        }
        catch [UnauthorizedAccessException] {}
        catch [IO.IOException] {}
        if ($deleteSucceeded -or -not (Test-Path -LiteralPath $guardedFile -PathType Leaf)) {
            Fail-NxbH2Entry 'FileShare.Read self-test allowed delete access'
        }

        $directoryHandle = [Nxb153H2SelfTestNative]::OpenDirectoryNoDeleteShare($guardedDirectory)
        $renameSucceeded = $false
        try {
            [IO.Directory]::Move($guardedDirectory, $renameTarget)
            $renameSucceeded = $true
        }
        catch [UnauthorizedAccessException] {}
        catch [IO.IOException] {}
        if ($renameSucceeded -or -not (Test-Path -LiteralPath $guardedDirectory -PathType Container)) {
            Fail-NxbH2Entry 'directory handle self-test allowed rename/delete authority'
        }

        $originalAcl = Get-Acl -LiteralPath $guardedDirectory -ErrorAction Stop
        $acl = Get-Acl -LiteralPath $guardedDirectory -ErrorAction Stop
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $denyRights = [IO.FileSystemRights]::WriteData -bor
            [IO.FileSystemRights]::AppendData -bor
            [IO.FileSystemRights]::CreateFiles -bor
            [IO.FileSystemRights]::CreateDirectories -bor
            [IO.FileSystemRights]::Delete -bor
            [IO.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [IO.FileSystemRights]::WriteAttributes -bor
            [IO.FileSystemRights]::WriteExtendedAttributes
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            $denyRights,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Deny
        )
        [void]$acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $guardedDirectory -AclObject $acl -ErrorAction Stop
        $aclApplied = $true

        $fileInjection = Join-Path $guardedDirectory ('file-' + [Guid]::NewGuid().ToString('N'))
        $dirInjection = Join-Path $guardedDirectory ('dir-' + [Guid]::NewGuid().ToString('N'))
        $created = $false
        try { [IO.File]::WriteAllText($fileInjection, 'x'); $created = $true }
        catch [UnauthorizedAccessException] {}
        catch [IO.IOException] {}
        if ($created -or (Test-Path -LiteralPath $fileInjection)) {
            Fail-NxbH2Entry 'ACL self-test allowed file injection'
        }
        $created = $false
        try { [void][IO.Directory]::CreateDirectory($dirInjection); $created = $true }
        catch [UnauthorizedAccessException] {}
        catch [IO.IOException] {}
        if ($created -or (Test-Path -LiteralPath $dirInjection)) {
            Fail-NxbH2Entry 'ACL self-test allowed directory injection'
        }

        & $executableProbe /d /c exit 0
        if ($LASTEXITCODE -ne 0) {
            Fail-NxbH2Entry "ACL/share-mode self-test blocked executable process launch: exit $LASTEXITCODE"
        }
    }
    catch {
        $primaryError = $_
    }
    finally {
        if ($aclApplied -and $null -ne $originalAcl) {
            try { Set-Acl -LiteralPath $guardedDirectory -AclObject $originalAcl -ErrorAction Stop }
            catch { $cleanupErrors.Add("ACL restore failed: $($_.Exception.Message)") }
        }
        if ($null -ne $directoryHandle) {
            try { $directoryHandle.Dispose() }
            catch { $cleanupErrors.Add("directory handle dispose failed: $($_.Exception.Message)") }
        }
        if ($null -ne $fileStream) {
            try { $fileStream.Dispose() }
            catch { $cleanupErrors.Add("file handle dispose failed: $($_.Exception.Message)") }
        }
        if (Test-Path -LiteralPath $testRoot) {
            try { Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop }
            catch { $cleanupErrors.Add("self-test cleanup failed: $($_.Exception.Message)") }
        }
    }

    if ($null -ne $primaryError) {
        if ($cleanupErrors.Count -gt 0) {
            throw "H2 primitive self-test failed: $($primaryError.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
        }
        throw $primaryError
    }
    if ($cleanupErrors.Count -gt 0) {
        Fail-NxbH2Entry ("H2 primitive self-test cleanup failed: " + ($cleanupErrors -join ' | '))
    }
}

if (-not $IsWindows) {
    Fail-NxbH2Entry 'Windows H2 entrypoint must run on Windows'
}
if ($HeadSha -notmatch '^[0-9a-f]{40}$') {
    Fail-NxbH2Entry 'exact head is not canonical 40-hex SHA-1'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$ValidationDirectory = [IO.Path]::GetFullPath($ValidationDirectory)
$h2InnerRelative = 'scripts/nxb-153-windows-immutable-source-h2-inner.ps1'
$h2InnerPath = Join-Path (Join-Path $RepoRoot 'scripts') 'nxb-153-windows-immutable-source-h2-inner.ps1'
$h2InnerStream = $null

try {
    $h2InnerStream = Open-NxbH2EntryPinnedFile -Path $h2InnerPath -Label 'Windows H2 inner runner'
    Assert-NxbH2EntryCommittedFile -Stream $h2InnerStream -RelativePath $h2InnerRelative -Label 'Windows H2 inner runner'

    $innerParameters = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        $innerParameters[$entry.Key] = $entry.Value
    }

    if ($SelfTest) {
        Invoke-NxbH2EntryPrimitiveSelfTest -Root $ValidationDirectory
    }

    & $h2InnerPath @innerParameters

    $finalOid = Get-NxbH2EntryGitBlobOid -Stream $h2InnerStream -Label 'Windows H2 inner runner final pinned object'
    $expectedOid = (git rev-parse "${HeadSha}:$h2InnerRelative").Trim()
    if ($LASTEXITCODE -ne 0 -or $finalOid -cne $expectedOid) {
        Fail-NxbH2Entry 'Windows H2 inner runner authority changed during execution'
    }

    if ($SelfTest) {
        Write-Host 'NXB-153 Windows H2 file-share/directory-handle/ACL/process primitive self-test passed.'
    }
}
finally {
    if ($null -ne $h2InnerStream) {
        $h2InnerStream.Dispose()
    }
}
