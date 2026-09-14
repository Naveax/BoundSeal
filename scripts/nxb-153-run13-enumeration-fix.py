#!/usr/bin/env python3
from pathlib import Path

path = Path("scripts/nxb-153-windows-immutable-source-enumeration-inner.ps1")
text = path.read_text(encoding="utf-8")
start = text.find("$script:NxbH2EnumerationLimit = 131072\n\nfunction Get-ChildItem {")
end = text.find("\nfunction Invoke-NxbH2EnumerationSelfTest {", start)
if start < 0 or end < 0:
    raise SystemExit("missing enumeration proxy patch anchor")
proxy = r'''$script:NxbH2EnumerationLimits = @{
    Count = 131072
}
$enumerationLimits = $script:NxbH2EnumerationLimits
$getChildItemProxy = {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [switch]$Force,
        [switch]$Recurse,
        [switch]$Directory,
        [switch]$File
    )

    if ($Directory -and $File) {
        throw 'NXB-153 Windows H2 enumeration guard failed: bounded Get-ChildItem proxy rejects simultaneous -Directory and -File'
    }

    $invoke = @{ LiteralPath = $LiteralPath }
    if ($Force) { $invoke.Force = $true }
    if ($Recurse) { $invoke.Recurse = $true }
    if ($Directory) { $invoke.Directory = $true }
    if ($File) { $invoke.File = $true }

    [Int64]$count = 0
    Microsoft.PowerShell.Management\Get-ChildItem @invoke | ForEach-Object {
        $count++
        if ($count -gt $enumerationLimits.Count) {
            throw "NXB-153 Windows H2 enumeration guard failed: Get-ChildItem enumeration-count bound exceeded for $LiteralPath"
        }
        $_
    }
}.GetNewClosure()
Set-Item -Path Function:\Get-ChildItem -Value $getChildItemProxy -Force
'''
text = text[:start] + proxy + text[end:]
text = text.replace("$savedLimit = $script:NxbH2EnumerationLimit", "$savedLimit = $script:NxbH2EnumerationLimits.Count", 1)
text = text.replace("$script:NxbH2EnumerationLimit = 4", "$script:NxbH2EnumerationLimits.Count = 4", 1)
text = text.replace("$script:NxbH2EnumerationLimit = 2", "$script:NxbH2EnumerationLimits.Count = 2", 1)
text = text.replace("$script:NxbH2EnumerationLimit = $savedLimit", "$script:NxbH2EnumerationLimits.Count = $savedLimit", 1)
for forbidden in [
    "$script:NxbH2EnumerationLimit =",
    "$script:NxbH2EnumerationLimit\n",
    "$script:NxbH2EnumerationLimit)",
    "$script:NxbH2EnumerationLimit]",
]:
    if forbidden in text:
        raise SystemExit(f"caller-sensitive enumeration scalar remains: {forbidden}")
path.write_text(text, encoding="utf-8", newline="\n")
