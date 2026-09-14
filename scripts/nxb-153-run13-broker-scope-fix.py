#!/usr/bin/env python3
from pathlib import Path

path = Path("scripts/nxb-153-windows-immutable-source-h2-broker-entry.ps1")
text = path.read_text(encoding="utf-8")

replacements = {
    "$script:NxbH2DeferredSnapshotRoot": "$brokerEntryState.DeferredSnapshotRoot",
    "$script:NxbH2BrokerHandoffEstablished": "$brokerEntryState.HandoffEstablished",
    "$script:NxbH2BrokerStopped": "$brokerEntryState.Stopped",
}
for old, new in replacements.items():
    text = text.replace(old, new)

old_state = '''$brokerEntryState.DeferredSnapshotRoot = $null
$brokerEntryState.HandoffEstablished = $false
$brokerEntryState.Stopped = $false
$primaryError = $null
'''
new_state = r'''$brokerEntryState = @{
    DeferredSnapshotRoot = $null
    HandoffEstablished = $false
    Stopped = $false
}
$testSnapshotPathProxy = (Get-Command Test-NxbH2BrokerSnapshotPath -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()
Set-Item -Path Function:\Test-NxbH2BrokerSnapshotPath -Value $testSnapshotPathProxy -Force
$primaryError = $null
'''
if old_state not in text:
    raise SystemExit("missing broker-entry state initialization anchor")
text = text.replace(old_state, new_state, 1)

proxy_end = r'''            Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters
        }
    }

    $innerParameters = @{}
'''
proxy_closure = r'''            Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters
        }

        $newItemProxy = (Get-Command New-Item -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()
        $testPathProxy = (Get-Command Test-Path -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()
        $removeItemProxy = (Get-Command Remove-Item -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()
        Set-Item -Path Function:\New-Item -Value $newItemProxy -Force
        Set-Item -Path Function:\Test-Path -Value $testPathProxy -Force
        Set-Item -Path Function:\Remove-Item -Value $removeItemProxy -Force
    }

    $innerParameters = @{}
'''
if proxy_end not in text:
    raise SystemExit("missing broker-entry proxy closure anchor")
text = text.replace(proxy_end, proxy_closure, 1)

for forbidden in replacements:
    if forbidden in text:
        raise SystemExit(f"caller-sensitive broker-entry state remains: {forbidden}")

path.write_text(text, encoding="utf-8", newline="\n")
