#!/usr/bin/env python3
from pathlib import Path

path = Path("scripts/nxb-153-windows-immutable-source-bounded-inner.ps1")
text = path.read_text(encoding="utf-8")

replacements = {
    "$script:NxbH2BrokerProcess": "$brokerState.Process",
    "$script:NxbH2BrokerSnapshotRoot": "$brokerState.SnapshotRoot",
    "$script:NxbH2CopyPython": "$brokerState.Python",
    "$script:NxbH2BrokerHelperPath": "$brokerState.HelperPath",
    "$script:NxbH2CopyExpected": "$copyState.Expected",
    "$script:NxbH2CopySourceRoot": "$copyState.SourceRoot",
    "$script:NxbH2CopyDestination": "$copyState.Destination",
    "$script:NxbH2CopyInvoked": "$copyState.Invoked",
}
for old, new in replacements.items():
    text = text.replace(old, new)

old_state = '''$copyState.Expected = $null
$copyState.SourceRoot = $null
$copyState.Destination = $null
$copyState.Invoked = $false
$brokerState.Python = $null
$brokerState.HelperPath = $null
$brokerState.Process = $null
$brokerState.SnapshotRoot = $null
$primaryError = $null
'''
new_state = r'''$copyState = @{
    Expected = $null
    SourceRoot = $null
    Destination = $null
    Invoked = $false
}
$brokerState = @{
    Python = $null
    HelperPath = $null
    Process = $null
    SnapshotRoot = $null
}

$startBrokerProxy = (Get-Command Start-NxbH2DestinationBroker -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()
$assertBrokerProxy = (Get-Command Assert-NxbH2DestinationBroker -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()
$stopBrokerProxy = (Get-Command Stop-NxbH2DestinationBroker -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()
Set-Item -Path Function:\Start-NxbH2DestinationBroker -Value $startBrokerProxy -Force
Set-Item -Path Function:\Assert-NxbH2DestinationBroker -Value $assertBrokerProxy -Force
Set-Item -Path Function:\Stop-NxbH2DestinationBroker -Value $stopBrokerProxy -Force

$primaryError = $null
'''
if old_state not in text:
    raise SystemExit("missing bounded H2 state initialization anchor")
text = text.replace(old_state, new_state, 1)

copy_end = '''        }
    }

    $innerParameters = @{}
'''
copy_closure = r'''        }
        $copyItemProxy = (Get-Command Copy-Item -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()
        Set-Item -Path Function:\Copy-Item -Value $copyItemProxy -Force
    }

    $innerParameters = @{}
'''
if copy_end not in text:
    raise SystemExit("missing Copy-Item closure anchor")
text = text.replace(copy_end, copy_closure, 1)

for forbidden in replacements:
    if forbidden in text:
        raise SystemExit(f"caller-sensitive bounded H2 state remains: {forbidden}")

path.write_text(text, encoding="utf-8", newline="\n")
