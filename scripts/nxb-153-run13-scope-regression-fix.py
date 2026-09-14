#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/nxb-core/tests/nxb153_admission_runtime_regression_source_contract.rs")
text = path.read_text(encoding="utf-8")

constant_anchor = 'const WINDOWS_H2_INNER_PATH: &str = "scripts/nxb-153-windows-immutable-source-h2-inner.ps1";\n'
constants = constant_anchor + '''const WINDOWS_ENUMERATION_GUARD_PATH: &str =\n    "scripts/nxb-153-windows-immutable-source-enumeration-inner.ps1";\nconst WINDOWS_BOUNDED_H2_PATH: &str =\n    "scripts/nxb-153-windows-immutable-source-bounded-inner.ps1";\nconst WINDOWS_BROKER_ENTRY_PATH: &str =\n    "scripts/nxb-153-windows-immutable-source-h2-broker-entry.ps1";\n'''
if "WINDOWS_ENUMERATION_GUARD_PATH" not in text:
    if constant_anchor not in text:
        raise SystemExit("missing Windows H2 constant anchor")
    text = text.replace(constant_anchor, constants, 1)

insert_anchor = "\n#[test]\nfn rust_toolchain_authority_self_test_uses_native_platform_model()"
tests = r'''

#[test]
fn windows_enumeration_proxy_captures_its_bound_across_nested_script_scopes() {
    let source = read_source(WINDOWS_ENUMERATION_GUARD_PATH);
    for marker in [
        "$script:NxbH2EnumerationLimits = @{",
        "$enumerationLimits = $script:NxbH2EnumerationLimits",
        r#"Set-Item -Path Function:\Get-ChildItem -Value $getChildItemProxy -Force"#,
    ] {
        assert!(
            source.contains(marker),
            "{WINDOWS_ENUMERATION_GUARD_PATH}: missing enumeration-state capture marker: {marker}"
        );
    }

    let start = required_offset(
        &source,
        "$getChildItemProxy = {",
        WINDOWS_ENUMERATION_GUARD_PATH,
    );
    let end_marker = "}.GetNewClosure()";
    let end = start
        + required_offset(
            &source[start..],
            end_marker,
            WINDOWS_ENUMERATION_GUARD_PATH,
        )
        + end_marker.len();
    let proxy = &source[start..end];
    for marker in [
        "$getChildItemProxy = {",
        "$enumerationLimits.Count",
        "}.GetNewClosure()",
    ] {
        assert!(
            proxy.contains(marker),
            "{WINDOWS_ENUMERATION_GUARD_PATH}: missing closure marker: {marker}"
        );
    }
    assert!(
        !proxy.contains("$script:"),
        "{WINDOWS_ENUMERATION_GUARD_PATH}: lexical proxy body still reaches caller-sensitive script scope"
    );
}

#[test]
fn windows_bounded_h2_cross_script_functions_capture_shared_state() {
    let source = read_source(WINDOWS_BOUNDED_H2_PATH);
    for marker in [
        "$copyState = @{",
        "$brokerState = @{",
        ".ScriptBlock.GetNewClosure()",
        r#"Set-Item -Path Function:\Start-NxbH2DestinationBroker -Value $startBrokerProxy -Force"#,
        r#"Set-Item -Path Function:\Assert-NxbH2DestinationBroker -Value $assertBrokerProxy -Force"#,
        r#"Set-Item -Path Function:\Stop-NxbH2DestinationBroker -Value $stopBrokerProxy -Force"#,
        r#"Set-Item -Path Function:\Copy-Item -Value $copyItemProxy -Force"#,
        "$copyState.Expected",
        "$brokerState.Process",
    ] {
        assert!(source.contains(marker), "{WINDOWS_BOUNDED_H2_PATH}: missing lexical/shared-state marker: {marker}");
    }
    for forbidden in ["$script:NxbH2Copy", "$script:NxbH2Broker"] {
        assert!(!source.contains(forbidden), "{WINDOWS_BOUNDED_H2_PATH}: caller-sensitive state remains: {forbidden}");
    }
}

#[test]
fn windows_broker_entry_proxies_capture_handoff_state() {
    let source = read_source(WINDOWS_BROKER_ENTRY_PATH);
    for marker in [
        "$brokerEntryState = @{",
        "$testSnapshotPathProxy = (Get-Command Test-NxbH2BrokerSnapshotPath",
        "$newItemProxy = (Get-Command New-Item",
        "$testPathProxy = (Get-Command Test-Path",
        "$removeItemProxy = (Get-Command Remove-Item",
        ".ScriptBlock.GetNewClosure()",
        r#"Set-Item -Path Function:\New-Item -Value $newItemProxy -Force"#,
        r#"Set-Item -Path Function:\Test-Path -Value $testPathProxy -Force"#,
        r#"Set-Item -Path Function:\Remove-Item -Value $removeItemProxy -Force"#,
        "$brokerEntryState.DeferredSnapshotRoot",
        "$brokerEntryState.HandoffEstablished",
        "$brokerEntryState.Stopped",
    ] {
        assert!(source.contains(marker), "{WINDOWS_BROKER_ENTRY_PATH}: missing lexical/shared-state marker: {marker}");
    }
    for forbidden in [
        "$script:NxbH2DeferredSnapshotRoot",
        "$script:NxbH2BrokerHandoffEstablished",
        "$script:NxbH2BrokerStopped",
    ] {
        assert!(!source.contains(forbidden), "{WINDOWS_BROKER_ENTRY_PATH}: caller-sensitive handoff state remains: {forbidden}");
    }
}
'''
if "windows_enumeration_proxy_captures_its_bound_across_nested_script_scopes" not in text:
    if insert_anchor not in text:
        raise SystemExit("missing runtime regression insertion anchor")
    text = text.replace(insert_anchor, tests + insert_anchor, 1)

path.write_text(text, encoding="utf-8", newline="\n")
