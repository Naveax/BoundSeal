use std::{
    fs,
    path::{Path, PathBuf},
};

const BOUNDED_H2_PATH: &str = "scripts/nxb-153-windows-immutable-source-bounded-inner.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

#[test]
fn bounded_h2_child_proxies_bind_helper_and_enumeration_authority_lexically() {
    let script = source(BOUNDED_H2_PATH);

    for binding in [
        "$failCopyEntryProxy = (Get-Command Fail-NxbH2CopyEntry -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()",
        "$readBrokerLineProxy = (Get-Command Read-NxbH2BrokerLine -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()",
        "$convertBrokerRecordProxy = (Get-Command ConvertFrom-NxbH2BrokerRecord -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()",
        "$startBrokerProxy = (Get-Command Start-NxbH2DestinationBroker -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()",
        "$assertBrokerProxy = (Get-Command Assert-NxbH2DestinationBroker -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()",
        "$stopBrokerProxy = (Get-Command Stop-NxbH2DestinationBroker -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()",
        "$enumerationProxy = (Get-Command Get-ChildItem -CommandType Function -ErrorAction Stop).ScriptBlock",
    ] {
        assert!(
            script.contains(binding),
            "bounded H2 must capture child-visible helper authority before proxy installation: {binding}"
        );
    }

    for invocation in [
        "& $failCopyEntryProxy -Message 'bounded Copy-Item shim rejected non-recursive/non-force invocation'",
        "foreach ($item in @(& $enumerationProxy -LiteralPath $sourceRoot -Force -ErrorAction Stop))",
        "& $startBrokerProxy -SourceRoot $sourceRoot -SnapshotRoot $destinationFull",
        "& $readBrokerLineProxy -Process $process -Label 'destination broker readiness' -TimeoutMilliseconds 1800000",
        "& $convertBrokerRecordProxy -Line $line -Label 'destination broker readiness'",
        "& $stopBrokerProxy -SnapshotRoot $brokerState.SnapshotRoot -AllowMissing",
    ] {
        assert!(
            script.contains(invocation),
            "bounded H2 proxy path must invoke captured authority lexically: {invocation}"
        );
    }

    assert!(
        !script.contains("foreach ($item in Get-ChildItem -LiteralPath $sourceRoot -Force -ErrorAction Stop)"),
        "Copy-Item shim must not bypass the inherited bounded enumeration proxy through dynamic cmdlet lookup"
    );
    assert!(
        !script.contains("                Start-NxbH2DestinationBroker -SourceRoot $sourceRoot -SnapshotRoot $destinationFull"),
        "Copy-Item shim must not dynamically resolve the broker starter from child scope"
    );

    let helper_capture = script
        .find("$failCopyEntryProxy =")
        .expect("helper authority capture must exist");
    let copy_closure = script
        .find("$copyItemProxy = (Get-Command Copy-Item")
        .expect("Copy-Item proxy closure must exist");
    let child_call = script
        .find("    & $entryInnerPath @innerParameters")
        .expect("bounded H2 must execute broker entry in child scope");

    assert!(
        helper_capture < copy_closure && copy_closure < child_call,
        "helper/enumeration authority must be captured before Copy-Item closure creation and child execution"
    );
}
