use std::{
    fs,
    path::{Path, PathBuf},
};

const BROKER_ENTRY_PATH: &str = "scripts/nxb-153-windows-immutable-source-h2-broker-entry.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

#[test]
fn h2_broker_child_proxies_bind_cross_scope_helpers_lexically() {
    let script = source(BROKER_ENTRY_PATH);

    for binding in [
        "$failBrokerEntryProxy = (Get-Command Fail-NxbH2BrokerEntry -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()",
        "$testSnapshotPathEvaluator = (Get-Command Test-NxbH2BrokerSnapshotPath -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()",
        "$assertDestinationBrokerProxy = (Get-Command Assert-NxbH2DestinationBroker -CommandType Function -ErrorAction Stop).ScriptBlock",
        "$stopDestinationBrokerProxy = (Get-Command Stop-NxbH2DestinationBroker -CommandType Function -ErrorAction Stop).ScriptBlock",
    ] {
        assert!(
            script.contains(binding),
            "broker entry must capture helper authority before installing child-visible proxy functions: {binding}"
        );
    }

    for invocation in [
        "(& $testSnapshotPathEvaluator -Path $Path)",
        "& $failBrokerEntryProxy -Message 'H2 snapshot root creation was requested more than once'",
        "& $assertDestinationBrokerProxy -SnapshotRoot $brokerEntryState.DeferredSnapshotRoot",
        "& $stopDestinationBrokerProxy -SnapshotRoot $brokerEntryState.DeferredSnapshotRoot -AllowMissing",
    ] {
        assert!(
            script.contains(invocation),
            "child-visible proxy must invoke captured helper authority lexically: {invocation}"
        );
    }

    assert!(
        !script.contains("(Test-NxbH2BrokerSnapshotPath -Path $Path)"),
        "New-Item proxy must not depend on dynamic lookup of the broker snapshot predicate"
    );

    let helper_capture = script
        .find("$testSnapshotPathEvaluator =")
        .expect("snapshot-path helper capture must exist");
    let new_item_closure = script
        .find("$newItemProxy = (Get-Command New-Item")
        .expect("New-Item proxy closure must exist");
    let child_call = script
        .find("    & $h2EntryPath @innerParameters")
        .expect("H2 entry must execute in child scope");

    assert!(
        helper_capture < new_item_closure && new_item_closure < child_call,
        "helper authority must be captured before proxy closure creation and child execution"
    );
}
