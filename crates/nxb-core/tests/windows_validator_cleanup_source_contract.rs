use std::{
    fs,
    path::{Path, PathBuf},
};

const VALIDATOR_PATH: &str = "scripts/validate-nxb-153-windows-inner.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source() -> String {
    fs::read_to_string(repository_root().join(VALIDATOR_PATH)).unwrap()
}

fn index(text: &str, marker: &str) -> usize {
    text.find(marker)
        .unwrap_or_else(|| panic!("{VALIDATOR_PATH}: missing marker: {marker}"))
}

#[test]
fn production_validator_uses_one_non_short_circuit_cleanup_state_machine() {
    let text = source();
    for marker in [
        "function Invoke-NxbValidationCleanup",
        "Label = 'immutable source stream'",
        "Label = 'Cargo.lock stream'",
        "Label = 'tooling receipt stream'",
        "Label = 'cargo-deny stream'",
        "Label = 'cargo-audit stream'",
        "Label = 'validation lock'",
        "$($entry.Label) cleanup failed:",
        "namespace handle cleanup failed at index ${index}",
        "location restoration failed",
        "$cleanupResult = Invoke-NxbValidationCleanup",
        "foreach ($cleanupError in $cleanupResult.Errors)",
        "Assert-NxbValidationOutcome",
    ] {
        assert!(
            text.contains(marker),
            "{VALIDATOR_PATH}: missing cleanup authority marker: {marker}"
        );
    }
    let finally = index(
        &text,
        "finally {\n    $cleanupResult = Invoke-NxbValidationCleanup",
    );
    let arbitration = text.rfind("Assert-NxbValidationOutcome `").unwrap();
    let pass = index(&text, "Write-Host 'NXB-153 Windows validation passed from an exact-head pinned write-denied source snapshot.'");
    assert!(finally < arbitration && arbitration < pass);
}

#[test]
fn evidence_publication_preserves_primary_failure_through_cleanup_failure() {
    let text = source();
    for marker in [
        "function Assert-NxbEvidencePublicationOutcome",
        "Windows validation evidence publication failed:",
        "Windows validation evidence handle cleanup failed after successful publication:",
        "Assert-NxbEvidencePublicationOutcome `",
        "-PrimaryFailure $evidencePrimaryFailure",
        "-CleanupFailure $evidenceCleanupFailure",
    ] {
        assert!(
            text.contains(marker),
            "{VALIDATOR_PATH}: missing evidence arbitration marker: {marker}"
        );
    }
}

#[test]
fn runtime_fault_self_test_drives_the_same_production_cleanup_and_arbitration_helpers() {
    let text = source();
    for marker in [
        "[ValidateSet('none', 'cleanup-faults')]",
        "function Invoke-NxbCleanupFaultSelfTest",
        "Cleanup self-test short-circuited before",
        "Cleanup self-test did not release/delete the validation lock",
        "Cleanup self-test did not restore the original PowerShell location",
        "Cleanup self-test reached PASS arbitration after a late cleanup failure",
        "Cleanup self-test did not preserve the evidence publication failure as primary",
        "NXB-153 Windows cleanup fault self-test passed.",
    ] {
        assert!(
            text.contains(marker),
            "{VALIDATOR_PATH}: missing runtime fault-proof marker: {marker}"
        );
    }
    assert!(text.matches("Invoke-NxbValidationCleanup `").count() >= 2);
    assert!(text.matches("Assert-NxbValidationOutcome").count() >= 3);
    assert!(text.matches("Assert-NxbEvidencePublicationOutcome").count() >= 2);
}
