use std::{
    fs,
    path::{Path, PathBuf},
};

const VALIDATOR_PATH: &str = "scripts/validate-nxb-153-windows-inner.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn validator_source() -> String {
    let path = repository_root().join(VALIDATOR_PATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn unique_index(text: &str, needle: &str) -> usize {
    let mut matches = text.match_indices(needle);
    let first = matches
        .next()
        .unwrap_or_else(|| panic!("{VALIDATOR_PATH}: missing required source marker: {needle}"));
    assert!(
        matches.next().is_none(),
        "{VALIDATOR_PATH}: source marker must occur exactly once: {needle}"
    );
    first.0
}

fn last_index(text: &str, needle: &str) -> usize {
    text.rfind(needle)
        .unwrap_or_else(|| panic!("{VALIDATOR_PATH}: missing required source marker: {needle}"))
}

#[test]
fn windows_validator_withholds_pass_until_all_cleanup_succeeds() {
    let text = validator_source();

    for marker in [
        "$primaryFailure = $null",
        "$cleanupErrors = [Collections.Generic.List[string]]::new()",
        "$locationPushed = $false",
        "$validationSucceeded = $false",
        "$evidencePrimaryFailure = $null",
        "$evidenceCleanupFailure = $null",
        "$evidencePrimaryFailure = $_",
        "$evidenceCleanupFailure = $_",
        "$validationSucceeded = $true",
        "$primaryFailure = $_",
        "immutable source stream cleanup failed",
        "Cargo.lock stream cleanup failed",
        "tooling receipt stream cleanup failed",
        "cargo-deny stream cleanup failed",
        "cargo-audit stream cleanup failed",
        "validation lock cleanup failed",
        "namespace handle cleanup failed at index ${index}",
        "location restoration failed",
        "NXB-153 Windows validation failed:",
        "NXB-153 Windows validation cleanup failed after otherwise successful validation:",
        "NXB-153 Windows validation reached cleanup without an explicit successful validation state.",
    ] {
        assert!(
            text.contains(marker),
            "{VALIDATOR_PATH}: missing cleanup/PASS-withholding marker: {marker}"
        );
    }

    for forbidden in [
        "if ($null -ne $immutableSourceStream) {\n        $immutableSourceStream.Dispose()",
        "if ($null -ne $cargoLockStream) {\n        $cargoLockStream.Dispose()",
        "if ($null -ne $receiptStream) {\n        $receiptStream.Dispose()",
        "if ($null -ne $denyToolStream) {\n        $denyToolStream.Dispose()",
        "if ($null -ne $auditToolStream) {\n        $auditToolStream.Dispose()",
        "if ($null -ne $validationLockStream) {\n        $validationLockStream.Dispose()",
        "$namespaceHandles[$index].Dispose()\n    }\n    Pop-Location",
    ] {
        assert!(
            !text.contains(forbidden),
            "{VALIDATOR_PATH}: legacy short-circuit cleanup pattern is present: {forbidden}"
        );
    }

    let push_index = unique_index(&text, "    Push-Location $RepoRoot");
    let pushed_index = unique_index(&text, "    $locationPushed = $true");
    let success_index = unique_index(&text, "    $validationSucceeded = $true");
    let primary_failure_gate = unique_index(&text, "if ($null -ne $primaryFailure) {");
    let cleanup_failure_gate = last_index(&text, "if ($cleanupErrors.Count -gt 0) {");
    let explicit_success_gate = unique_index(&text, "if (-not $validationSucceeded) {");
    let pass_index = unique_index(
        &text,
        "Write-Host 'NXB-153 Windows validation passed from an exact-head pinned write-denied source snapshot.'",
    );

    assert_eq!(
        text.matches("if ($cleanupErrors.Count -gt 0) {").count(),
        2,
        "{VALIDATOR_PATH}: expected primary-failure and cleanup-only cleanup-error gates"
    );
    assert!(
        push_index < pushed_index,
        "{VALIDATOR_PATH}: location authority must be marked only after Push-Location succeeds"
    );
    assert!(
        pushed_index < success_index,
        "{VALIDATOR_PATH}: successful validation must be recorded only after location authority is established"
    );
    assert!(
        success_index < primary_failure_gate,
        "{VALIDATOR_PATH}: cleanup/error arbitration must occur after the protected validation body"
    );
    assert!(
        primary_failure_gate < cleanup_failure_gate,
        "{VALIDATOR_PATH}: primary failure must be preserved before cleanup-only failure arbitration"
    );
    assert!(
        cleanup_failure_gate < explicit_success_gate && explicit_success_gate < pass_index,
        "{VALIDATOR_PATH}: PASS output must occur only after cleanup and explicit-success gates"
    );

    let evidence_primary_gate = unique_index(&text, "    if ($null -ne $evidencePrimaryFailure) {");
    let evidence_cleanup_gate = last_index(&text, "    if ($null -ne $evidenceCleanupFailure) {");
    assert_eq!(
        text.matches("if ($null -ne $evidenceCleanupFailure) {").count(),
        2,
        "{VALIDATOR_PATH}: expected combined-primary and cleanup-only evidence cleanup gates"
    );
    assert!(
        evidence_primary_gate < evidence_cleanup_gate && evidence_cleanup_gate < success_index,
        "{VALIDATOR_PATH}: evidence cleanup must preserve primary publication failure before validation success"
    );

    assert_eq!(
        text.matches("try { $namespaceHandles[$index].Dispose() }").count(),
        1,
        "{VALIDATOR_PATH}: namespace cleanup must remain one independently guarded reverse-order loop"
    );
    assert_eq!(
        text.matches("try { Pop-Location }").count(),
        1,
        "{VALIDATOR_PATH}: location restoration must be independently guarded exactly once"
    );
}
