#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"missing Windows cleanup-runtime anchor: {label}")
    return text.replace(old, new, 1)


def patch_validator() -> None:
    path = Path("scripts/validate-nxb-153-windows-inner.ps1")
    text = path.read_text(encoding="utf-8")

    old_param = '''[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)
'''
    new_param = '''[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [ValidateSet('none', 'cleanup-faults')]
    [string]$SelfTest = 'none'
)
'''
    if "[string]$SelfTest = 'none'" not in text:
        text = replace_once(text, old_param, new_param, "self-test parameter")

    insertion_anchor = '''$validationLockStream = $null
$auditToolStream = $null
'''
    helpers = r'''function Invoke-NxbValidationCleanup {
    param(
        [object]$ImmutableSourceStream,
        [object]$CargoLockStream,
        [object]$ReceiptStream,
        [object]$DenyToolStream,
        [object]$AuditToolStream,
        [object]$ValidationLockStream,
        [Parameter(Mandatory = $true)][System.Collections.IList]$NamespaceHandles,
        [Parameter(Mandatory = $true)][bool]$LocationPushed
    )

    $errors = [Collections.Generic.List[string]]::new()
    foreach ($entry in @(
        [pscustomobject]@{ Label = 'immutable source stream'; Value = $ImmutableSourceStream },
        [pscustomobject]@{ Label = 'Cargo.lock stream'; Value = $CargoLockStream },
        [pscustomobject]@{ Label = 'tooling receipt stream'; Value = $ReceiptStream },
        [pscustomobject]@{ Label = 'cargo-deny stream'; Value = $DenyToolStream },
        [pscustomobject]@{ Label = 'cargo-audit stream'; Value = $AuditToolStream },
        [pscustomobject]@{ Label = 'validation lock'; Value = $ValidationLockStream }
    )) {
        if ($null -eq $entry.Value) { continue }
        try { $entry.Value.Dispose() }
        catch { $errors.Add("$($entry.Label) cleanup failed: $($_.Exception.Message)") }
    }

    for ($index = $NamespaceHandles.Count - 1; $index -ge 0; $index--) {
        try { $NamespaceHandles[$index].Dispose() }
        catch { $errors.Add("namespace handle cleanup failed at index ${index}: $($_.Exception.Message)") }
    }
    if ($LocationPushed) {
        try { Pop-Location }
        catch { $errors.Add("location restoration failed: $($_.Exception.Message)") }
    }

    return [pscustomobject]@{ Errors = $errors }
}

function Assert-NxbEvidencePublicationOutcome {
    param(
        [object]$PrimaryFailure,
        [object]$CleanupFailure
    )

    if ($null -ne $PrimaryFailure) {
        if ($null -ne $CleanupFailure) {
            throw "Windows validation evidence publication failed: $($PrimaryFailure.Exception.Message); cleanup: $($CleanupFailure.Exception.Message)"
        }
        throw $PrimaryFailure
    }
    if ($null -ne $CleanupFailure) {
        throw "Windows validation evidence handle cleanup failed after successful publication: $($CleanupFailure.Exception.Message)"
    }
}

function Assert-NxbValidationOutcome {
    param(
        [object]$PrimaryFailure,
        [Parameter(Mandatory = $true)][Collections.Generic.List[string]]$CleanupErrors,
        [Parameter(Mandatory = $true)][bool]$ValidationSucceeded
    )

    if ($null -ne $PrimaryFailure) {
        if ($CleanupErrors.Count -gt 0) {
            throw "NXB-153 Windows validation failed: $($PrimaryFailure.Exception.Message); cleanup: $($CleanupErrors -join ' | ')"
        }
        throw $PrimaryFailure
    }
    if ($CleanupErrors.Count -gt 0) {
        throw "NXB-153 Windows validation cleanup failed after otherwise successful validation: $($CleanupErrors -join ' | ')"
    }
    if (-not $ValidationSucceeded) {
        throw 'NXB-153 Windows validation reached cleanup without an explicit successful validation state.'
    }
}

function New-NxbCleanupProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Fail,
        [Parameter(Mandatory = $true)][Collections.Generic.List[string]]$Log
    )
    $probe = [pscustomobject]@{
        Name = $Name
        Fail = $Fail
        Log = $Log
    }
    $probe | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        $this.Log.Add([string]$this.Name)
        if ($this.Fail) {
            throw "injected $($this.Name) cleanup failure"
        }
    }
    return $probe
}

function Invoke-NxbCleanupFaultSelfTest {
    $log = [Collections.Generic.List[string]]::new()
    $startLocation = (Get-Location).Path
    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("nxb153-cleanup-selftest-" + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    $lockPath = Join-Path $temporaryRoot 'validation.lock'
    $lock = [IO.FileStream]::new(
        $lockPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None,
        4096,
        [IO.FileOptions]::DeleteOnClose
    )
    $namespaceHandles = [Collections.ArrayList]::new()
    [void]$namespaceHandles.Add((New-NxbCleanupProbe -Name 'namespace-0' -Fail $false -Log $log))
    [void]$namespaceHandles.Add((New-NxbCleanupProbe -Name 'namespace-1' -Fail $false -Log $log))
    Push-Location $temporaryRoot

    $cleanup = Invoke-NxbValidationCleanup `
        -ImmutableSourceStream (New-NxbCleanupProbe -Name 'immutable' -Fail $true -Log $log) `
        -CargoLockStream (New-NxbCleanupProbe -Name 'cargo-lock' -Fail $false -Log $log) `
        -ReceiptStream (New-NxbCleanupProbe -Name 'receipt' -Fail $false -Log $log) `
        -DenyToolStream (New-NxbCleanupProbe -Name 'deny' -Fail $false -Log $log) `
        -AuditToolStream (New-NxbCleanupProbe -Name 'audit' -Fail $false -Log $log) `
        -ValidationLockStream $lock `
        -NamespaceHandles $namespaceHandles `
        -LocationPushed $true

    if ($cleanup.Errors.Count -ne 1 -or $cleanup.Errors[0] -notlike 'immutable source stream cleanup failed:*') {
        throw 'Cleanup self-test did not preserve the injected early cleanup failure.'
    }
    foreach ($expected in @('immutable', 'cargo-lock', 'receipt', 'deny', 'audit', 'namespace-1', 'namespace-0')) {
        if (-not $log.Contains($expected)) {
            throw "Cleanup self-test short-circuited before $expected."
        }
    }
    if (Test-Path -LiteralPath $lockPath) {
        throw 'Cleanup self-test did not release/delete the validation lock after an earlier cleanup failure.'
    }
    if ((Get-Location).Path -cne $startLocation) {
        throw 'Cleanup self-test did not restore the original PowerShell location.'
    }

    $lateErrors = [Collections.Generic.List[string]]::new()
    $lateErrors.Add('injected late cleanup failure')
    $passReached = $false
    try {
        Assert-NxbValidationOutcome -PrimaryFailure $null -CleanupErrors $lateErrors -ValidationSucceeded $true
        $passReached = $true
    }
    catch {
        if ($_.Exception.Message -notlike 'NXB-153 Windows validation cleanup failed after otherwise successful validation:*') {
            throw
        }
    }
    if ($passReached) {
        throw 'Cleanup self-test reached PASS arbitration after a late cleanup failure.'
    }

    $primary = [pscustomobject]@{ Exception = [Exception]::new('injected evidence publication failure') }
    $evidenceCleanup = [pscustomobject]@{ Exception = [Exception]::new('injected evidence cleanup failure') }
    $combinedObserved = $false
    try {
        Assert-NxbEvidencePublicationOutcome -PrimaryFailure $primary -CleanupFailure $evidenceCleanup
    }
    catch {
        if ($_.Exception.Message -like 'Windows validation evidence publication failed: injected evidence publication failure; cleanup: injected evidence cleanup failure') {
            $combinedObserved = $true
        }
        else {
            throw
        }
    }
    if (-not $combinedObserved) {
        throw 'Cleanup self-test did not preserve the evidence publication failure as primary.'
    }

    $emptyErrors = [Collections.Generic.List[string]]::new()
    Assert-NxbValidationOutcome -PrimaryFailure $null -CleanupErrors $emptyErrors -ValidationSucceeded $true

    Remove-Item -LiteralPath $temporaryRoot -Force
    Write-Host 'NXB-153 Windows cleanup fault self-test passed.'
}

if ($SelfTest -ceq 'cleanup-faults') {
    Invoke-NxbCleanupFaultSelfTest
    exit 0
}

'''
    if "function Invoke-NxbValidationCleanup" not in text:
        text = replace_once(text, insertion_anchor, helpers + insertion_anchor, "cleanup helper insertion")

    old_evidence = '''    if ($null -ne $evidencePrimaryFailure) {
        if ($null -ne $evidenceCleanupFailure) {
            throw "Windows validation evidence publication failed: $($evidencePrimaryFailure.Exception.Message); cleanup: $($evidenceCleanupFailure.Exception.Message)"
        }
        throw $evidencePrimaryFailure
    }
    if ($null -ne $evidenceCleanupFailure) {
        throw "Windows validation evidence handle cleanup failed after successful publication: $($evidenceCleanupFailure.Exception.Message)"
    }
'''
    new_evidence = '''    Assert-NxbEvidencePublicationOutcome `
        -PrimaryFailure $evidencePrimaryFailure `
        -CleanupFailure $evidenceCleanupFailure
'''
    if old_evidence in text:
        text = text.replace(old_evidence, new_evidence, 1)

    old_finally = '''finally {
    if ($null -ne $immutableSourceStream) {
        try { $immutableSourceStream.Dispose() }
        catch { $cleanupErrors.Add("immutable source stream cleanup failed: $($_.Exception.Message)") }
    }
    if ($null -ne $cargoLockStream) {
        try { $cargoLockStream.Dispose() }
        catch { $cleanupErrors.Add("Cargo.lock stream cleanup failed: $($_.Exception.Message)") }
    }
    if ($null -ne $receiptStream) {
        try { $receiptStream.Dispose() }
        catch { $cleanupErrors.Add("tooling receipt stream cleanup failed: $($_.Exception.Message)") }
    }
    if ($null -ne $denyToolStream) {
        try { $denyToolStream.Dispose() }
        catch { $cleanupErrors.Add("cargo-deny stream cleanup failed: $($_.Exception.Message)") }
    }
    if ($null -ne $auditToolStream) {
        try { $auditToolStream.Dispose() }
        catch { $cleanupErrors.Add("cargo-audit stream cleanup failed: $($_.Exception.Message)") }
    }
    if ($null -ne $validationLockStream) {
        try { $validationLockStream.Dispose() }
        catch { $cleanupErrors.Add("validation lock cleanup failed: $($_.Exception.Message)") }
    }
    for ($index = $namespaceHandles.Count - 1; $index -ge 0; $index--) {
        try { $namespaceHandles[$index].Dispose() }
        catch { $cleanupErrors.Add("namespace handle cleanup failed at index ${index}: $($_.Exception.Message)") }
    }
    if ($locationPushed) {
        try { Pop-Location }
        catch { $cleanupErrors.Add("location restoration failed: $($_.Exception.Message)") }
    }
}

if ($null -ne $primaryFailure) {
    if ($cleanupErrors.Count -gt 0) {
        throw "NXB-153 Windows validation failed: $($primaryFailure.Exception.Message); cleanup: $($cleanupErrors -join ' | ')"
    }
    throw $primaryFailure
}
if ($cleanupErrors.Count -gt 0) {
    throw "NXB-153 Windows validation cleanup failed after otherwise successful validation: $($cleanupErrors -join ' | ')"
}
if (-not $validationSucceeded) {
    throw 'NXB-153 Windows validation reached cleanup without an explicit successful validation state.'
}
'''
    new_finally = '''finally {
    $cleanupResult = Invoke-NxbValidationCleanup `
        -ImmutableSourceStream $immutableSourceStream `
        -CargoLockStream $cargoLockStream `
        -ReceiptStream $receiptStream `
        -DenyToolStream $denyToolStream `
        -AuditToolStream $auditToolStream `
        -ValidationLockStream $validationLockStream `
        -NamespaceHandles $namespaceHandles `
        -LocationPushed $locationPushed
    foreach ($cleanupError in $cleanupResult.Errors) {
        $cleanupErrors.Add([string]$cleanupError)
    }
}

Assert-NxbValidationOutcome `
    -PrimaryFailure $primaryFailure `
    -CleanupErrors $cleanupErrors `
    -ValidationSucceeded $validationSucceeded
'''
    if old_finally in text:
        text = text.replace(old_finally, new_finally, 1)

    path.write_text(text, encoding="utf-8", newline="\n")


def patch_source_contract() -> None:
    path = Path("crates/nxb-core/tests/windows_validator_cleanup_source_contract.rs")
    path.write_text(r'''use std::{fs, path::{Path, PathBuf}};

const VALIDATOR_PATH: &str = "scripts/validate-nxb-153-windows-inner.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source() -> String {
    fs::read_to_string(repository_root().join(VALIDATOR_PATH)).unwrap()
}

fn index(text: &str, marker: &str) -> usize {
    text.find(marker).unwrap_or_else(|| panic!("{VALIDATOR_PATH}: missing marker: {marker}"))
}

#[test]
fn production_validator_uses_one_non_short_circuit_cleanup_state_machine() {
    let text = source();
    for marker in [
        "function Invoke-NxbValidationCleanup",
        "immutable source stream cleanup failed",
        "Cargo.lock stream cleanup failed",
        "tooling receipt stream cleanup failed",
        "cargo-deny stream cleanup failed",
        "cargo-audit stream cleanup failed",
        "validation lock cleanup failed",
        "namespace handle cleanup failed at index ${index}",
        "location restoration failed",
        "$cleanupResult = Invoke-NxbValidationCleanup",
        "foreach ($cleanupError in $cleanupResult.Errors)",
        "Assert-NxbValidationOutcome",
    ] {
        assert!(text.contains(marker), "{VALIDATOR_PATH}: missing cleanup authority marker: {marker}");
    }
    let finally = index(&text, "finally {\n    $cleanupResult = Invoke-NxbValidationCleanup");
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
        assert!(text.contains(marker), "{VALIDATOR_PATH}: missing evidence arbitration marker: {marker}");
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
        assert!(text.contains(marker), "{VALIDATOR_PATH}: missing runtime fault-proof marker: {marker}");
    }
    assert!(text.matches("Invoke-NxbValidationCleanup `").count() >= 2);
    assert!(text.matches("Assert-NxbValidationOutcome").count() >= 3);
    assert!(text.matches("Assert-NxbEvidencePublicationOutcome").count() >= 2);
}
''', encoding="utf-8", newline="\n")


def main() -> None:
    patch_validator()
    patch_source_contract()


if __name__ == "__main__":
    main()
