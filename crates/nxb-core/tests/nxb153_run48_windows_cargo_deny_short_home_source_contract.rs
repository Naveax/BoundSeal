use std::{
    fs,
    path::{Path, PathBuf},
};

const DEPENDENCY_SOURCE_PATH: &str = "scripts/nxb-153-windows-dependency-source.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn windows_cargo_deny_uses_a_bounded_short_runtime_cargo_home() {
    let path = repository_root().join(DEPENDENCY_SOURCE_PATH);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()));

    for marker in [
        "$validationRoot = [IO.Path]::GetFullPath((Split-Path -Parent $SnapshotRoot))",
        "$denyHome = Join-Path $validationRoot ('.nxb-153-cargo-deny-' + [Guid]::NewGuid().ToString('N'))",
        "if ($denyHome.Length -gt 128)",
        "cargo-deny runtime CARGO_HOME unexpectedly already exists",
        "cargo-deny runtime CARGO_HOME became a reparse point",
        "$denyHomeHandle = Open-NxbDependencyDirectory -Path $denyHome -Label 'cargo-deny short CARGO_HOME'",
        "$denyConfigPath = Join-Path $denyHome 'config.toml'",
        "$denyConfigStream = Open-NxbDependencyFile -Path $denyConfigPath -Label 'cargo-deny short-home Cargo config'",
        "$env:CARGO_HOME = $denyHome",
        "-Arguments @('--locked', 'check') -Label 'cargo-deny checks'",
        "$denyAdvisoryRoot = Join-Path $denyHome 'advisory-dbs'",
        "cargo-deny advisory database root became a reparse point",
        "$env:CARGO_HOME = $gateHome",
        "cargo-deny config stream dispose",
        "Handle = $denyHomeHandle; Label = 'cargo-deny-home'",
        "@($gateHome, $vendorRoot, $fetchHome, $denyHome)",
    ] {
        assert!(
            source.contains(marker),
            "{DEPENDENCY_SOURCE_PATH}: missing cargo-deny short-home authority marker: {marker}"
        );
    }

    assert!(
        !source.contains("-Path $DenyPath -Arguments @('check') -Label 'cargo-deny checks'"),
        "{DEPENDENCY_SOURCE_PATH}: cargo-deny must not use the long gate CARGO_HOME advisory-db default"
    );
}
