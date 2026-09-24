use std::{
    fs,
    path::{Path, PathBuf},
};

const DEPENDENCY_SOURCE_PATH: &str = "scripts/nxb-153-windows-dependency-source.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn windows_rustsec_advisory_db_is_explicitly_bound_to_runtime_cargo_home() {
    let path = repository_root().join(DEPENDENCY_SOURCE_PATH);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()));

    for marker in [
        "$auditDb = Join-Path $RuntimeCargoHome 'advisory-db'",
        "advisory database runtime path unexpectedly already exists",
        "-Arguments @('audit', '--db', $auditDb)",
        "RustSec advisory database path was not materialized under the controlled runtime Cargo home",
        "RustSec advisory database path became a reparse point",
    ] {
        assert!(
            source.contains(marker),
            "{DEPENDENCY_SOURCE_PATH}: missing explicit RustSec advisory DB authority marker: {marker}"
        );
    }

    assert!(
        !source.contains("-Arguments @('audit') -Label 'RustSec cargo audit'"),
        "{DEPENDENCY_SOURCE_PATH}: RustSec must not fall back to ambient HOME/CARGO_HOME advisory DB selection"
    );
}
