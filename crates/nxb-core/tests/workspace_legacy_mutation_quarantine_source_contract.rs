use std::{fs, path::{Path, PathBuf}};

const NXB_PATH: &str = "crates/nxb-core/src/nxb.rs";
const ENTRY_PATH: &str = "crates/nxb-core/src/workspace_authority_entry.rs";
const WINDOWS_ENTRY_PATH: &str = "crates/nxb-core/src/workspace_windows_entry.rs";
const BASE_AUTHORITY_PATH: &str = "crates/nxb-core/src/workspace_authority.rs";
const WORKSPACE_IMPL_PATH: &str = "crates/nxb-core/src/workspace/mod.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

#[test]
fn public_workspace_module_is_the_composed_entry_not_the_legacy_base() {
    let nxb = source(NXB_PATH);
    for marker in [
        "#[path = \"workspace_authority.rs\"]\nmod workspace_authority_base;",
        "#[path = \"workspace_authority_entry.rs\"]\nmod workspace;",
    ] {
        assert!(nxb.contains(marker), "{NXB_PATH}: missing composed workspace route: {marker}");
    }

    let entry = source(ENTRY_PATH);
    for marker in [
        "pub(crate) use crate::workspace_authority_base::*;",
        "pub(crate) fn create_document(path: &Path, bytes: &[u8])",
        "workspace_authority_publication::create_document(path, bytes)",
        "pub(crate) fn doctor_value(workspace: &Path) -> Result<Value>",
        "workspace_doctor_probe::probe(&root)",
    ] {
        assert!(entry.contains(marker), "{ENTRY_PATH}: missing local shadow for legacy mutation route: {marker}");
    }
}

#[test]
fn legacy_authority_create_writer_has_no_internal_production_call_site() {
    let base = source(BASE_AUTHORITY_PATH);
    assert_eq!(
        base.matches("create_authority_document(").count(),
        2,
        "{BASE_AUTHORITY_PATH}: legacy authority writer must remain definition-only plus its single wrapper call"
    );
    assert!(base.contains("pub(crate) fn create_document(path: &Path, bytes: &[u8])"));
    assert!(base.contains("fn create_authority_document(path: &Path, bytes: &[u8])"));
}

#[test]
fn windows_workspace_shadows_historical_replace_and_migration_modules() {
    let nxb = source(NXB_PATH);
    for marker in [
        "#[cfg(not(windows))]\n#[path = \"workspace/mod.rs\"]\nmod workspace_impl;",
        "#[cfg(windows)]\n#[path = \"workspace_windows_entry.rs\"]\nmod workspace_impl;",
    ] {
        assert!(nxb.contains(marker), "{NXB_PATH}: missing Windows workspace selection: {marker}");
    }

    let entry = source(WINDOWS_ENTRY_PATH);
    for marker in [
        "#[path = \"workspace/mod.rs\"]\nmod base;",
        "pub(crate) use base::*;",
        "pub(crate) fn replace_document(path: &Path, bytes: &[u8])",
        "workspace_authority_replacement_windows::replace_document(path, bytes)",
        "#[path = \"workspace/migration.rs\"]\npub(crate) mod migration;",
    ] {
        assert!(entry.contains(marker), "{WINDOWS_ENTRY_PATH}: missing Windows local shadow: {marker}");
    }
}

#[test]
fn historical_pathname_delete_helpers_are_not_mistaken_for_active_authority() {
    let implementation = source(WORKSPACE_IMPL_PATH);
    for marker in [
        "fn write_probe(workspace: &Path) -> Result<()>",
        "pub(crate) fn remove_regular(path: &Path) -> Result<()>",
        "#[cfg(not(unix))]\nfn replace_file(source: &Path, destination: &Path) -> Result<()>"
    ] {
        assert!(implementation.contains(marker), "{WORKSPACE_IMPL_PATH}: expected quarantined legacy marker missing: {marker}");
    }

    let entry = source(ENTRY_PATH);
    assert!(entry.contains("workspace_doctor_probe::probe(&root)"));
    let windows_entry = source(WINDOWS_ENTRY_PATH);
    assert!(windows_entry.contains("workspace_authority_replacement_windows::replace_document(path, bytes)"));
}
