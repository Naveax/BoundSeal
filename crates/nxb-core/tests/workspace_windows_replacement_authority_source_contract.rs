use std::{fs, path::{Path, PathBuf}};

const ROOT_MANIFEST: &str = "Cargo.toml";
const CORE_MANIFEST: &str = "crates/nxb-core/Cargo.toml";
const NXB_PATH: &str = "crates/nxb-core/src/nxb.rs";
const ENTRY_PATH: &str = "crates/nxb-core/src/workspace_windows_entry.rs";
const REPLACEMENT_PATH: &str = "crates/nxb-core/src/workspace_authority_replacement_windows.rs";
const PLATFORM_PATH: &str = "crates/nxb-win32-fs-authority/src/lib.rs";
const PLATFORM_MANIFEST: &str = "crates/nxb-win32-fs-authority/Cargo.toml";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

#[test]
fn windows_unsafe_abi_is_isolated_from_the_forbid_unsafe_nxb_crate() {
    let root = source(ROOT_MANIFEST);
    let core = source(CORE_MANIFEST);
    let platform_manifest = source(PLATFORM_MANIFEST);
    let nxb = source(NXB_PATH);
    let platform = source(PLATFORM_PATH);
    let replacement = source(REPLACEMENT_PATH);

    assert!(root.contains("\"crates/nxb-win32-fs-authority\""));
    assert!(core.contains("[target.'cfg(windows)'.dependencies]"));
    assert!(core.contains("nxb-win32-fs-authority = { path = \"../nxb-win32-fs-authority\" }"));
    assert!(platform_manifest.contains("windows-sys = { version = \"=0.61.2\""));

    assert!(nxb.contains("#![forbid(unsafe_code)]"));
    assert!(nxb.contains("#[cfg(windows)]\nmod workspace_authority_replacement_windows;"));
    assert!(!replacement.contains("unsafe {"));

    for marker in [
        "GetFileInformationByHandle",
        "SetFileInformationByHandle",
        "FILE_RENAME_INFO",
        "FileRenameInfo",
        "pub fn file_identity(file: &File)",
        "pub fn rename_handle_relative_no_replace(",
        "Zeroed Anonymous means ReplaceIfExists = FALSE",
    ] {
        assert!(platform.contains(marker), "{PLATFORM_PATH}: missing Win32 ABI authority marker: {marker}");
    }
    assert!(platform.contains("unsafe {"), "{PLATFORM_PATH}: the audited ABI boundary must remain visible instead of leaking into nxb-core");
}

#[test]
fn windows_workspace_routes_migration_replacement_through_the_safe_handle_authority() {
    let nxb = source(NXB_PATH);
    let entry = source(ENTRY_PATH);

    for marker in [
        "#[cfg(not(windows))]\n#[path = \"workspace/mod.rs\"]\nmod workspace_impl;",
        "#[cfg(windows)]\n#[path = \"workspace_windows_entry.rs\"]\nmod workspace_impl;",
    ] {
        assert!(nxb.contains(marker), "{NXB_PATH}: missing platform workspace route: {marker}");
    }

    for marker in [
        "#[path = \"workspace/mod.rs\"]\nmod base;",
        "pub(crate) use base::*;",
        "pub(crate) fn replace_document(path: &Path, bytes: &[u8])",
        "workspace_authority_replacement_windows::replace_document(path, bytes)",
        "#[path = \"workspace/migration.rs\"]\npub(crate) mod migration;",
    ] {
        assert!(entry.contains(marker), "{ENTRY_PATH}: missing Windows workspace facade marker: {marker}");
    }
}

#[test]
fn windows_replacement_retains_parent_current_and_prepared_authorities_through_finalization() {
    let replacement = source(REPLACEMENT_PATH);
    for marker in [
        "handles: Vec<File>",
        ".access_mode(FILE_READ_ATTRIBUTES)",
        ".share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)",
        "FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT",
        ".access_mode(GENERIC_READ | DELETE)",
        ".share_mode(FILE_SHARE_READ)",
        "file_identity(&file)",
        "PreparedFileAuthority::create_named(",
        "replacement destination appeared after the migration observation",
        "replacement destination disappeared after the migration observation",
        "replacement destination bytes changed after the migration observation",
        "rename_handle_relative_no_replace(",
        ".share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)",
        "quarantined previous document",
        "prepared.claim_create_only(&destination)?;",
        "prepared.validate_destination_binding(&destination)?;",
        "parent.validate_named_binding()?;",
    ] {
        assert!(replacement.contains(marker), "{REPLACEMENT_PATH}: missing retained-authority marker: {marker}");
    }

    for forbidden in ["fs::rename(", "remove_file(", "remove_regular("] {
        let production = replacement
            .split("#[cfg(test)]")
            .next()
            .expect("Windows replacement production section is missing");
        assert!(!production.contains(forbidden), "{REPLACEMENT_PATH}: production replacement must not use pathname-destructive primitive: {forbidden}");
    }
}

#[test]
fn windows_replacement_regressions_cover_identity_observation_and_namespace_races() {
    let replacement = source(REPLACEMENT_PATH);
    for marker in [
        "fn replacement_quarantines_exact_previous_object_and_publishes_candidate()",
        "fn expected_current_mismatch_fails_before_namespace_mutation()",
        "fn retained_destination_denies_same_permission_path_swap()",
        "fn retained_ancestor_chain_denies_parent_replacement()",
        "fn expected_missing_destination_uses_create_only_claim()",
    ] {
        assert!(replacement.contains(marker), "{REPLACEMENT_PATH}: missing Windows replacement regression: {marker}");
    }

    let platform = source(PLATFORM_PATH);
    for marker in [
        "fn handle_relative_rename_preserves_exact_identity()",
        "fn no_replace_rename_preserves_existing_destination()",
        "fn source_handle_denies_rename_until_retained_authority_is_released()",
    ] {
        assert!(platform.contains(marker), "{PLATFORM_PATH}: missing Win32 primitive regression: {marker}");
    }
}
