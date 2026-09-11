use std::{fs, path::{Path, PathBuf}};

const WORKSPACE_PATH: &str = "crates/nxb-core/src/workspace/mod.rs";
const PREPARED_PATH: &str = "crates/nxb-core/src/prepared_file_authority.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

fn section<'a>(text: &'a str, path: &str, start: &str, end: &str) -> &'a str {
    let start_index = text
        .find(start)
        .unwrap_or_else(|| panic!("{path}: missing section start: {start}"));
    let tail = &text[start_index..];
    let end_relative = tail
        .find(end)
        .unwrap_or_else(|| panic!("{path}: missing section end: {end}"));
    &tail[..end_relative]
}

#[test]
fn generic_create_only_writer_retains_prepared_object_through_claim_and_finalization() {
    let workspace = source(WORKSPACE_PATH);
    let create = section(
        &workspace,
        WORKSPACE_PATH,
        "pub(crate) fn create_document(path: &Path, bytes: &[u8]) -> Result<()> {",
        "\n#[cfg(test)]\nfn create_document_with_operations",
    );

    for marker in [
        "crate::prepared_file_authority::PreparedFileAuthority::create_named(",
        ".claim_create_only(path)",
        "prepared.validate_destination_binding(path)?;",
        "sync_parent(parent)",
        "temporary_link_cleanup_failed: false",
        "parent_directory_sync_failed: true",
    ] {
        assert!(create.contains(marker), "{WORKSPACE_PATH}: missing generic prepared-publication marker: {marker}");
    }

    for forbidden in [
        "fs::hard_link(",
        "fs::remove_file(",
        "remove_regular(",
        "drop(output)",
    ] {
        assert!(
            !create.contains(forbidden),
            "{WORKSPACE_PATH}: generic create production path must not return to reusable pathname authority: {forbidden}"
        );
    }
}

#[test]
fn legacy_cleanup_injection_helper_is_test_only() {
    let workspace = source(WORKSPACE_PATH);
    assert!(workspace.contains("#[cfg(test)]\nfn create_document_with_operations"));
    assert!(workspace.contains("#[cfg(test)]\n#[derive(Debug)]\nstruct UnpublishedDocumentCleanupError"));
}

#[test]
fn generic_writer_composes_with_platform_specific_prepared_file_authority() {
    let prepared = source(PREPARED_PATH);
    for marker in [
        "pub(crate) fn claim_create_only(&self, destination: &Path) -> Result<()> {",
        "self.validate_destination_binding(destination)",
        "prepared_authority_detects_same_permission_path_replacement",
        "create_only_claim_uses_retained_inode_after_prepared_path_replacement",
        "prepared_windows_handle_denies_rename_until_authority_is_released",
    ] {
        assert!(prepared.contains(marker), "{PREPARED_PATH}: missing prepared authority marker: {marker}");
    }
}
