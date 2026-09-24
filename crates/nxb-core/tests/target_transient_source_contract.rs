use std::{
    fs,
    path::{Path, PathBuf},
};

const TARGET_PATH: &str = "crates/nxb-core/src/target.rs";
const WORKSPACE_PATH: &str = "crates/nxb-core/src/workspace/mod.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full_path = repository_root().join(path);
    fs::read_to_string(&full_path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full_path.display()))
}

fn required_index(text: &str, needle: &str, path: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("{path}: missing source marker: {needle}"))
}

#[test]
fn create_document_transient_recognizer_and_target_quarantine_remain_fail_closed() {
    let workspace = source(WORKSPACE_PATH);
    for marker in [
        "const CREATE_DOCUMENT_TEMPORARY_NONCE_HEX_LENGTH: usize = 24;",
        "pub(crate) fn create_document_temporary_destination(name: &str) -> Option<&str>",
        "name.strip_prefix('.')?.strip_suffix(\".tmp\")?",
        "body.rsplit_once('.')?",
        "destination.is_empty()",
        "nonce.len() != CREATE_DOCUMENT_TEMPORARY_NONCE_HEX_LENGTH",
        "byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)",
        ".and_then(create_document_temporary_destination)",
    ] {
        assert!(
            workspace.contains(marker),
            "{WORKSPACE_PATH}: missing exact create_document transient marker: {marker}"
        );
    }

    let count_start = required_index(
        &workspace,
        "fn count_regular_files(path: &Path)",
        WORKSPACE_PATH,
    );
    let count_body = &workspace[count_start..];
    let transient_filter = required_index(
        count_body,
        ".and_then(create_document_temporary_destination)",
        WORKSPACE_PATH,
    );
    let count_increment = required_index(count_body, ".checked_add(1)", WORKSPACE_PATH);
    assert!(
        transient_filter < count_increment,
        "{WORKSPACE_PATH}: canonical status counts must filter exact create_document transients before record increment"
    );

    let target = source(TARGET_PATH);
    assert!(
        target.contains("const MAX_TARGET_DIRECTORY_ENTRIES: usize = MAX_TARGET_PROFILES * 4;"),
        "{TARGET_PATH}: bounded target directory-entry budget is missing"
    );
    let load_start = required_index(&target, "fn load_profiles(", TARGET_PATH);
    let load_end_relative = target[load_start..]
        .find("\nfn read_profile(")
        .expect("target load_profiles boundary is missing");
    let load = &target[load_start..load_start + load_end_relative];

    let private_permissions = required_index(
        load,
        "workspace::validate_private_permissions(&path, false)?;",
        TARGET_PATH,
    );
    let entry_increment = required_index(load, ".checked_add(1)", TARGET_PATH);
    let entry_limit = required_index(load, "entries > MAX_TARGET_DIRECTORY_ENTRIES", TARGET_PATH);
    let transient_parser = required_index(
        load,
        "workspace::create_document_temporary_destination(name)",
        TARGET_PATH,
    );
    let profile_destination = required_index(load, ".strip_suffix(\".json\")", TARGET_PATH);
    let quarantine_continue = required_index(load, "continue;", TARGET_PATH);

    assert!(
        private_permissions < entry_increment
            && entry_increment < entry_limit
            && entry_limit < transient_parser
            && transient_parser < profile_destination
            && profile_destination < quarantine_continue,
        "{TARGET_PATH}: transient quarantine must occur only after path/type/private-permission and bounded entry accounting, before canonical record admission"
    );

    for forbidden in [
        "remove_file(",
        "remove_regular(",
        "replace_document(",
        "fs::rename(",
    ] {
        assert!(
            !load.contains(forbidden),
            "{TARGET_PATH}: target enumeration must quarantine, never mutate, transient residue: {forbidden}"
        );
    }
}
