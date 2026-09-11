use std::{fs, path::{Path, PathBuf}};

const NXB_PATH: &str = "crates/nxb-core/src/nxb.rs";
const PREPARED_PATH: &str = "crates/nxb-core/src/prepared_file_authority.rs";
const ENTRY_PATH: &str = "crates/nxb-core/src/workspace_authority_entry.rs";
const PUBLICATION_PATH: &str = "crates/nxb-core/src/workspace_authority_publication.rs";

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
fn prepared_authority_and_publication_writer_are_compiled_and_target_entry_overrides_create() {
    let nxb = source(NXB_PATH);
    for marker in [
        "mod prepared_file_authority;",
        "mod workspace_authority_publication;",
    ] {
        assert!(nxb.contains(marker), "{NXB_PATH}: missing source marker: {marker}");
    }

    let entry = source(ENTRY_PATH);
    for marker in [
        "pub(crate) fn create_document(path: &Path, bytes: &[u8]) -> Result<()>",
        "workspace_authority_publication::create_document(path, bytes)",
        "pub(crate) fn create_document_error_published(error: &anyhow::Error) -> bool",
        "workspace_authority_publication::error_published(error)",
    ] {
        assert!(entry.contains(marker), "{ENTRY_PATH}: missing prepared publication override: {marker}");
    }
}

#[test]
fn prepared_file_handle_stays_live_and_named_replacement_is_detected() {
    let prepared = source(PREPARED_PATH);
    for marker in [
        "file: fs::File",
        "options.write(true).read(true).create_new(true);",
        "file.write_all(bytes)?;",
        "file.sync_all()?;",
        "authority.validate_named_binding()?;",
        "prepared pathname no longer names the retained file authority",
        "published destination is not the retained prepared file authority",
        "prepared_authority_detects_same_permission_path_replacement",
    ] {
        assert!(prepared.contains(marker), "{PREPARED_PATH}: missing retained prepared authority marker: {marker}");
    }

    assert!(
        !prepared.contains("drop(file)"),
        "{PREPARED_PATH}: prepared handle must not be dropped before namespace claim/finalization"
    );
}

#[test]
fn linux_create_only_claim_uses_held_fd_not_the_reusable_temporary_pathname() {
    let prepared = source(PREPARED_PATH);
    let linux = section(
        &prepared,
        PREPARED_PATH,
        "#[cfg(target_os = \"linux\")]\n    pub(crate) fn claim_create_only",
        "\n    #[cfg(windows)]\n    pub(crate) fn claim_create_only",
    );

    for marker in [
        "const TRUSTED_LN: &str = \"/usr/bin/ln\";",
        "tool_metadata.uid() != 0",
        "tool_metadata.permissions().mode() & 0o022 != 0",
        "self.file.as_raw_fd()",
        "\"/proc/{}/fd/{}\"",
        ".arg(\"-L\")",
        ".arg(\"--\")",
        ".env_clear()",
        "self.validate_destination_binding(destination)",
    ] {
        assert!(linux.contains(marker), "{PREPARED_PATH}: Linux exact-object claim marker missing: {marker}");
    }
    assert!(
        !linux.contains("fs::hard_link(&self.path"),
        "{PREPARED_PATH}: Linux must never claim from the reusable prepared pathname"
    );
    assert!(
        prepared.contains("create_only_claim_uses_retained_inode_after_prepared_path_replacement"),
        "{PREPARED_PATH}: Linux prepared-path replacement regression is missing"
    );
}

#[test]
fn windows_prepared_handle_denies_namespace_replacement_through_claim() {
    let prepared = source(PREPARED_PATH);
    let create = section(
        &prepared,
        PREPARED_PATH,
        "#[cfg(windows)]\n        {",
        "\n        #[cfg(target_os = \"linux\")]",
    );
    for marker in [
        "const FILE_SHARE_READ: u32",
        ".share_mode(FILE_SHARE_READ)",
        "FILE_FLAG_OPEN_REPARSE_POINT",
    ] {
        assert!(create.contains(marker), "{PREPARED_PATH}: Windows prepared handle marker missing: {marker}");
    }
    assert!(!create.contains("FILE_SHARE_DELETE"), "{PREPARED_PATH}: Windows prepared handle must deny delete/rename sharing");
    assert!(!create.contains("FILE_SHARE_WRITE"), "{PREPARED_PATH}: Windows prepared handle must deny write sharing");

    let claim = section(
        &prepared,
        PREPARED_PATH,
        "#[cfg(windows)]\n    pub(crate) fn claim_create_only",
        "\n    #[cfg(all(unix, not(target_os = \"linux\")))]",
    );
    for marker in [
        "self.validate_named_binding()?;",
        "fs::hard_link(&self.path, destination)",
        "self.validate_destination_binding(destination)",
    ] {
        assert!(claim.contains(marker), "{PREPARED_PATH}: Windows exact prepared claim marker missing: {marker}");
    }
    assert!(prepared.contains("prepared_windows_handle_denies_rename_until_authority_is_released"));
}

#[test]
fn target_publication_never_pathname_deletes_prepared_residue_before_nxb112() {
    let publication = source(PUBLICATION_PATH);
    for marker in [
        "PreparedFileAuthority::create_named(&temporary, bytes)",
        ".claim_create_only(path)",
        "prepared.validate_destination_binding(path)?;",
        "Exact checked-object cleanup belongs to #112",
        "#106 quarantines this exact",
    ] {
        assert!(publication.contains(marker), "{PUBLICATION_PATH}: missing prepared publication marker: {marker}");
    }
    for forbidden in ["remove_file(", "remove_regular(", "fs::rename("] {
        assert!(
            !publication.contains(forbidden),
            "{PUBLICATION_PATH}: prepared residue cleanup must not re-resolve and mutate a pathname: {forbidden}"
        );
    }
}

#[test]
fn unsupported_prepared_claim_platforms_fail_closed() {
    let prepared = source(PREPARED_PATH);
    for marker in [
        "prepared file authority is unsupported on this Unix platform",
        "prepared file authority is unsupported on this platform",
        "prepared file create-only claim is unsupported on this Unix platform",
        "prepared file create-only claim is unsupported on this platform",
    ] {
        assert!(prepared.contains(marker), "{PREPARED_PATH}: fail-closed marker missing: {marker}");
    }
}
