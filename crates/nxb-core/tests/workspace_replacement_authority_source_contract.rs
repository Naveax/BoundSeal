use std::{fs, path::{Path, PathBuf}};

const NXB_PATH: &str = "crates/nxb-core/src/nxb.rs";
const MIGRATION_PATH: &str = "crates/nxb-core/src/workspace/migration.rs";
const REPLACEMENT_PATH: &str = "crates/nxb-core/src/workspace_authority_replacement.rs";
const CARGO_PATH: &str = "crates/nxb-core/Cargo.toml";

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
fn linux_replacement_authority_is_compiled_without_a_new_syscall_dependency() {
    let nxb = source(NXB_PATH);
    assert!(nxb.contains("#[cfg(target_os = \"linux\")]\nmod workspace_authority_replacement;"));

    let cargo = source(CARGO_PATH);
    assert!(
        !cargo.contains("rustix"),
        "{CARGO_PATH}: Linux replacement authority must not leave an unvalidated lockfile dependency"
    );
}

#[test]
fn migration_routes_linux_manifest_replacement_through_the_authority_module_only() {
    let migration = source(MIGRATION_PATH);
    for marker in [
        "#[cfg(target_os = \"linux\")]",
        "use crate::workspace_authority_replacement::replace_document;",
        "#[cfg(not(target_os = \"linux\"))]",
        "use super::replace_document;",
        "replace_document(&paths.manifest, &plan.target_bytes)?;",
    ] {
        assert!(migration.contains(marker), "{MIGRATION_PATH}: missing replacement routing marker: {marker}");
    }
}

#[test]
fn linux_replacement_retains_parent_and_file_objects_across_namespace_mutation() {
    let replacement = source(REPLACEMENT_PATH);
    let production = section(
        &replacement,
        REPLACEMENT_PATH,
        "struct ParentAuthority",
        "\n#[cfg(test)]",
    );

    for marker in [
        "O_DIRECTORY | O_NOFOLLOW",
        "file: File",
        "dev: u64",
        "ino: u64",
        "self.file.as_raw_fd()",
        "\"/proc/{}/fd/{}\"",
        "self.stable_path(source)",
        "self.stable_path(quarantine)",
        "parent.validate_named_binding()?;",
        "parent.validate_child_binding(\n            &quarantine_name,",
        "parent.validate_child_binding(destination, &prepared, \"replacement destination\")?;",
    ] {
        assert!(production.contains(marker), "{REPLACEMENT_PATH}: missing retained-authority marker: {marker}");
    }
}

#[test]
fn linux_replacement_uses_trusted_no_clobber_quarantine_and_exact_fd_publication() {
    let replacement = source(REPLACEMENT_PATH);
    let production = section(
        &replacement,
        REPLACEMENT_PATH,
        "struct ParentAuthority",
        "\n#[cfg(test)]",
    );

    for marker in [
        "const TRUSTED_MV: &str = \"/usr/bin/mv\";",
        "const TRUSTED_LN: &str = \"/usr/bin/ln\";",
        "metadata.uid() != 0",
        "metadata.permissions().mode() & 0o022 != 0",
        ".arg(\"-n\")",
        ".arg(\"-T\")",
        ".arg(\"-L\")",
        ".arg(\"--\")",
        ".env_clear()",
        "prepared.file.as_raw_fd()",
    ] {
        assert!(production.contains(marker), "{REPLACEMENT_PATH}: missing namespace-mutation marker: {marker}");
    }

    for forbidden in ["remove_file(", "remove_regular(", "fs::rename(", "remove_dir_all("] {
        assert!(
            !production.contains(forbidden),
            "{REPLACEMENT_PATH}: replacement production path must not pathname-delete or plain-rename residue: {forbidden}"
        );
    }
}

#[test]
fn replacement_regressions_cover_final_component_and_parent_namespace_substitution() {
    let replacement = source(REPLACEMENT_PATH);
    for marker in [
        "replacement_publishes_exact_prepared_inode_and_retires_previous_inode",
        "same_permission_destination_replacement_is_quarantined_but_never_deleted_or_published",
        "parent_directory_replacement_cannot_redirect_namespace_mutation",
        "missing_destination_is_create_only_from_retained_prepared_fd",
        "quarantined previous document pathname is not the retained file authority",
        "replacement parent pathname no longer names the retained directory authority",
    ] {
        assert!(replacement.contains(marker), "{REPLACEMENT_PATH}: missing regression marker: {marker}");
    }
}
