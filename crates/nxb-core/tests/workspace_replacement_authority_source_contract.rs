use std::{
    fs,
    path::{Path, PathBuf},
};

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
    assert!(!cargo.contains("rustix"));
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
        assert!(
            migration.contains(marker),
            "{MIGRATION_PATH}: missing marker: {marker}"
        );
    }
}

#[test]
fn linux_existing_destination_fails_closed_before_victim_mutation() {
    let replacement = source(REPLACEMENT_PATH);
    let production = section(
        &replacement,
        REPLACEMENT_PATH,
        "struct ParentAuthority",
        "\n#[cfg(test)]",
    );
    for marker in [
        "O_DIRECTORY | O_NOFOLLOW",
        "parent.validate_named_binding()?;",
        "parent.validate_child_binding(destination, previous, \"replacement destination\")?;",
        "Linux replacement of an existing document is unsupported without exact-victim namespace mutation authority",
        "prepared.file.as_raw_fd()",
    ] {
        assert!(production.contains(marker), "{REPLACEMENT_PATH}: missing marker: {marker}");
    }
    for forbidden in [
        "TRUSTED_MV",
        "quarantine_no_replace",
        ".arg(\"-n\")",
        ".arg(\"-T\")",
        "remove_file(",
        "remove_regular(",
        "fs::rename(",
        "remove_dir_all(",
    ] {
        assert!(
            !production.contains(forbidden),
            "{REPLACEMENT_PATH}: forbidden victim mutation marker: {forbidden}"
        );
    }
}

#[test]
fn linux_missing_destination_publication_remains_exact_fd_create_only() {
    let replacement = source(REPLACEMENT_PATH);
    let production = section(
        &replacement,
        REPLACEMENT_PATH,
        "struct ParentAuthority",
        "\n#[cfg(test)]",
    );
    assert!(
        replacement.contains("const TRUSTED_LN: &str = \"/usr/bin/ln\";"),
        "{REPLACEMENT_PATH}: missing trusted hard-link application marker"
    );
    for marker in [
        ".arg(\"-L\")",
        ".arg(\"--\")",
        ".env_clear()",
        "prepared.file.as_raw_fd()",
        "parent.claim_prepared(&prepared, destination)?;",
        "parent.validate_child_binding(destination, &prepared, \"replacement destination\")?;",
    ] {
        assert!(
            production.contains(marker),
            "{REPLACEMENT_PATH}: missing create-only marker: {marker}"
        );
    }
}

#[test]
fn replacement_regressions_preserve_existing_and_substituted_victims() {
    let replacement = source(REPLACEMENT_PATH);
    for marker in [
        "existing_destination_fails_closed_without_victim_mutation",
        "same_permission_destination_substitution_is_left_untouched",
        "parent_directory_replacement_cannot_redirect_namespace_mutation",
        "missing_destination_is_create_only_from_retained_prepared_fd",
        "replacement destination pathname is not the retained file authority",
        "replacement parent pathname no longer names the retained directory authority",
    ] {
        assert!(
            replacement.contains(marker),
            "{REPLACEMENT_PATH}: missing regression marker: {marker}"
        );
    }
}
