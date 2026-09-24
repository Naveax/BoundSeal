use std::{
    fs,
    path::{Path, PathBuf},
};

const MIGRATION_PATH: &str = "crates/nxb-core/src/workspace/migration.rs";
const PUBLICATION_PATH: &str = "crates/nxb-core/src/workspace_authority_publication.rs";
const RECEIPTS_PATH: &str = "crates/nxb-core/src/workspace_authority_receipts.rs";

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
fn committed_migration_cleanup_is_verification_only_not_pathname_deletion() {
    let migration = source(MIGRATION_PATH);
    let cleanup = section(
        &migration,
        MIGRATION_PATH,
        "fn cleanup(paths: &MigrationPaths) -> Result<()> {",
        "\nfn plan(source: &[u8]) -> Result<MigrationPlan>",
    );

    for marker in [
        "migration cleanup requires a committed receipt",
        "verify_retired_state(paths, &journal, &receipt_path)",
    ] {
        assert!(
            cleanup.contains(marker),
            "{MIGRATION_PATH}: committed cleanup verification marker missing: {marker}"
        );
    }
    for forbidden in ["remove_file(", "remove_regular(", "fs::rename("] {
        assert!(
            !cleanup.contains(forbidden),
            "{MIGRATION_PATH}: committed cleanup must not pathname-mutate retired journal state: {forbidden}"
        );
    }
}

#[test]
fn retired_state_must_validate_receipt_manifest_backup_and_applied_marker_before_stable() {
    let migration = source(MIGRATION_PATH);
    let transient = section(
        &migration,
        MIGRATION_PATH,
        "fn transient_state(paths: &MigrationPaths) -> Result<usize> {",
        "\nfn receipt_count(paths: &MigrationPaths) -> Result<usize>",
    );
    for marker in [
        "verify_retired_state(paths, &journal, &receipt_path)?;",
        "return Ok(0);",
    ] {
        assert!(
            transient.contains(marker),
            "{MIGRATION_PATH}: retired-state stability marker missing: {marker}"
        );
    }
    assert!(
        transient.find("verify_retired_state(paths, &journal, &receipt_path)?;")
            < transient.find("return Ok(0);"),
        "{MIGRATION_PATH}: retired state must be verified before it is reported stable"
    );

    let retired = section(
        &migration,
        MIGRATION_PATH,
        "fn verify_retired_state(",
        "\nfn validate_receipt(value: &MigrationReceipt)",
    );
    for marker in [
        "verify_committed(paths, journal, receipt_path)?;",
        "committed migration residue is incomplete",
        "retired source backup digest mismatch",
        "validate_journal_plan(journal, &plan)?;",
        "validate_marker(&marker, &plan)",
    ] {
        assert!(
            retired.contains(marker),
            "{MIGRATION_PATH}: retired-state authority marker missing: {marker}"
        );
    }
}

#[test]
fn migration_journals_and_receipts_use_prepared_authority_publication() {
    let migration = source(MIGRATION_PATH);
    for marker in [
        "crate::workspace_authority_publication::create_document(path, &bytes)",
        "crate::workspace_authority_publication::create_document(&paths.backup, source)?;",
        ".and_then(super::create_document_temporary_destination)",
    ] {
        assert!(
            migration.contains(marker),
            "{MIGRATION_PATH}: prepared-publication/quarantine marker missing: {marker}"
        );
    }

    let publication = source(PUBLICATION_PATH);
    for forbidden in ["remove_file(", "remove_regular(", "fs::rename("] {
        assert!(
            !publication.contains(forbidden),
            "{PUBLICATION_PATH}: prepared publication residue must not be pathname-deleted: {forbidden}"
        );
    }
}

#[test]
fn target_readiness_ignores_only_the_exact_create_document_temporary_shape() {
    let receipts = source(RECEIPTS_PATH);
    for marker in [
        "let file_name = entry.file_name();",
        ".and_then(crate::workspace_impl::create_document_temporary_destination)",
        ".is_some()",
        "continue;",
    ] {
        assert!(
            receipts.contains(marker),
            "{RECEIPTS_PATH}: migration receipt quarantine marker missing: {marker}"
        );
    }
}

#[test]
fn same_permission_retired_journal_replacement_regression_is_present() {
    let migration = source(MIGRATION_PATH);
    for marker in [
        "fn retired_migration_rejects_same_permission_replacement()",
        "assert!(transient_state(&paths).is_err());",
        "assert_eq!(fs::read(&paths.active).unwrap(), b\"{}\\n\");",
        "assert!(original.is_file());",
    ] {
        assert!(
            migration.contains(marker),
            "{MIGRATION_PATH}: retired replacement regression marker missing: {marker}"
        );
    }
}
