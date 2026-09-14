#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/nxb-core/tests/nxb153_run13_lint_source_contract.rs")
path.write_text(r'''use std::{fs, path::{Path, PathBuf}};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    fs::read_to_string(root().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn concrete_run13_unused_imports_are_removed_without_crate_wide_suppression() {
    let activation = source("crates/nxb-core/src/target/activation.rs");
    assert!(activation.contains(
        "#[cfg(test)]\nuse super::{SetupAuthorization, SetupAutomation, SetupPolicyBinding, SetupProgram};"
    ));

    let prepared = source("crates/nxb-core/src/prepared_file_authority.rs");
    assert!(prepared.contains("use std::os::unix::fs::PermissionsExt;"));
    assert!(!prepared.contains("use std::os::unix::fs::{MetadataExt, PermissionsExt};"));

    for path in [
        "crates/nxb-core/src/nxb.rs",
        "crates/nxb-core/src/main.rs",
        "crates/nxb-core/src/workspace_authority_entry.rs",
        "crates/nxb-core/src/workspace_windows_entry.rs",
    ] {
        let text = source(path);
        assert!(!text.contains("#![allow(warnings)]"), "{path}: broad warning suppression is forbidden");
        assert!(!text.contains("#![allow(dead_code)]"), "{path}: crate/module-wide dead-code suppression is forbidden");
        assert!(!text.contains("#![allow(unused)]"), "{path}: broad unused suppression is forbidden");
    }
}

#[test]
fn intentionally_retained_compatibility_items_use_item_scoped_dead_code_exceptions() {
    let directory = source("crates/nxb-core/src/directory_authority.rs");
    assert!(directory.matches("#[allow(dead_code)]\n    pub(crate) fn sync").count() >= 3);

    let authority = source("crates/nxb-core/src/workspace_authority.rs");
    for marker in [
        "#[allow(dead_code)]\nfn authority_exact_directory(path: &Path) -> bool {",
        "#[allow(dead_code)]\nstruct AuthorityUnpublishedCleanupError {",
        "#[allow(dead_code)]\npub(crate) fn create_document(path: &Path, bytes: &[u8]) -> Result<()> {",
        "#[allow(dead_code)]\nfn create_authority_document(path: &Path, bytes: &[u8]) -> Result<()> {",
        "#[allow(dead_code)]\nfn remove_authority_temporary(path: &Path) -> Result<()> {",
        "#[allow(dead_code)]\nfn sync_authority_directory(path: &Path) -> Result<()> {",
    ] {
        assert!(authority.contains(marker), "workspace authority compatibility marker missing: {marker}");
    }

    let workspace = source("crates/nxb-core/src/workspace/mod.rs");
    for marker in [
        "#[allow(dead_code)]\nstruct DoctorResult {",
        "#[allow(dead_code)]\nstruct DoctorCheck {",
        "#[allow(dead_code)]\nenum CheckStatus {",
        "#[allow(dead_code)]\npub(crate) fn doctor_value(workspace: &Path) -> Result<Value> {",
        "#[allow(dead_code)]\nfn doctor_result(workspace: &Path) -> DoctorResult {",
        "#[allow(dead_code)]\npub(crate) fn replace_document(path: &Path, bytes: &[u8]) -> Result<()> {",
        "#[allow(dead_code)]\nfn write_probe(workspace: &Path) -> Result<()> {",
        "#[allow(dead_code)]\nfn pass_check(name: impl Into<String>, detail: impl Into<String>) -> DoctorCheck {",
        "#[allow(dead_code)]\nfn fail_check(name: impl Into<String>, detail: impl Into<String>) -> DoctorCheck {",
        "#[allow(dead_code)]\npub(crate) fn remove_regular(path: &Path) -> Result<()> {",
    ] {
        assert!(workspace.contains(marker), "legacy workspace compatibility marker missing: {marker}");
    }
}

#[test]
fn run13_clippy_needless_return_is_removed_at_the_platform_dispatch_boundary() {
    let doctor = source("crates/nxb-core/src/workspace_doctor_probe.rs");
    assert!(!doctor.contains("return run_linux(directory);"));
    assert!(!doctor.contains("return run_windows(directory);"));
    assert!(doctor.contains("run_linux(directory)"));
    assert!(doctor.contains("run_windows(directory)"));
}
''', encoding="utf-8", newline="\n")
