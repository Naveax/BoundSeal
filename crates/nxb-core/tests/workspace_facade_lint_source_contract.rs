use std::{
    fs,
    path::{Path, PathBuf},
};

const ENTRY_PATH: &str = "crates/nxb-core/src/workspace_authority_entry.rs";
const WINDOWS_ENTRY_PATH: &str = "crates/nxb-core/src/workspace_windows_entry.rs";
const NXB_PATH: &str = "crates/nxb-core/src/nxb.rs";
const PREPARED_AUTHORITY_PATH: &str = "crates/nxb-core/src/prepared_file_authority.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

#[test]
fn intentional_glob_shadow_exceptions_are_local_and_single_lint_only() {
    for path in [ENTRY_PATH, WINDOWS_ENTRY_PATH] {
        let text = source(path);
        assert!(
            text.starts_with("#![allow(hidden_glob_reexports)]\n"),
            "{path}: intentional facade shadow must have one local hidden_glob_reexports exception"
        );
        for forbidden in [
            "#![allow(warnings)]",
            "#![allow(unused)]",
            "#![allow(dead_code)]",
            "#![allow(unused_imports)]",
            "#![allow(clippy::all)]",
        ] {
            assert!(
                !text.contains(forbidden),
                "{path}: facade composition must not broaden lint suppression: {forbidden}"
            );
        }
    }
}

#[test]
fn binary_crate_keeps_unsafe_forbidden_while_facades_only_relax_shadow_lint() {
    let nxb = source(NXB_PATH);
    assert!(
        nxb.starts_with("#![forbid(unsafe_code)]"),
        "{NXB_PATH}: binary crate must continue to forbid unsafe code"
    );
    assert!(
        !nxb.contains("allow(hidden_glob_reexports)"),
        "{NXB_PATH}: facade-specific lint exception must not become crate-wide"
    );
}

#[test]
fn prepared_publication_uses_scoped_workspace_admission_for_pinned_child_paths() {
    let prepared = source(PREPARED_AUTHORITY_PATH);
    assert!(
        prepared
            .matches("crate::workspace::reject_path_indirections")
            .count()
            >= 6,
        "{PREPARED_AUTHORITY_PATH}: prepared publication must admit target-scoped /proc/self/fd or Windows pinned child paths through the workspace facade"
    );
    assert_eq!(
        prepared
            .matches("crate::workspace_impl::reject_path_indirections")
            .count(),
        1,
        "{PREPARED_AUTHORITY_PATH}: only the external trusted Linux tool path may bypass scoped workspace admission"
    );
    assert!(
        prepared.contains(
            "crate::workspace_impl::reject_path_indirections(tool, \"Linux hard-link system tool\")?;"
        ),
        "{PREPARED_AUTHORITY_PATH}: the sole unscoped admission must remain the external trusted Linux tool"
    );
}
