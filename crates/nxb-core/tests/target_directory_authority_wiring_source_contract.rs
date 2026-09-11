use std::{
    fs,
    path::{Path, PathBuf},
};

const NXB_PATH: &str = "crates/nxb-core/src/nxb.rs";
const FACADE_PATH: &str = "crates/nxb-core/src/workspace_authority.rs";
const RECEIPTS_PATH: &str = "crates/nxb-core/src/workspace_authority_receipts.rs";
const TARGET_PATH: &str = "crates/nxb-core/src/target.rs";
const ACTIVATION_PATH: &str = "crates/nxb-core/src/target/activation.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let path = repository_root().join(path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
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
fn crate_routes_target_workspace_calls_through_the_authority_facade() {
    let nxb = source(NXB_PATH);
    for marker in [
        "#[path = \"workspace/mod.rs\"]\nmod workspace_impl;",
        "#[path = \"workspace_authority.rs\"]\nmod workspace;",
        "mod workspace_authority_receipts;",
    ] {
        assert!(
            nxb.contains(marker),
            "{NXB_PATH}: workspace authority routing marker missing: {marker}"
        );
    }
}

#[test]
fn every_target_cli_command_retains_one_authority_scope_for_the_entire_result_path() {
    let target = source(TARGET_PATH);
    let run = section(
        &target,
        TARGET_PATH,
        "pub(crate) fn run(args: TargetArgs) -> ExitCode {",
        "\n#[derive(Debug, Clone, Serialize)]\nstruct SetupProgram",
    );
    let scope = run
        .find("let _authority_scope = workspace::target_authority_scope();")
        .expect("target run must acquire one operation authority scope");
    let dispatch = run
        .find("match args.command")
        .expect("target run command dispatch is missing");
    let result_gate = run
        .rfind("match result")
        .expect("target run final result gate is missing");
    assert!(
        scope < dispatch && dispatch < result_gate,
        "{TARGET_PATH}: authority scope must outlive command dispatch through final result handling"
    );
}

#[test]
fn target_readiness_and_target_records_resolve_under_retained_authorities() {
    let target = source(TARGET_PATH);

    let ready = section(
        &target,
        TARGET_PATH,
        "fn ready_workspace(",
        "\nfn targets_directory(",
    );
    for marker in [
        "workspace::validate_workspace_root(workspace_path, true)?",
        "workspace::status_value(&root)?",
        "workspace::migration::status_value(&root)?",
    ] {
        assert!(
            ready.contains(marker),
            "{TARGET_PATH}: readiness authority marker missing: {marker}"
        );
    }

    let targets = section(
        &target,
        TARGET_PATH,
        "fn targets_directory(",
        "\nfn load_profiles(",
    );
    assert!(
        targets.contains("workspace::pin_private_child_path(root, \"targets\", \"target directory\")"),
        "{TARGET_PATH}: targets must resolve through the retained workspace root authority"
    );
    for forbidden in ["fs::metadata(", "root.join(\"targets\")"] {
        assert!(
            !targets.contains(forbidden),
            "{TARGET_PATH}: targets authority must not fall back to a check-then-pathname sequence: {forbidden}"
        );
    }

    let list = section(&target, TARGET_PATH, "fn list_value(", "\nfn show_value(");
    assert!(
        list.contains("workspace::logical_authority_path(&root).display().to_string()"),
        "{TARGET_PATH}: public workspace output must not leak Linux /proc/self/fd authority paths"
    );
}

#[test]
fn guided_activation_pins_state_and_targets_before_any_continuity_read_or_publication() {
    let activation = source(ACTIVATION_PATH);
    let body = section(
        &activation,
        ACTIVATION_PATH,
        "pub(super) fn activate_value(",
        "\nfn activation_value(",
    );

    let root = body
        .find("workspace::validate_workspace_root(workspace_path, true)?")
        .expect("activation root authority acquisition is missing");
    let targets = body
        .find("super::targets_directory(&root)?")
        .expect("activation targets authority acquisition is missing");
    let state = body
        .find("workspace::pin_private_child_path(")
        .expect("activation state authority acquisition is missing");
    let profile = body
        .find("let profile_path = targets.join(")
        .expect("activation profile path construction is missing");
    let artifact = body
        .find("let artifact_path = state.join(")
        .expect("activation artifact path must be derived from the pinned state authority");
    let first_exists = body
        .find("workspace::safe_exists(&profile_path)?")
        .expect("activation profile existence gate is missing");

    assert!(
        root < targets
            && targets < state
            && state < profile
            && profile < artifact
            && artifact < first_exists,
        "{ACTIVATION_PATH}: root/targets/state authorities must be acquired before continuity observation/publication"
    );
    assert!(
        !body.contains("root.join(&artifact_relative_path)"),
        "{ACTIVATION_PATH}: guided artifact must not be resolved again through the workspace pathname"
    );
}

#[test]
fn facade_retains_authorities_and_binds_reads_publications_and_migration_state_to_them() {
    let facade = source(FACADE_PATH);

    for marker in [
        "thread_local!",
        "root: Option<DirectoryAuthority>",
        "children: BTreeMap<String, DirectoryAuthority>",
        "pub(crate) struct TargetAuthorityScope;",
        "pub(crate) fn target_authority_scope()",
        "impl Drop for TargetAuthorityScope",
        "DirectoryAuthority::pin_private(workspace, \"workspace root\", require_absolute)?",
        "authority.pin_private_child(name, label)?",
        "pub(crate) fn logical_authority_path(",
    ] {
        assert!(
            facade.contains(marker),
            "{FACADE_PATH}: retained authority lifecycle marker missing: {marker}"
        );
    }

    let status = section(
        &facade,
        FACADE_PATH,
        "pub(crate) fn status_value(",
        "\npub(crate) mod migration",
    );
    assert!(
        status.contains("for directory in TARGET_READY_DIRECTORIES"),
        "{FACADE_PATH}: target readiness must pin the canonical workspace children"
    );
    assert!(
        status.contains("root_child_path(crate::workspace_impl::MANIFEST_FILE"),
        "{FACADE_PATH}: manifest readiness read must be rooted in the retained workspace authority"
    );

    let migration = section(
        &facade,
        FACADE_PATH,
        "pub(crate) mod migration",
        "\npub(crate) fn reject_path_indirections(",
    );
    for marker in [
        "pin_private_child_path(workspace, \"state\", \"migration state directory\")?",
        "workspace_authority_receipts::validate_target_readiness_receipts(workspace)?",
    ] {
        assert!(
            migration.contains(marker),
            "{FACADE_PATH}: migration readiness marker missing: {marker}"
        );
    }

    let receipts = source(RECEIPTS_PATH);
    for marker in [
        "const MAX_RECEIPTS: usize = 1_024;",
        "migration receipts directory contains a non-file entry",
        "workspace_impl::validate_private_permissions(&receipts, true)?",
        "workspace_impl::validate_private_permissions(&path, false)?",
        "count > MAX_RECEIPTS",
    ] {
        assert!(
            receipts.contains(marker),
            "{RECEIPTS_PATH}: preserved migration receipt readiness marker missing: {marker}"
        );
    }

    let read = section(
        &facade,
        FACADE_PATH,
        "pub(crate) fn read_document(",
        "\nfn read_authority_document(",
    );
    assert!(
        read.contains("read_authority_document(path, label)"),
        "{FACADE_PATH}: workspace record reads under target scope must use authority-bound reads"
    );

    let create = section(
        &facade,
        FACADE_PATH,
        "fn create_authority_document(",
        "\nfn remove_authority_temporary(",
    );
    for marker in [
        "if !authority_exact_directory(parent)",
        "create_new(true)",
        "fs::hard_link(&temporary, path)",
        "sync_authority_directory(parent)",
    ] {
        assert!(
            create.contains(marker),
            "{FACADE_PATH}: authority-bound create-only publication marker missing: {marker}"
        );
    }
}

#[test]
fn authority_paths_fail_closed_instead_of_silently_falling_back_to_unpinned_names() {
    let facade = source(FACADE_PATH);
    for marker in [
        "target operation attempted to switch workspace authority after admission",
        "child directory request is not rooted in the admitted workspace authority",
        "attempted pathname fallback beneath an admitted workspace authority",
        "reject_logical_authority_fallback(path, label)?;",
        "reject_logical_authority_fallback(path, \"workspace authority existence check\")?;",
        "reject_logical_authority_fallback(path, \"workspace create-only publication\")?;",
        "create-only publication parent is not the retained directory authority",
        "publication parent directory authority is no longer retained",
        "live workspace document authority is unsupported on this Unix platform",
        "live workspace document authority is unsupported on this platform",
    ] {
        assert!(
            facade.contains(marker),
            "{FACADE_PATH}: fail-closed authority marker missing: {marker}"
        );
    }
}
