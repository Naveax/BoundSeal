use std::{
    fs,
    path::{Path, PathBuf},
};

const TARGET_PATH: &str = "crates/nxb-core/src/target.rs";
const WORKSPACE_PATH: &str = "crates/nxb-core/src/workspace/mod.rs";
const AUTHORITY_PATH: &str = "crates/nxb-core/src/workspace/read_authority.rs";
const WINDOWS_PATH: &str = "crates/nxb-core/src/workspace/windows.rs";
const SCOPE_IMPORT_PATH: &str = "crates/nxb-core/src/target/scope_import.rs";

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
fn target_operator_sources_delegate_to_the_generalized_pinned_reader() {
    let target = source(TARGET_PATH);
    let helper = section(
        &target,
        TARGET_PATH,
        "fn read_bounded_source(",
        "\nfn profile_path(",
    );
    assert!(
        helper.contains("workspace::read_bounded_source(path, label, maximum)"),
        "{TARGET_PATH}: operator source helper must delegate to the workspace authority primitive"
    );
    for forbidden in ["fs::metadata(", "File::open(", ".read_to_end("] {
        assert!(
            !helper.contains(forbidden),
            "{TARGET_PATH}: operator source helper must not reintroduce path-check-then-open I/O: {forbidden}"
        );
    }

    let workspace = source(WORKSPACE_PATH);
    let wrapper = section(
        &workspace,
        WORKSPACE_PATH,
        "pub(crate) fn read_bounded_source(",
        "\nfn write_probe(",
    );
    assert!(
        wrapper.contains("read_authority::read_bounded_source(path, label, maximum)"),
        "{WORKSPACE_PATH}: bounded source reads must share the workspace read-authority implementation"
    );

    let authority = source(AUTHORITY_PATH);
    for marker in [
        "enum ReadPermission",
        "WorkspacePrivate",
        "OperatorProvided",
        "read_bounded(path, label, maximum, ReadPermission::OperatorProvided)",
        "let parent_authority = pin_parent_namespace(path, label)?;",
        "let mut file = open_document_authority(authority_path, label)?;",
        ".take(maximum + 1)",
        "let final_metadata = file",
        "validate_platform_stability(",
    ] {
        assert!(
            authority.contains(marker),
            "{AUTHORITY_PATH}: generalized bounded read is missing authority marker: {marker}"
        );
    }
}

#[test]
fn linux_and_windows_source_authority_pin_the_parent_namespace_and_final_file() {
    let authority = source(AUTHORITY_PATH);
    let linux_parent = section(
        &authority,
        AUTHORITY_PATH,
        "#[cfg(target_os = \"linux\")]\nfn pin_parent_namespace(",
        "\n#[cfg(windows)]\nfn pin_parent_namespace(",
    );
    for marker in [
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "opened.dev() != expected.dev()",
        "opened.ino() != expected.ino()",
        "named.dev() != opened.dev()",
        "named.ino() != opened.ino()",
        "/proc/self/fd/",
        "stable_parent.join(file_name)",
    ] {
        assert!(
            linux_parent.contains(marker),
            "{AUTHORITY_PATH}: Linux parent authority is missing marker: {marker}"
        );
    }

    let windows_parent = section(
        &authority,
        AUTHORITY_PATH,
        "#[cfg(windows)]\nfn pin_parent_namespace(",
        "\n#[cfg(all(unix, not(target_os = \"linux\")))]\nfn pin_parent_namespace(",
    );
    for marker in [
        "FILE_READ_ATTRIBUTES",
        "FILE_SHARE_READ",
        "FILE_SHARE_WRITE",
        "FILE_FLAG_BACKUP_SEMANTICS",
        "FILE_FLAG_OPEN_REPARSE_POINT",
        ".ancestors()",
        ".share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)",
        "current_parent != canonical_parent",
    ] {
        assert!(
            windows_parent.contains(marker),
            "{AUTHORITY_PATH}: Windows parent namespace authority is missing marker: {marker}"
        );
    }
    assert!(
        !windows_parent.contains("FILE_SHARE_DELETE"),
        "{AUTHORITY_PATH}: pinned Windows parent handles must deny delete/rename sharing"
    );

    let windows = source(WINDOWS_PATH);
    let final_handle = section(
        &windows,
        WINDOWS_PATH,
        "pub(super) fn open_document_read_authority(",
        "\npub(super) fn set_private_directory_permissions(",
    );
    for marker in [
        ".share_mode(FILE_SHARE_READ)",
        ".custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)",
        "is_reparse_point(&metadata) || !metadata.is_file()",
    ] {
        assert!(
            final_handle.contains(marker),
            "{WINDOWS_PATH}: Windows final-file authority is missing marker: {marker}"
        );
    }
}

#[test]
fn operator_inputs_keep_their_exact_existing_size_caps_and_do_not_require_workspace_private_acl() {
    let target = source(TARGET_PATH);
    assert!(
        target.contains("const MAX_POLICY_BYTES: u64 = 1024 * 1024;"),
        "{TARGET_PATH}: policy cap drifted from 1 MiB"
    );
    assert!(
        target.contains("const MAX_AUTHORIZATION_BYTES: u64 = 8 * 1024 * 1024;"),
        "{TARGET_PATH}: authorization cap drifted from 8 MiB"
    );

    let scope = source(SCOPE_IMPORT_PATH);
    assert!(
        scope.contains("const MAX_SCOPE_IMPORT_BYTES: u64 = 64 * 1024;"),
        "{SCOPE_IMPORT_PATH}: scope-import cap drifted from 64 KiB"
    );

    let authority = source(AUTHORITY_PATH);
    let linux_validation = section(
        &authority,
        AUTHORITY_PATH,
        "#[cfg(target_os = \"linux\")]\nfn validate_platform_authority(",
        "\n#[cfg(windows)]\nfn validate_platform_authority(",
    );
    let windows_validation = section(
        &authority,
        AUTHORITY_PATH,
        "#[cfg(windows)]\nfn validate_platform_authority(",
        "\n#[cfg(all(unix, not(target_os = \"linux\")))]\nfn validate_platform_authority(",
    );
    for body in [linux_validation, windows_validation] {
        assert!(
            body.contains("permission == ReadPermission::WorkspacePrivate"),
            "{AUTHORITY_PATH}: private-permission validation must be conditional on workspace records"
        );
    }

    assert!(
        authority.contains("linux_operator_source_uses_exact_caller_cap_without_private_mode_requirement"),
        "{AUTHORITY_PATH}: Linux exact-cap/non-private operator-source regression test is missing"
    );
    assert!(
        authority.contains("windows_operator_source_does_not_require_workspace_private_acl"),
        "{AUTHORITY_PATH}: Windows exact-cap/non-private operator-source regression test is missing"
    );
}
