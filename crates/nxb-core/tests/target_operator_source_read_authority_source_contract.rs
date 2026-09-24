use std::{
    fs,
    path::{Path, PathBuf},
};

const TARGET_PATH: &str = "crates/nxb-core/src/target.rs";
const WORKSPACE_PATH: &str = "crates/nxb-core/src/workspace/mod.rs";
const WORKSPACE_AUTHORITY_PATH: &str = "crates/nxb-core/src/workspace_authority.rs";
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
    assert!(
        workspace.contains("pub(crate) use read_authority::set_finalized_read_test_hook;"),
        "{WORKSPACE_PATH}: Linux consumer-race tests must reach the finalized read hook"
    );

    let facade = source(WORKSPACE_AUTHORITY_PATH);
    assert!(
        facade.contains("pub(crate) fn read_bounded_source(path: &Path, label: &str, maximum: u64)"),
        "{WORKSPACE_AUTHORITY_PATH}: active target authority must shadow bounded operator-source reads"
    );
    for marker in [
        "stable_authority_path(path)",
        "authority_exact_directory(parent)",
        "read_authority_bounded_source(&stable_path, label, maximum)",
        "crate::workspace_impl::read_bounded_source(path, label, maximum)",
    ] {
        assert!(
            facade.contains(marker),
            "{WORKSPACE_AUTHORITY_PATH}: authority-aware bounded source read is missing marker: {marker}"
        );
    }

    let authority = source(AUTHORITY_PATH);
    assert!(
        authority.contains("#[cfg(all(test, target_os = \"linux\"))]\nfn set_read_gate_test_hook"),
        "{AUTHORITY_PATH}: deterministic read-race hook must stay Linux-test-only"
    );
    assert!(
        !authority.contains("#[cfg(test)]\nfn set_read_gate_test_hook"),
        "{AUTHORITY_PATH}: generic test builds must not retain the Linux read-race hook"
    );
    assert!(
        !authority
            .contains("set_finalized_read_test_hook(hook: Option<Box<dyn FnMut(&Path, &str)>>)"),
        "{AUTHORITY_PATH}: finalized read hook must reuse its named alias under -D warnings"
    );
    assert!(
        !authority.contains("\ntype FinalizedReadTestHook = Box<dyn FnMut(&Path, &str)>;"),
        "{AUTHORITY_PATH}: the crate-visible finalized read setter must not expose a more-private alias"
    );
    for marker in [
        "pub(crate) type FinalizedReadTestHook = Box<dyn FnMut(&Path, &str)>;",
        "pub(crate) fn set_finalized_read_test_hook(hook: Option<FinalizedReadTestHook>)",
        "pub(crate) fn set_finalized_read_test_hook",
        "invoke_finalized_read_test_hook(path, label);",
    ] {
        assert!(
            authority.contains(marker),
            "{AUTHORITY_PATH}: finalized pinned-byte consumer hook is missing marker: {marker}"
        );
    }
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
        "const DELETE: u32 = 0x0001_0000;",
        "ancestor == canonical_parent",
        "FILE_READ_ATTRIBUTES | DELETE",
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
    for marker in [
        "fn windows_operator_source_rejects_reparse_parent_junction()",
        ".arg(\"mklink\")",
        ".arg(\"/J\")",
        "read_bounded_source(&through_reparse, \"test operator source\", 64)",
    ] {
        assert!(
            authority.contains(marker),
            "{AUTHORITY_PATH}: Windows reparse-parent runtime regression is missing marker: {marker}"
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
        authority.contains(
            "linux_operator_source_uses_exact_caller_cap_without_private_mode_requirement"
        ),
        "{AUTHORITY_PATH}: Linux exact-cap/non-private operator-source regression test is missing"
    );
    assert!(
        authority.contains("windows_operator_source_does_not_require_workspace_private_acl"),
        "{AUTHORITY_PATH}: Windows exact-cap/non-private operator-source regression test is missing"
    );
}

#[test]
fn operator_consumers_only_hash_compile_and_parse_returned_pinned_bytes() {
    let target = source(TARGET_PATH);
    for marker in [
        "let authorization_bytes = read_bounded_source(",
        "let authorization_document_sha256 = workspace::sha256(&authorization_bytes);",
        "let policy_bytes = read_bounded_source(policy_path, \"target policy\", MAX_POLICY_BYTES)?;",
        "&authorization_bytes,\n        &policy_bytes,",
        "let policy = parse_policy(policy_bytes)?;",
        "document_sha256: workspace::sha256(authorization_bytes)",
        "policy_sha256: workspace::sha256(policy_bytes)",
        "workspace::sha256(&policy_bytes) != profile.policy_sha256",
        "workspace::sha256(&authorization_bytes) != profile.authorization.document_sha256",
        "let policy = parse_policy(&policy_bytes)?;",
    ] {
        assert!(
            target.contains(marker),
            "{TARGET_PATH}: pinned operator bytes no longer feed the expected consumer: {marker}"
        );
    }

    let scope = source(SCOPE_IMPORT_PATH);
    for marker in [
        "let bytes = read_bounded_source(path, \"guided scope import\", MAX_SCOPE_IMPORT_BYTES)?;",
        "serde_json::from_slice(&bytes)",
    ] {
        assert!(
            scope.contains(marker),
            "{SCOPE_IMPORT_PATH}: scope import must parse only the returned pinned bytes: {marker}"
        );
    }

    let authority = source(AUTHORITY_PATH);
    for marker in [
        "linux_reader_fails_closed_when_final_path_is_replaced_after_initial_validation",
        "linux_reader_fails_closed_on_in_place_size_drift_at_the_read_gate",
        "linux_reader_fails_closed_on_same_size_content_drift_after_read",
    ] {
        assert!(
            authority.contains(marker),
            "{AUTHORITY_PATH}: deterministic pinned-byte race regression is missing: {marker}"
        );
    }

    for marker in [
        "policy_hash_consumes_pinned_bytes_after_post_validation_path_swap",
        "authorization_hash_consumes_pinned_bytes_after_post_validation_path_swap",
        "scope_import_consumes_pinned_bytes_after_post_validation_path_swap",
    ] {
        assert!(
            target.contains(marker),
            "{TARGET_PATH}: pinned-byte consumer race regression is missing: {marker}"
        );
    }
}
