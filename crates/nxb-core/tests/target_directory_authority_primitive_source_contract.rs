use std::{
    fs,
    path::{Path, PathBuf},
};

const NXB_PATH: &str = "crates/nxb-core/src/nxb.rs";
const AUTHORITY_PATH: &str = "crates/nxb-core/src/directory_authority.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let path = repository_root().join(path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn section<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let start_index = text
        .find(start)
        .unwrap_or_else(|| panic!("{AUTHORITY_PATH}: missing section start: {start}"));
    let tail = &text[start_index..];
    let end_relative = tail
        .find(end)
        .unwrap_or_else(|| panic!("{AUTHORITY_PATH}: missing section end: {end}"));
    &tail[..end_relative]
}

#[test]
fn live_directory_authority_is_compiled_as_an_explicit_nxb153_staging_boundary() {
    let nxb = source(NXB_PATH);
    assert!(
        nxb.contains("mod directory_authority;"),
        "{NXB_PATH}: live directory authority primitive must be compiled"
    );
    assert!(
        nxb.contains("NXB-153/#108 staging; remove when target wiring lands"),
        "{NXB_PATH}: temporary dead-code staging must remain explicit until target wiring lands"
    );
}

#[test]
fn linux_authority_uses_opened_directory_identity_and_handle_derived_namespace() {
    let authority = source(AUTHORITY_PATH);
    let linux_root = section(
        &authority,
        "#[cfg(target_os = \"linux\")]\nfn pin_private_directory(",
        "\n#[cfg(target_os = \"linux\")]\nfn pin_private_child(",
    );
    for marker in [
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "opened.dev() != expected.dev()",
        "opened.ino() != expected.ino()",
        "named.dev() != opened.dev()",
        "named.ino() != opened.ino()",
        "/proc/self/fd/",
        "handle.as_raw_fd()",
        "validate_private_linux_directory(&opened, label)?",
    ] {
        assert!(
            linux_root.contains(marker),
            "{AUTHORITY_PATH}: Linux root authority is missing marker: {marker}"
        );
    }

    let linux_child = section(
        &authority,
        "#[cfg(target_os = \"linux\")]\nfn pin_private_child(",
        "\n#[cfg(target_os = \"linux\")]\nfn validate_private_linux_directory(",
    );
    for marker in [
        "let candidate = parent.stable_path.join(name);",
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "opened.dev() != expected.dev()",
        "opened.ino() != expected.ino()",
        "/proc/self/fd/",
    ] {
        assert!(
            linux_child.contains(marker),
            "{AUTHORITY_PATH}: Linux child authority is missing marker: {marker}"
        );
    }

    assert!(
        authority.contains("pinned_root_survives_original_path_replacement_without_redirection"),
        "{AUTHORITY_PATH}: Linux root replacement regression is missing"
    );
    assert!(
        authority.contains("pinned_child_survives_child_path_replacement_without_redirection"),
        "{AUTHORITY_PATH}: Linux child replacement regression is missing"
    );
}

#[test]
fn windows_authority_holds_reparse_safe_ancestor_and_child_handles_without_delete_share() {
    let authority = source(AUTHORITY_PATH);
    let windows_root = section(
        &authority,
        "#[cfg(windows)]\nfn pin_private_directory(",
        "\n#[cfg(windows)]\nfn pin_private_child(",
    );
    for marker in [
        "FILE_READ_ATTRIBUTES",
        "FILE_SHARE_READ",
        "FILE_SHARE_WRITE",
        "FILE_FLAG_BACKUP_SEMANTICS",
        "FILE_FLAG_OPEN_REPARSE_POINT",
        ".ancestors()",
        ".share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)",
        "metadata_is_reparse_point(&metadata)",
        "validate_private_permissions(&canonical, true)?",
    ] {
        assert!(
            windows_root.contains(marker),
            "{AUTHORITY_PATH}: Windows root authority is missing marker: {marker}"
        );
    }
    assert!(
        !windows_root.contains("FILE_SHARE_DELETE"),
        "{AUTHORITY_PATH}: Windows root authority must deny delete/rename sharing"
    );

    let windows_child = section(
        &authority,
        "#[cfg(windows)]\nfn pin_private_child(",
        "\n#[cfg(all(unix, not(target_os = \"linux\")))]\nfn pin_private_directory(",
    );
    for marker in [
        "let candidate = parent.stable_path.join(name);",
        ".share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)",
        "FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT",
        "handle.try_clone()",
        "handles.push(child);",
    ] {
        assert!(
            windows_child.contains(marker),
            "{AUTHORITY_PATH}: Windows child authority is missing marker: {marker}"
        );
    }
    assert!(
        !windows_child.contains("FILE_SHARE_DELETE"),
        "{AUTHORITY_PATH}: Windows child authority must deny delete/rename sharing"
    );

    assert!(
        authority.contains("pinned_windows_root_denies_rename_until_authority_is_released"),
        "{AUTHORITY_PATH}: Windows root lifetime regression is missing"
    );
    assert!(
        authority.contains("pinned_windows_child_denies_rename_until_child_authority_is_released"),
        "{AUTHORITY_PATH}: Windows child lifetime regression is missing"
    );
}

#[test]
fn unsupported_platforms_fail_closed_and_child_resolution_is_single_component_only() {
    let authority = source(AUTHORITY_PATH);
    for marker in [
        "live workspace directory authority is unsupported on this Unix platform",
        "live workspace directory authority is unsupported on this platform",
        "child name must be one literal path component",
    ] {
        assert!(
            authority.contains(marker),
            "{AUTHORITY_PATH}: fail-closed authority marker missing: {marker}"
        );
    }
}
