use std::{fs, path::PathBuf};

const WORKSPACE_PATH: &str = "crates/nxb-core/src/workspace/mod.rs";
const READ_AUTHORITY_PATH: &str = "crates/nxb-core/src/workspace/read_authority.rs";
const WINDOWS_PATH: &str = "crates/nxb-core/src/workspace/windows.rs";

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

fn index(text: &str, needle: &str, path: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("{path}: missing source marker: {needle}"))
}

#[test]
fn workspace_read_document_delegates_to_pinned_authority() {
    let workspace = source(WORKSPACE_PATH);
    assert!(
        workspace.contains("mod read_authority;"),
        "{WORKSPACE_PATH}: read authority module is not bound"
    );
    let start = index(
        &workspace,
        "pub(crate) fn read_document(path: &Path, label: &str) -> Result<Vec<u8>>",
        WORKSPACE_PATH,
    );
    let body = &workspace[start..];
    let end = body
        .find("\n}\n")
        .expect("workspace read_document boundary is missing")
        + 3;
    let body = &body[..end];
    assert!(
        body.contains("read_authority::read_document(path, label)"),
        "{WORKSPACE_PATH}: read_document must delegate to the pinned authority module"
    );
    for forbidden in ["File::open(path)", "fs::read(path)", "fs::metadata(path)"] {
        assert!(
            !body.contains(forbidden),
            "{WORKSPACE_PATH}: pathname check-then-read authority returned: {forbidden}"
        );
    }
}

#[test]
fn linux_read_authority_is_no_follow_same_handle_and_identity_bound() {
    let authority = source(READ_AUTHORITY_PATH);
    let production = authority
        .split("#[cfg(all(test, target_os = \"linux\"))]")
        .next()
        .expect("read-authority production boundary is missing");

    for marker in [
        "const O_NOFOLLOW: i32 = 0o400000;",
        ".custom_flags(O_NOFOLLOW)",
        "let mut file = open_document_authority(path, label)?;",
        "let initial = file",
        "(&mut file)",
        ".take(MAX_DOCUMENT_BYTES + 1)",
        "let final_metadata = file",
        "opened.dev() != named.dev() || opened.ino() != named.ino()",
        "initial.mtime() != final_metadata.mtime()",
        "initial.ctime() != final_metadata.ctime()",
        "validate_platform_authority(path, final_metadata, label)",
    ] {
        assert!(
            production.contains(marker),
            "{READ_AUTHORITY_PATH}: missing Linux/same-handle authority marker: {marker}"
        );
    }

    let open = index(
        production,
        "let mut file = open_document_authority(path, label)?;",
        READ_AUTHORITY_PATH,
    );
    let initial = index(production, "let initial = file", READ_AUTHORITY_PATH);
    let validate = index(
        production,
        "validate_platform_authority(path, &initial, label)?;",
        READ_AUTHORITY_PATH,
    );
    let read = index(production, "(&mut file)", READ_AUTHORITY_PATH);
    let final_metadata = index(production, "let final_metadata = file", READ_AUTHORITY_PATH);
    let stability = index(
        production,
        "validate_platform_stability(path, &initial, &final_metadata, label)?;",
        READ_AUTHORITY_PATH,
    );
    assert!(
        open < initial
            && initial < validate
            && validate < read
            && read < final_metadata
            && final_metadata < stability,
        "{READ_AUTHORITY_PATH}: opened-handle validation/read/stability ordering changed"
    );

    for forbidden in [
        "fs::read(path)",
        "File::open(path)",
        "remove_file(",
        "rename(",
        "replace_document(",
    ] {
        assert!(
            !production.contains(forbidden),
            "{READ_AUTHORITY_PATH}: read authority must not re-open or mutate by pathname: {forbidden}"
        );
    }
}

#[test]
fn windows_read_authority_pins_reparse_and_share_lifetime() {
    let windows = source(WINDOWS_PATH);
    for marker in [
        "const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;",
        "const FILE_SHARE_READ: u32 = 0x0000_0001;",
        "pub(super) fn open_document_read_authority(path: &Path) -> Result<fs::File>",
        ".share_mode(FILE_SHARE_READ)",
        ".custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)",
        "if is_reparse_point(&metadata) || !metadata.is_file()",
    ] {
        assert!(
            windows.contains(marker),
            "{WINDOWS_PATH}: missing pinned Windows read authority marker: {marker}"
        );
    }
    assert!(
        !windows.contains("const FILE_SHARE_WRITE"),
        "{WINDOWS_PATH}: pinned read authority must not admit write sharing"
    );
    assert!(
        !windows.contains("const FILE_SHARE_DELETE"),
        "{WINDOWS_PATH}: pinned read authority must not admit delete/rename sharing"
    );

    let authority = source(READ_AUTHORITY_PATH);
    for marker in [
        "super::windows::open_document_read_authority(path)",
        "super::windows::is_reparse_point(&named)",
        "super::validate_private_permissions(path, false)",
    ] {
        assert!(
            authority.contains(marker),
            "{READ_AUTHORITY_PATH}: missing Windows authority use marker: {marker}"
        );
    }
}
