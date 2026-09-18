use std::{
    fs,
    path::{Path, PathBuf},
};

const LINUX_INNER_PATH: &str = "scripts/nxb-153-linux-immutable-source-inner.sh";
const WINDOWS_FS_PATH: &str = "crates/nxb-core/src/win32_fs_authority_lib.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_source(relative_path: &str) -> String {
    let path = repository_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

#[test]
fn windows_utf16_nul_guard_uses_rust_197_manual_contains_form() {
    let source = read_source(WINDOWS_FS_PATH);

    assert!(
        source.contains("wide.is_empty() || wide.contains(&0)"),
        "{WINDOWS_FS_PATH}: Win32 UTF-16 NUL guard must use contains() under -D warnings"
    );
    assert!(
        !source.contains("wide.iter().any(|value| *value == 0)"),
        "{WINDOWS_FS_PATH}: Rust 1.97 clippy::manual_contains regression returned"
    );
}

#[test]
fn linux_security_tools_run_from_receipt_bound_read_only_stable_paths() {
    let source = read_source(LINUX_INNER_PATH);

    for marker in [
        r#"anchored_tool_root="/proc/self/fd/$repo_fd/$tools_relative""#,
        r#"stable_tool_root="$tmp_root/validation-tools""#,
        r#"cp --reflink=never -- "$anchored_audit_path" "$audit_path""#,
        r#"cp --reflink=never -- "$anchored_deny_path" "$deny_path""#,
        r#"private cargo-audit snapshot differs from the receipt-bound SHA-256"#,
        r#"private cargo-deny snapshot differs from the receipt-bound SHA-256"#,
        r#"mount --bind "$stable_tool_root" "$stable_tool_root""#,
        r#"mount -o remount,bind,ro "$stable_tool_root""#,
        r#"assert_readonly_mount "$stable_tool_root" "validation tool snapshot""#,
        r#"scripts/nxb-153-sealed-tool.py inspect"#,
        r#""$audit_path" audit"#,
        r#""$deny_path" check"#,
        r#"private cargo-audit snapshot changed during execution"#,
        r#"private cargo-deny snapshot changed during execution"#,
    ] {
        assert!(
            source.contains(marker),
            "{LINUX_INNER_PATH}: missing stable immutable tool-execution marker: {marker}"
        );
    }

    assert!(
        !source.contains("scripts/nxb-153-sealed-tool.py run \\\n"),
        "{LINUX_INNER_PATH}: path-sensitive cargo-audit must not execute from an anonymous memfd"
    );
}
