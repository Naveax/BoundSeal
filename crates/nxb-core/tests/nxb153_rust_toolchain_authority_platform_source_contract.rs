use std::{fs, path::Path};

const AUTHORITY_PATH: &str = "scripts/nxb-153-rust-toolchain-authority.py";

fn source() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::read_to_string(root.join(AUTHORITY_PATH)).expect("authority source must be UTF-8")
}

#[test]
fn self_test_uses_native_descriptor_model_and_portable_windows_collision_checks() {
    let text = source();
    let start = text.find("def self_test():").expect("self-test is missing");
    let end = text[start..]
        .find("\n\ndef main():")
        .map(|offset| start + offset)
        .expect("self-test boundary is missing");
    let body = &text[start..end];

    for marker in [
        "native_model = \"windows\" if os.name == \"nt\" else \"linux\"",
        "first_native = digest_tree(first, native_model)",
        "second_native = digest_tree(second, native_model)",
        "digest_tree(bounded, native_model, max_files=1)",
        "digest_tree(bounded, native_model, max_total_bytes=1)",
        "digest_tree(directory_bound, native_model, max_directories=1)",
        "digest_tree(symlink_root, native_model)",
        "windows_relative_bytes(\"Tool.exe\")",
        "windows_relative_bytes(\"tool.exe\")",
        "if os.name != \"nt\":",
    ] {
        assert!(
            body.contains(marker),
            "{AUTHORITY_PATH}: missing marker: {marker}"
        );
    }

    for forbidden in [
        "first_linux = digest_tree(first, \"linux\")",
        "second_linux = digest_tree(second, \"linux\")",
        "digest_tree(bounded, \"linux\", max_files=1)",
        "digest_tree(bounded, \"linux\", max_total_bytes=1)",
        "digest_tree(directory_bound, \"linux\", max_directories=1)",
        "digest_tree(symlink_root, \"linux\")",
    ] {
        assert!(
            !body.contains(forbidden),
            "{AUTHORITY_PATH}: Windows self-test would still invoke Linux descriptor authority: {forbidden}"
        );
    }
}
