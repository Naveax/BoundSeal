use std::{
    fs,
    path::{Path, PathBuf},
};

const LINUX_GATE: &str = "scripts/nxb-153-linux-immutable-source-inner.sh";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn linux_exact_head_gate_covers_docs_and_all_target_workspace_tests() {
    let path = repository_root().join(LINUX_GATE);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()));

    for marker in [
        "cargo_gate check --workspace --all-targets --all-features --locked",
        "cargo_gate clippy --workspace --all-targets --all-features --locked -- -D warnings",
        "RUSTDOCFLAGS='-D warnings' cargo_gate doc --workspace --all-features --no-deps --locked",
        "cargo_gate test --workspace --all-targets --all-features --locked -- --test-threads=1",
    ] {
        assert!(
            source.contains(marker),
            "{LINUX_GATE}: missing exact-head admission gate marker: {marker}"
        );
    }

    assert!(
        !source.contains("cargo_gate test --workspace --all-features --locked -- --test-threads=1"),
        "{LINUX_GATE}: workspace test gate must retain --all-targets"
    );
}
