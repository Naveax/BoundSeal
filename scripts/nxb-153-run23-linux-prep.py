from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement anchor, found {count}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


activation = Path("crates/nxb-core/tests/target_activation_cli.rs")
target_import = Path("crates/nxb-core/tests/target_import_cli.rs")
linux_gate = Path("scripts/nxb-153-linux-immutable-source-inner.sh")

replace_once(
    activation,
    '''    assert_eq!(\n        status\n            .pointer("/records/targets")\n            .and_then(Value::as_u64),\n        Some(1)\n    );''',
    '''    assert_eq!(\n        status.pointer("/records/targets").and_then(Value::as_u64),\n        Some(1)\n    );''',
)

replace_once(
    target_import,
    '''    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 1);\n    assert_eq!(fs::read_dir(root.join("config")).unwrap().count(), 0);''',
    '''    let target_names = fs::read_dir(root.join("targets"))\n        .unwrap()\n        .map(|entry| entry.unwrap().file_name())\n        .collect::<Vec<_>>();\n    assert_eq!(\n        target_names\n            .iter()\n            .filter(|name| name.to_string_lossy() == "example-app.json")\n            .count(),\n        1\n    );\n    assert_eq!(fs::read_dir(root.join("config")).unwrap().count(), 0);''',
)

replace_once(
    linux_gate,
    '''            cargo_gate check --workspace --all-targets --all-features --locked\n            cargo_gate clippy --workspace --all-targets --all-features --locked -- -D warnings\n            cargo_gate test --workspace --all-features --locked -- --test-threads=1''',
    '''            cargo_gate check --workspace --all-targets --all-features --locked\n            cargo_gate clippy --workspace --all-targets --all-features --locked -- -D warnings\n            RUSTDOCFLAGS='-D warnings' cargo_gate doc --workspace --all-features --no-deps --locked\n            cargo_gate test --workspace --all-targets --all-features --locked -- --test-threads=1''',
)

contract = Path("crates/nxb-core/tests/nxb153_run23_admission_gate_coverage_source_contract.rs")
contract.write_text(
    r'''use std::{
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
''',
    encoding="utf-8",
)
