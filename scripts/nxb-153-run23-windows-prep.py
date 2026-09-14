from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement anchor, found {count}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


windows_gate = Path("scripts/nxb-153-windows-dependency-source.ps1")
git_output_guard = Path("scripts/nxb-153-windows-immutable-source-git-output-inner.ps1")
enumeration_guard = Path("scripts/nxb-153-windows-immutable-source-enumeration-inner.ps1")

replace_once(
    windows_gate,
    "        Invoke-NxbDependencyCargo -Arguments @('check', '--workspace', '--all-targets', '--all-features', '--locked') -Label 'workspace cargo check'\n        Invoke-NxbDependencyCargo -Arguments @('clippy', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings') -Label 'workspace cargo clippy'\n        Invoke-NxbDependencyCargo -Arguments @('test', '--workspace', '--all-features', '--locked', '--', '--test-threads=1') -Label 'workspace cargo test'",
    "        Invoke-NxbDependencyCargo -Arguments @('check', '--workspace', '--all-targets', '--all-features', '--locked') -Label 'workspace cargo check'\n        Invoke-NxbDependencyCargo -Arguments @('clippy', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings') -Label 'workspace cargo clippy'\n        $env:RUSTDOCFLAGS = '-D warnings'\n        try {\n            Invoke-NxbDependencyCargo -Arguments @('doc', '--workspace', '--all-features', '--no-deps', '--locked') -Label 'workspace cargo doc'\n        }\n        finally {\n            Remove-Item Env:RUSTDOCFLAGS -ErrorAction SilentlyContinue\n        }\n        Invoke-NxbDependencyCargo -Arguments @('test', '--workspace', '--all-targets', '--all-features', '--locked', '--', '--test-threads=1') -Label 'workspace cargo test'",
)

replace_once(
    git_output_guard,
    "    . $innerPath @innerParameters",
    "    & $innerPath @innerParameters",
)
replace_once(
    enumeration_guard,
    "    . $innerPath @innerParameters",
    "    & $innerPath @innerParameters",
)

contract = Path("crates/nxb-core/tests/nxb153_run23_windows_admission_gate_coverage_source_contract.rs")
contract.write_text(
    r'''use std::{
    fs,
    path::{Path, PathBuf},
};

const WINDOWS_GATE: &str = "scripts/nxb-153-windows-dependency-source.ps1";
const GIT_OUTPUT_GUARD: &str = "scripts/nxb-153-windows-immutable-source-git-output-inner.ps1";
const ENUMERATION_GUARD: &str = "scripts/nxb-153-windows-immutable-source-enumeration-inner.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

#[test]
fn windows_exact_head_gate_covers_docs_and_all_target_workspace_tests() {
    let source = source(WINDOWS_GATE);

    for marker in [
        "@('check', '--workspace', '--all-targets', '--all-features', '--locked')",
        "@('clippy', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings')",
        "$env:RUSTDOCFLAGS = '-D warnings'",
        "@('doc', '--workspace', '--all-features', '--no-deps', '--locked')",
        "Remove-Item Env:RUSTDOCFLAGS -ErrorAction SilentlyContinue",
        "@('test', '--workspace', '--all-targets', '--all-features', '--locked', '--', '--test-threads=1')",
    ] {
        assert!(
            source.contains(marker),
            "{WINDOWS_GATE}: missing exact-head admission gate marker: {marker}"
        );
    }

    assert!(
        !source.contains("@('test', '--workspace', '--all-features', '--locked', '--', '--test-threads=1')"),
        "{WINDOWS_GATE}: workspace test gate must retain --all-targets"
    );
}

#[test]
fn windows_h2_nested_wrappers_execute_in_child_scope() {
    for path in [GIT_OUTPUT_GUARD, ENUMERATION_GUARD] {
        let source = source(path);
        assert!(
            source.contains("& $innerPath @innerParameters"),
            "{path}: nested wrapper must execute through child scope"
        );
        assert!(
            !source.contains(". $innerPath @innerParameters"),
            "{path}: dot-sourcing can overwrite retained outer authority handles"
        );
    }
}
''',
    encoding="utf-8",
)
