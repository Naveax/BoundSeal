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
publication = Path("crates/nxb-core/src/workspace_authority_publication.rs")
workspace = Path("crates/nxb-core/src/workspace/mod.rs")
prepared = Path("crates/nxb-core/src/prepared_file_authority.rs")

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

replace_once(
    publication,
    "use std::{fs, path::Path};",
    "#[cfg(unix)]\nuse std::fs;\nuse std::path::Path;",
)
replace_once(
    workspace,
    "pub(crate) mod migration;\nmod read_authority;",
    "#[cfg(not(windows))]\npub(crate) mod migration;\nmod read_authority;",
)
replace_once(
    workspace,
    "    fs::{self, File, OpenOptions},\n    io::Write,",
    "    fs::{self, OpenOptions},\n    io::Write,",
)
replace_once(
    workspace,
    "use anyhow::{bail, Context, Result};",
    "#[cfg(unix)]\nuse std::fs::File;\n\nuse anyhow::{bail, Context, Result};",
)
replace_once(
    prepared,
    "    path: PathBuf,\n    file: fs::File,",
    "    path: PathBuf,\n    // The Windows handle is intentionally retained for its sharing lifetime.\n    #[cfg_attr(windows, allow(dead_code))]\n    file: fs::File,",
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
const PUBLICATION: &str = "crates/nxb-core/src/workspace_authority_publication.rs";
const WORKSPACE: &str = "crates/nxb-core/src/workspace/mod.rs";
const PREPARED: &str = "crates/nxb-core/src/prepared_file_authority.rs";

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

#[test]
fn windows_workspace_composition_avoids_duplicate_and_unix_only_warning_paths() {
    let publication = source(PUBLICATION);
    assert!(publication.contains("#[cfg(unix)]\nuse std::fs;"));
    assert!(!publication.contains("use std::{fs, path::Path};"));

    let workspace = source(WORKSPACE);
    assert!(workspace.contains("#[cfg(not(windows))]\npub(crate) mod migration;"));
    assert!(workspace.contains("fs::{self, OpenOptions}"));
    assert!(workspace.contains("#[cfg(unix)]\nuse std::fs::File;"));
    assert!(!workspace.contains("fs::{self, File, OpenOptions}"));

    let prepared = source(PREPARED);
    assert!(prepared.contains(
        "#[cfg_attr(windows, allow(dead_code))]\n    file: fs::File,"
    ));
    assert!(!prepared.contains("#![allow(dead_code)]"));
}
''',
    encoding="utf-8",
)
