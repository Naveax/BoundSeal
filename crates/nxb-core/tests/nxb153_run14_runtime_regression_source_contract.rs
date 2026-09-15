use std::{
    fs,
    path::{Path, PathBuf},
};

const WINDOWS_BROKER_ENTRY_PATH: &str =
    "scripts/nxb-153-windows-immutable-source-h2-broker-entry.ps1";
const PREPARED_FILE_AUTHORITY_PATH: &str = "crates/nxb-core/src/prepared_file_authority.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

fn required_offset(source: &str, marker: &str, path: &str) -> usize {
    source
        .find(marker)
        .unwrap_or_else(|| panic!("{path}: missing source marker: {marker}"))
}

fn required_section<'a>(source: &'a str, path: &str, start: &str, end: &str) -> &'a str {
    let start_offset = required_offset(source, start, path);
    let tail = &source[start_offset..];
    let end_offset = tail
        .find(end)
        .unwrap_or_else(|| panic!("{path}: missing section end: {end}"));
    &tail[..end_offset]
}

#[test]
fn windows_h2_snapshot_path_helper_is_lexically_captured_before_child_proxy_handoff() {
    let source = read_source(WINDOWS_BROKER_ENTRY_PATH);
    let definition = required_offset(
        &source,
        "function Test-NxbH2BrokerSnapshotPath {",
        WINDOWS_BROKER_ENTRY_PATH,
    );
    let capture = required_offset(
        &source,
        "$testSnapshotPathEvaluator = (Get-Command Test-NxbH2BrokerSnapshotPath -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()",
        WINDOWS_BROKER_ENTRY_PATH,
    );
    let new_item_closure = required_offset(
        &source,
        "$newItemProxy = (Get-Command New-Item -CommandType Function -ErrorAction Stop).ScriptBlock.GetNewClosure()",
        WINDOWS_BROKER_ENTRY_PATH,
    );
    let new_item_install = required_offset(
        &source,
        r"Set-Item -Path Function:\New-Item -Value $newItemProxy -Force",
        WINDOWS_BROKER_ENTRY_PATH,
    );
    let child_call = required_offset(
        &source,
        "    & $h2EntryPath @innerParameters",
        WINDOWS_BROKER_ENTRY_PATH,
    );

    assert!(
        definition < capture
            && capture < new_item_closure
            && new_item_closure < new_item_install
            && new_item_install < child_call,
        "{WINDOWS_BROKER_ENTRY_PATH}: snapshot-path authority must be defined and lexically captured before child-visible proxy closure installation and H2 child handoff"
    );
    assert!(
        source.contains("(& $testSnapshotPathEvaluator -Path $Path)"),
        "{WINDOWS_BROKER_ENTRY_PATH}: New-Item proxy must invoke the captured snapshot-path evaluator"
    );
    assert!(
        !source.contains(r"Set-Item -Path Function:\Test-NxbH2BrokerSnapshotPath"),
        "{WINDOWS_BROKER_ENTRY_PATH}: snapshot-path authority must not depend on reinstalling a named helper into child scope"
    );
    assert!(
        !source.contains("(Test-NxbH2BrokerSnapshotPath -Path $Path)"),
        "{WINDOWS_BROKER_ENTRY_PATH}: child proxy must not dynamically resolve the snapshot-path helper"
    );
}

#[test]
fn linux_prepared_fd_claim_uses_procfs_visible_pid_instead_of_namespace_local_getpid() {
    let source = read_source(PREPARED_FILE_AUTHORITY_PATH);

    for marker in [
        "fn linux_proc_visible_pid() -> Result<String>",
        "fs::read_link(\"/proc/self\")",
        "procfs-visible Linux process identity is not canonical decimal digits",
        "let proc_pid = linux_proc_visible_pid()?;",
        "\"/proc/{}/fd/{}\"",
        "let destination_for_child = linux_external_process_path(destination)?;",
        "proc_visible_pid_names_the_retained_process_in_the_active_proc_mount",
    ] {
        assert!(
            source.contains(marker),
            "{PREPARED_FILE_AUTHORITY_PATH}: missing run-14 procfs authority marker: {marker}"
        );
    }

    let claim = required_section(
        &source,
        PREPARED_FILE_AUTHORITY_PATH,
        "#[cfg(target_os = \"linux\")]\n    pub(crate) fn claim_create_only",
        "\n    #[cfg(windows)]\n    pub(crate) fn claim_create_only",
    );
    assert!(
        !claim.contains("std::process::id()"),
        "{PREPARED_FILE_AUTHORITY_PATH}: external Linux hard-link source must not use a PID-namespace-local getpid value as procfs authority"
    );
    assert!(
        claim.contains("linux_proc_visible_pid()?"),
        "{PREPARED_FILE_AUTHORITY_PATH}: Linux retained-FD claim must resolve the PID visible through the active proc mount"
    );
}
