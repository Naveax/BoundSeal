use std::{fs, path::{Path, PathBuf}};

const NXB_PATH: &str = "crates/nxb-core/src/nxb.rs";
const ENTRY_PATH: &str = "crates/nxb-core/src/workspace_authority_entry.rs";
const FACADE_PATH: &str = "crates/nxb-core/src/workspace_facade.rs";
const PROBE_PATH: &str = "crates/nxb-core/src/workspace_doctor_probe.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
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
fn workspace_cli_routes_doctor_through_the_entry_override() {
    let nxb = source(NXB_PATH);
    assert!(nxb.contains("mod workspace_doctor_probe;"));
    assert!(nxb.contains("#[path = \"workspace_authority_entry.rs\"]\nmod workspace;"));

    let facade = source(FACADE_PATH);
    assert!(facade.contains("workspace::doctor_value(workspace_path)?"));

    let entry = source(ENTRY_PATH);
    let doctor = section(
        &entry,
        ENTRY_PATH,
        "pub(crate) fn doctor_value(workspace: &Path) -> Result<Value> {",
        "\npub(crate) fn status_value",
    );
    for marker in [
        "crate::workspace_doctor_probe::run(&root.join(\"tmp\"))",
        "\"name\": \"atomic_write_probe\"",
        "object-lifetime create/write/sync/finalization succeeded",
    ] {
        assert!(doctor.contains(marker), "{ENTRY_PATH}: missing doctor override marker: {marker}");
    }
    assert!(
        !doctor.contains("workspace_impl::doctor_value"),
        "{ENTRY_PATH}: workspace CLI doctor must not fall back to the pathname-cleanup probe"
    );
}

#[test]
fn linux_doctor_probe_uses_an_unnamed_tmpfile_object() {
    let probe = source(PROBE_PATH);
    let linux = section(
        &probe,
        PROBE_PATH,
        "#[cfg(target_os = \"linux\")]\nfn run_linux",
        "\n#[cfg(windows)]\nfn run_windows",
    );

    for marker in [
        "const O_TMPFILE: i32 = 0o20200000;",
        ".mode(0o600)",
        ".custom_flags(O_TMPFILE)",
        "file.write_all(PROBE_BYTES)?;",
        "file.sync_all()?;",
        "initial.permissions().mode()",
        "final_metadata.len() != PROBE_BYTES.len() as u64",
    ] {
        assert!(linux.contains(marker), "{PROBE_PATH}: missing Linux unnamed-probe marker: {marker}");
    }
}

#[test]
fn windows_doctor_probe_uses_delete_on_close_object_lifetime_cleanup() {
    let probe = source(PROBE_PATH);
    let windows = section(
        &probe,
        PROBE_PATH,
        "#[cfg(windows)]\nfn run_windows",
        "\n#[cfg(all(test, target_os = \"linux\"))]",
    );

    for marker in [
        "const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;",
        "const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;",
        "FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE",
        ".attributes(FILE_ATTRIBUTE_TEMPORARY)",
        "FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_DELETE_ON_CLOSE",
        "file.write_all(PROBE_BYTES)?;",
        "file.sync_all()?;",
        "drop(file);",
        "ErrorKind::NotFound => Ok(())",
    ] {
        assert!(windows.contains(marker), "{PROBE_PATH}: missing Windows delete-on-close marker: {marker}");
    }
}

#[test]
fn production_probe_never_performs_pathname_cleanup() {
    let probe = source(PROBE_PATH);
    let production = section(
        &probe,
        PROBE_PATH,
        "pub(crate) fn run(directory: &Path) -> Result<()> {",
        "\n#[cfg(all(test, target_os = \"linux\"))]",
    );
    for forbidden in [
        "remove_file(",
        "remove_regular(",
        "fs::rename(",
        "remove_dir_all(",
    ] {
        assert!(
            !production.contains(forbidden),
            "{PROBE_PATH}: production doctor probe must not pathname-clean its object: {forbidden}"
        );
    }
}

#[test]
fn platform_regressions_require_zero_probe_residue() {
    let probe = source(PROBE_PATH);
    for marker in [
        "unnamed_probe_leaves_no_directory_entry",
        "delete_on_close_probe_leaves_no_directory_entry",
        "assert_eq!(fs::read_dir(&root).unwrap().count(), before);",
    ] {
        assert!(probe.contains(marker), "{PROBE_PATH}: missing doctor-probe regression marker: {marker}");
    }
}
