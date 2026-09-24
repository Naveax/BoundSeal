use std::{
    fs,
    path::{Path, PathBuf},
};

const WINDOWS_TOOLCHAIN_AUTHORITY_PATH: &str = "scripts/nxb-153-rust-toolchain-authority.py";
const LINUX_REPLACEMENT_AUTHORITY_PATH: &str =
    "crates/nxb-core/src/workspace_authority_replacement.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

#[test]
fn windows_toolchain_open_identity_uses_stable_object_identity_before_timestamp_stability() {
    let authority = source(WINDOWS_TOOLCHAIN_AUTHORITY_PATH);
    for marker in [
        "def same_file_object(first, second):",
        "first.st_dev == second.st_dev",
        "and first.st_ino == second.st_ino",
        "and first.st_ino != 0",
        "if platform_model == \"windows\":",
        "if not same_file_object(opened, expected) or opened.st_size != expected.st_size:",
        "if total != opened.st_size or metadata_identity(after) != metadata_identity(opened):",
        "self-test same-object identity rejected timestamp normalization",
    ] {
        assert!(
            authority.contains(marker),
            "{WINDOWS_TOOLCHAIN_AUTHORITY_PATH}: missing run-15 Windows identity marker: {marker}"
        );
    }
}

#[test]
fn linux_replacement_external_procfs_paths_use_the_pid_visible_in_the_active_proc_mount() {
    let replacement = source(LINUX_REPLACEMENT_AUTHORITY_PATH);
    for marker in [
        "fn linux_proc_visible_pid() -> Result<String>",
        "fs::read_link(\"/proc/self\")",
        "fn external_stable_path(&self, name: &OsStr, proc_pid: &str) -> PathBuf",
        "let proc_pid = linux_proc_visible_pid()?;",
        "let destination = self.external_stable_path(destination, &proc_pid);",
        "proc_visible_pid_resolves_retained_parent_fd_in_the_active_proc_mount",
    ] {
        assert!(
            replacement.contains(marker),
            "{LINUX_REPLACEMENT_AUTHORITY_PATH}: missing run-15 procfs marker: {marker}"
        );
    }

    let production_end = replacement
        .find("\n#[cfg(test)]")
        .expect("replacement authority is missing its test boundary");
    assert!(
        !replacement[..production_end].contains("std::process::id()"),
        "{LINUX_REPLACEMENT_AUTHORITY_PATH}: production external procfs authority must not use namespace-local getpid"
    );
}
