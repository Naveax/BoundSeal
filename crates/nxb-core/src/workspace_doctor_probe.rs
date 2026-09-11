use std::{fs, io::Write, path::Path};

use anyhow::{bail, Context, Result};

const PROBE_BYTES: &[u8] = b"nxb-doctor-probe\n";

pub(crate) fn run(directory: &Path) -> Result<()> {
    crate::workspace_impl::reject_path_indirections(directory, "doctor probe directory")?;
    crate::workspace_impl::validate_private_permissions(directory, true)?;

    #[cfg(target_os = "linux")]
    {
        return run_linux(directory);
    }
    #[cfg(windows)]
    {
        return run_windows(directory);
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = directory;
        bail!("object-lifetime doctor write probe is unsupported on this platform")
    }
}

#[cfg(target_os = "linux")]
fn run_linux(directory: &Path) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // Linux asm-generic: O_TMPFILE = __O_TMPFILE | O_DIRECTORY.
    // This creates an unnamed inode in `directory`; closing the final file
    // descriptor removes it without any pathname cleanup authority.
    const O_TMPFILE: i32 = 0o20200000;

    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(O_TMPFILE);
    let mut file = options
        .open(directory)
        .with_context(|| format!("could not create unnamed doctor probe in {}", directory.display()))?;

    let initial = file
        .metadata()
        .context("could not inspect unnamed doctor probe")?;
    if !initial.is_file() {
        bail!("unnamed doctor probe is not a regular file object");
    }
    let mode = initial.permissions().mode();
    if mode & 0o077 != 0 || mode & 0o600 != 0o600 {
        bail!("unnamed doctor probe permissions are not private");
    }

    file.write_all(PROBE_BYTES)?;
    file.sync_all()?;
    let final_metadata = file
        .metadata()
        .context("could not re-inspect unnamed doctor probe")?;
    if final_metadata.len() != PROBE_BYTES.len() as u64 {
        bail!("unnamed doctor probe size changed unexpectedly");
    }
    Ok(())
}

#[cfg(windows)]
fn run_windows(directory: &Path) -> Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;

    let path = directory.join(format!(
        "doctor-write-probe-{}.tmp",
        crate::workspace_impl::random_hex(12)?
    ));
    crate::workspace_impl::reject_path_indirections(&path, "doctor probe path")?;

    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .attributes(FILE_ATTRIBUTE_TEMPORARY)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_DELETE_ON_CLOSE);
    let mut file = options
        .open(&path)
        .with_context(|| format!("could not create delete-on-close doctor probe {}", path.display()))?;

    let initial = file
        .metadata()
        .context("could not inspect delete-on-close doctor probe")?;
    if !initial.is_file() || initial.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("delete-on-close doctor probe is a reparse point or non-file");
    }

    file.write_all(PROBE_BYTES)?;
    file.sync_all()?;
    let final_metadata = file
        .metadata()
        .context("could not re-inspect delete-on-close doctor probe")?;
    if final_metadata.file_size() != PROBE_BYTES.len() as u64
        || final_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        bail!("delete-on-close doctor probe changed unexpectedly");
    }

    drop(file);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!("delete-on-close doctor probe pathname remains populated after handle close"),
        Err(error) => Err(error).with_context(|| {
            format!(
                "could not verify delete-on-close doctor probe finalization {}",
                path.display()
            )
        }),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn unnamed_probe_leaves_no_directory_entry() {
        let root = std::env::temp_dir().join(format!(
            "nxb-doctor-probe-{}-{}",
            std::process::id(),
            crate::workspace_impl::random_hex(8).unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let before = fs::read_dir(&root).unwrap().count();

        run(&root).unwrap();

        assert_eq!(fs::read_dir(&root).unwrap().count(), before);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn delete_on_close_probe_leaves_no_directory_entry() {
        let root = std::env::temp_dir().join(format!(
            "nxb-doctor-probe-{}-{}",
            std::process::id(),
            crate::workspace_impl::random_hex(8).unwrap()
        ));
        fs::create_dir(&root).unwrap();
        crate::workspace_impl::set_private_directory_permissions(&root).unwrap();
        let before = fs::read_dir(&root).unwrap().count();

        run(&root).unwrap();

        assert_eq!(fs::read_dir(&root).unwrap().count(), before);
        fs::remove_dir_all(root).unwrap();
    }
}
