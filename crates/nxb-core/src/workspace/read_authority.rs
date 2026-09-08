use std::{fs, io::Read, path::Path};

use anyhow::{bail, Context, Result};

use super::{reject_path_indirections, validate_private_permissions, MAX_DOCUMENT_BYTES};

pub(super) fn read_document(path: &Path, label: &str) -> Result<Vec<u8>> {
    reject_path_indirections(path, label)?;
    let mut file = open_document_authority(path, label)?;
    let initial = file
        .metadata()
        .with_context(|| format!("could not inspect pinned {label}: {}", path.display()))?;
    validate_opened_metadata(&initial, label)?;
    validate_platform_authority(path, &initial, label)?;

    let mut bytes = Vec::with_capacity(initial.len() as usize);
    (&mut file)
        .take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read pinned {label}: {}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        bail!("{label} exceeds the supported size limit or is empty");
    }

    let final_metadata = file
        .metadata()
        .with_context(|| format!("could not re-inspect pinned {label}: {}", path.display()))?;
    validate_opened_metadata(&final_metadata, label)?;
    if bytes.len() as u64 != initial.len() || final_metadata.len() != initial.len() {
        bail!("{label} changed size while being read");
    }
    validate_platform_stability(path, &initial, &final_metadata, label)?;
    Ok(bytes)
}

fn validate_opened_metadata(metadata: &fs::Metadata, label: &str) -> Result<()> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_DOCUMENT_BYTES {
        bail!("{label} size or type is invalid");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_document_authority(path: &Path, label: &str) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    const O_NOFOLLOW: i32 = 0o400000;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("could not open pinned {label}: {}", path.display()))
}

#[cfg(windows)]
fn open_document_authority(path: &Path, _label: &str) -> Result<fs::File> {
    super::windows::open_document_read_authority(path)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_document_authority(_path: &Path, _label: &str) -> Result<fs::File> {
    bail!("workspace document authority is unsupported on this Unix platform")
}

#[cfg(not(any(unix, windows)))]
fn open_document_authority(_path: &Path, _label: &str) -> Result<fs::File> {
    bail!("workspace document authority is unsupported on this platform")
}

#[cfg(target_os = "linux")]
fn validate_platform_authority(path: &Path, opened: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = opened.permissions().mode();
    if mode & 0o077 != 0 || mode & 0o600 != 0o600 {
        bail!("{label} permissions are not private");
    }

    reject_path_indirections(path, label)?;
    let named = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect named {label}: {}", path.display()))?;
    if named.file_type().is_symlink() || !named.is_file() {
        bail!("{label} pathname no longer names a regular file");
    }
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        bail!("{label} pathname identity changed after the document was opened");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_platform_authority(path: &Path, _opened: &fs::Metadata, label: &str) -> Result<()> {
    reject_path_indirections(path, label)?;
    let named = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect named {label}: {}", path.display()))?;
    if super::windows::is_reparse_point(&named) || !named.is_file() {
        bail!("{label} pathname no longer names a regular non-reparse file");
    }
    validate_private_permissions(path, false)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn validate_platform_authority(_path: &Path, _opened: &fs::Metadata, _label: &str) -> Result<()> {
    bail!("workspace document authority is unsupported on this Unix platform")
}

#[cfg(not(any(unix, windows)))]
fn validate_platform_authority(_path: &Path, _opened: &fs::Metadata, _label: &str) -> Result<()> {
    bail!("workspace document authority is unsupported on this platform")
}

#[cfg(target_os = "linux")]
fn validate_platform_stability(
    path: &Path,
    initial: &fs::Metadata,
    final_metadata: &fs::Metadata,
    label: &str,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if initial.dev() != final_metadata.dev()
        || initial.ino() != final_metadata.ino()
        || initial.mtime() != final_metadata.mtime()
        || initial.mtime_nsec() != final_metadata.mtime_nsec()
        || initial.ctime() != final_metadata.ctime()
        || initial.ctime_nsec() != final_metadata.ctime_nsec()
    {
        bail!("{label} file authority changed while being read");
    }
    validate_platform_authority(path, final_metadata, label)
}

#[cfg(windows)]
fn validate_platform_stability(
    path: &Path,
    _initial: &fs::Metadata,
    final_metadata: &fs::Metadata,
    label: &str,
) -> Result<()> {
    if super::windows::is_reparse_point(final_metadata) || !final_metadata.is_file() {
        bail!("pinned {label} changed type while being read");
    }
    validate_platform_authority(path, final_metadata, label)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn validate_platform_stability(
    _path: &Path,
    _initial: &fs::Metadata,
    _final_metadata: &fs::Metadata,
    _label: &str,
) -> Result<()> {
    bail!("workspace document authority is unsupported on this Unix platform")
}

#[cfg(not(any(unix, windows)))]
fn validate_platform_stability(
    _path: &Path,
    _initial: &fs::Metadata,
    _final_metadata: &fs::Metadata,
    _label: &str,
) -> Result<()> {
    bail!("workspace document authority is unsupported on this platform")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nxb-read-authority-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn linux_no_follow_rejects_final_symlink() {
        let root = temporary_root("nofollow");
        fs::create_dir(&root).unwrap();
        let target = root.join("target.json");
        let link = root.join("link.json");
        private_file(&target, b"{}\n");
        symlink(&target, &link).unwrap();

        assert!(open_document_authority(&link, "test document").is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linux_named_path_identity_rejects_post_open_replacement() {
        let root = temporary_root("identity");
        fs::create_dir(&root).unwrap();
        let path = root.join("record.json");
        let replacement = root.join("replacement.json");
        let original = root.join("original.json");
        private_file(&path, b"original\n");
        private_file(&replacement, b"replacement\n");

        let file = open_document_authority(&path, "test document").unwrap();
        let opened = file.metadata().unwrap();
        fs::rename(&path, &original).unwrap();
        fs::rename(&replacement, &path).unwrap();

        let error = validate_platform_authority(&path, &opened, "test document").unwrap_err();
        assert!(error.to_string().contains("identity changed"));

        fs::remove_dir_all(root).unwrap();
    }
}
