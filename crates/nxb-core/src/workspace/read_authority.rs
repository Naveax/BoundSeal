use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};

use super::{reject_path_indirections, MAX_DOCUMENT_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadPermission {
    WorkspacePrivate,
    OperatorProvided,
}

struct PinnedParentNamespace {
    stable_child_path: PathBuf,
    #[cfg(target_os = "linux")]
    _parent: fs::File,
    #[cfg(windows)]
    _parents: Vec<fs::File>,
}

impl PinnedParentNamespace {
    fn child_path(&self) -> &Path {
        &self.stable_child_path
    }
}

pub(super) fn read_document(path: &Path, label: &str) -> Result<Vec<u8>> {
    read_bounded(
        path,
        label,
        MAX_DOCUMENT_BYTES,
        ReadPermission::WorkspacePrivate,
    )
}

pub(super) fn read_bounded_source(path: &Path, label: &str, maximum: u64) -> Result<Vec<u8>> {
    read_bounded(path, label, maximum, ReadPermission::OperatorProvided)
}

fn read_bounded(
    path: &Path,
    label: &str,
    maximum: u64,
    permission: ReadPermission,
) -> Result<Vec<u8>> {
    if maximum == 0 || maximum == u64::MAX {
        bail!("{label} read limit is invalid");
    }

    let parent_authority = pin_parent_namespace(path, label)?;
    let authority_path = parent_authority.child_path();
    let mut file = open_document_authority(authority_path, label)?;
    let initial = file
        .metadata()
        .with_context(|| format!("could not inspect pinned {label}: {}", path.display()))?;
    validate_opened_metadata(&initial, label, maximum)?;
    validate_platform_authority(authority_path, &initial, label, permission)?;

    let capacity = usize::try_from(initial.len()).context("pinned source size does not fit memory")?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read pinned {label}: {}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        bail!("{label} exceeds the supported size limit or is empty");
    }

    let final_metadata = file
        .metadata()
        .with_context(|| format!("could not re-inspect pinned {label}: {}", path.display()))?;
    validate_opened_metadata(&final_metadata, label, maximum)?;
    if bytes.len() as u64 != initial.len() || final_metadata.len() != initial.len() {
        bail!("{label} changed size while being read");
    }
    validate_platform_stability(
        authority_path,
        &initial,
        &final_metadata,
        label,
        permission,
    )?;
    Ok(bytes)
}

fn validate_opened_metadata(metadata: &fs::Metadata, label: &str, maximum: u64) -> Result<()> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!("{label} size or type is invalid");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn pin_parent_namespace(path: &Path, label: &str) -> Result<PinnedParentNamespace> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };

    const O_DIRECTORY: i32 = 0o200000;
    const O_NOFOLLOW: i32 = 0o400000;

    reject_path_indirections(path, label)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{label} path has no final file name"))?
        .to_os_string();
    let raw_parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} path has no parent"))?;
    let parent = if raw_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        raw_parent
    };
    let canonical_parent = fs::canonicalize(parent)
        .with_context(|| format!("could not canonicalize {label} parent {}", parent.display()))?;
    reject_path_indirections(&canonical_parent, label)?;

    let expected = fs::symlink_metadata(&canonical_parent).with_context(|| {
        format!(
            "could not inspect admitted {label} parent {}",
            canonical_parent.display()
        )
    })?;
    if expected.file_type().is_symlink() || !expected.is_dir() {
        bail!("{label} parent is not a regular directory authority");
    }

    let parent_handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(&canonical_parent)
        .with_context(|| {
            format!(
                "could not pin {label} parent directory {}",
                canonical_parent.display()
            )
        })?;
    let opened = parent_handle.metadata().with_context(|| {
        format!(
            "could not inspect pinned {label} parent {}",
            canonical_parent.display()
        )
    })?;
    if !opened.is_dir() || opened.dev() != expected.dev() || opened.ino() != expected.ino() {
        bail!("{label} parent identity changed while directory authority was acquired");
    }

    let named = fs::symlink_metadata(&canonical_parent).with_context(|| {
        format!(
            "could not re-inspect named {label} parent {}",
            canonical_parent.display()
        )
    })?;
    if named.file_type().is_symlink()
        || !named.is_dir()
        || named.dev() != opened.dev()
        || named.ino() != opened.ino()
    {
        bail!("{label} parent pathname identity changed after pinning");
    }

    let stable_parent = PathBuf::from(format!("/proc/self/fd/{}", parent_handle.as_raw_fd()));
    let stable_metadata = fs::metadata(&stable_parent)
        .with_context(|| format!("could not resolve pinned {label} parent through /proc/self/fd"))?;
    if !stable_metadata.is_dir()
        || stable_metadata.dev() != opened.dev()
        || stable_metadata.ino() != opened.ino()
    {
        bail!("{label} parent handle-derived namespace does not match the pinned directory");
    }

    Ok(PinnedParentNamespace {
        stable_child_path: stable_parent.join(file_name),
        _parent: parent_handle,
    })
}

#[cfg(windows)]
fn pin_parent_namespace(path: &Path, label: &str) -> Result<PinnedParentNamespace> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    reject_path_indirections(path, label)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{label} path has no final file name"))?
        .to_os_string();
    let raw_parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} path has no parent"))?;
    let parent = if raw_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        raw_parent
    };
    let canonical_parent = fs::canonicalize(parent)
        .with_context(|| format!("could not canonicalize {label} parent {}", parent.display()))?;
    reject_path_indirections(&canonical_parent, label)?;

    let mut ancestors = canonical_parent
        .ancestors()
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    ancestors.reverse();

    let mut handles = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let handle = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&ancestor)
            .with_context(|| {
                format!(
                    "could not pin {label} ancestor directory {}",
                    ancestor.display()
                )
            })?;
        let metadata = handle.metadata().with_context(|| {
            format!(
                "could not inspect pinned {label} ancestor {}",
                ancestor.display()
            )
        })?;
        if !metadata.is_dir() || super::windows::is_reparse_point(&metadata) {
            bail!(
                "pinned {label} ancestor is a reparse point or non-directory: {}",
                ancestor.display()
            );
        }
        handles.push(handle);
    }

    reject_path_indirections(&canonical_parent, label)?;
    let current_parent = fs::canonicalize(parent).with_context(|| {
        format!(
            "could not re-canonicalize pinned {label} parent {}",
            parent.display()
        )
    })?;
    if current_parent != canonical_parent {
        bail!("{label} parent pathname changed while directory authority was acquired");
    }
    let named = fs::symlink_metadata(&canonical_parent).with_context(|| {
        format!(
            "could not re-inspect pinned {label} parent {}",
            canonical_parent.display()
        )
    })?;
    if !named.is_dir() || super::windows::is_reparse_point(&named) {
        bail!("{label} parent is no longer a regular non-reparse directory");
    }

    Ok(PinnedParentNamespace {
        stable_child_path: canonical_parent.join(file_name),
        _parents: handles,
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn pin_parent_namespace(_path: &Path, _label: &str) -> Result<PinnedParentNamespace> {
    bail!("pinned parent namespace authority is unsupported on this Unix platform")
}

#[cfg(not(any(unix, windows)))]
fn pin_parent_namespace(_path: &Path, _label: &str) -> Result<PinnedParentNamespace> {
    bail!("pinned parent namespace authority is unsupported on this platform")
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
fn validate_platform_authority(
    path: &Path,
    opened: &fs::Metadata,
    label: &str,
    permission: ReadPermission,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if permission == ReadPermission::WorkspacePrivate {
        let mode = opened.permissions().mode();
        if mode & 0o077 != 0 || mode & 0o600 != 0o600 {
            bail!("{label} permissions are not private");
        }
    }

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
fn validate_platform_authority(
    path: &Path,
    _opened: &fs::Metadata,
    label: &str,
    permission: ReadPermission,
) -> Result<()> {
    let named = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect named {label}: {}", path.display()))?;
    if super::windows::is_reparse_point(&named) || !named.is_file() {
        bail!("{label} pathname no longer names a regular non-reparse file");
    }
    if permission == ReadPermission::WorkspacePrivate {
        super::validate_private_permissions(path, false)?;
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn validate_platform_authority(
    _path: &Path,
    _opened: &fs::Metadata,
    _label: &str,
    _permission: ReadPermission,
) -> Result<()> {
    bail!("workspace document authority is unsupported on this Unix platform")
}

#[cfg(not(any(unix, windows)))]
fn validate_platform_authority(
    _path: &Path,
    _opened: &fs::Metadata,
    _label: &str,
    _permission: ReadPermission,
) -> Result<()> {
    bail!("workspace document authority is unsupported on this platform")
}

#[cfg(target_os = "linux")]
fn validate_platform_stability(
    path: &Path,
    initial: &fs::Metadata,
    final_metadata: &fs::Metadata,
    label: &str,
    permission: ReadPermission,
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
    validate_platform_authority(path, final_metadata, label, permission)
}

#[cfg(windows)]
fn validate_platform_stability(
    path: &Path,
    initial: &fs::Metadata,
    final_metadata: &fs::Metadata,
    label: &str,
    permission: ReadPermission,
) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    if super::windows::is_reparse_point(final_metadata)
        || !final_metadata.is_file()
        || initial.creation_time() != final_metadata.creation_time()
        || initial.last_write_time() != final_metadata.last_write_time()
        || initial.file_size() != final_metadata.file_size()
    {
        bail!("pinned {label} changed identity, type or content metadata while being read");
    }
    validate_platform_authority(path, final_metadata, label, permission)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn validate_platform_stability(
    _path: &Path,
    _initial: &fs::Metadata,
    _final_metadata: &fs::Metadata,
    _label: &str,
    _permission: ReadPermission,
) -> Result<()> {
    bail!("workspace document authority is unsupported on this Unix platform")
}

#[cfg(not(any(unix, windows)))]
fn validate_platform_stability(
    _path: &Path,
    _initial: &fs::Metadata,
    _final_metadata: &fs::Metadata,
    _label: &str,
    _permission: ReadPermission,
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

    fn file_with_mode(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        file_with_mode(path, bytes, 0o600);
    }

    #[test]
    fn linux_no_follow_rejects_final_symlink() {
        let root = temporary_root("nofollow");
        fs::create_dir(&root).unwrap();
        let target = root.join("target.json");
        let link = root.join("link.json");
        private_file(&target, b"{}\n");
        symlink(&target, &link).unwrap();

        assert!(read_bounded_source(&link, "test operator source", 64).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linux_operator_source_uses_exact_caller_cap_without_private_mode_requirement() {
        let root = temporary_root("operator-cap");
        fs::create_dir(&root).unwrap();
        let path = root.join("source.bin");
        file_with_mode(&path, b"12345678", 0o644);

        assert_eq!(
            read_bounded_source(&path, "test operator source", 8).unwrap(),
            b"12345678"
        );
        assert!(read_bounded_source(&path, "test operator source", 7).is_err());
        assert!(read_document(&path, "test workspace document").is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linux_pinned_parent_namespace_survives_pathname_replacement_without_redirection() {
        let root = temporary_root("parent-replacement");
        let admitted = root.join("admitted");
        let replacement = root.join("replacement");
        let moved = root.join("moved");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&admitted).unwrap();
        fs::create_dir(&replacement).unwrap();
        let path = admitted.join("record.bin");
        fs::write(&path, b"admitted").unwrap();
        fs::write(replacement.join("record.bin"), b"replacement").unwrap();

        let parent = pin_parent_namespace(&path, "test operator source").unwrap();
        fs::rename(&admitted, &moved).unwrap();
        fs::rename(&replacement, &admitted).unwrap();

        let mut file = open_document_authority(parent.child_path(), "test operator source").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"admitted");

        drop(file);
        drop(parent);
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

        let error = validate_platform_authority(
            &path,
            &opened,
            "test document",
            ReadPermission::WorkspacePrivate,
        )
        .unwrap_err();
        assert!(error.to_string().contains("identity changed"));

        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nxb-read-authority-windows-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn pinned_windows_parent_handles_block_rename_until_drop() {
        let root = temporary_root();
        fs::create_dir(&root).unwrap();
        let parent_path = root.join("parent");
        fs::create_dir(&parent_path).unwrap();
        let path = parent_path.join("record.bin");
        fs::write(&path, b"operator source").unwrap();

        let pinned = pin_parent_namespace(&path, "test operator source").unwrap();
        let renamed = root.join("renamed-parent");
        assert!(fs::rename(&parent_path, &renamed).is_err());

        drop(pinned);
        fs::rename(&parent_path, &renamed).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn windows_operator_source_does_not_require_workspace_private_acl() {
        let root = temporary_root();
        fs::create_dir(&root).unwrap();
        let path = root.join("operator-source.bin");
        fs::write(&path, b"12345678").unwrap();

        assert_eq!(
            read_bounded_source(&path, "test operator source", 8).unwrap(),
            b"12345678"
        );
        assert!(read_bounded_source(&path, "test operator source", 7).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_windows_read_handle_blocks_write_delete_and_rename_until_drop() {
        let root = temporary_root();
        fs::create_dir(&root).unwrap();
        super::super::set_private_directory_permissions(&root).unwrap();
        let path = root.join("record.json");
        fs::write(&path, b"{}\n").unwrap();
        super::super::set_private_file_permissions(&path).unwrap();

        let pinned = open_document_authority(&path, "test document").unwrap();
        validate_platform_authority(
            &path,
            &pinned.metadata().unwrap(),
            "test document",
            ReadPermission::WorkspacePrivate,
        )
        .unwrap();

        assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::remove_file(&path).is_err());
        let renamed = root.join("renamed.json");
        assert!(fs::rename(&path, &renamed).is_err());

        drop(pinned);
        fs::rename(&path, &renamed).unwrap();
        fs::remove_file(&renamed).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
