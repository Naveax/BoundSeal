use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context, Result};

/// Live authority over one admitted private workspace directory.
///
/// Filesystem I/O after admission must use `path()`, not `display_path()`.
/// Linux derives the stable path from the held directory descriptor through
/// `/proc/self/fd`; Windows retains a no-delete-share handle chain so the
/// canonical pathname cannot be replaced for the authority lifetime.
pub(crate) struct DirectoryAuthority {
    logical_path: PathBuf,
    stable_path: PathBuf,
    #[cfg(target_os = "linux")]
    _handle: fs::File,
    #[cfg(windows)]
    _handles: Vec<fs::File>,
}

impl DirectoryAuthority {
    pub(crate) fn pin_private(path: &Path, label: &str, require_absolute: bool) -> Result<Self> {
        if require_absolute && !path.is_absolute() {
            bail!("{label} path must be absolute");
        }
        pin_private_directory(path, label)
    }

    pub(crate) fn pin_private_child(&self, name: &str, label: &str) -> Result<Self> {
        validate_child_name(name, label)?;
        pin_private_child(self, name, label)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.stable_path
    }

    pub(crate) fn display_path(&self) -> &Path {
        &self.logical_path
    }

    pub(crate) fn child_path(&self, name: &str, label: &str) -> Result<PathBuf> {
        validate_child_name(name, label)?;
        Ok(self.stable_path.join(name))
    }

    pub(crate) fn read_dir(&self, label: &str) -> Result<fs::ReadDir> {
        fs::read_dir(&self.stable_path).with_context(|| {
            format!(
                "could not enumerate pinned {label} directory {}",
                self.logical_path.display()
            )
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn sync(&self, label: &str) -> Result<()> {
        self._handle.sync_all().with_context(|| {
            format!(
                "could not synchronize pinned {label} directory {}",
                self.logical_path.display()
            )
        })
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    pub(crate) fn sync(&self, _label: &str) -> Result<()> {
        bail!("live workspace directory authority is unsupported on this Unix platform")
    }

    #[cfg(not(unix))]
    pub(crate) fn sync(&self, _label: &str) -> Result<()> {
        Ok(())
    }
}

fn validate_child_name(name: &str, label: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 || name.chars().any(char::is_control) {
        bail!("{label} child name is invalid");
    }
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("{label} child name must be one literal path component");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn pin_private_directory(path: &Path, label: &str) -> Result<DirectoryAuthority> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };

    const O_DIRECTORY: i32 = 0o200000;
    const O_NOFOLLOW: i32 = 0o400000;

    crate::workspace::reject_path_indirections(path, label)?;
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("could not canonicalize {label} {}", path.display()))?;
    crate::workspace::reject_path_indirections(&canonical, label)?;

    let expected = fs::symlink_metadata(&canonical)
        .with_context(|| format!("could not inspect admitted {label} {}", canonical.display()))?;
    if expected.file_type().is_symlink() || !expected.is_dir() {
        bail!("{label} is not a regular directory authority");
    }

    let handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(&canonical)
        .with_context(|| format!("could not pin {label} directory {}", canonical.display()))?;
    let opened = handle
        .metadata()
        .with_context(|| format!("could not inspect pinned {label} {}", canonical.display()))?;
    if !opened.is_dir() || opened.dev() != expected.dev() || opened.ino() != expected.ino() {
        bail!("{label} identity changed while directory authority was acquired");
    }
    validate_private_linux_directory(&opened, label)?;

    let named = fs::symlink_metadata(&canonical)
        .with_context(|| format!("could not re-inspect named {label} {}", canonical.display()))?;
    if named.file_type().is_symlink()
        || !named.is_dir()
        || named.dev() != opened.dev()
        || named.ino() != opened.ino()
    {
        bail!("{label} pathname identity changed after pinning");
    }

    let stable = PathBuf::from(format!("/proc/self/fd/{}", handle.as_raw_fd()));
    let stable_metadata = fs::metadata(&stable)
        .with_context(|| format!("could not resolve pinned {label} through /proc/self/fd"))?;
    if !stable_metadata.is_dir()
        || stable_metadata.dev() != opened.dev()
        || stable_metadata.ino() != opened.ino()
    {
        bail!("{label} handle-derived namespace does not match the pinned directory");
    }

    Ok(DirectoryAuthority {
        logical_path: canonical,
        stable_path: stable,
        _handle: handle,
    })
}

#[cfg(target_os = "linux")]
fn pin_private_child(
    parent: &DirectoryAuthority,
    name: &str,
    label: &str,
) -> Result<DirectoryAuthority> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };

    const O_DIRECTORY: i32 = 0o200000;
    const O_NOFOLLOW: i32 = 0o400000;

    let candidate = parent.stable_path.join(name);
    let expected = fs::symlink_metadata(&candidate).with_context(|| {
        format!(
            "could not inspect admitted {label} child {}",
            parent.logical_path.join(name).display()
        )
    })?;
    if expected.file_type().is_symlink() || !expected.is_dir() {
        bail!("{label} child is not a regular directory authority");
    }

    let handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(&candidate)
        .with_context(|| {
            format!(
                "could not pin {label} child directory {}",
                parent.logical_path.join(name).display()
            )
        })?;
    let opened = handle.metadata().with_context(|| {
        format!(
            "could not inspect pinned {label} child {}",
            parent.logical_path.join(name).display()
        )
    })?;
    if !opened.is_dir() || opened.dev() != expected.dev() || opened.ino() != expected.ino() {
        bail!("{label} child identity changed while directory authority was acquired");
    }
    validate_private_linux_directory(&opened, label)?;

    let named = fs::symlink_metadata(&candidate).with_context(|| {
        format!(
            "could not re-inspect pinned {label} child {}",
            parent.logical_path.join(name).display()
        )
    })?;
    if named.file_type().is_symlink()
        || !named.is_dir()
        || named.dev() != opened.dev()
        || named.ino() != opened.ino()
    {
        bail!("{label} child pathname identity changed after pinning");
    }

    let stable = PathBuf::from(format!("/proc/self/fd/{}", handle.as_raw_fd()));
    let stable_metadata = fs::metadata(&stable)
        .with_context(|| format!("could not resolve pinned {label} child through /proc/self/fd"))?;
    if !stable_metadata.is_dir()
        || stable_metadata.dev() != opened.dev()
        || stable_metadata.ino() != opened.ino()
    {
        bail!("{label} child handle-derived namespace does not match the pinned directory");
    }

    Ok(DirectoryAuthority {
        logical_path: parent.logical_path.join(name),
        stable_path: stable,
        _handle: handle,
    })
}

#[cfg(target_os = "linux")]
fn validate_private_linux_directory(metadata: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 || mode & 0o700 != 0o700 {
        bail!("{label} directory permissions are not private");
    }
    Ok(())
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn pin_private_directory(path: &Path, label: &str) -> Result<DirectoryAuthority> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    crate::workspace::reject_path_indirections(path, label)?;
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("could not canonicalize {label} {}", path.display()))?;
    crate::workspace::reject_path_indirections(&canonical, label)?;

    let mut ancestors = canonical
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
        if !metadata.is_dir() || metadata_is_reparse_point(&metadata) {
            bail!(
                "pinned {label} ancestor is a reparse point or non-directory: {}",
                ancestor.display()
            );
        }
        handles.push(handle);
    }

    let current = fs::canonicalize(path)
        .with_context(|| format!("could not re-canonicalize pinned {label} {}", path.display()))?;
    if current != canonical {
        bail!("{label} pathname changed while directory authority was acquired");
    }
    let named = fs::symlink_metadata(&canonical)
        .with_context(|| format!("could not re-inspect pinned {label} {}", canonical.display()))?;
    if !named.is_dir() || metadata_is_reparse_point(&named) {
        bail!("{label} is no longer a regular non-reparse directory");
    }
    crate::workspace::validate_private_permissions(&canonical, true)?;

    Ok(DirectoryAuthority {
        logical_path: canonical.clone(),
        stable_path: canonical,
        _handles: handles,
    })
}

#[cfg(windows)]
fn pin_private_child(
    parent: &DirectoryAuthority,
    name: &str,
    label: &str,
) -> Result<DirectoryAuthority> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let candidate = parent.stable_path.join(name);
    let named = fs::symlink_metadata(&candidate).with_context(|| {
        format!(
            "could not inspect admitted {label} child {}",
            parent.logical_path.join(name).display()
        )
    })?;
    if !named.is_dir() || metadata_is_reparse_point(&named) {
        bail!("{label} child is a reparse point or non-directory");
    }

    let child = fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&candidate)
        .with_context(|| {
            format!(
                "could not pin {label} child directory {}",
                parent.logical_path.join(name).display()
            )
        })?;
    let opened = child.metadata().with_context(|| {
        format!(
            "could not inspect pinned {label} child {}",
            parent.logical_path.join(name).display()
        )
    })?;
    if !opened.is_dir() || metadata_is_reparse_point(&opened) {
        bail!("pinned {label} child is a reparse point or non-directory");
    }
    crate::workspace::validate_private_permissions(&candidate, true)?;

    let mut handles = Vec::with_capacity(parent._handles.len() + 1);
    for handle in &parent._handles {
        handles.push(
            handle
                .try_clone()
                .with_context(|| format!("could not retain parent handle for pinned {label} child"))?,
        );
    }
    handles.push(child);

    Ok(DirectoryAuthority {
        logical_path: parent.logical_path.join(name),
        stable_path: candidate,
        _handles: handles,
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn pin_private_directory(_path: &Path, _label: &str) -> Result<DirectoryAuthority> {
    bail!("live workspace directory authority is unsupported on this Unix platform")
}

#[cfg(all(unix, not(target_os = "linux")))]
fn pin_private_child(
    _parent: &DirectoryAuthority,
    _name: &str,
    _label: &str,
) -> Result<DirectoryAuthority> {
    bail!("live workspace directory authority is unsupported on this Unix platform")
}

#[cfg(not(any(unix, windows)))]
fn pin_private_directory(_path: &Path, _label: &str) -> Result<DirectoryAuthority> {
    bail!("live workspace directory authority is unsupported on this platform")
}

#[cfg(not(any(unix, windows)))]
fn pin_private_child(
    _parent: &DirectoryAuthority,
    _name: &str,
    _label: &str,
) -> Result<DirectoryAuthority> {
    bail!("live workspace directory authority is unsupported on this platform")
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nxb-directory-authority-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn make_private(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn pinned_root_survives_original_path_replacement_without_redirection() {
        let root = temporary_root("root-replacement");
        let replacement = temporary_root("root-replacement-new");
        let moved = temporary_root("root-replacement-moved");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&replacement).unwrap();
        make_private(&root);
        make_private(&replacement);
        fs::write(root.join("sentinel"), b"admitted").unwrap();
        fs::write(replacement.join("sentinel"), b"replacement").unwrap();

        let authority = DirectoryAuthority::pin_private(&root, "test root", true).unwrap();
        fs::rename(&root, &moved).unwrap();
        fs::rename(&replacement, &root).unwrap();

        let stable = authority.child_path("sentinel", "test sentinel").unwrap();
        assert_eq!(fs::read(stable).unwrap(), b"admitted");

        drop(authority);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[test]
    fn pinned_child_survives_child_path_replacement_without_redirection() {
        let root = temporary_root("child-replacement");
        fs::create_dir(&root).unwrap();
        make_private(&root);
        let targets = root.join("targets");
        let replacement = root.join("replacement");
        let moved = root.join("moved");
        fs::create_dir(&targets).unwrap();
        fs::create_dir(&replacement).unwrap();
        make_private(&targets);
        make_private(&replacement);
        fs::write(targets.join("sentinel"), b"admitted").unwrap();
        fs::write(replacement.join("sentinel"), b"replacement").unwrap();

        let root_authority = DirectoryAuthority::pin_private(&root, "test root", true).unwrap();
        let targets_authority = root_authority
            .pin_private_child("targets", "test targets")
            .unwrap();
        fs::rename(&targets, &moved).unwrap();
        fs::rename(&replacement, &targets).unwrap();

        let stable = targets_authority
            .child_path("sentinel", "test sentinel")
            .unwrap();
        assert_eq!(fs::read(stable).unwrap(), b"admitted");

        drop(targets_authority);
        drop(root_authority);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn non_private_directory_is_rejected_from_live_workspace_authority() {
        let root = temporary_root("permissions");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(DirectoryAuthority::pin_private(&root, "test root", true).is_err());

        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nxb-directory-authority-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn pinned_windows_root_denies_rename_until_authority_is_released() {
        let root = temporary_root("root-rename");
        fs::create_dir(&root).unwrap();
        crate::workspace::set_private_directory_permissions(&root).unwrap();
        let moved = root.with_extension("moved");

        let authority = DirectoryAuthority::pin_private(&root, "test root", true).unwrap();
        assert!(fs::rename(&root, &moved).is_err());

        drop(authority);
        fs::rename(&root, &moved).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[test]
    fn pinned_windows_child_denies_rename_until_child_authority_is_released() {
        let root = temporary_root("child-rename");
        fs::create_dir(&root).unwrap();
        crate::workspace::set_private_directory_permissions(&root).unwrap();
        let targets = root.join("targets");
        fs::create_dir(&targets).unwrap();
        crate::workspace::set_private_directory_permissions(&targets).unwrap();
        let moved = root.join("targets-moved");

        let root_authority = DirectoryAuthority::pin_private(&root, "test root", true).unwrap();
        let targets_authority = root_authority
            .pin_private_child("targets", "test targets")
            .unwrap();
        assert!(fs::rename(&targets, &moved).is_err());

        drop(targets_authority);
        drop(root_authority);
        fs::rename(&targets, &moved).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
