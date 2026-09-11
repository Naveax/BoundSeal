use std::{fs, io::Write, path::{Path, PathBuf}};

use anyhow::{bail, Context, Result};

/// Live authority over one prepared workspace file.
///
/// The opened file remains retained from creation through namespace claim or
/// replacement finalization. Callers must not treat the temporary pathname as
/// authority; it is diagnostic/cleanup state only.
pub(crate) struct PreparedFileAuthority {
    path: PathBuf,
    file: fs::File,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl PreparedFileAuthority {
    pub(crate) fn create_named(path: &Path, bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() as u64 > crate::workspace_impl::MAX_DOCUMENT_BYTES {
            bail!("prepared document size is invalid");
        }

        crate::workspace_impl::reject_path_indirections(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("prepared file has no parent"))?,
            "prepared file parent",
        )?;
        crate::workspace_impl::reject_path_indirections(path, "prepared file")?;

        let mut options = fs::OpenOptions::new();
        options.write(true).read(true).create_new(true);

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;

            const FILE_SHARE_READ: u32 = 0x0000_0001;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            const O_NOFOLLOW: i32 = 0o400000;
            options.custom_flags(O_NOFOLLOW);
        }

        #[cfg(all(unix, not(target_os = "linux")))]
        {
            bail!("prepared file authority is unsupported on this Unix platform");
        }

        #[cfg(not(any(unix, windows)))]
        {
            bail!("prepared file authority is unsupported on this platform");
        }

        let mut file = options
            .open(path)
            .with_context(|| format!("could not create prepared file {}", path.display()))?;

        crate::workspace_impl::set_private_file_permissions(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;

        let metadata = file
            .metadata()
            .with_context(|| format!("could not inspect prepared file {}", path.display()))?;
        if !metadata.is_file() {
            bail!("prepared workspace object is not a regular file");
        }

        #[cfg(windows)]
        if crate::workspace_impl::windows::is_reparse_point(&metadata) {
            bail!("prepared workspace object is a reparse point");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 || mode & 0o600 != 0o600 {
                bail!("prepared workspace object permissions are not private");
            }
        }

        let authority = Self {
            path: path.to_path_buf(),
            #[cfg(unix)]
            dev: {
                use std::os::unix::fs::MetadataExt;
                metadata.dev()
            },
            #[cfg(unix)]
            ino: {
                use std::os::unix::fs::MetadataExt;
                metadata.ino()
            },
            file,
        };
        authority.validate_named_binding()?;
        Ok(authority)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn file(&self) -> &fs::File {
        &self.file
    }

    pub(crate) fn validate_named_binding(&self) -> Result<()> {
        let named = fs::symlink_metadata(&self.path)
            .with_context(|| format!("could not inspect prepared path {}", self.path.display()))?;
        if named.file_type().is_symlink() || !named.is_file() {
            bail!("prepared pathname no longer names a regular file");
        }

        #[cfg(windows)]
        if crate::workspace_impl::windows::is_reparse_point(&named) {
            bail!("prepared pathname became a reparse point");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if named.dev() != self.dev || named.ino() != self.ino {
                bail!("prepared pathname no longer names the retained file authority");
            }
        }

        Ok(())
    }

    pub(crate) fn validate_destination_binding(&self, destination: &Path) -> Result<()> {
        let destination_metadata = fs::symlink_metadata(destination).with_context(|| {
            format!(
                "could not inspect published prepared destination {}",
                destination.display()
            )
        })?;
        if destination_metadata.file_type().is_symlink() || !destination_metadata.is_file() {
            bail!("published destination is not a regular prepared file");
        }

        #[cfg(windows)]
        if crate::workspace_impl::windows::is_reparse_point(&destination_metadata) {
            bail!("published destination is a reparse point");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if destination_metadata.dev() != self.dev || destination_metadata.ino() != self.ino {
                bail!("published destination is not the retained prepared file authority");
            }
        }

        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn prepared_authority_detects_same_permission_path_replacement() {
        let root = std::env::temp_dir().join(format!(
            "nxb-prepared-authority-{}-{}",
            std::process::id(),
            crate::workspace_impl::random_hex(8).unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let prepared = root.join("prepared.tmp");
        let moved = root.join("moved.tmp");
        let replacement = root.join("replacement.tmp");

        let authority = PreparedFileAuthority::create_named(&prepared, b"prepared\n").unwrap();
        fs::rename(&prepared, &moved).unwrap();
        fs::write(&replacement, b"replacement\n").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &prepared).unwrap();

        assert!(authority.validate_named_binding().is_err());
        assert_eq!(fs::read(authority.file()).unwrap(), b"prepared\n");

        drop(authority);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn prepared_windows_handle_denies_rename_until_authority_is_released() {
        let root = std::env::temp_dir().join(format!(
            "nxb-prepared-authority-{}-{}",
            std::process::id(),
            crate::workspace_impl::random_hex(8).unwrap()
        ));
        fs::create_dir(&root).unwrap();
        crate::workspace_impl::set_private_directory_permissions(&root).unwrap();
        let prepared = root.join("prepared.tmp");
        let moved = root.join("moved.tmp");

        let authority = PreparedFileAuthority::create_named(&prepared, b"prepared\n").unwrap();
        assert!(fs::rename(&prepared, &moved).is_err());
        drop(authority);
        fs::rename(&prepared, &moved).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
