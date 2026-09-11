use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use nxb_win32_fs_authority::{file_identity, rename_handle_relative_no_replace, FileIdentity};

const DELETE: u32 = 0x0001_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

struct ParentAuthority {
    logical_path: PathBuf,
    handles: Vec<File>,
}

impl ParentAuthority {
    fn open(path: &Path) -> Result<Self> {
        crate::workspace_impl::reject_path_indirections(path, "replacement parent")?;
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("could not canonicalize replacement parent {}", path.display()))?;
        crate::workspace_impl::reject_path_indirections(&canonical, "replacement parent")?;

        let mut ancestors = canonical.ancestors().map(Path::to_path_buf).collect::<Vec<_>>();
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
                        "could not retain replacement parent ancestor {}",
                        ancestor.display()
                    )
                })?;
            let metadata = handle.metadata().with_context(|| {
                format!(
                    "could not inspect replacement parent ancestor {}",
                    ancestor.display()
                )
            })?;
            if !metadata.is_dir()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                bail!("replacement parent ancestor is a reparse point or non-directory");
            }
            handles.push(handle);
        }
        if handles.is_empty() {
            bail!("replacement parent authority did not retain a directory handle");
        }
        crate::workspace_impl::validate_private_permissions(&canonical, true)?;

        let authority = Self {
            logical_path: canonical,
            handles,
        };
        authority.validate_named_binding()?;
        Ok(authority)
    }

    fn handle(&self) -> Result<&File> {
        self.handles
            .last()
            .ok_or_else(|| anyhow::anyhow!("replacement parent authority handle is missing"))
    }

    fn child(&self, name: &OsStr) -> Result<PathBuf> {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            bail!("replacement child name must be one literal path component");
        }
        Ok(self.logical_path.join(name))
    }

    fn validate_named_binding(&self) -> Result<()> {
        crate::workspace_impl::reject_path_indirections(&self.logical_path, "replacement parent")?;
        let current = fs::canonicalize(&self.logical_path).with_context(|| {
            format!(
                "could not re-canonicalize replacement parent {}",
                self.logical_path.display()
            )
        })?;
        if current != self.logical_path {
            bail!("replacement parent pathname no longer names the retained authority");
        }
        let named = fs::symlink_metadata(&self.logical_path).with_context(|| {
            format!(
                "could not re-inspect replacement parent {}",
                self.logical_path.display()
            )
        })?;
        if !named.is_dir() || named.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("replacement parent is no longer a regular non-reparse directory");
        }
        Ok(())
    }
}

struct RetainedCurrent {
    file: File,
    identity: FileIdentity,
    bytes: Vec<u8>,
}

impl RetainedCurrent {
    fn open(path: &Path, label: &str) -> Result<Option<Self>> {
        let mut options = fs::OpenOptions::new();
        options
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("could not retain {label} {}", path.display()))
            }
        };
        let metadata = file
            .metadata()
            .with_context(|| format!("could not inspect retained {label} {}", path.display()))?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("retained {label} is a reparse point or non-file");
        }
        if metadata.len() > crate::workspace_impl::MAX_DOCUMENT_BYTES {
            bail!("retained {label} exceeds the supported document size");
        }
        crate::workspace_impl::validate_private_permissions(path, false)?;

        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .with_context(|| format!("could not read retained {label} {}", path.display()))?;
        if bytes.len() as u64 > crate::workspace_impl::MAX_DOCUMENT_BYTES {
            bail!("retained {label} exceeded the supported document size while reading");
        }
        let identity = file_identity(&file).context("could not read retained Win32 file identity")?;
        Ok(Some(Self {
            file,
            identity,
            bytes,
        }))
    }
}

pub(crate) fn replace_document(path: &Path, bytes: &[u8]) -> Result<()> {
    replace_document_with_hook(path, bytes, None, || Ok(()))
}

pub(crate) fn replace_document_if_current(
    path: &Path,
    bytes: &[u8],
    expected_current: &[u8],
) -> Result<()> {
    replace_document_with_hook(path, bytes, Some(expected_current), || Ok(()))
}

fn replace_document_with_hook<F>(
    path: &Path,
    bytes: &[u8],
    expected_current: Option<&[u8]>,
    before_quarantine: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    if bytes.is_empty() || bytes.len() as u64 > crate::workspace_impl::MAX_DOCUMENT_BYTES {
        bail!("replacement document size is invalid");
    }
    let parent_path = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("replacement document has no parent"))?;
    let destination_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("replacement document has no file name"))?;
    let parent = ParentAuthority::open(parent_path)?;
    let destination = parent.child(destination_name)?;

    let nonce = crate::workspace_impl::random_hex(12)?;
    let prepared_name = format!(".workspace.migrate.{nonce}.tmp");
    let quarantine_name = format!(".workspace.retired.{nonce}.json");
    let prepared_path = parent.child(OsStr::new(&prepared_name))?;
    let quarantine_path = parent.child(OsStr::new(&quarantine_name))?;
    let prepared = crate::prepared_file_authority::PreparedFileAuthority::create_named(
        &prepared_path,
        bytes,
    )?;
    let current = RetainedCurrent::open(&destination, "replacement destination")?;

    if let Some(expected) = expected_current {
        match (expected.is_empty(), current.as_ref()) {
            (true, None) => {}
            (true, Some(_)) => {
                bail!("replacement destination appeared after the migration observation")
            }
            (false, None) => {
                bail!("replacement destination disappeared after the migration observation")
            }
            (false, Some(actual)) if actual.bytes.as_slice() == expected => {}
            (false, Some(_)) => {
                bail!("replacement destination bytes changed after the migration observation")
            }
        }
    }

    before_quarantine()?;

    if let Some(current) = current.as_ref() {
        rename_handle_relative_no_replace(
            &current.file,
            parent.handle()?,
            OsStr::new(&quarantine_name),
        )
        .with_context(|| {
            format!(
                "could not quarantine retained replacement destination {}",
                destination.display()
            )
        })?;
        let quarantined = RetainedCurrent::open(&quarantine_path, "quarantined previous document")?
            .ok_or_else(|| anyhow::anyhow!("quarantined previous document is missing"))?;
        if quarantined.identity != current.identity {
            bail!("quarantined previous document is not the retained Win32 file authority");
        }
    }

    prepared.claim_create_only(&destination)?;
    prepared.validate_destination_binding(&destination)?;
    parent.validate_named_binding()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nxb-windows-replacement-{name}-{}-{}",
            std::process::id(),
            crate::workspace_impl::random_hex(8).unwrap()
        ));
        fs::create_dir(&path).unwrap();
        crate::workspace_impl::set_private_directory_permissions(&path).unwrap();
        path
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        crate::workspace_impl::set_private_file_permissions(path).unwrap();
    }

    #[test]
    fn replacement_quarantines_exact_previous_object_and_publishes_candidate() {
        let root = root("exact");
        let destination = root.join("workspace.json");
        private_file(&destination, b"old\n");

        replace_document_if_current(&destination, b"new\n", b"old\n").unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new\n");
        assert!(fs::read_dir(&root).unwrap().filter_map(|entry| entry.ok()).any(|entry| {
            entry.file_name().to_string_lossy().starts_with(".workspace.retired.")
                && fs::read(entry.path()).ok().as_deref() == Some(b"old\n")
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expected_current_mismatch_fails_before_namespace_mutation() {
        let root = root("expected-mismatch");
        let destination = root.join("workspace.json");
        private_file(&destination, b"changed\n");

        let error = replace_document_if_current(&destination, b"new\n", b"expected\n")
            .unwrap_err();
        assert!(error.to_string().contains("bytes changed"));
        assert_eq!(fs::read(&destination).unwrap(), b"changed\n");
        assert!(!fs::read_dir(&root).unwrap().filter_map(|entry| entry.ok()).any(|entry| {
            entry.file_name().to_string_lossy().starts_with(".workspace.retired.")
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_destination_denies_same_permission_path_swap() {
        let root = root("swap");
        let destination = root.join("workspace.json");
        let moved = root.join("moved.json");
        let replacement = root.join("replacement.json");
        private_file(&destination, b"old\n");
        private_file(&replacement, b"attacker\n");

        replace_document_with_hook(&destination, b"new\n", Some(b"old\n"), || {
            assert!(fs::rename(&destination, &moved).is_err());
            assert!(fs::rename(&replacement, &destination).is_err());
            Ok(())
        })
        .unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new\n");
        assert_eq!(fs::read(&replacement).unwrap(), b"attacker\n");
        assert!(!moved.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_ancestor_chain_denies_parent_replacement() {
        let container = root("parent-container");
        let root = container.join("workspace");
        fs::create_dir(&root).unwrap();
        crate::workspace_impl::set_private_directory_permissions(&root).unwrap();
        let destination = root.join("workspace.json");
        private_file(&destination, b"old\n");
        let moved = container.join("workspace-moved");

        replace_document_with_hook(&destination, b"new\n", Some(b"old\n"), || {
            assert!(fs::rename(&root, &moved).is_err());
            Ok(())
        })
        .unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new\n");
        assert!(!moved.exists());
        fs::remove_dir_all(container).unwrap();
    }

    #[test]
    fn expected_missing_destination_uses_create_only_claim() {
        let root = root("missing");
        let destination = root.join("workspace.json");

        replace_document_if_current(&destination, b"new\n", b"").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new\n");
        fs::remove_dir_all(root).unwrap();
    }
}
