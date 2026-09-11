use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};

const O_DIRECTORY: i32 = 0o200000;
const O_NOFOLLOW: i32 = 0o400000;
const TRUSTED_LN: &str = "/usr/bin/ln";
const TRUSTED_MV: &str = "/usr/bin/mv";

struct ParentAuthority {
    logical_path: PathBuf,
    file: File,
    dev: u64,
    ino: u64,
}

impl ParentAuthority {
    fn open(path: &Path) -> Result<Self> {
        crate::workspace_impl::reject_path_indirections(path, "replacement parent")?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW);
        let file = options
            .open(path)
            .with_context(|| format!("could not pin replacement parent {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("could not inspect replacement parent {}", path.display()))?;
        if !metadata.is_dir() {
            bail!("replacement parent is not a directory authority");
        }
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 || mode & 0o700 != 0o700 {
            bail!("replacement parent permissions are not private");
        }

        let authority = Self {
            logical_path: path.to_path_buf(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            file,
        };
        authority.validate_named_binding()?;
        Ok(authority)
    }

    fn stable_path(&self, name: &OsStr) -> PathBuf {
        PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.file.as_raw_fd()
        ))
        .join(name)
    }

    fn validate_named_binding(&self) -> Result<()> {
        crate::workspace_impl::reject_path_indirections(
            &self.logical_path,
            "replacement parent",
        )?;
        let named = fs::symlink_metadata(&self.logical_path).with_context(|| {
            format!(
                "could not inspect named replacement parent {}",
                self.logical_path.display()
            )
        })?;
        if named.file_type().is_symlink()
            || !named.is_dir()
            || named.dev() != self.dev
            || named.ino() != self.ino
        {
            bail!("replacement parent pathname no longer names the retained directory authority");
        }
        Ok(())
    }

    fn open_regular(&self, name: &OsStr, label: &str) -> Result<Option<RetainedFileAuthority>> {
        let path = self.stable_path(name);
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(O_NOFOLLOW);
        match options.open(&path) {
            Ok(file) => {
                let metadata = file.metadata().with_context(|| {
                    format!("could not inspect retained {label} in replacement parent")
                })?;
                if !metadata.is_file() {
                    bail!("retained {label} is not a regular file authority");
                }
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 || mode & 0o600 != 0o600 {
                    bail!("retained {label} permissions are not private");
                }
                Ok(Some(RetainedFileAuthority {
                    file,
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                }))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| {
                format!("could not open retained {label} in replacement parent")
            }),
        }
    }

    fn create_prepared(&self, name: &OsStr, bytes: &[u8]) -> Result<RetainedFileAuthority> {
        let path = self.stable_path(name);
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(O_NOFOLLOW);
        let mut file = options
            .open(&path)
            .context("could not create retained replacement candidate")?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;

        let metadata = file
            .metadata()
            .context("could not inspect retained replacement candidate")?;
        if !metadata.is_file() {
            bail!("retained replacement candidate is not a regular file authority");
        }
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 || mode & 0o600 != 0o600 {
            bail!("retained replacement candidate permissions are not private");
        }

        Ok(RetainedFileAuthority {
            file,
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    fn validate_child_binding(
        &self,
        name: &OsStr,
        expected: &RetainedFileAuthority,
        label: &str,
    ) -> Result<()> {
        let Some(actual) = self.open_regular(name, label)? else {
            bail!("{label} pathname disappeared after namespace mutation");
        };
        if actual.dev != expected.dev || actual.ino != expected.ino {
            bail!("{label} pathname is not the retained file authority");
        }
        Ok(())
    }

    fn quarantine_no_replace(&self, source: &OsStr, quarantine: &OsStr) -> Result<()> {
        let tool = trusted_tool(TRUSTED_MV, "Linux no-clobber move tool")?;
        let source = self.stable_path(source);
        let quarantine = self.stable_path(quarantine);
        let output = Command::new(tool)
            .arg("-n")
            .arg("-T")
            .arg("--")
            .arg(&source)
            .arg(&quarantine)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .env_clear()
            .output()
            .context("could not execute trusted Linux no-clobber move tool")?;
        if !output.status.success() {
            bail!(
                "trusted Linux no-clobber move failed with status {}: {}",
                output.status,
                bounded_stderr(&output.stderr)
            );
        }
        Ok(())
    }

    fn claim_prepared(
        &self,
        prepared: &RetainedFileAuthority,
        destination: &OsStr,
    ) -> Result<()> {
        let tool = trusted_tool(TRUSTED_LN, "Linux hard-link tool")?;
        let source = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            prepared.file.as_raw_fd()
        ));
        let destination = self.stable_path(destination);
        let output = Command::new(tool)
            .arg("-L")
            .arg("--")
            .arg(&source)
            .arg(&destination)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .env_clear()
            .output()
            .context("could not execute trusted Linux hard-link tool")?;
        if !output.status.success() {
            bail!(
                "trusted Linux hard-link tool failed with status {}: {}",
                output.status,
                bounded_stderr(&output.stderr)
            );
        }
        Ok(())
    }
}

struct RetainedFileAuthority {
    file: File,
    dev: u64,
    ino: u64,
}

fn trusted_tool(path: &'static str, label: &str) -> Result<&'static Path> {
    let tool = Path::new(path);
    crate::workspace_impl::reject_path_indirections(tool, label)?;
    let metadata = fs::symlink_metadata(tool)
        .with_context(|| format!("trusted system tool is missing: {path}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("trusted system tool authority is invalid: {path}");
    }
    Ok(tool)
}

fn bounded_stderr(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().take(512).collect()
}

pub(crate) fn replace_document(path: &Path, bytes: &[u8]) -> Result<()> {
    replace_document_with_hook(path, bytes, || Ok(()))
}

fn replace_document_with_hook<F>(path: &Path, bytes: &[u8], before_quarantine: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    if bytes.is_empty() || bytes.len() as u64 > crate::workspace_impl::MAX_DOCUMENT_BYTES {
        bail!("replacement document size is invalid");
    }

    let parent_path = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("replacement document has no parent"))?;
    let destination = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("replacement document has no file name"))?;
    let parent = ParentAuthority::open(parent_path)?;

    let nonce = crate::workspace_impl::random_hex(12)?;
    let prepared_name = OsString::from(format!(".workspace.migrate.{nonce}.tmp"));
    let quarantine_name = OsString::from(format!(".workspace.retired.{nonce}.json"));
    let prepared = parent.create_prepared(&prepared_name, bytes)?;
    let previous = parent.open_regular(destination, "replacement destination")?;

    if let Some(previous) = previous.as_ref() {
        before_quarantine()?;
        parent.validate_named_binding()?;
        parent.quarantine_no_replace(destination, &quarantine_name)?;
        parent.validate_child_binding(
            &quarantine_name,
            previous,
            "quarantined previous document",
        )?;
    }

    parent.claim_prepared(&prepared, destination)?;
    parent.validate_child_binding(destination, &prepared, "replacement destination")?;
    parent.file.sync_all().context("could not synchronize replacement parent")?;
    parent.validate_named_binding()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nxb-replacement-{name}-{}-{}",
            std::process::id(),
            crate::workspace_impl::random_hex(8).unwrap()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn replacement_publishes_exact_prepared_inode_and_retires_previous_inode() {
        let root = root("exact");
        let destination = root.join("workspace.json");
        fs::write(&destination, b"old\n").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();
        let old = fs::metadata(&destination).unwrap();

        replace_document(&destination, b"new\n").unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new\n");
        let retired = fs::read_dir(&root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .find(|entry| entry.file_name().to_string_lossy().starts_with(".workspace.retired."))
            .expect("previous document quarantine is missing");
        let retired_metadata = retired.metadata().unwrap();
        assert_eq!(retired_metadata.dev(), old.dev());
        assert_eq!(retired_metadata.ino(), old.ino());
        assert_eq!(fs::read(retired.path()).unwrap(), b"old\n");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn same_permission_destination_replacement_is_quarantined_but_never_deleted_or_published() {
        let root = root("race");
        let destination = root.join("workspace.json");
        let admitted = root.join("admitted.json");
        fs::write(&destination, b"admitted\n").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();

        let error = replace_document_with_hook(&destination, b"candidate\n", || {
            fs::rename(&destination, &admitted)?;
            fs::write(&destination, b"substituted\n")?;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
            Ok(())
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("quarantined previous document pathname is not the retained file authority"));
        assert_eq!(fs::read(&admitted).unwrap(), b"admitted\n");
        assert!(!destination.exists());
        assert!(fs::read_dir(&root).unwrap().filter_map(|entry| entry.ok()).any(|entry| {
            entry.file_name().to_string_lossy().starts_with(".workspace.retired.")
                && fs::read(entry.path()).ok().as_deref() == Some(b"substituted\n")
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parent_directory_replacement_cannot_redirect_namespace_mutation() {
        let root = root("parent-race");
        let moved = root.with_extension("retained");
        let destination = root.join("workspace.json");
        fs::write(&destination, b"old\n").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();

        let error = replace_document_with_hook(&destination, b"candidate\n", || {
            fs::rename(&root, &moved)?;
            fs::create_dir(&root)?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
            let attacker = root.join("workspace.json");
            fs::write(&attacker, b"attacker\n")?;
            fs::set_permissions(&attacker, fs::Permissions::from_mode(0o600))?;
            Ok(())
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("replacement parent pathname no longer names the retained directory authority"));
        assert_eq!(fs::read(root.join("workspace.json")).unwrap(), b"attacker\n");
        assert_eq!(fs::read(moved.join("workspace.json")).unwrap(), b"old\n");

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[test]
    fn missing_destination_is_create_only_from_retained_prepared_fd() {
        let root = root("missing");
        let destination = root.join("workspace.json");

        replace_document(&destination, b"new\n").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new\n");

        fs::remove_dir_all(root).unwrap();
    }
}
