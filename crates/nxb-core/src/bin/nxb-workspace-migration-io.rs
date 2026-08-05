use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{de::DeserializeOwned, Serialize};

use crate::{hex, manifest_schema, MANIFEST_FILE, MAX_DOCUMENT_BYTES};

#[cfg(windows)]
#[path = "nxb-product-windows.rs"]
mod windows_security;

const STATE_DIRECTORY: &str = "state";
const RECEIPTS_DIRECTORY: &str = "migrations";
const ACTIVE_FILE: &str = "migration-active.json";
const BACKUP_FILE: &str = "migration-source.json";
const APPLIED_FILE: &str = "migration-applied.json";
const MAX_RECEIPTS: usize = 1_024;

#[derive(Debug)]
pub(crate) struct MigrationPaths {
    pub(crate) manifest: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) receipts: PathBuf,
    pub(crate) active: PathBuf,
    pub(crate) backup: PathBuf,
    pub(crate) applied: PathBuf,
}

impl MigrationPaths {
    pub(crate) fn receipt(&self, migration_id: &str) -> PathBuf {
        self.receipts.join(format!("{migration_id}.json"))
    }
}

pub(crate) fn paths(root: &Path) -> MigrationPaths {
    let state = root.join(STATE_DIRECTORY);
    MigrationPaths {
        manifest: root.join(MANIFEST_FILE),
        receipts: state.join(RECEIPTS_DIRECTORY),
        active: state.join(ACTIVE_FILE),
        backup: state.join(BACKUP_FILE),
        applied: state.join(APPLIED_FILE),
        state,
    }
}

pub(crate) fn validate_workspace_root(workspace: &Path) -> Result<PathBuf> {
    if !workspace.is_absolute() { bail!("workspace path must be absolute"); }
    reject_path_indirections(workspace, "workspace root")?;
    let metadata = fs::metadata(workspace).with_context(|| format!("workspace is missing: {}", workspace.display()))?;
    if !metadata.is_dir() { bail!("workspace root is not a directory"); }
    validate_private_permissions(workspace, true)?;
    let canonical = fs::canonicalize(workspace)?;
    reject_path_indirections(&canonical, "canonical workspace root")?;
    Ok(canonical)
}

pub(crate) fn ensure_state_layout(root: &Path) -> Result<MigrationPaths> {
    let value = paths(root);
    reject_path_indirections(&value.state, "migration state directory")?;
    let metadata = fs::metadata(&value.state).context("migration state directory is missing")?;
    if !metadata.is_dir() { bail!("migration state path is not a directory"); }
    validate_private_permissions(&value.state, true)?;
    if !value.receipts.exists() {
        fs::create_dir(&value.receipts)?;
        set_private_directory_permissions(&value.receipts)?;
    }
    reject_path_indirections(&value.receipts, "migration receipts directory")?;
    validate_private_permissions(&value.receipts, true)?;
    Ok(value)
}

pub(crate) fn transient_state(paths: &MigrationPaths) -> Result<usize> {
    [safe_exists(&paths.active)?, safe_exists(&paths.backup)?, safe_exists(&paths.applied)?]
        .into_iter()
        .try_fold(0_usize, |count, present| count.checked_add(usize::from(present)).ok_or_else(|| anyhow::anyhow!("transient count overflow")))
}

pub(crate) fn receipt_count(paths: &MigrationPaths) -> Result<usize> {
    if !paths.receipts.exists() { return Ok(0); }
    reject_path_indirections(&paths.receipts, "migration receipts directory")?;
    validate_private_permissions(&paths.receipts, true)?;
    let mut count = 0_usize;
    for entry in fs::read_dir(&paths.receipts)? {
        let path = entry?.path();
        reject_path_indirections(&path, "migration receipt")?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() { bail!("migration receipts directory contains a non-file entry"); }
        validate_private_permissions(&path, false)?;
        count = count.checked_add(1).ok_or_else(|| anyhow::anyhow!("receipt count overflow"))?;
        if count > MAX_RECEIPTS { bail!("migration receipt count exceeds the supported limit"); }
    }
    Ok(count)
}

pub(crate) fn optional_manifest_schema(path: &Path) -> Result<Option<u32>> {
    if !safe_exists(path)? { return Ok(None); }
    Ok(Some(manifest_schema(&read_document(path, "workspace manifest")?)?))
}

pub(crate) fn read_json<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    serde_json::from_slice(&read_document(path, label)?).with_context(|| format!("{label} is invalid JSON"))
}

pub(crate) fn read_optional_document(path: &Path, label: &str) -> Result<Vec<u8>> {
    if safe_exists(path)? { read_document(path, label) } else { Ok(Vec::new()) }
}

pub(crate) fn read_document(path: &Path, label: &str) -> Result<Vec<u8>> {
    reject_path_indirections(path, label)?;
    let metadata = fs::metadata(path).with_context(|| format!("{label} is missing: {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_DOCUMENT_BYTES {
        bail!("{label} size or type is invalid");
    }
    validate_private_permissions(path, false)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES { bail!("{label} exceeds the supported size limit"); }
    Ok(bytes)
}

pub(crate) fn create_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    create_document(path, &bytes)
}

pub(crate) fn create_document(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow::anyhow!("output path has no parent"))?;
    reject_path_indirections(parent, "output parent")?;
    let name = path.file_name().and_then(|value| value.to_str()).ok_or_else(|| anyhow::anyhow!("output file name is invalid"))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", random_hex(12)?));
    let result = (|| {
        let mut output = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        set_private_file_permissions(&temporary)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);
        if safe_exists(path)? { bail!("create-new destination already exists"); }
        fs::rename(&temporary, path)?;
        sync_parent(parent)
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

pub(crate) fn replace_document(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow::anyhow!("manifest has no parent"))?;
    reject_path_indirections(parent, "manifest parent")?;
    reject_path_indirections(path, "workspace manifest")?;
    let temporary = parent.join(format!(".workspace.migrate.{}.tmp", random_hex(12)?));
    let result = (|| {
        let mut output = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        set_private_file_permissions(&temporary)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);
        replace_file(&temporary, path)?;
        set_private_file_permissions(path)?;
        sync_parent(parent)
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

pub(crate) fn cleanup(paths: &MigrationPaths) -> Result<()> {
    remove_if_exists(&paths.applied)?;
    remove_if_exists(&paths.active)?;
    remove_if_exists(&paths.backup)
}

fn remove_if_exists(path: &Path) -> Result<()> {
    if safe_exists(path)? { remove_regular(path) } else { Ok(()) }
}

pub(crate) fn remove_regular(path: &Path) -> Result<()> {
    reject_path_indirections(path, "migration transient file")?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() { bail!("migration transient path is not a regular file"); }
    fs::remove_file(path)?;
    Ok(())
}

pub(crate) fn safe_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) { bail!("path indirection is not allowed: {}", path.display()); }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn reject_path_indirections(path: &Path, label: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => continue,
            Component::ParentDir => bail!("{label} must not contain parent traversal"),
            Component::Normal(value) => current.push(value),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || is_reparse_point(&metadata) => bail!("{label} contains a path indirection: {}", current.display()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut value = vec![0_u8; bytes];
    SystemRandom::new().fill(&mut value).map_err(|_| anyhow::anyhow!("operating-system randomness is unavailable"))?;
    let encoded = hex(&value);
    value.fill(0);
    Ok(encoded)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool { windows_security::is_reparse_point(metadata) }
#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool { false }

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(windows)]
fn set_private_directory_permissions(path: &Path) -> Result<()> { windows_security::set_private_directory_permissions(path) }
#[cfg(not(any(unix, windows)))]
fn set_private_directory_permissions(_path: &Path) -> Result<()> { Ok(()) }

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(windows)]
fn set_private_file_permissions(path: &Path) -> Result<()> { windows_security::set_private_file_permissions(path) }
#[cfg(not(any(unix, windows)))]
fn set_private_file_permissions(_path: &Path) -> Result<()> { Ok(()) }

#[cfg(unix)]
fn validate_private_permissions(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 { bail!("workspace path permissions are too broad"); }
    let required = if directory { 0o700 } else { 0o600 };
    if mode & required != required { bail!("workspace path permissions are incomplete"); }
    Ok(())
}
#[cfg(windows)]
fn validate_private_permissions(path: &Path, directory: bool) -> Result<()> { windows_security::validate_private_permissions(path, directory) }
#[cfg(not(any(unix, windows)))]
fn validate_private_permissions(_path: &Path, _directory: bool) -> Result<()> { Ok(()) }

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<()> { File::open(parent)?.sync_all()?; Ok(()) }
#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<()> { Ok(()) }

#[cfg(unix)]
fn replace_file(source: &Path, destination: &Path) -> Result<()> { fs::rename(source, destination)?; Ok(()) }
#[cfg(not(unix))]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() { remove_regular(destination)?; }
    fs::rename(source, destination)?;
    Ok(())
}
