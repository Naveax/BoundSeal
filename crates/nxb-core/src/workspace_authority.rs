use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::directory_authority::DirectoryAuthority;

pub(crate) use crate::workspace_impl::*;

const TARGET_READY_DIRECTORIES: &[&str] = &[
    "config", "targets", "sessions", "runs", "evidence", "reports", "state", "tmp",
];
const TARGET_MIGRATION_TRANSIENTS: &[&str] = &[
    "migration-active.json",
    "migration-source.json",
    "migration-applied.json",
];

#[derive(Default)]
struct TargetAuthorityState {
    depth: usize,
    requested_root: Option<PathBuf>,
    root: Option<DirectoryAuthority>,
    children: BTreeMap<String, DirectoryAuthority>,
}

thread_local! {
    static TARGET_AUTHORITY: RefCell<TargetAuthorityState> =
        RefCell::new(TargetAuthorityState::default());
}

pub(crate) struct TargetAuthorityScope;

pub(crate) fn target_authority_scope() -> TargetAuthorityScope {
    TARGET_AUTHORITY.with(|state| {
        let mut state = state.borrow_mut();
        if state.depth == 0 {
            *state = TargetAuthorityState::default();
        }
        state.depth = state.depth.saturating_add(1);
    });
    TargetAuthorityScope
}

impl Drop for TargetAuthorityScope {
    fn drop(&mut self) {
        TARGET_AUTHORITY.with(|state| {
            let mut state = state.borrow_mut();
            state.depth = state.depth.saturating_sub(1);
            if state.depth == 0 {
                *state = TargetAuthorityState::default();
            }
        });
    }
}

fn target_authority_active() -> bool {
    TARGET_AUTHORITY.with(|state| state.borrow().depth != 0)
}

pub(crate) fn validate_workspace_root(workspace: &Path, require_absolute: bool) -> Result<PathBuf> {
    if !target_authority_active() {
        return crate::workspace_impl::validate_workspace_root(workspace, require_absolute);
    }

    TARGET_AUTHORITY.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(root) = state.root.as_ref() {
            let requested_match = state
                .requested_root
                .as_deref()
                .is_some_and(|requested| requested == workspace);
            if workspace == root.path() || workspace == root.display_path() || requested_match {
                return Ok(root.path().to_path_buf());
            }
            bail!("target operation attempted to switch workspace authority after admission");
        }

        let authority = DirectoryAuthority::pin_private(workspace, "workspace root", require_absolute)?;
        let stable = authority.path().to_path_buf();
        state.requested_root = Some(workspace.to_path_buf());
        state.root = Some(authority);
        Ok(stable)
    })
}

pub(crate) fn pin_private_child_path(
    root: &Path,
    name: &str,
    label: &str,
) -> Result<PathBuf> {
    if !target_authority_active() {
        let child = root.join(name);
        crate::workspace_impl::reject_path_indirections(&child, label)?;
        let metadata = fs::metadata(&child)
            .with_context(|| format!("{label} is missing: {}", child.display()))?;
        if !metadata.is_dir() {
            bail!("{label} is not a directory");
        }
        crate::workspace_impl::validate_private_permissions(&child, true)?;
        return Ok(child);
    }

    TARGET_AUTHORITY.with(|state| {
        let mut state = state.borrow_mut();
        let authority = state
            .root
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("workspace root authority was not admitted"))?;
        if root != authority.path() && root != authority.display_path() {
            bail!("child directory request is not rooted in the admitted workspace authority");
        }
        if let Some(child) = state.children.get(name) {
            return Ok(child.path().to_path_buf());
        }

        let child = authority.pin_private_child(name, label)?;
        let stable = child.path().to_path_buf();
        state.children.insert(name.to_owned(), child);
        Ok(stable)
    })
}

fn root_child_path(name: &str, label: &str) -> Result<PathBuf> {
    TARGET_AUTHORITY.with(|state| {
        let state = state.borrow();
        let root = state
            .root
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("workspace root authority was not admitted"))?;
        root.child_path(name, label)
    })
}

pub(crate) fn logical_authority_path(path: &Path) -> PathBuf {
    if !target_authority_active() {
        return path.to_path_buf();
    }

    TARGET_AUTHORITY.with(|state| {
        let state = state.borrow();
        for child in state.children.values() {
            if let Ok(relative) = path.strip_prefix(child.path()) {
                return child.display_path().join(relative);
            }
        }
        if let Some(root) = state.root.as_ref() {
            if let Ok(relative) = path.strip_prefix(root.path()) {
                return root.display_path().join(relative);
            }
        }
        path.to_path_buf()
    })
}

fn authority_base(path: &Path) -> Option<(PathBuf, PathBuf)> {
    if !target_authority_active() {
        return None;
    }

    TARGET_AUTHORITY.with(|state| {
        let state = state.borrow();
        for child in state.children.values() {
            if path.strip_prefix(child.path()).is_ok() {
                return Some((
                    child.path().to_path_buf(),
                    child.display_path().to_path_buf(),
                ));
            }
        }
        state.root.as_ref().and_then(|root| {
            path.strip_prefix(root.path()).ok().map(|_| {
                (
                    root.path().to_path_buf(),
                    root.display_path().to_path_buf(),
                )
            })
        })
    })
}

fn logical_authority_contains(path: &Path) -> bool {
    if !target_authority_active() {
        return false;
    }

    TARGET_AUTHORITY.with(|state| {
        let state = state.borrow();
        if state
            .children
            .values()
            .any(|child| path.strip_prefix(child.display_path()).is_ok())
        {
            return true;
        }
        state
            .root
            .as_ref()
            .is_some_and(|root| path.strip_prefix(root.display_path()).is_ok())
    })
}

fn reject_logical_authority_fallback(path: &Path, label: &str) -> Result<()> {
    if logical_authority_contains(path) {
        bail!(
            "{label} attempted pathname fallback beneath an admitted workspace authority: {}",
            path.display()
        );
    }
    Ok(())
}

fn authority_exact_directory(path: &Path) -> bool {
    if !target_authority_active() {
        return false;
    }
    TARGET_AUTHORITY.with(|state| {
        let state = state.borrow();
        state
            .root
            .as_ref()
            .is_some_and(|root| root.path() == path)
            || state.children.values().any(|child| child.path() == path)
    })
}

pub(crate) fn status_value(workspace: &Path) -> Result<Value> {
    if authority_base(workspace).is_none() {
        reject_logical_authority_fallback(workspace, "workspace status")?;
        return crate::workspace_impl::status_value(workspace);
    }

    let manifest_path = root_child_path(crate::workspace_impl::MANIFEST_FILE, "workspace manifest")?;
    let manifest_bytes = read_document(&manifest_path, "workspace manifest")?;
    let manifest: crate::workspace_impl::ManifestV1 = serde_json::from_slice(&manifest_bytes)
        .context("workspace manifest is invalid")?;
    crate::workspace_impl::validate_manifest_v1(&manifest)?;

    for directory in TARGET_READY_DIRECTORIES {
        let _ = pin_private_child_path(workspace, directory, "workspace canonical directory")?;
    }

    Ok(json!({
        "status": "ready",
        "workspace": logical_authority_path(workspace).display().to_string(),
        "workspace_id": manifest.workspace_id,
        "name": manifest.name,
        "schema_version": manifest.schema_version,
        "created_at": manifest.created_at,
        "records": {},
    }))
}

pub(crate) mod migration {
    use super::*;

    pub(crate) fn apply_value(workspace: &Path) -> Result<Value> {
        crate::workspace_impl::migration::apply_value(workspace)
    }

    pub(crate) fn recover_value(workspace: &Path) -> Result<Value> {
        crate::workspace_impl::migration::recover_value(workspace)
    }

    pub(crate) fn status_value(workspace: &Path) -> Result<Value> {
        if authority_base(workspace).is_none() {
            reject_logical_authority_fallback(workspace, "migration status")?;
            return crate::workspace_impl::migration::status_value(workspace);
        }

        let state = pin_private_child_path(workspace, "state", "migration state directory")?;
        let mut pending = 0_usize;
        for name in TARGET_MIGRATION_TRANSIENTS {
            if safe_exists(&state.join(name))? {
                pending = pending
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("migration transient count overflow"))?;
            }
        }
        let receipts =
            crate::workspace_authority_receipts::validate_target_readiness_receipts(workspace)?;

        Ok(json!({
            "status": if pending == 0 { "stable" } else { "recovery_required" },
            "workspace": logical_authority_path(workspace).display().to_string(),
            "schema_version": Value::Null,
            "migration_id": Value::Null,
            "recovery": "none",
            "details": {
                "pending_files": pending.to_string(),
                "receipts": receipts.to_string()
            }
        }))
    }
}

pub(crate) fn reject_path_indirections(path: &Path, label: &str) -> Result<()> {
    let Some((base, _logical)) = authority_base(path) else {
        reject_logical_authority_fallback(path, label)?;
        return crate::workspace_impl::reject_path_indirections(path, label);
    };

    let relative = path
        .strip_prefix(&base)
        .context("authority path escaped its pinned directory")?;
    let mut current = base;
    for component in relative.components() {
        match component {
            Component::CurDir => continue,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("{label} must remain beneath its pinned directory authority")
            }
            Component::Normal(value) => current.push(value),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata_is_indirection(&metadata) => {
                bail!("{label} contains a path indirection: {}", current.display())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("could not inspect {}", current.display()))
            }
        }
    }
    Ok(())
}

fn metadata_is_indirection(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub(crate) fn safe_exists(path: &Path) -> Result<bool> {
    if authority_base(path).is_none() {
        reject_logical_authority_fallback(path, "workspace authority existence check")?;
        return crate::workspace_impl::safe_exists(path);
    }
    reject_path_indirections(path, "workspace authority path")?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata_is_indirection(&metadata) {
                bail!("path indirection is not allowed: {}", path.display());
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn read_document(path: &Path, label: &str) -> Result<Vec<u8>> {
    if authority_base(path).is_none() {
        reject_logical_authority_fallback(path, label)?;
        return crate::workspace_impl::read_document(path, label);
    }
    read_authority_document(path, label)
}

fn read_authority_document(path: &Path, label: &str) -> Result<Vec<u8>> {
    reject_path_indirections(path, label)?;
    let mut file = open_authority_file(path, label)?;
    let initial = file
        .metadata()
        .with_context(|| format!("could not inspect pinned {label}: {}", path.display()))?;
    validate_opened_document(path, &initial, label)?;

    let capacity = usize::try_from(initial.len()).context("workspace document size does not fit memory")?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(crate::workspace_impl::MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read pinned {label}: {}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > crate::workspace_impl::MAX_DOCUMENT_BYTES {
        bail!("{label} exceeds the supported size limit or is empty");
    }

    let final_metadata = file
        .metadata()
        .with_context(|| format!("could not re-inspect pinned {label}: {}", path.display()))?;
    if bytes.len() as u64 != initial.len() || final_metadata.len() != initial.len() {
        bail!("{label} changed size while being read");
    }
    validate_document_stability(path, &initial, &final_metadata, label)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn open_authority_file(path: &Path, label: &str) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    const O_NOFOLLOW: i32 = 0o400000;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("could not open pinned {label}: {}", path.display()))
}

#[cfg(windows)]
fn open_authority_file(path: &Path, label: &str) -> Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("could not open pinned {label}: {}", path.display()))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_authority_file(_path: &Path, _label: &str) -> Result<fs::File> {
    bail!("live workspace document authority is unsupported on this Unix platform")
}

#[cfg(not(any(unix, windows)))]
fn open_authority_file(_path: &Path, _label: &str) -> Result<fs::File> {
    bail!("live workspace document authority is unsupported on this platform")
}

fn validate_opened_document(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > crate::workspace_impl::MAX_DOCUMENT_BYTES
    {
        bail!("{label} size or type is invalid");
    }
    crate::workspace_impl::validate_private_permissions(path, false)?;
    validate_named_document_identity(path, metadata, label)
}

#[cfg(target_os = "linux")]
fn validate_named_document_identity(path: &Path, opened: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let named = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect named {label}: {}", path.display()))?;
    if named.file_type().is_symlink() || !named.is_file() {
        bail!("{label} pathname no longer names a regular file");
    }
    if named.dev() != opened.dev() || named.ino() != opened.ino() {
        bail!("{label} pathname identity changed after open");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_named_document_identity(path: &Path, _opened: &fs::Metadata, label: &str) -> Result<()> {
    let named = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect named {label}: {}", path.display()))?;
    if metadata_is_indirection(&named) || !named.is_file() {
        bail!("{label} pathname no longer names a regular non-reparse file");
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn validate_named_document_identity(
    _path: &Path,
    _opened: &fs::Metadata,
    _label: &str,
) -> Result<()> {
    bail!("live workspace document authority is unsupported on this Unix platform")
}

#[cfg(not(any(unix, windows)))]
fn validate_named_document_identity(
    _path: &Path,
    _opened: &fs::Metadata,
    _label: &str,
) -> Result<()> {
    bail!("live workspace document authority is unsupported on this platform")
}

#[cfg(target_os = "linux")]
fn validate_document_stability(
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
    validate_named_document_identity(path, final_metadata, label)
}

#[cfg(windows)]
fn validate_document_stability(
    path: &Path,
    initial: &fs::Metadata,
    final_metadata: &fs::Metadata,
    label: &str,
) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    if metadata_is_indirection(final_metadata)
        || !final_metadata.is_file()
        || initial.creation_time() != final_metadata.creation_time()
        || initial.last_write_time() != final_metadata.last_write_time()
        || initial.file_size() != final_metadata.file_size()
    {
        bail!("pinned {label} changed identity, type or content metadata while being read");
    }
    validate_named_document_identity(path, final_metadata, label)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn validate_document_stability(
    _path: &Path,
    _initial: &fs::Metadata,
    _final_metadata: &fs::Metadata,
    _label: &str,
) -> Result<()> {
    bail!("live workspace document authority is unsupported on this Unix platform")
}

#[cfg(not(any(unix, windows)))]
fn validate_document_stability(
    _path: &Path,
    _initial: &fs::Metadata,
    _final_metadata: &fs::Metadata,
    _label: &str,
) -> Result<()> {
    bail!("live workspace document authority is unsupported on this platform")
}

#[derive(Debug, Clone, Copy)]
struct AuthorityPublicationFinalization {
    temporary_cleanup_failed: bool,
    parent_sync_failed: bool,
}

#[derive(Debug)]
struct AuthorityPublishedDocumentError {
    finalization: AuthorityPublicationFinalization,
    detail: String,
}

impl std::fmt::Display for AuthorityPublishedDocumentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "authority-bound create-only destination is visible but finalization is incomplete (temporary_cleanup_failed={}, parent_sync_failed={}): {}",
            self.finalization.temporary_cleanup_failed,
            self.finalization.parent_sync_failed,
            self.detail
        )
    }
}

impl std::error::Error for AuthorityPublishedDocumentError {}

#[derive(Debug)]
struct AuthorityUnpublishedCleanupError {
    operation: String,
    cleanup: String,
}

impl std::fmt::Display for AuthorityUnpublishedCleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "authority-bound destination was not published but temporary cleanup failed (operation={}; cleanup={})",
            self.operation, self.cleanup
        )
    }
}

impl std::error::Error for AuthorityUnpublishedCleanupError {}

pub(crate) fn create_document_error_published(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<AuthorityPublishedDocumentError>()
        .is_some()
        || crate::workspace_impl::create_document_error_published(error)
}

pub(crate) fn create_document(path: &Path, bytes: &[u8]) -> Result<()> {
    if authority_base(path).is_none() {
        reject_logical_authority_fallback(path, "workspace create-only publication")?;
        return crate::workspace_impl::create_document(path, bytes);
    }
    create_authority_document(path, bytes)
}

fn create_authority_document(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > crate::workspace_impl::MAX_DOCUMENT_BYTES {
        bail!("output document size is invalid");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("output path has no parent"))?;
    if !authority_exact_directory(parent) {
        bail!("create-only publication parent is not the retained directory authority");
    }
    reject_path_indirections(path, "output path")?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("output file name is invalid"))?;
    let temporary = parent.join(format!(
        ".{name}.{}.tmp",
        crate::workspace_impl::random_hex(12)?
    ));

    let prepared = (|| {
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("could not create temporary file {}", temporary.display()))?;
        crate::workspace_impl::set_private_file_permissions(&temporary)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);
        crate::workspace_impl::validate_private_permissions(&temporary, false)
    })();
    if let Err(error) = prepared {
        if let Err(cleanup) = remove_authority_temporary(&temporary) {
            return Err(AuthorityUnpublishedCleanupError {
                operation: format!("temporary preparation failed: {error:#}"),
                cleanup: format!("{cleanup:#}"),
            }
            .into());
        }
        return Err(error);
    }

    if let Err(error) = fs::hard_link(&temporary, path) {
        let cleanup = remove_authority_temporary(&temporary).err();
        if let Some(cleanup) = cleanup {
            return Err(AuthorityUnpublishedCleanupError {
                operation: format!("destination claim failed: {error}"),
                cleanup: format!("{cleanup:#}"),
            }
            .into());
        }
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            bail!("create-new destination already exists: {}", path.display());
        }
        return Err(error).with_context(|| {
            format!(
                "could not atomically claim authority-bound destination {}",
                path.display()
            )
        });
    }

    let cleanup_error = remove_authority_temporary(&temporary).err();
    let sync_error = sync_authority_directory(parent).err();
    if cleanup_error.is_some() || sync_error.is_some() {
        let finalization = AuthorityPublicationFinalization {
            temporary_cleanup_failed: cleanup_error.is_some(),
            parent_sync_failed: sync_error.is_some(),
        };
        let mut details = Vec::new();
        if let Some(error) = cleanup_error {
            details.push(format!("temporary cleanup failed: {error:#}"));
        }
        if let Some(error) = sync_error {
            details.push(format!("parent sync failed: {error:#}"));
        }
        return Err(AuthorityPublishedDocumentError {
            finalization,
            detail: details.join("; "),
        }
        .into());
    }

    Ok(())
}

fn remove_authority_temporary(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("could not remove authority temporary {}", path.display())),
    }
}

fn sync_authority_directory(path: &Path) -> Result<()> {
    TARGET_AUTHORITY.with(|state| {
        let state = state.borrow();
        if let Some(root) = state.root.as_ref() {
            if root.path() == path {
                return root.sync("workspace root");
            }
        }
        for child in state.children.values() {
            if child.path() == path {
                return child.sync("workspace child");
            }
        }
        bail!("publication parent directory authority is no longer retained")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_facade_preserves_pathname_workspace_behavior() {
        assert!(!target_authority_active());
    }
}
