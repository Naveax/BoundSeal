use std::{fs, path::Path};

use anyhow::{bail, Context, Result};

use crate::prepared_file_authority::PreparedFileAuthority;

#[derive(Debug)]
struct PreparedPublishedDocumentError {
    parent_sync_failed: bool,
    detail: String,
}

impl std::fmt::Display for PreparedPublishedDocumentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "prepared-authority create-only destination is visible but finalization is incomplete (parent_sync_failed={}): {}",
            self.parent_sync_failed, self.detail
        )
    }
}

impl std::error::Error for PreparedPublishedDocumentError {}

pub(crate) fn error_published(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<PreparedPublishedDocumentError>()
        .is_some()
}

/// Target-operation create-only publication bound to one retained prepared file.
///
/// The exact temporary pathname is intentionally not deleted here. On Linux a
/// same-user namespace adversary can replace that name while the retained file
/// descriptor remains authoritative; on Windows the retained handle prevents
/// replacement until drop, after which pathname cleanup would open a new race.
/// Exact checked-object cleanup belongs to #112. #106 quarantines this exact
/// create-document transient form so residue never becomes target authority.
pub(crate) fn create_document(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > crate::workspace_impl::MAX_DOCUMENT_BYTES {
        bail!("output document size is invalid");
    }

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("output path has no parent"))?;
    crate::workspace::reject_path_indirections(parent, "output parent")?;
    crate::workspace::reject_path_indirections(path, "output path")?;

    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("output file name is invalid"))?;
    let temporary = parent.join(format!(
        ".{name}.{}.tmp",
        crate::workspace_impl::random_hex(12)?
    ));

    let prepared = PreparedFileAuthority::create_named(&temporary, bytes)
        .with_context(|| format!("could not prepare create-only document {}", path.display()))?;

    prepared
        .claim_create_only(path)
        .with_context(|| format!("could not claim create-only destination {}", path.display()))?;
    prepared.validate_destination_binding(path)?;

    if let Err(error) = sync_parent(parent) {
        return Err(PreparedPublishedDocumentError {
            parent_sync_failed: true,
            detail: format!("parent-directory sync failed: {error:#}"),
        }
        .into());
    }

    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<()> {
    fs::File::open(parent)
        .with_context(|| format!("could not open publication parent {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("could not synchronize publication parent {}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<()> {
    Ok(())
}
