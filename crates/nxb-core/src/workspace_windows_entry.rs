use std::path::Path;

use anyhow::Result;

#[path = "workspace/mod.rs"]
mod base;

pub(crate) use base::*;

pub(crate) fn replace_document(path: &Path, bytes: &[u8]) -> Result<()> {
    let observed = if base::safe_exists(path)? {
        base::read_document(path, "workspace replacement observation")?
    } else {
        Vec::new()
    };
    crate::workspace_authority_replacement_windows::replace_document_if_current(
        path,
        bytes,
        &observed,
    )
}

#[path = "workspace/migration.rs"]
pub(crate) mod migration;
