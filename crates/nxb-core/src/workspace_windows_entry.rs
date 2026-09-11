use std::path::Path;

use anyhow::Result;

#[path = "workspace/mod.rs"]
mod base;

pub(crate) use base::*;

pub(crate) fn replace_document(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::workspace_authority_replacement_windows::replace_document(path, bytes)
}

#[path = "workspace/migration.rs"]
pub(crate) mod migration;
