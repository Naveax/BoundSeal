use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

pub(crate) use crate::workspace_authority_base::*;

pub(crate) fn create_document(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::workspace_authority_publication::create_document(path, bytes)
}

pub(crate) fn create_document_error_published(error: &anyhow::Error) -> bool {
    crate::workspace_authority_publication::error_published(error)
        || crate::workspace_authority_base::create_document_error_published(error)
}

pub(crate) fn status_value(workspace: &Path) -> Result<Value> {
    let mut value = crate::workspace_authority_base::status_value(workspace)?;
    let records = crate::workspace_authority_records::count_target_readiness_records(workspace)?;
    let object = value
        .as_object_mut()
        .context("workspace authority status returned a non-object JSON document")?;
    object.insert(
        "records".to_owned(),
        serde_json::to_value(records).context("could not serialize workspace authority records")?,
    );
    Ok(value)
}
