use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use super::{canonical_paths, guided_origin, read_bounded_source, validate_path_relationships};

const SCOPE_IMPORT_SCHEMA_VERSION: u32 = 1;
const MAX_SCOPE_IMPORT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeImportV1 {
    schema_version: u32,
    origin: String,
    include_paths: Vec<String>,
    #[serde(default)]
    exclude_paths: Vec<String>,
    #[serde(default)]
    allow_subdomains: bool,
}

pub(super) struct ImportedScope {
    pub(super) origin: String,
    pub(super) include_paths: Vec<String>,
    pub(super) exclude_paths: Vec<String>,
    pub(super) allow_subdomains: bool,
}

pub(super) fn load_scope_import(path: &Path) -> Result<ImportedScope> {
    let bytes = read_bounded_source(path, "guided scope import", MAX_SCOPE_IMPORT_BYTES)?;
    let imported: ScopeImportV1 = serde_json::from_slice(&bytes)
        .context("guided scope import must be bounded UTF-8 JSON matching schema version 1")?;

    if imported.schema_version != SCOPE_IMPORT_SCHEMA_VERSION {
        bail!("unsupported guided scope import schema version");
    }
    if imported.include_paths.is_empty() {
        bail!("guided scope import requires at least one explicit include path");
    }

    let origin = guided_origin(&imported.origin)?;
    let include_paths = canonical_paths(imported.include_paths, true)?;
    let exclude_paths = canonical_paths(imported.exclude_paths, false)?;
    validate_path_relationships(&include_paths, &exclude_paths)?;

    Ok(ImportedScope {
        origin,
        include_paths,
        exclude_paths,
        allow_subdomains: imported.allow_subdomains,
    })
}
