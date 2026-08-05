#![forbid(unsafe_code)]

use std::{collections::BTreeMap, path::{Path, PathBuf}, process::ExitCode};

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[path = "nxb-workspace-migration-engine.rs"]
mod engine;
#[path = "nxb-workspace-migration-io.rs"]
mod migration_io;
#[cfg(test)]
#[path = "nxb-workspace-migration-tests.rs"]
mod tests;

pub(crate) const PRODUCT_NAME: &str = "NXBounty";
pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 1;
pub(crate) const JOURNAL_VERSION: u32 = 1;
pub(crate) const RECEIPT_VERSION: u32 = 1;
pub(crate) const MANIFEST_FILE: &str = "workspace.json";
pub(crate) const MAX_DOCUMENT_BYTES: u64 = 64 * 1024;
const APPLY_EXIT_CODE: u8 = 40;
const RECOVER_EXIT_CODE: u8 = 41;
const STATUS_EXIT_CODE: u8 = 42;

#[derive(Debug, Parser)]
#[command(name = "nxb-workspace-migrate", version, about = "NXBounty crash-safe workspace migration helper")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Apply { #[arg(long)] workspace: PathBuf, #[arg(long)] json: bool },
    Recover { #[arg(long)] workspace: PathBuf, #[arg(long)] json: bool },
    Status { #[arg(long)] workspace: PathBuf, #[arg(long)] json: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyManifestV0 {
    pub(crate) schema_version: u32,
    pub(crate) product: String,
    pub(crate) workspace_id: String,
    pub(crate) name: String,
    pub(crate) created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestV1 {
    pub(crate) schema_version: u32,
    pub(crate) product: String,
    pub(crate) workspace_id: String,
    pub(crate) name: String,
    pub(crate) created_at: String,
    pub(crate) secret_storage: SecretStorageBoundary,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecretStorageBoundary { ExternalProviderOnly }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedJournal {
    pub(crate) journal_version: u32,
    pub(crate) migration_id: String,
    pub(crate) from_schema: u32,
    pub(crate) to_schema: u32,
    pub(crate) source_sha256: String,
    pub(crate) target_sha256: String,
    pub(crate) prepared_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppliedMarker {
    pub(crate) journal_version: u32,
    pub(crate) migration_id: String,
    pub(crate) target_sha256: String,
    pub(crate) applied_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MigrationReceipt {
    pub(crate) receipt_version: u32,
    pub(crate) migration_id: String,
    pub(crate) from_schema: u32,
    pub(crate) to_schema: u32,
    pub(crate) source_sha256: String,
    pub(crate) target_sha256: String,
    pub(crate) committed_at: String,
}

#[derive(Debug)]
pub(crate) struct MigrationPlan {
    pub(crate) migration_id: String,
    pub(crate) source_sha256: String,
    pub(crate) target_sha256: String,
    pub(crate) target_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryDisposition { None, Recovered, Cleanup }

#[derive(Debug, Serialize)]
struct CommandResult {
    status: &'static str,
    workspace: String,
    schema_version: Option<u32>,
    migration_id: Option<String>,
    recovery: &'static str,
    details: BTreeMap<String, String>,
}

fn main() -> ExitCode {
    let command = Cli::parse().command;
    let (code, result) = match command {
        Command::Apply { workspace, json } => (APPLY_EXIT_CODE, apply(&workspace, json)),
        Command::Recover { workspace, json } => (RECOVER_EXIT_CODE, recover(&workspace, json)),
        Command::Status { workspace, json } => (STATUS_EXIT_CODE, status(&workspace, json)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NXB-MIGRATION-{code}: {error:#}");
            ExitCode::from(code)
        }
    }
}

fn apply(workspace: &Path, json: bool) -> Result<()> {
    let root = migration_io::validate_workspace_root(workspace)?;
    let paths = migration_io::ensure_state_layout(&root)?;
    let mut recovery = engine::recover(&paths)?;
    let source = migration_io::read_document(&paths.manifest, "workspace manifest")?;
    let schema = manifest_schema(&source)?;
    let mut migration_id = None;
    let status = match schema {
        CURRENT_SCHEMA_VERSION => {
            validate_manifest_v1(&serde_json::from_slice(&source).context("current manifest is invalid")?)?;
            "current"
        }
        0 => {
            let plan = engine::plan(&source)?;
            engine::prepare(&paths, &plan, &source)?;
            recovery = engine::recover(&paths)?;
            migration_id = Some(plan.migration_id);
            "migrated"
        }
        newer if newer > CURRENT_SCHEMA_VERSION => bail!("workspace schema {newer} is newer than this product"),
        other => bail!("no migration path exists from workspace schema {other}"),
    };
    let final_bytes = migration_io::read_document(&paths.manifest, "workspace manifest")?;
    let final_schema = manifest_schema(&final_bytes)?;
    if final_schema != CURRENT_SCHEMA_VERSION { bail!("workspace did not reach the current schema"); }
    emit(CommandResult {
        status,
        workspace: root.display().to_string(),
        schema_version: Some(final_schema),
        migration_id,
        recovery: recovery_label(recovery),
        details: BTreeMap::new(),
    }, json)
}

fn recover(workspace: &Path, json: bool) -> Result<()> {
    let root = migration_io::validate_workspace_root(workspace)?;
    let paths = migration_io::ensure_state_layout(&root)?;
    let recovery = engine::recover(&paths)?;
    emit(CommandResult {
        status: "recovered",
        workspace: root.display().to_string(),
        schema_version: migration_io::optional_manifest_schema(&paths.manifest)?,
        migration_id: None,
        recovery: recovery_label(recovery),
        details: BTreeMap::new(),
    }, json)
}

fn status(workspace: &Path, json: bool) -> Result<()> {
    let root = migration_io::validate_workspace_root(workspace)?;
    let paths = migration_io::paths(&root);
    let pending = migration_io::transient_state(&paths)?;
    let mut details = BTreeMap::new();
    details.insert("pending_files".into(), pending.to_string());
    details.insert("receipts".into(), migration_io::receipt_count(&paths)?.to_string());
    emit(CommandResult {
        status: if pending == 0 { "stable" } else { "recovery_required" },
        workspace: root.display().to_string(),
        schema_version: migration_io::optional_manifest_schema(&paths.manifest)?,
        migration_id: None,
        recovery: "none",
        details,
    }, json)
}

pub(crate) fn manifest_schema(bytes: &[u8]) -> Result<u32> {
    let value: serde_json::Value = serde_json::from_slice(bytes).context("manifest is not valid JSON")?;
    let raw = value.get("schema_version").and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("manifest schema_version is missing or invalid"))?;
    u32::try_from(raw).context("manifest schema_version is too large")
}

pub(crate) fn validate_manifest_v1(manifest: &ManifestV1) -> Result<()> {
    validate_common(manifest.schema_version, &manifest.product, &manifest.workspace_id, &manifest.name, &manifest.created_at)?;
    if manifest.schema_version != CURRENT_SCHEMA_VERSION { bail!("current manifest schema is invalid"); }
    if manifest.secret_storage != SecretStorageBoundary::ExternalProviderOnly { bail!("unsupported secret-storage boundary"); }
    Ok(())
}

pub(crate) fn validate_common(schema: u32, product: &str, id: &str, name: &str, created_at: &str) -> Result<()> {
    if schema > CURRENT_SCHEMA_VERSION { bail!("workspace schema is newer than this product"); }
    if product != PRODUCT_NAME { bail!("workspace product identity does not match"); }
    validate_identifier(id, "workspace_id")?;
    if name.trim() != name || name.is_empty() || name.len() > 96 || name.chars().any(char::is_control) {
        bail!("workspace name is invalid");
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(created_at).context("created_at is invalid")?;
    if parsed.offset().local_minus_utc() != 0 { bail!("created_at must use UTC"); }
    Ok(())
}

pub(crate) fn validate_identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty() || value.len() > 192 || !value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')) {
        bail!("invalid {field}");
    }
    Ok(())
}

pub(crate) fn validate_sha(value: &str, field: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { bail!("invalid {field}"); }
    Ok(())
}

pub(crate) fn now() -> String { Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true) }
pub(crate) fn sha256(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }
pub(crate) fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes { out.push(H[(b >> 4) as usize] as char); out.push(H[(b & 15) as usize] as char); }
    out
}

fn recovery_label(value: RecoveryDisposition) -> &'static str {
    match value { RecoveryDisposition::None => "none", RecoveryDisposition::Recovered => "recovered_and_committed", RecoveryDisposition::Cleanup => "committed_cleanup" }
}

fn emit(value: CommandResult, json: bool) -> Result<()> {
    if json { println!("{}", serde_json::to_string_pretty(&value)?); }
    else { for (key, value) in serde_json::to_value(value)?.as_object().into_iter().flatten() { println!("{key}: {value}"); } }
    Ok(())
}
