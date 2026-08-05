#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use clap::{Parser, Subcommand};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(windows)]
#[path = "nxb-product-windows.rs"]
mod windows_security;

const PRODUCT_NAME: &str = "NXBounty";
const WORKSPACE_SCHEMA_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "workspace.json";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const INIT_EXIT_CODE: u8 = 10;
const DOCTOR_EXIT_CODE: u8 = 20;
const STATUS_EXIT_CODE: u8 = 30;
const CANONICAL_DIRECTORIES: &[&str] = &[
    "config",
    "targets",
    "sessions",
    "runs",
    "evidence",
    "reports",
    "state",
    "tmp",
];

#[derive(Debug, Parser)]
#[command(
    name = "nxb-product",
    version,
    about = "NXBounty Windows-first product workspace shell"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a new local NXBounty workspace.
    Init {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long, default_value = "Default Workspace")]
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Validate workspace structure and local write safety without network access.
    Doctor {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Print a redacted workspace summary.
    Status {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WorkspaceManifest {
    schema_version: u32,
    product: String,
    workspace_id: String,
    name: String,
    created_at: String,
    secret_storage: SecretStorageBoundary,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SecretStorageBoundary {
    ExternalProviderOnly,
}

#[derive(Debug, Serialize)]
struct InitResult {
    status: &'static str,
    workspace: String,
    workspace_id: String,
    schema_version: u32,
    directories_created: usize,
}

#[derive(Debug, Serialize)]
struct DoctorResult {
    status: &'static str,
    workspace: String,
    workspace_id: Option<String>,
    checks: Vec<DoctorCheck>,
    errors: usize,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    status: CheckStatus,
    detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CheckStatus {
    Pass,
    Fail,
}

#[derive(Debug, Serialize)]
struct StatusResult {
    status: &'static str,
    workspace: String,
    workspace_id: String,
    name: String,
    schema_version: u32,
    created_at: String,
    records: BTreeMap<String, u64>,
}

fn main() -> ExitCode {
    let command = Cli::parse().command;
    let (exit_code, result) = match command {
        Command::Init {
            workspace,
            name,
            json,
        } => (INIT_EXIT_CODE, initialize_workspace(&workspace, &name, json)),
        Command::Doctor { workspace, json } => {
            (DOCTOR_EXIT_CODE, doctor_workspace(&workspace, json))
        }
        Command::Status { workspace, json } => {
            (STATUS_EXIT_CODE, status_workspace(&workspace, json))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NXB-PRODUCT-{exit_code}: {error:#}");
            ExitCode::from(exit_code)
        }
    }
}

fn initialize_workspace(workspace: &Path, name: &str, json: bool) -> Result<()> {
    validate_workspace_name(name)?;
    reject_path_indirections(workspace, "workspace root")?;

    let root_created = !workspace.exists();
    if root_created {
        fs::create_dir_all(workspace)
            .with_context(|| format!("could not create workspace {}", workspace.display()))?;
    } else {
        let metadata = fs::metadata(workspace)
            .with_context(|| format!("could not inspect workspace {}", workspace.display()))?;
        if !metadata.is_dir() {
            bail!("workspace root is not a directory: {}", workspace.display());
        }
        let mut entries = fs::read_dir(workspace)
            .with_context(|| format!("could not inspect workspace {}", workspace.display()))?;
        if entries.next().transpose()?.is_some() {
            bail!("workspace directory is not empty: {}", workspace.display());
        }
    }

    let result = initialize_workspace_inner(workspace, name, json);
    if result.is_err() {
        cleanup_partial_workspace(workspace, root_created);
    }
    result
}

fn initialize_workspace_inner(workspace: &Path, name: &str, json: bool) -> Result<()> {
    reject_path_indirections(workspace, "workspace root")?;
    let canonical_root = fs::canonicalize(workspace)
        .with_context(|| format!("could not canonicalize workspace {}", workspace.display()))?;
    reject_path_indirections(&canonical_root, "canonical workspace root")?;
    set_private_directory_permissions(&canonical_root)?;

    for directory in CANONICAL_DIRECTORIES {
        let path = canonical_root.join(directory);
        fs::create_dir(&path)
            .with_context(|| format!("could not create workspace directory {}", path.display()))?;
        set_private_directory_permissions(&path)?;
    }

    let manifest = WorkspaceManifest {
        schema_version: WORKSPACE_SCHEMA_VERSION,
        product: PRODUCT_NAME.into(),
        workspace_id: generate_workspace_id(&canonical_root)?,
        name: name.into(),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        secret_storage: SecretStorageBoundary::ExternalProviderOnly,
    };
    atomic_write_json(&canonical_root.join(MANIFEST_FILE), &manifest)?;

    print_result(
        &InitResult {
            status: "initialized",
            workspace: canonical_root.display().to_string(),
            workspace_id: manifest.workspace_id,
            schema_version: manifest.schema_version,
            directories_created: CANONICAL_DIRECTORIES.len(),
        },
        json,
    )
}

fn doctor_workspace(workspace: &Path, json: bool) -> Result<()> {
    let mut checks = Vec::new();
    let canonical_root = match validate_workspace_root(workspace) {
        Ok(root) => {
            checks.push(pass_check(
                "workspace_root",
                format!("canonical root: {}", root.display()),
            ));
            Some(root)
        }
        Err(error) => {
            checks.push(fail_check("workspace_root", error.to_string()));
            None
        }
    };

    let mut workspace_id = None;
    if let Some(root) = &canonical_root {
        match read_manifest(root) {
            Ok(manifest) => {
                workspace_id = Some(manifest.workspace_id.clone());
                checks.push(pass_check(
                    "manifest",
                    format!(
                        "schema={} secret_storage=external_provider_only",
                        manifest.schema_version
                    ),
                ));
            }
            Err(error) => checks.push(fail_check("manifest", error.to_string())),
        }

        for directory in CANONICAL_DIRECTORIES {
            let path = root.join(directory);
            match validate_private_directory(&path) {
                Ok(()) => checks.push(pass_check(
                    format!("directory_{directory}"),
                    path.display().to_string(),
                )),
                Err(error) => checks.push(fail_check(
                    format!("directory_{directory}"),
                    error.to_string(),
                )),
            }
        }

        match write_probe(root) {
            Ok(()) => checks.push(pass_check(
                "atomic_write_probe",
                "create-new, private-permissions, sync and cleanup succeeded",
            )),
            Err(error) => checks.push(fail_check("atomic_write_probe", error.to_string())),
        }
    }

    let errors = checks
        .iter()
        .filter(|check| check.status == CheckStatus::Fail)
        .count();
    print_result(
        &DoctorResult {
            status: if errors == 0 { "healthy" } else { "unhealthy" },
            workspace: workspace.display().to_string(),
            workspace_id,
            checks,
            errors,
        },
        json,
    )?;
    if errors > 0 {
        bail!("workspace doctor found {errors} failing check(s)");
    }
    Ok(())
}

fn status_workspace(workspace: &Path, json: bool) -> Result<()> {
    let canonical_root = validate_workspace_root(workspace)?;
    let manifest = read_manifest(&canonical_root)?;
    let mut records = BTreeMap::new();
    for directory in ["targets", "sessions", "runs", "evidence", "reports"] {
        records.insert(
            directory.to_string(),
            count_regular_files(&canonical_root.join(directory))?,
        );
    }
    print_result(
        &StatusResult {
            status: "ready",
            workspace: canonical_root.display().to_string(),
            workspace_id: manifest.workspace_id,
            name: manifest.name,
            schema_version: manifest.schema_version,
            created_at: manifest.created_at,
            records,
        },
        json,
    )
}

fn validate_workspace_root(workspace: &Path) -> Result<PathBuf> {
    reject_path_indirections(workspace, "workspace root")?;
    let metadata = fs::metadata(workspace)
        .with_context(|| format!("workspace does not exist: {}", workspace.display()))?;
    if !metadata.is_dir() {
        bail!("workspace root is not a directory: {}", workspace.display());
    }
    validate_private_permissions(workspace, true)?;
    let canonical = fs::canonicalize(workspace)
        .with_context(|| format!("could not canonicalize workspace {}", workspace.display()))?;
    reject_path_indirections(&canonical, "canonical workspace root")?;
    Ok(canonical)
}

fn read_manifest(workspace: &Path) -> Result<WorkspaceManifest> {
    let path = workspace.join(MANIFEST_FILE);
    reject_path_indirections(&path, "workspace manifest")?;
    let metadata = fs::metadata(&path)
        .with_context(|| format!("workspace manifest is missing: {}", path.display()))?;
    if !metadata.is_file() {
        bail!("workspace manifest is not a regular file: {}", path.display());
    }
    if metadata.len() == 0 || metadata.len() > MAX_MANIFEST_BYTES {
        bail!("workspace manifest size is invalid: {}", path.display());
    }
    validate_private_permissions(&path, false)?;
    let mut input = String::with_capacity(metadata.len() as usize);
    File::open(&path)
        .with_context(|| format!("could not open workspace manifest {}", path.display()))?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_string(&mut input)
        .with_context(|| format!("could not read workspace manifest {}", path.display()))?;
    if input.len() as u64 > MAX_MANIFEST_BYTES {
        bail!("workspace manifest exceeds the read limit: {}", path.display());
    }
    let manifest: WorkspaceManifest = serde_json::from_str(&input)
        .with_context(|| format!("workspace manifest is invalid: {}", path.display()))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &WorkspaceManifest) -> Result<()> {
    if manifest.schema_version != WORKSPACE_SCHEMA_VERSION {
        bail!(
            "unsupported workspace schema version: {}",
            manifest.schema_version
        );
    }
    if manifest.product != PRODUCT_NAME {
        bail!("workspace product identity does not match");
    }
    validate_identifier(&manifest.workspace_id, "workspace_id")?;
    validate_workspace_name(&manifest.name)?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&manifest.created_at)
        .context("workspace created_at is not valid RFC3339 time")?;
    if created_at.offset().local_minus_utc() != 0 {
        bail!("workspace created_at must use UTC");
    }
    if manifest.secret_storage != SecretStorageBoundary::ExternalProviderOnly {
        bail!("workspace secret-storage boundary is unsupported");
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<()> {
    reject_path_indirections(path, "workspace directory")?;
    let metadata = fs::metadata(path)
        .with_context(|| format!("workspace directory is missing: {}", path.display()))?;
    if !metadata.is_dir() {
        bail!("workspace path is not a directory: {}", path.display());
    }
    validate_private_permissions(path, true)
}

fn reject_path_indirections(path: &Path, field: &str) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("could not resolve current directory")?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata_is_indirection(&metadata) => {
                bail!(
                    "{field} must not traverse a symbolic link or reparse point: {}",
                    current.display()
                )
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
        windows_security::is_reparse_point(metadata)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn generate_workspace_id(workspace: &Path) -> Result<String> {
    let mut random = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| anyhow::anyhow!("operating-system randomness is unavailable"))?;
    let mut digest = Sha256::new();
    digest.update(b"nxb-product-workspace-v1");
    digest.update(random);
    digest.update(workspace.as_os_str().to_string_lossy().as_bytes());
    digest.update(
        Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_le_bytes(),
    );
    random.fill(0);
    Ok(format!("nxb-workspace-{}", &lower_hex(&digest.finalize())[..32]))
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("output path has no parent"))?;
    reject_path_indirections(parent, "output parent")?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("output file name is not valid UTF-8"))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", random_hex(12)?));
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("could not create temporary file {}", temporary.display()))?;
        set_private_file_permissions(&temporary)?;
        let mut bytes = serde_json::to_vec_pretty(value)?;
        bytes.push(b'\n');
        output.write_all(&bytes)?;
        output.sync_all()?;
        drop(output);
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "could not publish {} as {}",
                temporary.display(),
                path.display()
            )
        })?;
        validate_private_permissions(path, false)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_probe(workspace: &Path) -> Result<()> {
    let path = workspace
        .join("tmp")
        .join(format!("doctor-write-probe-{}.tmp", random_hex(12)?));
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("could not create write probe {}", path.display()))?;
        set_private_file_permissions(&path)?;
        output.write_all(b"nxb-doctor-probe\n")?;
        output.sync_all()?;
        drop(output);
        validate_private_permissions(&path, false)?;
        fs::remove_file(&path)
            .with_context(|| format!("could not remove write probe {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&path);
    }
    result
}

fn count_regular_files(path: &Path) -> Result<u64> {
    validate_private_directory(path)?;
    let mut count = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path)?;
        if metadata_is_indirection(&metadata) {
            bail!(
                "record directory contains a symbolic link or reparse point: {}",
                entry_path.display()
            );
        }
        if metadata.is_file() {
            count = count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("record count overflow"))?;
        }
    }
    Ok(count)
}

fn cleanup_partial_workspace(workspace: &Path, root_created: bool) {
    remove_path_without_following(&workspace.join(MANIFEST_FILE));
    if let Ok(entries) = fs::read_dir(workspace) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            if file_name.to_string_lossy().starts_with(".workspace.json.") {
                remove_path_without_following(&entry.path());
            }
        }
    }
    for directory in CANONICAL_DIRECTORIES.iter().rev() {
        remove_path_without_following(&workspace.join(directory));
    }
    if root_created {
        let _ = fs::remove_dir(workspace);
    }
}

fn remove_path_without_following(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata_is_indirection(&metadata) {
        if metadata.is_dir() {
            let _ = fs::remove_dir(path);
        } else {
            let _ = fs::remove_file(path);
        }
    } else if metadata.is_dir() {
        let _ = fs::remove_dir_all(path);
    } else {
        let _ = fs::remove_file(path);
    }
}

fn validate_workspace_name(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed != value
        || trimmed.is_empty()
        || trimmed.len() > 96
        || trimmed.chars().any(char::is_control)
    {
        bail!("workspace name must contain 1-96 printable characters without edge whitespace");
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("invalid {field}");
    }
    Ok(())
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut value = vec![0_u8; bytes];
    SystemRandom::new()
        .fill(&mut value)
        .map_err(|_| anyhow::anyhow!("operating-system randomness is unavailable"))?;
    let encoded = lower_hex(&value);
    value.fill(0);
    Ok(encoded)
}

fn pass_check(name: impl Into<String>, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status: CheckStatus::Pass,
        detail: detail.into(),
    }
}

fn fail_check(name: impl Into<String>, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status: CheckStatus::Fail,
        detail: detail.into(),
    }
}

fn print_result<T: Serialize>(value: &T, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }
    let object = serde_json::to_value(value)?;
    if let Some(map) = object.as_object() {
        for (key, value) in map {
            if value.is_array() || value.is_object() {
                println!("{key}: {}", serde_json::to_string(value)?);
            } else if let Some(text) = value.as_str() {
                println!("{key}: {text}");
            } else {
                println!("{key}: {value}");
            }
        }
    }
    Ok(())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn set_private_directory_permissions(path: &Path) -> Result<()> {
    windows_security::set_private_directory_permissions(path)
}

#[cfg(all(not(unix), not(windows)))]
fn set_private_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    windows_security::set_private_file_permissions(path)
}

#[cfg(all(not(unix), not(windows)))]
fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_permissions(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        bail!("workspace path permissions are too broad: {}", path.display());
    }
    let required = if directory { 0o700 } else { 0o600 };
    if mode & required != required {
        bail!("workspace path permissions are incomplete: {}", path.display());
    }
    Ok(())
}

#[cfg(windows)]
fn validate_private_permissions(path: &Path, directory: bool) -> Result<()> {
    windows_security::validate_private_permissions(path, directory)
}

#[cfg(all(not(unix), not(windows)))]
fn validate_private_permissions(_path: &Path, _directory: bool) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_path(test_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nxb-product-{test_name}-{}-{}",
            std::process::id(),
            random_hex(16).unwrap()
        ))
    }

    #[test]
    fn initializes_and_reads_canonical_workspace() {
        let path = temporary_path("init");
        initialize_workspace(&path, "Test Workspace", true).unwrap();
        let root = validate_workspace_root(&path).unwrap();
        let manifest = read_manifest(&root).unwrap();
        assert_eq!(manifest.schema_version, WORKSPACE_SCHEMA_VERSION);
        assert_eq!(
            manifest.secret_storage,
            SecretStorageBoundary::ExternalProviderOnly
        );
        for directory in CANONICAL_DIRECTORIES {
            assert!(root.join(directory).is_dir());
        }
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn refuses_non_empty_workspace() {
        let path = temporary_path("non-empty");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("existing.txt"), b"occupied").unwrap();
        let error = initialize_workspace(&path, "Test Workspace", true).unwrap_err();
        assert!(error.to_string().contains("not empty"));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn doctor_detects_missing_canonical_directory() {
        let path = temporary_path("doctor");
        initialize_workspace(&path, "Test Workspace", true).unwrap();
        fs::remove_dir(path.join("evidence")).unwrap();
        let error = doctor_workspace(&path, true).unwrap_err();
        assert!(error.to_string().contains("failing check"));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn status_counts_only_regular_records() {
        let path = temporary_path("status");
        initialize_workspace(&path, "Test Workspace", true).unwrap();
        fs::write(path.join("targets").join("one.json"), b"{}\n").unwrap();
        fs::create_dir(path.join("targets").join("nested")).unwrap();
        let root = validate_workspace_root(&path).unwrap();
        assert_eq!(count_regular_files(&root.join("targets")).unwrap(), 1);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn invalid_name_does_not_leave_workspace() {
        let path = temporary_path("invalid-name");
        assert!(initialize_workspace(&path, " bad ", true).is_err());
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_workspace_component() {
        use std::os::unix::fs::symlink;

        let root = temporary_path("symlink-root");
        let target = temporary_path("symlink-target");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&target).unwrap();
        symlink(&target, root.join("linked")).unwrap();
        let error = reject_path_indirections(&root.join("linked").join("workspace"), "test")
            .unwrap_err();
        assert!(error.to_string().contains("symbolic link or reparse point"));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(target).unwrap();
    }
}
