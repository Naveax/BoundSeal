use std::{
    ffi::OsString,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Map, Value};

const INIT_EXIT_CODE: u8 = 10;
const DOCTOR_EXIT_CODE: u8 = 20;
const STATUS_EXIT_CODE: u8 = 30;
const MIGRATION_APPLY_EXIT_CODE: u8 = 40;
const MIGRATION_RECOVER_EXIT_CODE: u8 = 41;
const MIGRATION_STATUS_EXIT_CODE: u8 = 42;
const DISPATCH_EXIT_CODE: u8 = 90;
const MAX_HELPER_OUTPUT_BYTES: u64 = 256 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Args)]
pub(crate) struct WorkspaceArgs {
    #[command(subcommand)]
    command: WorkspaceCommand,
}

#[derive(Debug, Subcommand)]
enum WorkspaceCommand {
    /// Initialize a private local NXBounty workspace.
    Init {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long, default_value = "Default Workspace")]
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Validate workspace structure, permissions and migration state.
    Doctor {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Print a redacted workspace and migration summary.
    Status {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Apply, recover or inspect crash-safe workspace schema migrations.
    Migrate {
        #[command(subcommand)]
        command: MigrationCommand,
    },
}

#[derive(Debug, Subcommand)]
enum MigrationCommand {
    Apply {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Recover {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

pub(crate) fn run(args: WorkspaceArgs) -> ExitCode {
    let (failure_code, result) = match args.command {
        WorkspaceCommand::Init {
            workspace,
            name,
            json,
        } => (
            INIT_EXIT_CODE,
            run_product_init(&workspace, &name, json),
        ),
        WorkspaceCommand::Doctor { workspace, json } => (
            DOCTOR_EXIT_CODE,
            run_combined_workspace_view(&workspace, json, ViewKind::Doctor),
        ),
        WorkspaceCommand::Status { workspace, json } => (
            STATUS_EXIT_CODE,
            run_combined_workspace_view(&workspace, json, ViewKind::Status),
        ),
        WorkspaceCommand::Migrate { command } => match command {
            MigrationCommand::Apply { workspace, json } => (
                MIGRATION_APPLY_EXIT_CODE,
                run_migration_command("apply", &workspace, json),
            ),
            MigrationCommand::Recover { workspace, json } => (
                MIGRATION_RECOVER_EXIT_CODE,
                run_migration_command("recover", &workspace, json),
            ),
            MigrationCommand::Status { workspace, json } => (
                MIGRATION_STATUS_EXIT_CODE,
                run_migration_command("status", &workspace, json),
            ),
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NXB-WORKSPACE-{failure_code}: {error:#}");
            ExitCode::from(failure_code)
        }
    }
}

fn run_product_init(workspace: &Path, name: &str, json_output: bool) -> Result<()> {
    let output = invoke_helper(
        HelperKind::Product,
        [
            OsString::from("init"),
            OsString::from("--workspace"),
            workspace.as_os_str().to_owned(),
            OsString::from("--name"),
            OsString::from(name),
            OsString::from("--json"),
        ],
    )?;
    ensure_helper_success(&output, INIT_EXIT_CODE, "workspace init")?;
    let value = parse_json_output(&output, "workspace init")?;
    emit_value(&value, json_output)
}

#[derive(Clone, Copy)]
enum ViewKind {
    Doctor,
    Status,
}

fn run_combined_workspace_view(
    workspace: &Path,
    json_output: bool,
    kind: ViewKind,
) -> Result<()> {
    let product_command = match kind {
        ViewKind::Doctor => "doctor",
        ViewKind::Status => "status",
    };
    let product = invoke_helper(
        HelperKind::Product,
        [
            OsString::from(product_command),
            OsString::from("--workspace"),
            workspace.as_os_str().to_owned(),
            OsString::from("--json"),
        ],
    )?;
    let product_failure = match kind {
        ViewKind::Doctor => DOCTOR_EXIT_CODE,
        ViewKind::Status => STATUS_EXIT_CODE,
    };
    ensure_helper_success(&product, product_failure, product_command)?;
    let mut product_value = parse_json_output(&product, product_command)?;

    let migration = invoke_helper(
        HelperKind::Migration,
        [
            OsString::from("status"),
            OsString::from("--workspace"),
            workspace.as_os_str().to_owned(),
            OsString::from("--json"),
        ],
    )?;
    ensure_helper_success(
        &migration,
        MIGRATION_STATUS_EXIT_CODE,
        "migration status",
    )?;
    let migration_value = parse_json_output(&migration, "migration status")?;
    let migration_stable = migration_value
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status == "stable");

    let object = product_value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("product helper returned a non-object JSON document"))?;
    object.insert("migration".into(), migration_value.clone());

    match kind {
        ViewKind::Doctor => {
            integrate_doctor_migration(object, &migration_value, migration_stable)?
        }
        ViewKind::Status => {
            if !migration_stable {
                object.insert("status".into(), Value::String("recovery_required".into()));
            }
        }
    }

    emit_value(&product_value, json_output)?;
    if migration_stable {
        Ok(())
    } else {
        bail!("workspace migration recovery is required before product use")
    }
}

fn integrate_doctor_migration(
    object: &mut Map<String, Value>,
    migration: &Value,
    migration_stable: bool,
) -> Result<()> {
    let checks = object
        .get_mut("checks")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("doctor helper output is missing checks"))?;
    let detail = if migration_stable {
        format!(
            "schema={} receipts={} pending_files=0",
            migration
                .get("schema_version")
                .and_then(Value::as_u64)
                .map_or_else(|| "unknown".to_string(), |value| value.to_string()),
            migration
                .pointer("/details/receipts")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        )
    } else {
        format!(
            "status={} pending_files={}",
            migration
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            migration
                .pointer("/details/pending_files")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        )
    };
    checks.push(json!({
        "name": "migration_state",
        "status": if migration_stable { "pass" } else { "fail" },
        "detail": detail,
    }));

    if !migration_stable {
        let errors = object.get("errors").and_then(Value::as_u64).unwrap_or(0);
        object.insert(
            "errors".into(),
            Value::from(
                errors
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("doctor error count overflow"))?,
            ),
        );
        object.insert("status".into(), Value::String("unhealthy".into()));
    }
    Ok(())
}

fn run_migration_command(command: &str, workspace: &Path, json_output: bool) -> Result<()> {
    let output = invoke_helper(
        HelperKind::Migration,
        [
            OsString::from(command),
            OsString::from("--workspace"),
            workspace.as_os_str().to_owned(),
            OsString::from("--json"),
        ],
    )?;
    let expected = match command {
        "apply" => MIGRATION_APPLY_EXIT_CODE,
        "recover" => MIGRATION_RECOVER_EXIT_CODE,
        "status" => MIGRATION_STATUS_EXIT_CODE,
        _ => DISPATCH_EXIT_CODE,
    };
    ensure_helper_success(&output, expected, command)?;
    emit_value(&parse_json_output(&output, command)?, json_output)
}

#[derive(Clone, Copy)]
enum HelperKind {
    Product,
    Migration,
}

impl HelperKind {
    fn file_name(self) -> &'static str {
        match self {
            HelperKind::Product => {
                if cfg!(windows) {
                    "nxb-product.exe"
                } else {
                    "nxb-product"
                }
            }
            HelperKind::Migration => {
                if cfg!(windows) {
                    "nxb-workspace-migrate.exe"
                } else {
                    "nxb-workspace-migrate"
                }
            }
        }
    }
}

struct HelperOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn invoke_helper<I>(kind: HelperKind, arguments: I) -> Result<HelperOutput>
where
    I: IntoIterator<Item = OsString>,
{
    let executable = helper_path(kind)?;
    let mut command = Command::new(&executable);
    command
        .args(arguments)
        .current_dir(
            executable
                .parent()
                .ok_or_else(|| anyhow::anyhow!("helper executable has no parent"))?,
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    preserve_required_environment(&mut command);

    let mut child = command
        .spawn()
        .with_context(|| format!("could not start helper {}", executable.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("helper stdout pipe is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("helper stderr pipe is unavailable"))?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));

    let deadline = Instant::now() + HELPER_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().context("could not inspect helper status")? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("helper execution exceeded the bounded timeout");
        }
        thread::sleep(Duration::from_millis(50));
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("helper stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("helper stderr reader panicked"))??;
    Ok(HelperOutput {
        status,
        stdout,
        stderr,
    })
}

fn helper_path(kind: HelperKind) -> Result<PathBuf> {
    let current = std::env::current_exe().context("could not resolve the nxb executable")?;
    reject_path_indirections(&current, "nxb executable")?;
    let parent = current
        .parent()
        .ok_or_else(|| anyhow::anyhow!("nxb executable has no parent directory"))?;
    reject_path_indirections(parent, "nxb executable directory")?;
    let helper = parent.join(kind.file_name());
    reject_path_indirections(&helper, "workspace helper")?;
    let metadata = fs::metadata(&helper)
        .with_context(|| format!("workspace helper is missing: {}", helper.display()))?;
    if !metadata.is_file() {
        bail!("workspace helper is not a regular file: {}", helper.display());
    }
    Ok(helper)
}

fn ensure_helper_success(output: &HelperOutput, expected_code: u8, label: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let actual = output.status.code();
    let detail = bounded_text(&output.stderr);
    match actual {
        Some(code) if code == i32::from(expected_code) => {
            bail!("{label} failed: {detail}")
        }
        Some(code) => bail!(
            "{label} helper returned unexpected exit code {code}; expected {expected_code}: {detail}"
        ),
        None => bail!("{label} helper terminated without an exit code: {detail}"),
    }
}

fn parse_json_output(output: &HelperOutput, label: &str) -> Result<Value> {
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("{label} helper returned invalid JSON"))
}

fn emit_value(value: &Value, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }
    emit_human_value(None, value, 0)
}

fn emit_human_value(key: Option<&str>, value: &Value, depth: usize) -> Result<()> {
    match value {
        Value::Object(object) => {
            if let Some(key) = key {
                println!("{}{}:", "  ".repeat(depth), key);
            }
            let next_depth = depth + usize::from(key.is_some());
            for (child_key, child_value) in object {
                emit_human_value(Some(child_key), child_value, next_depth)?;
            }
        }
        Value::Array(values) => {
            if let Some(key) = key {
                println!("{}{}:", "  ".repeat(depth), key);
            }
            let next_depth = depth + usize::from(key.is_some());
            for value in values {
                println!("{}- {}", "  ".repeat(next_depth), compact_json(value)?);
            }
        }
        _ => {
            let key = key.ok_or_else(|| anyhow::anyhow!("scalar output is missing a key"))?;
            println!("{}{}: {}", "  ".repeat(depth), key, scalar_text(value));
        }
    }
    Ok(())
}

fn compact_json(value: &Value) -> Result<String> {
    serde_json::to_string(value).context("could not serialize output value")
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

fn read_bounded<R: Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_HELPER_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_HELPER_OUTPUT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "helper output exceeds the supported limit",
        ));
    }
    Ok(bytes)
}

fn bounded_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().take(1_024).collect()
}

fn preserve_required_environment(command: &mut Command) {
    for name in ["SystemRoot", "WINDIR", "TEMP", "TMP", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("RUST_BACKTRACE", "0");
}

fn reject_path_indirections(path: &Path, label: &str) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("could not resolve current directory")?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => continue,
            Component::ParentDir => bail!("{label} must not contain parent traversal"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_names_are_fixed() {
        assert!(HelperKind::Product.file_name().starts_with("nxb-product"));
        assert!(HelperKind::Migration
            .file_name()
            .starts_with("nxb-workspace-migrate"));
    }

    #[test]
    fn doctor_migration_integration_marks_recovery_required() {
        let mut object = Map::from_iter([
            ("status".into(), Value::String("healthy".into())),
            ("errors".into(), Value::from(0_u64)),
            ("checks".into(), Value::Array(Vec::new())),
        ]);
        let migration = json!({
            "status": "recovery_required",
            "schema_version": 1,
            "details": {"pending_files": "1", "receipts": "0"}
        });
        integrate_doctor_migration(&mut object, &migration, false).unwrap();
        assert_eq!(
            object.get("status").and_then(Value::as_str),
            Some("unhealthy")
        );
        assert_eq!(object.get("errors").and_then(Value::as_u64), Some(1));
    }
}
