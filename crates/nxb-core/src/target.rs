use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};

use crate::workspace;

const PROFILE_SCHEMA_VERSION: u32 = 1;
const DISABLE_RECEIPT_VERSION: u32 = 1;
const CREATE_EXIT_CODE: u8 = 50;
const LIST_EXIT_CODE: u8 = 51;
const SHOW_EXIT_CODE: u8 = 52;
const DISABLE_EXIT_CODE: u8 = 53;
const MAX_TARGET_PROFILES: usize = 1_024;
const MAX_PATH_RULES: usize = 64;
const MAX_PATH_BYTES: usize = 512;
const ALLOWED_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

#[derive(Debug, Args)]
pub(crate) struct TargetArgs {
    #[command(subcommand)]
    command: TargetCommand,
}

#[derive(Debug, Subcommand)]
enum TargetCommand {
    /// Create one immutable networkless target profile.
    Create {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        origin: String,
        #[arg(long = "include-path")]
        include_paths: Vec<String>,
        #[arg(long = "exclude-path")]
        exclude_paths: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// List canonical target profiles without resolving or contacting them.
    List {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        include_disabled: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show one canonical target profile.
    Show {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Disable one target using an immutable create-only receipt.
    Disable {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long, value_enum)]
        reason: DisableReason,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum DisableReason {
    OperatorHold,
    ProgramEnded,
    ScopeRemoved,
    AuthorizationExpired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TargetProfile {
    schema_version: u32,
    target_id: String,
    name: String,
    origin: String,
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
    allowed_methods: Vec<String>,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DisableReceipt {
    receipt_version: u32,
    target_id: String,
    profile_sha256: String,
    reason: DisableReason,
    disabled_at: String,
}

#[derive(Debug, Serialize)]
struct EffectiveTarget {
    target_id: String,
    name: String,
    origin: String,
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
    allowed_methods: Vec<String>,
    created_at: String,
    status: &'static str,
    disabled_reason: Option<DisableReason>,
    disabled_at: Option<String>,
    network_activity: &'static str,
}

#[derive(Debug, Serialize)]
struct TargetList {
    status: &'static str,
    workspace: String,
    count: usize,
    targets: Vec<EffectiveTarget>,
    network_activity: &'static str,
}

pub(crate) fn run(args: TargetArgs) -> ExitCode {
    let (failure_code, result) = match args.command {
        TargetCommand::Create {
            workspace,
            id,
            name,
            origin,
            include_paths,
            exclude_paths,
            json,
        } => (
            CREATE_EXIT_CODE,
            create_value(
                &workspace,
                &id,
                &name,
                &origin,
                include_paths,
                exclude_paths,
            )
            .and_then(|value| emit_value(&value, json)),
        ),
        TargetCommand::List {
            workspace,
            include_disabled,
            json,
        } => (
            LIST_EXIT_CODE,
            list_value(&workspace, include_disabled).and_then(|value| emit_value(&value, json)),
        ),
        TargetCommand::Show {
            workspace,
            id,
            json,
        } => (
            SHOW_EXIT_CODE,
            show_value(&workspace, &id).and_then(|value| emit_value(&value, json)),
        ),
        TargetCommand::Disable {
            workspace,
            id,
            reason,
            json,
        } => (
            DISABLE_EXIT_CODE,
            disable_value(&workspace, &id, reason).and_then(|value| emit_value(&value, json)),
        ),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("NXB-TARGET-{failure_code}: {error:#}");
            ExitCode::from(failure_code)
        }
    }
}

fn create_value(
    workspace_path: &Path,
    id: &str,
    name: &str,
    origin: &str,
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
) -> Result<Value> {
    let root = ready_workspace(workspace_path)?;
    let targets = targets_directory(&root)?;
    validate_target_id(id)?;
    validate_target_name(name)?;
    let origin = canonical_origin(origin)?;
    let include_paths = canonical_paths(include_paths, true)?;
    let exclude_paths = canonical_paths(exclude_paths, false)?;
    validate_path_relationships(&include_paths, &exclude_paths)?;

    let profile = TargetProfile {
        schema_version: PROFILE_SCHEMA_VERSION,
        target_id: id.to_owned(),
        name: name.to_owned(),
        origin,
        include_paths,
        exclude_paths,
        allowed_methods: ALLOWED_METHODS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        created_at: workspace::now(),
    };
    validate_profile(&profile)?;
    let path = profile_path(&targets, id);
    if workspace::safe_exists(&disable_path(&targets, id))? {
        bail!("target disable receipt already exists without a creatable profile");
    }
    let bytes = canonical_json(&profile)?;
    workspace::create_document(&path, &bytes)?;
    serde_json::to_value(effective_target(profile, None))
        .context("could not serialize target profile")
}

fn list_value(workspace_path: &Path, include_disabled: bool) -> Result<Value> {
    let root = ready_workspace(workspace_path)?;
    let profiles = load_profiles(&targets_directory(&root)?)?;
    let mut targets = Vec::with_capacity(profiles.len());
    for (profile, receipt) in profiles.into_values() {
        if receipt.is_some() && !include_disabled {
            continue;
        }
        targets.push(effective_target(profile, receipt));
    }
    serde_json::to_value(TargetList {
        status: "ready",
        workspace: root.display().to_string(),
        count: targets.len(),
        targets,
        network_activity: "none",
    })
    .context("could not serialize target list")
}

fn show_value(workspace_path: &Path, id: &str) -> Result<Value> {
    let root = ready_workspace(workspace_path)?;
    let targets = targets_directory(&root)?;
    validate_target_id(id)?;
    let profile = read_profile(&profile_path(&targets, id))?;
    let receipt = read_optional_receipt(&disable_path(&targets, id), &profile)?;
    serde_json::to_value(effective_target(profile, receipt))
        .context("could not serialize target profile")
}

fn disable_value(workspace_path: &Path, id: &str, reason: DisableReason) -> Result<Value> {
    let root = ready_workspace(workspace_path)?;
    let targets = targets_directory(&root)?;
    validate_target_id(id)?;
    let profile_path = profile_path(&targets, id);
    let profile_bytes = workspace::read_document(&profile_path, "target profile")?;
    let profile: TargetProfile =
        serde_json::from_slice(&profile_bytes).context("target profile is invalid JSON")?;
    validate_profile(&profile)?;
    if profile_bytes != canonical_json(&profile)? {
        bail!("target profile is not canonical JSON");
    }
    if profile.target_id != id {
        bail!("target profile identity does not match its file name");
    }
    let receipt_path = disable_path(&targets, id);
    if workspace::safe_exists(&receipt_path)? {
        let existing = read_receipt(&receipt_path, &profile)?;
        return serde_json::to_value(effective_target(profile, Some(existing)))
            .context("could not serialize disabled target");
    }
    let receipt = DisableReceipt {
        receipt_version: DISABLE_RECEIPT_VERSION,
        target_id: id.to_owned(),
        profile_sha256: workspace::sha256(&profile_bytes),
        reason,
        disabled_at: workspace::now(),
    };
    validate_receipt(&receipt, &profile, &profile_bytes)?;
    workspace::create_document(&receipt_path, &canonical_json(&receipt)?)?;
    serde_json::to_value(effective_target(profile, Some(receipt)))
        .context("could not serialize disabled target")
}

fn ready_workspace(workspace_path: &Path) -> Result<PathBuf> {
    let root = workspace::validate_workspace_root(workspace_path, true)?;
    let migration = workspace::migration::status_value(&root)?;
    if migration.get("status").and_then(Value::as_str) != Some("stable") {
        bail!("workspace migration recovery is required before target operations");
    }
    Ok(root)
}

fn targets_directory(root: &Path) -> Result<PathBuf> {
    let targets = root.join("targets");
    workspace::reject_path_indirections(&targets, "target directory")?;
    let metadata = fs::metadata(&targets).context("target directory is missing")?;
    if !metadata.is_dir() {
        bail!("target path is not a directory");
    }
    workspace::validate_private_permissions(&targets, true)?;
    Ok(targets)
}

fn load_profiles(
    targets: &Path,
) -> Result<BTreeMap<String, (TargetProfile, Option<DisableReceipt>)>> {
    let mut profile_files = BTreeMap::<String, PathBuf>::new();
    let mut receipt_files = BTreeMap::<String, PathBuf>::new();
    let mut entries = 0_usize;
    for entry in fs::read_dir(targets)? {
        let path = entry?.path();
        workspace::reject_path_indirections(&path, "target record")?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() {
            bail!("target directory contains a non-file entry: {}", path.display());
        }
        workspace::validate_private_permissions(&path, false)?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("target record count overflow"))?;
        if entries > MAX_TARGET_PROFILES.saturating_mul(2) {
            bail!("target record count exceeds the supported limit");
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow::anyhow!("target record file name is invalid"))?;
        if let Some(id) = name.strip_suffix(".disabled.json") {
            validate_target_id(id)?;
            if receipt_files.insert(id.to_owned(), path).is_some() {
                bail!("duplicate target disable receipt");
            }
        } else if let Some(id) = name.strip_suffix(".json") {
            validate_target_id(id)?;
            if profile_files.insert(id.to_owned(), path).is_some() {
                bail!("duplicate target profile");
            }
        } else {
            bail!("target directory contains an unsupported record: {name}");
        }
    }
    if profile_files.len() > MAX_TARGET_PROFILES {
        bail!("target profile count exceeds the supported limit");
    }
    for id in receipt_files.keys() {
        if !profile_files.contains_key(id) {
            bail!("disable receipt exists without its target profile: {id}");
        }
    }

    let mut profiles = BTreeMap::new();
    for (id, path) in profile_files {
        let profile = read_profile(&path)?;
        if profile.target_id != id {
            bail!("target profile identity does not match its file name");
        }
        let receipt = match receipt_files.get(&id) {
            Some(path) => Some(read_receipt(path, &profile)?),
            None => None,
        };
        profiles.insert(id, (profile, receipt));
    }
    Ok(profiles)
}

fn read_profile(path: &Path) -> Result<TargetProfile> {
    let bytes = workspace::read_document(path, "target profile")?;
    let profile: TargetProfile =
        serde_json::from_slice(&bytes).context("target profile is invalid JSON")?;
    validate_profile(&profile)?;
    if bytes != canonical_json(&profile)? {
        bail!("target profile is not canonical JSON");
    }
    Ok(profile)
}

fn read_optional_receipt(
    path: &Path,
    profile: &TargetProfile,
) -> Result<Option<DisableReceipt>> {
    if workspace::safe_exists(path)? {
        Ok(Some(read_receipt(path, profile)?))
    } else {
        Ok(None)
    }
}

fn read_receipt(path: &Path, profile: &TargetProfile) -> Result<DisableReceipt> {
    let profile_bytes = canonical_json(profile)?;
    let receipt_bytes = workspace::read_document(path, "target disable receipt")?;
    let receipt: DisableReceipt = serde_json::from_slice(&receipt_bytes)
        .context("target disable receipt is invalid JSON")?;
    validate_receipt(&receipt, profile, &profile_bytes)?;
    if receipt_bytes != canonical_json(&receipt)? {
        bail!("target disable receipt is not canonical JSON");
    }
    Ok(receipt)
}

fn validate_profile(profile: &TargetProfile) -> Result<()> {
    if profile.schema_version != PROFILE_SCHEMA_VERSION {
        bail!("unsupported target profile schema");
    }
    validate_target_id(&profile.target_id)?;
    validate_target_name(&profile.name)?;
    if canonical_origin(&profile.origin)? != profile.origin {
        bail!("target origin is not canonical");
    }
    let includes = canonical_paths(profile.include_paths.clone(), true)?;
    let excludes = canonical_paths(profile.exclude_paths.clone(), false)?;
    if includes != profile.include_paths || excludes != profile.exclude_paths {
        bail!("target path rules are not canonical");
    }
    validate_path_relationships(&includes, &excludes)?;
    if profile.allowed_methods.len() != ALLOWED_METHODS.len()
        || !profile
            .allowed_methods
            .iter()
            .zip(ALLOWED_METHODS.iter())
            .all(|(actual, expected)| actual.as_str() == *expected)
    {
        bail!("target profile methods exceed the read-only product boundary");
    }
    validate_time(&profile.created_at, "created_at")
}

fn validate_receipt(
    receipt: &DisableReceipt,
    profile: &TargetProfile,
    profile_bytes: &[u8],
) -> Result<()> {
    if receipt.receipt_version != DISABLE_RECEIPT_VERSION
        || receipt.target_id != profile.target_id
        || receipt.profile_sha256 != workspace::sha256(profile_bytes)
    {
        bail!("target disable receipt does not match its immutable profile");
    }
    workspace::validate_sha(&receipt.profile_sha256, "profile_sha256")?;
    validate_time(&receipt.disabled_at, "disabled_at")
}

fn canonical_origin(input: &str) -> Result<String> {
    if input.trim() != input || input.len() > 512 || input.chars().any(char::is_control) {
        bail!("target origin contains invalid whitespace or control characters");
    }
    if input.contains('*') || input.contains('\\') {
        bail!("target origin must not contain wildcards or backslashes");
    }
    let parsed = Url::parse(input).context("target origin is not a valid URL")?;
    if parsed.scheme() != "https"
        || parsed.cannot_be_a_base()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        bail!("target origin must be an HTTPS origin without credentials, path, query or fragment");
    }
    let host = match parsed.host() {
        Some(Host::Domain(value)) => value.to_ascii_lowercase(),
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => {
            bail!("target origin must not use an IP literal")
        }
        None => bail!("target origin is missing a host"),
    };
    validate_public_domain(&host)?;
    let port = parsed.port().unwrap_or(443);
    Ok(if port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{port}")
    })
}

fn validate_public_domain(host: &str) -> Result<()> {
    if host.len() > 253
        || !host.contains('.')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        bail!("target origin host is not a canonical public DNS name");
    }
    const DENIED_SUFFIXES: &[&str] = &[
        ".localhost",
        ".local",
        ".internal",
        ".invalid",
        ".test",
        ".example",
        ".home.arpa",
    ];
    if host == "localhost"
        || DENIED_SUFFIXES
            .iter()
            .any(|suffix| host.ends_with(suffix))
    {
        bail!("target origin host uses a reserved or local DNS suffix");
    }
    if host.parse::<IpAddr>().is_ok() {
        bail!("target origin host must not be an IP literal");
    }
    Ok(())
}

fn canonical_paths(mut paths: Vec<String>, include: bool) -> Result<Vec<String>> {
    if include && paths.is_empty() {
        paths.push("/".to_owned());
    }
    if paths.len() > MAX_PATH_RULES {
        bail!("target path rule count exceeds the supported limit");
    }
    let mut canonical = BTreeSet::new();
    for path in paths {
        validate_scope_path(&path)?;
        if !include && path == "/" {
            bail!("excluding the root path would leave no usable target scope");
        }
        if !canonical.insert(path) {
            bail!("target path rules must not contain duplicates");
        }
    }
    if include && canonical.is_empty() {
        bail!("target must include at least one path prefix");
    }
    Ok(canonical.into_iter().collect())
}

fn validate_scope_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('\\')
        || path.contains('?')
        || path.contains('#')
        || path.contains('%')
        || path.contains('*')
        || (path != "/" && path.ends_with('/'))
        || path
            .chars()
            .any(|value| value.is_control() || value.is_whitespace())
    {
        bail!("target path prefix is not canonical");
    }
    for segment in path.split('/') {
        if matches!(segment, "." | "..") {
            bail!("target path prefix contains dot traversal");
        }
    }
    Ok(())
}

fn validate_path_relationships(includes: &[String], excludes: &[String]) -> Result<()> {
    for excluded in excludes {
        if includes.iter().any(|included| included == excluded) {
            bail!("an excluded path must not remove an entire included prefix");
        }
        if !includes
            .iter()
            .any(|included| path_is_within(excluded, included))
        {
            bail!("excluded path is outside every included path prefix");
        }
    }
    Ok(())
}

fn path_is_within(candidate: &str, prefix: &str) -> bool {
    prefix == "/"
        || candidate == prefix
        || candidate
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn validate_target_id(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if !(3..=64).contains(&bytes.len())
        || (!bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit())
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        || value.ends_with('-')
        || value.contains("--")
    {
        bail!("target id must be a 3-64 character lowercase slug");
    }
    Ok(())
}

fn validate_target_name(value: &str) -> Result<()> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > 96
        || value.chars().any(char::is_control)
    {
        bail!("target name must contain 1-96 printable characters without edge whitespace");
    }
    Ok(())
}

fn validate_time(value: &str, field: &str) -> Result<()> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{field} is invalid"))?;
    if parsed.offset().local_minus_utc() != 0 {
        bail!("{field} must use UTC");
    }
    Ok(())
}

fn profile_path(targets: &Path, id: &str) -> PathBuf {
    targets.join(format!("{id}.json"))
}

fn disable_path(targets: &Path, id: &str) -> PathBuf {
    targets.join(format!("{id}.disabled.json"))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn effective_target(profile: TargetProfile, receipt: Option<DisableReceipt>) -> EffectiveTarget {
    EffectiveTarget {
        target_id: profile.target_id,
        name: profile.name,
        origin: profile.origin,
        include_paths: profile.include_paths,
        exclude_paths: profile.exclude_paths,
        allowed_methods: profile.allowed_methods,
        created_at: profile.created_at,
        status: if receipt.is_some() {
            "disabled"
        } else {
            "active"
        },
        disabled_reason: receipt.as_ref().map(|value| value.reason),
        disabled_at: receipt.map(|value| value.disabled_at),
        network_activity: "none",
    }
}

fn emit_value(value: &Value, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else if let Some(object) = value.as_object() {
        for (key, item) in object {
            match item {
                Value::Array(_) | Value::Object(_) => {
                    println!("{key}: {}", serde_json::to_string(item)?);
                }
                Value::String(item) => println!("{key}: {item}"),
                other => println!("{key}: {other}"),
            }
        }
    } else {
        println!("{}", serde_json::to_string(value)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nxb-target-{name}-{}-{}",
            std::process::id(),
            workspace::random_hex(8).unwrap()
        ))
    }

    #[test]
    fn creates_lists_shows_and_disables_target() {
        let root = workspace_path("lifecycle");
        workspace::initialize_value(&root, "Target Test").unwrap();
        let created = create_value(
            &root,
            "example-app",
            "Example App",
            "https://example.org",
            vec!["/api".into()],
            vec!["/api/logout".into()],
        )
        .unwrap();
        assert_eq!(
            created.get("status").and_then(Value::as_str),
            Some("active")
        );
        assert_eq!(
            created.get("network_activity").and_then(Value::as_str),
            Some("none")
        );
        assert_eq!(
            list_value(&root, false)
                .unwrap()
                .get("count")
                .and_then(Value::as_u64),
            Some(1)
        );
        let disabled = disable_value(&root, "example-app", DisableReason::OperatorHold).unwrap();
        assert_eq!(
            disabled.get("status").and_then(Value::as_str),
            Some("disabled")
        );
        assert_eq!(
            list_value(&root, false)
                .unwrap()
                .get("count")
                .and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            list_value(&root, true)
                .unwrap()
                .get("count")
                .and_then(Value::as_u64),
            Some(1)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_non_https_credentials_ip_and_reserved_hosts() {
        for origin in [
            "http://example.org",
            "https://user@example.org",
            "https://127.0.0.1",
            "https://service.internal",
            "https://*.example.org",
        ] {
            assert!(canonical_origin(origin).is_err(), "origin accepted: {origin}");
        }
    }

    #[test]
    fn rejects_ambiguous_or_out_of_scope_paths() {
        for path in [
            "api",
            "//api",
            "/api/../admin",
            "/api%2fadmin",
            "/api?x=1",
        ] {
            assert!(validate_scope_path(path).is_err(), "path accepted: {path}");
        }
        assert!(validate_path_relationships(&["/api".into()], &["/admin".into()]).is_err());
    }

    #[test]
    fn target_operations_require_stable_migration_state() {
        let root = workspace_path("migration");
        workspace::initialize_value(&root, "Target Test").unwrap();
        let active = root.join("state").join("migration-active.json");
        fs::write(&active, b"{}\n").unwrap();
        workspace::set_private_file_permissions(&active).unwrap();
        assert!(list_value(&root, false).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
