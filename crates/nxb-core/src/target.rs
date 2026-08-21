mod activation;
mod guided_policy;
mod scope_import;

use activation::activate_value;
use guided_policy::{compile_guided_policy, GuidedPolicyArtifact};
use scope_import::load_scope_import;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Args, Subcommand, ValueEnum};
use nxb_policy::{CompiledPolicy, TargetPolicy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};

use crate::{
    diagnostic::{self, DiagnosticSpec},
    workspace,
};

const PROFILE_SCHEMA_VERSION: u32 = 2;
const DISABLE_RECEIPT_VERSION: u32 = 1;
const CREATE_EXIT_CODE: u8 = 50;
const LIST_EXIT_CODE: u8 = 51;
const SHOW_EXIT_CODE: u8 = 52;
const DISABLE_EXIT_CODE: u8 = 53;
const VALIDATE_EXIT_CODE: u8 = 54;
const SETUP_EXIT_CODE: u8 = 55;
const ACTIVATE_EXIT_CODE: u8 = 56;
const MAX_TARGET_PROFILES: usize = 1_024;
const MAX_PATH_RULES: usize = 64;
const MAX_PATH_BYTES: usize = 512;
const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_AUTHORIZATION_BYTES: u64 = 8 * 1024 * 1024;
const READ_ONLY_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

const CREATE_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-TARGET-CREATE-REJECTED",
    domain: "target",
    operation: "create",
    text_prefix: "NXB-TARGET-50",
};
const LIST_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-TARGET-LIST-INVALID",
    domain: "target",
    operation: "list",
    text_prefix: "NXB-TARGET-51",
};
const SHOW_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-TARGET-SHOW-INVALID",
    domain: "target",
    operation: "show",
    text_prefix: "NXB-TARGET-52",
};
const DISABLE_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-TARGET-DISABLE-REJECTED",
    domain: "target",
    operation: "disable",
    text_prefix: "NXB-TARGET-53",
};
const VALIDATE_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-TARGET-VALIDATE-INVALID",
    domain: "target",
    operation: "validate",
    text_prefix: "NXB-TARGET-54",
};
const SETUP_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB153-TARGET-SETUP-REJECTED",
    domain: "target",
    operation: "setup",
    text_prefix: "NXB-TARGET-55",
};
const ACTIVATE_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB153-TARGET-ACTIVATE-REJECTED",
    domain: "target",
    operation: "activate",
    text_prefix: "NXB-TARGET-56",
};

#[derive(Debug, Args)]
pub(crate) struct TargetArgs {
    #[command(subcommand)]
    command: TargetCommand,
}

#[derive(Debug, Subcommand)]
enum TargetCommand {
    /// Preview one guided authorization-bound target setup without persistent mutation.
    Setup {
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
        program_name: String,
        #[arg(long)]
        program_platform: String,
        #[arg(long)]
        program_reference: Option<String>,
        #[arg(long)]
        authorization_reference: String,
        #[arg(long)]
        authorization_document: PathBuf,
        #[arg(long)]
        researcher: String,
        #[arg(long, value_enum)]
        authorization_basis: AuthorizationBasis,
        #[arg(long)]
        authorization_expires_at: String,
        #[arg(long)]
        acknowledge_authorization: String,
        #[arg(long)]
        allow_subdomains: bool,
        #[arg(long, default_value_t = 1.0)]
        max_requests_per_second: f64,
        #[arg(long, default_value_t = 1)]
        max_concurrency: u16,
        #[arg(long, default_value_t = 10)]
        max_total_requests: u64,
        #[arg(long)]
        json: bool,
    },
    /// Preview one bounded operator-provided scope import through the guided compiler.
    SetupImport {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        scope_import: PathBuf,
        #[arg(long)]
        program_name: String,
        #[arg(long)]
        program_platform: String,
        #[arg(long)]
        program_reference: Option<String>,
        #[arg(long)]
        authorization_reference: String,
        #[arg(long)]
        authorization_document: PathBuf,
        #[arg(long)]
        researcher: String,
        #[arg(long, value_enum)]
        authorization_basis: AuthorizationBasis,
        #[arg(long)]
        authorization_expires_at: String,
        #[arg(long)]
        acknowledge_authorization: String,
        #[arg(long, default_value_t = 1.0)]
        max_requests_per_second: f64,
        #[arg(long, default_value_t = 1)]
        max_concurrency: u16,
        #[arg(long, default_value_t = 10)]
        max_total_requests: u64,
        #[arg(long)]
        json: bool,
    },
    /// Activate one exact guided preview using the immutable target profile boundary.
    Activate {
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
        program_name: String,
        #[arg(long)]
        program_platform: String,
        #[arg(long)]
        program_reference: Option<String>,
        #[arg(long)]
        authorization_reference: String,
        #[arg(long)]
        authorization_document: PathBuf,
        #[arg(long)]
        researcher: String,
        #[arg(long, value_enum)]
        authorization_basis: AuthorizationBasis,
        #[arg(long)]
        authorization_expires_at: String,
        #[arg(long)]
        acknowledge_authorization: String,
        #[arg(long)]
        allow_subdomains: bool,
        #[arg(long, default_value_t = 1.0)]
        max_requests_per_second: f64,
        #[arg(long, default_value_t = 1)]
        max_concurrency: u16,
        #[arg(long, default_value_t = 10)]
        max_total_requests: u64,
        #[arg(long)]
        confirm_preview_sha: String,
        #[arg(long)]
        acknowledge_activation: String,
        #[arg(long)]
        json: bool,
    },
    /// Activate one bounded imported scope after exact preview confirmation.
    ActivateImport {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        scope_import: PathBuf,
        #[arg(long)]
        program_name: String,
        #[arg(long)]
        program_platform: String,
        #[arg(long)]
        program_reference: Option<String>,
        #[arg(long)]
        authorization_reference: String,
        #[arg(long)]
        authorization_document: PathBuf,
        #[arg(long)]
        researcher: String,
        #[arg(long, value_enum)]
        authorization_basis: AuthorizationBasis,
        #[arg(long)]
        authorization_expires_at: String,
        #[arg(long)]
        acknowledge_authorization: String,
        #[arg(long, default_value_t = 1.0)]
        max_requests_per_second: f64,
        #[arg(long, default_value_t = 1)]
        max_concurrency: u16,
        #[arg(long, default_value_t = 10)]
        max_total_requests: u64,
        #[arg(long)]
        confirm_preview_sha: String,
        #[arg(long)]
        acknowledge_activation: String,
        #[arg(long)]
        json: bool,
    },
    /// Create one immutable, authorization-bound, networkless target profile.
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
        authorization_reference: String,
        #[arg(long)]
        authorization_document: PathBuf,
        #[arg(long)]
        policy: PathBuf,
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
    /// Revalidate one profile against exact policy and authorization source bytes.
    Validate {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        authorization_document: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum AuthorizationBasis {
    ProgramPolicy,
    OwnedAsset,
    WrittenPermission,
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
    program: ProgramMetadata,
    authorization: AuthorizationBinding,
    policy_sha256: String,
    identity_sha256: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProgramMetadata {
    name: String,
    platform: String,
    reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthorizationBinding {
    reference: String,
    document_sha256: String,
}

#[derive(Serialize)]
struct ProfileIdentity<'a> {
    schema_version: u32,
    target_id: &'a str,
    name: &'a str,
    origin: &'a str,
    include_paths: &'a [String],
    exclude_paths: &'a [String],
    allowed_methods: &'a [String],
    program: &'a ProgramMetadata,
    authorization: &'a AuthorizationBinding,
    policy_sha256: &'a str,
    created_at: &'a str,
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
    program: ProgramMetadata,
    authorization_reference: String,
    authorization_sha256: String,
    policy_sha256: String,
    identity_sha256: String,
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
    let (failure_code, diagnostic_spec, json_output, result) = match args.command {
        TargetCommand::Setup {
            workspace,
            id,
            name,
            origin,
            include_paths,
            exclude_paths,
            program_name,
            program_platform,
            program_reference,
            authorization_reference,
            authorization_document,
            researcher,
            authorization_basis,
            authorization_expires_at,
            acknowledge_authorization,
            allow_subdomains,
            max_requests_per_second,
            max_concurrency,
            max_total_requests,
            json,
        } => (
            SETUP_EXIT_CODE,
            SETUP_DIAGNOSTIC,
            json,
            build_guided_setup(
                &workspace,
                &id,
                &name,
                &origin,
                include_paths,
                exclude_paths,
                &program_name,
                &program_platform,
                program_reference.as_deref(),
                &authorization_reference,
                &authorization_document,
                &researcher,
                authorization_basis,
                &authorization_expires_at,
                &acknowledge_authorization,
                allow_subdomains,
                max_requests_per_second,
                max_concurrency,
                max_total_requests,
            )
            .and_then(|build| emit_setup_preview(&build.preview, json)),
        ),
        TargetCommand::SetupImport {
            workspace,
            id,
            name,
            scope_import,
            program_name,
            program_platform,
            program_reference,
            authorization_reference,
            authorization_document,
            researcher,
            authorization_basis,
            authorization_expires_at,
            acknowledge_authorization,
            max_requests_per_second,
            max_concurrency,
            max_total_requests,
            json,
        } => (
            SETUP_EXIT_CODE,
            SETUP_DIAGNOSTIC,
            json,
            load_scope_import(&scope_import)
                .and_then(|scope| {
                    let origin = scope.origin;
                    let include_paths = scope.include_paths;
                    let exclude_paths = scope.exclude_paths;
                    let allow_subdomains = scope.allow_subdomains;

                    build_guided_setup(
                        &workspace,
                        &id,
                        &name,
                        &origin,
                        include_paths,
                        exclude_paths,
                        &program_name,
                        &program_platform,
                        program_reference.as_deref(),
                        &authorization_reference,
                        &authorization_document,
                        &researcher,
                        authorization_basis,
                        &authorization_expires_at,
                        &acknowledge_authorization,
                        allow_subdomains,
                        max_requests_per_second,
                        max_concurrency,
                        max_total_requests,
                    )
                })
                .and_then(|build| emit_setup_preview(&build.preview, json)),
        ),
        TargetCommand::Activate {
            workspace,
            id,
            name,
            origin,
            include_paths,
            exclude_paths,
            program_name,
            program_platform,
            program_reference,
            authorization_reference,
            authorization_document,
            researcher,
            authorization_basis,
            authorization_expires_at,
            acknowledge_authorization,
            allow_subdomains,
            max_requests_per_second,
            max_concurrency,
            max_total_requests,
            confirm_preview_sha,
            acknowledge_activation,
            json,
        } => (
            ACTIVATE_EXIT_CODE,
            ACTIVATE_DIAGNOSTIC,
            json,
            activate_value(
                &workspace,
                &id,
                &name,
                &origin,
                include_paths,
                exclude_paths,
                &program_name,
                &program_platform,
                program_reference.as_deref(),
                &authorization_reference,
                &authorization_document,
                &researcher,
                authorization_basis,
                &authorization_expires_at,
                &acknowledge_authorization,
                allow_subdomains,
                max_requests_per_second,
                max_concurrency,
                max_total_requests,
                &confirm_preview_sha,
                &acknowledge_activation,
            )
            .and_then(|value| emit_value(&value, json)),
        ),
        TargetCommand::ActivateImport {
            workspace,
            id,
            name,
            scope_import,
            program_name,
            program_platform,
            program_reference,
            authorization_reference,
            authorization_document,
            researcher,
            authorization_basis,
            authorization_expires_at,
            acknowledge_authorization,
            max_requests_per_second,
            max_concurrency,
            max_total_requests,
            confirm_preview_sha,
            acknowledge_activation,
            json,
        } => (
            ACTIVATE_EXIT_CODE,
            ACTIVATE_DIAGNOSTIC,
            json,
            load_scope_import(&scope_import)
                .and_then(|scope| {
                    let origin = scope.origin;
                    let include_paths = scope.include_paths;
                    let exclude_paths = scope.exclude_paths;
                    let allow_subdomains = scope.allow_subdomains;

                    activate_value(
                        &workspace,
                        &id,
                        &name,
                        &origin,
                        include_paths,
                        exclude_paths,
                        &program_name,
                        &program_platform,
                        program_reference.as_deref(),
                        &authorization_reference,
                        &authorization_document,
                        &researcher,
                        authorization_basis,
                        &authorization_expires_at,
                        &acknowledge_authorization,
                        allow_subdomains,
                        max_requests_per_second,
                        max_concurrency,
                        max_total_requests,
                        &confirm_preview_sha,
                        &acknowledge_activation,
                    )
                })
                .and_then(|value| emit_value(&value, json)),
        ),
        TargetCommand::Create {
            workspace,
            id,
            name,
            origin,
            include_paths,
            exclude_paths,
            authorization_reference,
            authorization_document,
            policy,
            json,
        } => (
            CREATE_EXIT_CODE,
            CREATE_DIAGNOSTIC,
            json,
            create_value(
                &workspace,
                &id,
                &name,
                &origin,
                include_paths,
                exclude_paths,
                &authorization_reference,
                &authorization_document,
                &policy,
            )
            .and_then(|value| emit_value(&value, json)),
        ),
        TargetCommand::List {
            workspace,
            include_disabled,
            json,
        } => (
            LIST_EXIT_CODE,
            LIST_DIAGNOSTIC,
            json,
            list_value(&workspace, include_disabled).and_then(|value| emit_value(&value, json)),
        ),
        TargetCommand::Show {
            workspace,
            id,
            json,
        } => (
            SHOW_EXIT_CODE,
            SHOW_DIAGNOSTIC,
            json,
            show_value(&workspace, &id).and_then(|value| emit_value(&value, json)),
        ),
        TargetCommand::Disable {
            workspace,
            id,
            reason,
            json,
        } => (
            DISABLE_EXIT_CODE,
            DISABLE_DIAGNOSTIC,
            json,
            disable_value(&workspace, &id, reason).and_then(|value| emit_value(&value, json)),
        ),
        TargetCommand::Validate {
            workspace,
            id,
            authorization_document,
            policy,
            json,
        } => (
            VALIDATE_EXIT_CODE,
            VALIDATE_DIAGNOSTIC,
            json,
            validate_value(&workspace, &id, &authorization_document, &policy)
                .and_then(|value| emit_value(&value, json)),
        ),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            diagnostic::emit_failure(diagnostic_spec, failure_code, json_output, &error);
            ExitCode::from(failure_code)
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct SetupProgram {
    name: String,
    platform: String,
    reference: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SetupAuthorization {
    reference: String,
    document_sha256: String,
    researcher: String,
    basis: AuthorizationBasis,
    expires_at: String,
    acknowledged: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SetupAutomation {
    allowed_methods: Vec<String>,
    allow_subdomains: bool,
    active_testing: bool,
    oob_callbacks: bool,
    credential_bruteforce: bool,
    destructive_testing: bool,
    max_requests_per_second: f64,
    max_concurrency: u16,
    max_total_requests: u64,
}

#[derive(Debug, Clone, Serialize)]
struct SetupPolicyBinding {
    schema_version: u32,
    policy_snapshot_sha256: String,
    policy_document_sha256: String,
    compiled: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SetupPreviewIdentity {
    schema_version: u32,
    status: &'static str,
    target_id: String,
    name: String,
    origin: String,
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
    program: SetupProgram,
    authorization: SetupAuthorization,
    automation: SetupAutomation,
    policy: SetupPolicyBinding,
    hard_denied_actions: Vec<String>,
    network_activity: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct SetupPreview {
    #[serde(flatten)]
    identity: SetupPreviewIdentity,
    preview_sha256: String,
}

struct GuidedSetupBuild {
    preview: SetupPreview,
    authorization_bytes: Vec<u8>,
    policy: GuidedPolicyArtifact,
}

#[allow(clippy::too_many_arguments)]
fn build_guided_setup(
    workspace_path: &Path,
    id: &str,
    name: &str,
    origin: &str,
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
    program_name: &str,
    program_platform: &str,
    program_reference: Option<&str>,
    authorization_reference: &str,
    authorization_document: &Path,
    researcher: &str,
    authorization_basis: AuthorizationBasis,
    authorization_expires_at: &str,
    acknowledge_authorization: &str,
    allow_subdomains: bool,
    max_requests_per_second: f64,
    max_concurrency: u16,
    max_total_requests: u64,
) -> Result<GuidedSetupBuild> {
    let _root = ready_workspace(workspace_path)?;

    validate_target_id(id)?;
    validate_target_name(name)?;

    let origin = guided_origin(origin)?;

    if include_paths.is_empty() {
        bail!("guided target setup requires at least one explicit include path");
    }

    let include_paths = canonical_paths(include_paths, true)?;

    let exclude_paths = canonical_paths(exclude_paths, false)?;

    validate_path_relationships(&include_paths, &exclude_paths)?;

    validate_setup_text(program_name, "program name", 96)?;

    validate_setup_platform(program_platform)?;

    let program_reference = program_reference
        .map(|value| {
            validate_safe_reference(value, "program reference")?;

            Ok::<String, anyhow::Error>(value.to_owned())
        })
        .transpose()?;

    validate_safe_reference(authorization_reference, "authorization reference")?;

    validate_setup_text(researcher, "authorization researcher", 128)?;

    if acknowledge_authorization != "I_HAVE_EXPLICIT_AUTHORIZATION" {
        bail!("guided target setup requires the exact explicit authorization acknowledgement");
    }

    let expires_at = canonical_setup_expiry(authorization_expires_at)?;

    validate_setup_budget(max_requests_per_second, max_concurrency, max_total_requests)?;

    let authorization_bytes = read_bounded_source(
        authorization_document,
        "authorization document",
        MAX_AUTHORIZATION_BYTES,
    )?;

    let authorization_document_sha256 = workspace::sha256(&authorization_bytes);

    let policy = compile_guided_policy(
        &origin,
        program_name,
        program_platform,
        program_reference.as_deref(),
        researcher,
        &expires_at,
        allow_subdomains,
        max_requests_per_second,
        max_concurrency,
        max_total_requests,
    )?;

    let identity = SetupPreviewIdentity {
        schema_version: 1,
        status: "preview",
        target_id: id.to_owned(),
        name: name.to_owned(),
        origin,
        include_paths,
        exclude_paths,
        program: SetupProgram {
            name: program_name.to_owned(),
            platform: program_platform.to_owned(),
            reference: program_reference,
        },
        authorization: SetupAuthorization {
            reference: authorization_reference.to_owned(),
            document_sha256: authorization_document_sha256,
            researcher: researcher.to_owned(),
            basis: authorization_basis,
            expires_at,
            acknowledged: true,
        },
        automation: SetupAutomation {
            allowed_methods: policy.allowed_methods.clone(),
            allow_subdomains,
            active_testing: policy.compiled.active_testing_enabled(),
            oob_callbacks: policy.compiled.oob_callbacks_enabled(),
            credential_bruteforce: false,
            destructive_testing: false,
            max_requests_per_second: policy.compiled.maximum_requests_per_second(),
            max_concurrency: policy.compiled.maximum_concurrency(),
            max_total_requests: policy.compiled.maximum_total_requests(),
        },
        policy: SetupPolicyBinding {
            schema_version: 1,
            policy_snapshot_sha256: policy.snapshot_sha256.clone(),
            policy_document_sha256: policy.document_sha256.clone(),
            compiled: true,
        },
        hard_denied_actions: vec![
            "credential_bruteforce".to_owned(),
            "destructive_testing".to_owned(),
            "state_changing_http_methods".to_owned(),
        ],
        network_activity: "none",
    };

    let preview_sha256 = workspace::sha256(&serde_json::to_vec(&identity)?);

    Ok(GuidedSetupBuild {
        preview: SetupPreview {
            identity,
            preview_sha256,
        },
        authorization_bytes,
        policy,
    })
}

fn guided_origin(input: &str) -> Result<String> {
    let parsed = Url::parse(input).context("guided target origin is not a valid URL")?;

    if parsed.port().is_some_and(|port| port != 443) {
        bail!("guided target setup supports only the exact HTTPS/443 origin boundary");
    }

    let canonical = canonical_origin(input)?;

    let canonical_url =
        Url::parse(&canonical).context("canonical guided target origin is invalid")?;

    if canonical_url.port_or_known_default() != Some(443) {
        bail!("guided target setup supports only the exact HTTPS/443 origin boundary");
    }

    Ok(canonical)
}

fn validate_setup_text(value: &str, field: &str, maximum_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("{field} must be bounded printable text without edge whitespace");
    }

    Ok(())
}

fn validate_setup_platform(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.is_ascii()
        || value.to_ascii_lowercase() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("program platform must be a bounded non-secret identifier");
    }

    Ok(())
}

fn canonical_setup_expiry(value: &str) -> Result<String> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .context("authorization expiry is not valid RFC3339")?;

    if parsed.offset().local_minus_utc() != 0 {
        bail!("authorization expiry must use UTC");
    }

    let parsed = parsed.with_timezone(&Utc);

    if parsed <= Utc::now() {
        bail!("authorization expiry must be in the future");
    }

    Ok(parsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn validate_setup_budget(
    max_requests_per_second: f64,
    max_concurrency: u16,
    max_total_requests: u64,
) -> Result<()> {
    if !max_requests_per_second.is_finite()
        || max_requests_per_second <= 0.0
        || max_requests_per_second > 5.0
    {
        bail!("guided max_requests_per_second must be finite and between 0 and 5");
    }

    if !(1..=8).contains(&max_concurrency) {
        bail!("guided max_concurrency must be between 1 and 8");
    }

    if !(1..=100_000).contains(&max_total_requests) {
        bail!("guided max_total_requests must be between 1 and 100000");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_value(
    workspace_path: &Path,
    id: &str,
    name: &str,
    origin: &str,
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
    authorization_reference: &str,
    authorization_document: &Path,
    policy_path: &Path,
) -> Result<Value> {
    let root = ready_workspace(workspace_path)?;
    let _targets = targets_directory(&root)?;

    validate_target_id(id)?;
    validate_target_name(name)?;
    validate_safe_reference(authorization_reference, "authorization reference")?;

    let _ = canonical_origin(origin)?;

    let canonical_includes = canonical_paths(include_paths.clone(), true)?;
    let canonical_excludes = canonical_paths(exclude_paths.clone(), false)?;

    validate_path_relationships(&canonical_includes, &canonical_excludes)?;

    let policy_bytes = read_bounded_source(policy_path, "target policy", MAX_POLICY_BYTES)?;

    let authorization_bytes = read_bounded_source(
        authorization_document,
        "authorization document",
        MAX_AUTHORIZATION_BYTES,
    )?;

    create_value_from_bytes(
        workspace_path,
        id,
        name,
        origin,
        include_paths,
        exclude_paths,
        authorization_reference,
        &authorization_bytes,
        &policy_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn create_value_from_bytes(
    workspace_path: &Path,
    id: &str,
    name: &str,
    origin: &str,
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
    authorization_reference: &str,
    authorization_bytes: &[u8],
    policy_bytes: &[u8],
) -> Result<Value> {
    if policy_bytes.is_empty() || policy_bytes.len() as u64 > MAX_POLICY_BYTES {
        bail!("target policy size is invalid");
    }

    if authorization_bytes.is_empty() || authorization_bytes.len() as u64 > MAX_AUTHORIZATION_BYTES
    {
        bail!("authorization document size is invalid");
    }

    let root = ready_workspace(workspace_path)?;
    let targets = targets_directory(&root)?;

    validate_target_id(id)?;
    validate_target_name(name)?;

    validate_safe_reference(authorization_reference, "authorization reference")?;

    let origin = canonical_origin(origin)?;

    let include_paths = canonical_paths(include_paths, true)?;

    let exclude_paths = canonical_paths(exclude_paths, false)?;

    validate_path_relationships(&include_paths, &exclude_paths)?;

    let policy = parse_policy(policy_bytes)?;
    let compiled = policy.clone().compile(Utc::now())?;

    let program = program_metadata(&policy)?;

    let allowed_methods = validate_policy_binding(&compiled, &origin)?;

    let mut profile = TargetProfile {
        schema_version: PROFILE_SCHEMA_VERSION,
        target_id: id.to_owned(),
        name: name.to_owned(),
        origin,
        include_paths,
        exclude_paths,
        allowed_methods,
        program,
        authorization: AuthorizationBinding {
            reference: authorization_reference.to_owned(),
            document_sha256: workspace::sha256(authorization_bytes),
        },
        policy_sha256: workspace::sha256(policy_bytes),
        identity_sha256: String::new(),
        created_at: workspace::now(),
    };

    profile.identity_sha256 = profile_identity_sha256(&profile)?;

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

fn validate_value(
    workspace_path: &Path,
    id: &str,
    authorization_document: &Path,
    policy_path: &Path,
) -> Result<Value> {
    let root = ready_workspace(workspace_path)?;
    let targets = targets_directory(&root)?;
    validate_target_id(id)?;
    let profile = read_profile(&profile_path(&targets, id))?;
    let receipt = read_optional_receipt(&disable_path(&targets, id), &profile)?;

    let policy_bytes = read_bounded_source(policy_path, "target policy", MAX_POLICY_BYTES)?;
    let authorization_bytes = read_bounded_source(
        authorization_document,
        "authorization document",
        MAX_AUTHORIZATION_BYTES,
    )?;
    if workspace::sha256(&policy_bytes) != profile.policy_sha256 {
        bail!("target policy digest does not match the immutable profile");
    }
    if workspace::sha256(&authorization_bytes) != profile.authorization.document_sha256 {
        bail!("authorization document digest does not match the immutable profile");
    }

    let policy = parse_policy(&policy_bytes)?;
    let compiled = policy.clone().compile(Utc::now())?;
    if program_metadata(&policy)? != profile.program {
        bail!("program metadata does not match the supplied target policy");
    }
    if validate_policy_binding(&compiled, &profile.origin)? != profile.allowed_methods {
        bail!("target method boundary does not match the supplied policy");
    }

    let mut value = serde_json::to_value(effective_target(profile, receipt))
        .context("could not serialize validated target")?;
    value["validation"] = serde_json::json!({
        "policy_sha256": workspace::sha256(&policy_bytes),
        "authorization_sha256": workspace::sha256(&authorization_bytes),
        "status": "valid",
    });
    Ok(value)
}

fn ready_workspace(workspace_path: &Path) -> Result<PathBuf> {
    let root = workspace::validate_workspace_root(workspace_path, true)?;
    let status = workspace::status_value(&root)?;
    if status.get("status").and_then(Value::as_str) != Some("ready") {
        bail!("workspace is not ready for target operations");
    }
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
            bail!(
                "target directory contains a non-file entry: {}",
                path.display()
            );
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

fn read_optional_receipt(path: &Path, profile: &TargetProfile) -> Result<Option<DisableReceipt>> {
    if workspace::safe_exists(path)? {
        Ok(Some(read_receipt(path, profile)?))
    } else {
        Ok(None)
    }
}

fn read_receipt(path: &Path, profile: &TargetProfile) -> Result<DisableReceipt> {
    let profile_bytes = canonical_json(profile)?;
    let receipt_bytes = workspace::read_document(path, "target disable receipt")?;
    let receipt: DisableReceipt =
        serde_json::from_slice(&receipt_bytes).context("target disable receipt is invalid JSON")?;
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
    validate_allowed_methods(&profile.allowed_methods)?;
    validate_program_metadata(&profile.program)?;
    validate_safe_reference(&profile.authorization.reference, "authorization reference")?;
    workspace::validate_sha(
        &profile.authorization.document_sha256,
        "authorization document SHA-256",
    )?;
    workspace::validate_sha(&profile.policy_sha256, "target policy SHA-256")?;
    workspace::validate_sha(&profile.identity_sha256, "target identity SHA-256")?;
    validate_time(&profile.created_at, "created_at")?;
    if profile_identity_sha256(profile)? != profile.identity_sha256 {
        bail!("target profile identity digest does not match its content");
    }
    Ok(())
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

fn parse_policy(bytes: &[u8]) -> Result<TargetPolicy> {
    let text = std::str::from_utf8(bytes).context("target policy must be UTF-8 TOML")?;
    TargetPolicy::from_toml(text).map_err(Into::into)
}

fn program_metadata(policy: &TargetPolicy) -> Result<ProgramMetadata> {
    let metadata = ProgramMetadata {
        name: policy.program.name.clone(),
        platform: policy.program.platform.clone(),
        reference: policy.program.policy_url.clone(),
    };
    validate_program_metadata(&metadata)?;
    Ok(metadata)
}

fn validate_program_metadata(metadata: &ProgramMetadata) -> Result<()> {
    validate_target_name(&metadata.name)?;
    if metadata.platform.is_empty()
        || metadata.platform.len() > 64
        || metadata.platform.to_ascii_lowercase() != metadata.platform
        || !metadata
            .platform
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("program platform must be a lowercase ASCII identifier");
    }
    if let Some(reference) = &metadata.reference {
        validate_safe_reference(reference, "program reference")?;
    }
    Ok(())
}

fn validate_policy_binding(compiled: &CompiledPolicy, origin: &str) -> Result<Vec<String>> {
    let url = Url::parse(origin).context("canonical target origin is invalid")?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("canonical target origin has no host"))?;
    if !compiled.allows_host(host) {
        bail!("target origin host is not permitted by the supplied policy");
    }
    let allowed = READ_ONLY_METHODS
        .iter()
        .filter(|method| compiled.allows_request(&url, method))
        .map(|method| (*method).to_owned())
        .collect::<Vec<_>>();
    if !allowed
        .iter()
        .any(|method| matches!(method.as_str(), "GET" | "HEAD"))
    {
        bail!("target policy does not permit GET or HEAD for the exact origin");
    }
    validate_allowed_methods(&allowed)?;
    Ok(allowed)
}

fn validate_allowed_methods(methods: &[String]) -> Result<()> {
    if methods.is_empty()
        || methods.len() > READ_ONLY_METHODS.len()
        || methods.windows(2).any(|pair| pair[0] >= pair[1])
        || methods
            .iter()
            .any(|method| !READ_ONLY_METHODS.contains(&method.as_str()))
    {
        bail!("target methods exceed the read-only product boundary or are not canonical");
    }
    Ok(())
}

fn profile_identity_sha256(profile: &TargetProfile) -> Result<String> {
    let identity = ProfileIdentity {
        schema_version: profile.schema_version,
        target_id: &profile.target_id,
        name: &profile.name,
        origin: &profile.origin,
        include_paths: &profile.include_paths,
        exclude_paths: &profile.exclude_paths,
        allowed_methods: &profile.allowed_methods,
        program: &profile.program,
        authorization: &profile.authorization,
        policy_sha256: &profile.policy_sha256,
        created_at: &profile.created_at,
    };
    Ok(workspace::sha256(&serde_json::to_vec(&identity)?))
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
    if host == "localhost" || DENIED_SUFFIXES.iter().any(|suffix| host.ends_with(suffix)) {
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
        || path.contains("//")
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
        if includes
            .iter()
            .any(|included| path_is_within(included, excluded))
        {
            bail!("an excluded path must not shadow an explicitly included prefix");
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

fn validate_safe_reference(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || !value.is_ascii()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'#')
        })
    {
        bail!("{field} must be a bounded non-secret reference without query, credentials or whitespace");
    }
    if value.starts_with("https://") {
        let url = Url::parse(value).with_context(|| format!("{field} is not a valid HTTPS URL"))?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("{field} URL must not contain credentials, query or fragment");
        }
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

fn read_bounded_source(path: &Path, label: &str, maximum: u64) -> Result<Vec<u8>> {
    workspace::reject_path_indirections(path, label)?;
    let metadata =
        fs::metadata(path).with_context(|| format!("{label} is missing: {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!("{label} size or type is invalid");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("{label} exceeds the supported size limit");
    }
    Ok(bytes)
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
        program: profile.program,
        authorization_reference: profile.authorization.reference,
        authorization_sha256: profile.authorization.document_sha256,
        policy_sha256: profile.policy_sha256,
        identity_sha256: profile.identity_sha256,
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

fn emit_setup_preview(preview: &SetupPreview, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(preview)?);
        return Ok(());
    }

    let identity = &preview.identity;

    println!("status: {}", identity.status);
    println!("target_id: {}", identity.target_id);
    println!("name: {}", identity.name);
    println!("origin: {}", identity.origin);

    println!("include_paths:");
    for path in &identity.include_paths {
        println!("  - {path}");
    }

    println!("exclude_paths:");
    if identity.exclude_paths.is_empty() {
        println!("  - (none)");
    } else {
        for path in &identity.exclude_paths {
            println!("  - {path}");
        }
    }

    println!(
        "allowed_methods: {}",
        identity.automation.allowed_methods.join(", ")
    );
    println!("allow_subdomains: {}", identity.automation.allow_subdomains);
    println!(
        "max_requests_per_second: {}",
        identity.automation.max_requests_per_second
    );
    println!("max_concurrency: {}", identity.automation.max_concurrency);
    println!(
        "max_total_requests: {}",
        identity.automation.max_total_requests
    );

    println!("active_testing: {}", identity.automation.active_testing);
    println!("oob_callbacks: {}", identity.automation.oob_callbacks);
    println!(
        "credential_bruteforce: {}",
        identity.automation.credential_bruteforce
    );
    println!(
        "destructive_testing: {}",
        identity.automation.destructive_testing
    );

    println!(
        "authorization_reference: {}",
        identity.authorization.reference
    );
    println!(
        "authorization_sha256: {}",
        identity.authorization.document_sha256
    );
    println!(
        "authorization_expires_at: {}",
        identity.authorization.expires_at
    );

    println!(
        "policy_snapshot_sha256: {}",
        identity.policy.policy_snapshot_sha256
    );
    println!(
        "policy_document_sha256: {}",
        identity.policy.policy_document_sha256
    );

    println!("hard_denied_actions:");
    for action in &identity.hard_denied_actions {
        println!("  - {action}");
    }

    println!("preview_sha256: {}", preview.preview_sha256);
    println!("network_activity: {}", identity.network_activity);

    Ok(())
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

    struct Fixture {
        root: PathBuf,
        policy: PathBuf,
        authorization: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "nxb-target-v2-{}-{}",
                std::process::id(),
                workspace::random_hex(8).unwrap()
            ));
            workspace::initialize_value(&root, "Target Test").unwrap();
            let policy = root.join("tmp").join("policy.toml");
            let authorization = root.join("tmp").join("authorization.txt");
            let policy_text = r#"schema_version = 1

[program]
name = "Example Program"
platform = "hackerone"
policy_url = "https://hackerone.com/example"

[scope]
include_hosts = ["example.org"]
exclude_hosts = []
allowed_schemes = ["https"]
allowed_methods = ["GET", "HEAD", "OPTIONS"]
allow_subdomains = false

[automation]
active_testing = false
credential_bruteforce = false
destructive_testing = false
oob_callbacks = false
max_requests_per_second = 1.0
max_concurrency = 1
max_total_requests = 10

[authorization]
confirmed = true
researcher = "test-researcher"
policy_snapshot_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
expires_at = 2099-01-01T00:00:00Z
"#;
            workspace::create_document(&policy, policy_text.as_bytes()).unwrap();
            workspace::create_document(
                &authorization,
                b"Bearer secret-that-must-never-be-persisted\n",
            )
            .unwrap();
            Self {
                root,
                policy,
                authorization,
            }
        }

        fn create(&self) -> Value {
            create_value(
                &self.root,
                "example-app",
                "Example App",
                "https://example.org",
                vec!["/api".into()],
                vec!["/api/logout".into()],
                "hackerone/program/example#scope-2026",
                &self.authorization,
                &self.policy,
            )
            .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn creates_validates_lists_shows_and_disables_target() {
        let fixture = Fixture::new();
        let created = fixture.create();
        assert_eq!(
            created.get("status").and_then(Value::as_str),
            Some("active")
        );
        assert_eq!(
            validate_value(
                &fixture.root,
                "example-app",
                &fixture.authorization,
                &fixture.policy,
            )
            .unwrap()
            .pointer("/validation/status")
            .and_then(Value::as_str),
            Some("valid")
        );
        assert_eq!(
            list_value(&fixture.root, false)
                .unwrap()
                .get("count")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            show_value(&fixture.root, "example-app")
                .unwrap()
                .get("policy_sha256")
                .and_then(Value::as_str)
                .map(str::len),
            Some(64)
        );
        let disabled =
            disable_value(&fixture.root, "example-app", DisableReason::OperatorHold).unwrap();
        assert_eq!(
            disabled.get("status").and_then(Value::as_str),
            Some("disabled")
        );
    }

    #[test]
    fn secret_source_bytes_and_paths_are_not_persisted() {
        let fixture = Fixture::new();
        fixture.create();
        let text =
            fs::read_to_string(fixture.root.join("targets").join("example-app.json")).unwrap();
        assert!(!text.contains("Bearer"));
        assert!(!text.contains("secret-that-must-never-be-persisted"));
        assert!(!text.contains(fixture.policy.to_string_lossy().as_ref()));
        assert!(!text.contains(fixture.authorization.to_string_lossy().as_ref()));
    }

    #[test]
    fn rejects_unsafe_origin_path_reference_and_policy_scope() {
        let fixture = Fixture::new();
        assert!(create_value(
            &fixture.root,
            "unsafe-origin",
            "Unsafe",
            "https://user@example.org",
            vec!["/".into()],
            Vec::new(),
            "hackerone/program/example#scope-2026",
            &fixture.authorization,
            &fixture.policy,
        )
        .is_err());
        assert!(create_value(
            &fixture.root,
            "unsafe-path",
            "Unsafe",
            "https://example.org",
            vec!["/api%2fadmin".into()],
            Vec::new(),
            "hackerone/program/example#scope-2026",
            &fixture.authorization,
            &fixture.policy,
        )
        .is_err());
        assert!(create_value(
            &fixture.root,
            "unsafe-reference",
            "Unsafe",
            "https://example.org",
            vec!["/".into()],
            Vec::new(),
            "https://example.org/scope?token=secret",
            &fixture.authorization,
            &fixture.policy,
        )
        .is_err());
        assert!(create_value(
            &fixture.root,
            "outside-policy",
            "Unsafe",
            "https://other.example.org",
            vec!["/".into()],
            Vec::new(),
            "hackerone/program/example#scope-2026",
            &fixture.authorization,
            &fixture.policy,
        )
        .is_err());
    }

    #[test]
    fn active_profile_tamper_is_rejected_by_identity_digest() {
        let fixture = Fixture::new();
        fixture.create();
        let path = fixture.root.join("targets").join("example-app.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["name"] = Value::String("Tampered Name".into());
        let mut bytes = serde_json::to_vec_pretty(&value).unwrap();
        bytes.push(b'\n');
        workspace::replace_document(&path, &bytes).unwrap();
        assert!(show_value(&fixture.root, "example-app").is_err());
    }

    #[test]
    fn source_digest_drift_is_rejected() {
        let fixture = Fixture::new();
        fixture.create();
        workspace::replace_document(&fixture.authorization, b"different authorization\n").unwrap();
        assert!(validate_value(
            &fixture.root,
            "example-app",
            &fixture.authorization,
            &fixture.policy,
        )
        .is_err());
    }

    #[test]
    fn pending_migration_blocks_target_operations() {
        let fixture = Fixture::new();
        workspace::create_document(
            &fixture.root.join("state").join("migration-active.json"),
            b"{}\n",
        )
        .unwrap();
        assert!(list_value(&fixture.root, false).is_err());
    }
}
