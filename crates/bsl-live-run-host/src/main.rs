#![forbid(unsafe_code)]

use std::{
    fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use nxb_live_adapter::LiveAdapterConfig;
use nxb_live_run_host::{
    consume_launch_activation_once, LiveRunLaunchActivationCertificate,
    LiveRunLaunchActivationPayload, LiveRunLaunchBundle, LiveRunLaunchBundleParameters,
};
use nxb_operator::OperatorConfig;
use nxb_policy::TargetPolicy;
use nxb_resumable_runner::RunnerManifest;
use nxb_session_injection::SessionInjectionManifest;
use nxb_unified_operator::UnifiedOperatorPlan;
use nxb_vault_provider::{ExternalVaultBootstrapReceipt, ExternalVaultSessionPlan};
use serde::{de::DeserializeOwned, Serialize};

const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_KEY_HEX_BYTES: usize = 4 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "nxb-live-run-host",
    version,
    about = "NXB-145 signed live-run launch control plane"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    BuildBundle {
        #[command(flatten)]
        artifacts: ArtifactArgs,
        #[arg(long)]
        launch_id: String,
        #[arg(long)]
        dns_resolver_id: String,
        #[arg(long, default_value_t = 8)]
        maximum_dns_addresses: u16,
        #[arg(long, default_value_t = 300)]
        maximum_dns_ttl_seconds: u32,
        #[arg(long)]
        signer_public_key_hex: String,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    VerifyBundle {
        #[command(flatten)]
        artifacts: ArtifactArgs,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    ActivationTemplate {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        activation_id: String,
        #[arg(long)]
        not_before: String,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        output: PathBuf,
    },
    VerifyActivation {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        activation: PathBuf,
        #[arg(long)]
        public_key_hex: String,
        #[arg(long)]
        now: Option<String>,
    },
    ConsumeActivation {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        activation: PathBuf,
        #[arg(long)]
        public_key_hex: String,
        #[arg(long)]
        state_directory: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
}

#[derive(Debug, clap::Args)]
struct ArtifactArgs {
    #[arg(long)]
    unified_plan: PathBuf,
    #[arg(long)]
    runner_manifest: PathBuf,
    #[arg(long)]
    external_vault_plan: PathBuf,
    #[arg(long)]
    external_bootstrap_receipt: PathBuf,
    #[arg(long)]
    injection_manifest: PathBuf,
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    operator_config: PathBuf,
    #[arg(long)]
    adapter_config: PathBuf,
}

struct Artifacts {
    unified_plan: UnifiedOperatorPlan,
    runner_manifest: RunnerManifest,
    external_vault_plan: ExternalVaultSessionPlan,
    external_bootstrap_receipt: ExternalVaultBootstrapReceipt,
    injection_manifest: SessionInjectionManifest,
    policy: nxb_policy::CompiledPolicy,
    operator_config: OperatorConfig,
    adapter_config: LiveAdapterConfig,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::BuildBundle {
            artifacts,
            launch_id,
            dns_resolver_id,
            maximum_dns_addresses,
            maximum_dns_ttl_seconds,
            signer_public_key_hex,
            expires_at,
            output,
            now,
        } => {
            let now = parse_now(now)?;
            let artifacts = read_artifacts(artifacts, now)?;
            let bundle = LiveRunLaunchBundle::build(
                LiveRunLaunchBundleParameters {
                    launch_id,
                    dns_resolver_id,
                    maximum_dns_addresses,
                    maximum_dns_ttl_seconds,
                    created_at_epoch_seconds: now.timestamp(),
                    expires_at_epoch_seconds: parse_timestamp(&expires_at)?.timestamp(),
                    signer_public_key: decode_key(&signer_public_key_hex)?,
                },
                &artifacts.unified_plan,
                &artifacts.runner_manifest,
                &artifacts.external_vault_plan,
                &artifacts.external_bootstrap_receipt,
                &artifacts.injection_manifest,
                &artifacts.policy,
                &artifacts.operator_config,
                &artifacts.adapter_config,
            )?;
            write_json(&output, &bundle)?;
            println!("live_run_launch_bundle: valid");
            println!("bundle_sha256: {}", bundle.bundle_sha256);
            println!("network_activity: none");
            println!("output: {}", output.display());
            Ok(())
        }
        Command::VerifyBundle {
            artifacts,
            bundle,
            now,
        } => {
            let now = parse_now(now)?;
            let artifacts = read_artifacts(artifacts, now)?;
            let bundle: LiveRunLaunchBundle = read_json(&bundle)?;
            bundle.verify_artifacts(
                &artifacts.unified_plan,
                &artifacts.runner_manifest,
                &artifacts.external_vault_plan,
                &artifacts.external_bootstrap_receipt,
                &artifacts.injection_manifest,
                &artifacts.policy,
                &artifacts.operator_config,
                &artifacts.adapter_config,
                now.timestamp(),
            )?;
            println!("live_run_launch_bundle: valid");
            println!("bundle_sha256: {}", bundle.bundle_sha256);
            println!("network_activity: none");
            Ok(())
        }
        Command::ActivationTemplate {
            bundle,
            activation_id,
            not_before,
            expires_at,
            output,
        } => {
            let bundle: LiveRunLaunchBundle = read_json(&bundle)?;
            let payload = LiveRunLaunchActivationPayload::template(
                activation_id,
                &bundle,
                parse_timestamp(&not_before)?.timestamp(),
                parse_timestamp(&expires_at)?.timestamp(),
            )?;
            write_json(&output, &payload)?;
            println!("live_run_activation_template: valid");
            println!("network_activity: none");
            println!("output: {}", output.display());
            Ok(())
        }
        Command::VerifyActivation {
            bundle,
            activation,
            public_key_hex,
            now,
        } => {
            let bundle: LiveRunLaunchBundle = read_json(&bundle)?;
            let activation: LiveRunLaunchActivationCertificate = read_json(&activation)?;
            activation.verify(
                &bundle,
                &decode_key(&public_key_hex)?,
                parse_now(now)?.timestamp(),
            )?;
            println!("live_run_activation: valid");
            println!("network_activity: none");
            Ok(())
        }
        Command::ConsumeActivation {
            bundle,
            activation,
            public_key_hex,
            state_directory,
            now,
        } => {
            let bundle: LiveRunLaunchBundle = read_json(&bundle)?;
            let activation: LiveRunLaunchActivationCertificate = read_json(&activation)?;
            let consumed = consume_launch_activation_once(
                &state_directory,
                &bundle,
                &activation,
                &decode_key(&public_key_hex)?,
                parse_now(now)?.timestamp(),
            )?;
            println!("live_run_activation: consumed");
            println!(
                "activation_certificate_sha256: {}",
                consumed.activation_certificate_sha256()
            );
            println!("marker: {}", consumed.marker_path().display());
            println!("network_activity: none");
            Ok(())
        }
    }
}

fn read_artifacts(arguments: ArtifactArgs, now: DateTime<Utc>) -> Result<Artifacts> {
    let policy_text = read_text(&arguments.policy)?;
    let policy = TargetPolicy::from_toml(&policy_text)?.compile(now)?;
    Ok(Artifacts {
        unified_plan: read_json(&arguments.unified_plan)?,
        runner_manifest: read_json(&arguments.runner_manifest)?,
        external_vault_plan: read_json(&arguments.external_vault_plan)?,
        external_bootstrap_receipt: read_json(&arguments.external_bootstrap_receipt)?,
        injection_manifest: read_json(&arguments.injection_manifest)?,
        policy,
        operator_config: read_json(&arguments.operator_config)?,
        adapter_config: read_json(&arguments.adapter_config)?,
    })
}

fn parse_now(value: Option<String>) -> Result<DateTime<Utc>> {
    match value {
        Some(value) => parse_timestamp(&value),
        None => Ok(Utc::now()),
    }
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid RFC3339 timestamp: {value}"))
        .map(|value| value.with_timezone(&Utc))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = read_bytes(path)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("could not parse JSON artifact {}", path.display()))
}

fn read_text(path: &Path) -> Result<String> {
    String::from_utf8(read_bytes(path)?)
        .with_context(|| format!("artifact is not UTF-8: {}", path.display()))
}

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("could not stat {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_ARTIFACT_BYTES {
        bail!("artifact is not a bounded regular file: {}", path.display());
    }
    fs::read(path).with_context(|| format!("could not read {}", path.display()))
}

fn decode_key(value: &str) -> Result<Vec<u8>> {
    if value.len() > MAX_KEY_HEX_BYTES
        || value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("public key must be exactly 32 bytes of lowercase hex");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = nibble(pair[0]).context("invalid public-key hex")?;
            let low = nibble(pair[1]).context("invalid public-key hex")?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(value).context("could not serialize artifact")?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        bail!("serialized artifact exceeds its byte bound");
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("could not create {}", temporary.display()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("could not write {}", temporary.display()))?;
    fs::hard_link(&temporary, path)
        .with_context(|| format!("could not publish {} without clobbering", path.display()))?;
    fs::remove_file(&temporary)
        .with_context(|| format!("could not remove {}", temporary.display()))?;
    Ok(())
}
