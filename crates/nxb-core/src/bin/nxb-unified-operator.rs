#![forbid(unsafe_code)]

#[path = "../live_orchestrator.rs"]
#[allow(dead_code, unused_imports)]
mod live_orchestrator;

#[path = "../discovery_session.rs"]
#[allow(dead_code)]
mod discovery_session;

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use discovery_session::DiscoverySessionPlan;
use nxb_session_injection::SessionInjectionManifest;
use nxb_unified_operator::{
    consume_activation_once, UnifiedComponentBinding, UnifiedOperatorActivationCertificate,
    UnifiedOperatorActivationPayload, UnifiedOperatorPlan, UnifiedOperatorPlanParameters,
};
use nxb_vault_provider::{
    ExternalVaultBootstrapReceipt, ExternalVaultSessionPlan, ProviderDeliverySpec,
};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

const MAX_UNIFIED_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_UNIFIED_KEY_FILE_BYTES: u64 = 4 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "nxb-unified-operator",
    version,
    about = "Networkless NXB-141 unified operator artifact binder"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify NXB-137/138/139 artifacts and emit one signed-activation-ready plan.
    Plan {
        #[arg(long)]
        discovery_plan: PathBuf,
        #[arg(long)]
        injection_manifest: PathBuf,
        #[arg(long)]
        external_vault_plan: PathBuf,
        #[arg(long)]
        external_vault_receipt: PathBuf,
        #[arg(long)]
        activation_public_key: PathBuf,
        #[arg(long)]
        operator_id: String,
        #[arg(long, default_value_t = 4)]
        checkpoint_interval_requests: u64,
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        maximum_workspace_bytes: u64,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    /// Verify one unified operator plan without consuming activation state.
    VerifyPlan {
        path: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    /// Emit canonical payload bytes for external Ed25519 signing.
    ActivationTemplate {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        activation_id: String,
        #[arg(long)]
        not_before: String,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    /// Verify one externally signed unified activation certificate.
    VerifyActivation {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        activation: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    /// Atomically consume a verified activation without performing network activity.
    ConsumeActivation {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        activation: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        state_directory: PathBuf,
        #[arg(long)]
        confirm_consume: bool,
        #[arg(long)]
        now: Option<String>,
    },
}

#[derive(Debug, Serialize)]
struct ActivationTemplateDocument {
    payload: UnifiedOperatorActivationPayload,
    signing_payload_hex: String,
    signing_payload_sha256: String,
    signature_hex: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Plan {
            discovery_plan,
            injection_manifest,
            external_vault_plan,
            external_vault_receipt,
            activation_public_key,
            operator_id,
            checkpoint_interval_requests,
            maximum_workspace_bytes,
            expires_at,
            output,
            now,
        } => build_unified_plan(
            &discovery_plan,
            &injection_manifest,
            &external_vault_plan,
            &external_vault_receipt,
            &activation_public_key,
            operator_id,
            checkpoint_interval_requests,
            maximum_workspace_bytes,
            parse_timestamp(&expires_at)?,
            &output,
            parse_now(now)?,
        ),
        Command::VerifyPlan { path, now } => {
            let plan: UnifiedOperatorPlan = read_json(&path)?;
            plan.verify(parse_now(now)?.timestamp())?;
            println!("unified_operator_plan: valid");
            println!("plan_sha256: {}", plan.plan_sha256);
            println!("binding_sha256: {}", plan.binding_sha256);
            println!("network_activity: none");
            Ok(())
        }
        Command::ActivationTemplate {
            plan,
            activation_id,
            not_before,
            expires_at,
            output,
            now,
        } => activation_template(
            &plan,
            activation_id,
            parse_timestamp(&not_before)?,
            parse_timestamp(&expires_at)?,
            &output,
            parse_now(now)?,
        ),
        Command::VerifyActivation {
            plan,
            activation,
            public_key,
            now,
        } => verify_activation(&plan, &activation, &public_key, parse_now(now)?),
        Command::ConsumeActivation {
            plan,
            activation,
            public_key,
            state_directory,
            confirm_consume,
            now,
        } => consume_activation(
            &plan,
            &activation,
            &public_key,
            &state_directory,
            confirm_consume,
            parse_now(now)?,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_unified_plan(
    discovery_plan_path: &Path,
    injection_manifest_path: &Path,
    external_vault_plan_path: &Path,
    external_vault_receipt_path: &Path,
    activation_public_key_path: &Path,
    operator_id: String,
    checkpoint_interval_requests: u64,
    maximum_workspace_bytes: u64,
    expires_at: DateTime<Utc>,
    output: &Path,
    now: DateTime<Utc>,
) -> Result<()> {
    let discovery: DiscoverySessionPlan = read_json(discovery_plan_path)?;
    let injection: SessionInjectionManifest = read_json(injection_manifest_path)?;
    let external: ExternalVaultSessionPlan = read_json(external_vault_plan_path)?;
    let receipt: ExternalVaultBootstrapReceipt = read_json(external_vault_receipt_path)?;
    let now_epoch_seconds = now.timestamp();

    discovery.verify(now)?;
    injection.verify(now_epoch_seconds)?;
    external.validate()?;
    if external.plan_sha256 != external.calculate_sha256()? {
        bail!("external-vault plan digest mismatch");
    }
    receipt.verify()?;
    verify_external_lifecycle(&external, &receipt, now_epoch_seconds)?;
    verify_component_bindings(&discovery, &injection, &external, &receipt)?;

    let activation_public_key = read_lower_hex_file(activation_public_key_path)?;
    if activation_public_key.len() != 32 {
        bail!("unified activation public key must contain 32 Ed25519 bytes");
    }
    let allowed_path_prefixes = verified_authenticated_paths(&discovery, &injection)?;
    let component_expires_at_epoch_seconds = [
        discovery.expires_at_epoch_seconds,
        injection.expires_at_epoch_seconds,
        external.session_expires_at_epoch_seconds,
    ]
    .into_iter()
    .min()
    .context("component expiration set is empty")?;

    let binding = UnifiedComponentBinding {
        discovery_plan_sha256: discovery.plan_sha256.clone(),
        policy_sha256: discovery.policy_sha256.clone(),
        target_origin_sha256: discovery.target_origin_sha256.clone(),
        discovery_session_id: discovery.session_id.clone(),
        authority: injection.authority.clone(),
        run_id: injection.run_id.clone(),
        worker_id: injection.worker_id.clone(),
        account_id: injection.account_id.clone(),
        tenant_id: injection.tenant_id.clone(),
        role_id: injection.role_id.clone(),
        session_injection_manifest_sha256: injection.manifest_sha256.clone(),
        external_vault_plan_sha256: external.plan_sha256.clone(),
        external_vault_bootstrap_receipt_sha256: receipt.receipt_sha256.clone(),
        external_session_id_sha256: receipt.session_id_sha256.clone(),
        provider_id: receipt.provider_id.clone(),
        provider_instance_sha256: receipt.provider_instance_sha256.clone(),
        provider_capability_sha256: receipt.capability_sha256.clone(),
        secret_binding_root_sha256: receipt.secret_binding_root_sha256.clone(),
        secret_count: receipt.secret_count,
        allowed_path_prefixes,
        maximum_requests: discovery.maximum_requests,
        maximum_depth: discovery.maximum_depth,
        maximum_response_body_bytes: discovery.maximum_response_body_bytes,
        maximum_total_response_bytes: discovery.maximum_total_response_bytes,
        minimum_request_interval_milliseconds: discovery.minimum_request_interval_milliseconds,
        maximum_concurrency: discovery.maximum_concurrency,
        component_expires_at_epoch_seconds,
    };
    let plan = UnifiedOperatorPlan::build(UnifiedOperatorPlanParameters {
        operator_id,
        binding,
        checkpoint_interval_requests,
        maximum_workspace_bytes,
        created_at_epoch_seconds: now_epoch_seconds,
        expires_at_epoch_seconds: expires_at.timestamp(),
        activation_public_key,
    })?;
    plan.verify(now_epoch_seconds)?;
    write_json(output, &plan)?;

    println!("unified_operator_plan: valid");
    println!("plan_sha256: {}", plan.plan_sha256);
    println!("binding_sha256: {}", plan.binding_sha256);
    println!("maximum_requests: {}", plan.binding.maximum_requests);
    println!("secret_count: {}", plan.binding.secret_count);
    println!("network_activity: none");
    println!("output: {}", output.display());
    Ok(())
}

fn verify_external_lifecycle(
    plan: &ExternalVaultSessionPlan,
    receipt: &ExternalVaultBootstrapReceipt,
    now_epoch_seconds: i64,
) -> Result<()> {
    if now_epoch_seconds < plan.created_at_epoch_seconds
        || now_epoch_seconds > plan.session_expires_at_epoch_seconds
    {
        bail!("external vault session is outside its active window");
    }
    if receipt.completed_at_epoch_seconds < plan.created_at_epoch_seconds
        || receipt.completed_at_epoch_seconds > plan.expires_at_epoch_seconds
        || receipt.completed_at_epoch_seconds > now_epoch_seconds
    {
        bail!("external vault bootstrap receipt time is invalid");
    }
    if receipt.plan_sha256 != plan.plan_sha256
        || receipt.discovery_plan_sha256 != plan.discovery_plan_sha256
        || receipt.target_origin_sha256 != plan.target_origin_sha256
        || receipt.provider_id != plan.provider.provider_id
        || receipt.provider_instance_sha256 != plan.provider.provider_instance_sha256
        || receipt.capability_sha256 != plan.provider.capability_sha256
        || receipt.secret_count as usize != plan.secrets.len()
    {
        bail!("external vault receipt does not match its signed plan");
    }
    Ok(())
}

fn verify_component_bindings(
    discovery: &DiscoverySessionPlan,
    injection: &SessionInjectionManifest,
    external: &ExternalVaultSessionPlan,
    receipt: &ExternalVaultBootstrapReceipt,
) -> Result<()> {
    if injection.discovery_plan_sha256 != discovery.plan_sha256
        || external.discovery_plan_sha256 != discovery.plan_sha256
        || injection.target_origin_sha256 != discovery.target_origin_sha256
        || external.target_origin_sha256 != discovery.target_origin_sha256
        || receipt.discovery_plan_sha256 != discovery.plan_sha256
        || receipt.target_origin_sha256 != discovery.target_origin_sha256
    {
        bail!("component discovery or target-origin bindings do not match");
    }
    if injection.authority != external.authority {
        bail!("session injection and external vault authorities do not match");
    }
    for (left, right, field) in [
        (&injection.run_id, &external.run_id, "run_id"),
        (&injection.worker_id, &external.worker_id, "worker_id"),
        (&injection.account_id, &external.account_id, "account_id"),
        (&injection.tenant_id, &external.tenant_id, "tenant_id"),
        (&injection.role_id, &external.role_id, "role_id"),
    ] {
        if left != right {
            bail!("component account partition mismatch: {field}");
        }
    }
    if sha256_bytes(injection.session_id.as_bytes()) != receipt.session_id_sha256 {
        bail!("session injection does not reference the provisioned external session");
    }

    let manifest_handles = injection
        .bootstrap_secret_handles
        .iter()
        .map(|handle| sha256_bytes(handle.as_str().as_bytes()))
        .collect::<BTreeSet<_>>();
    let receipt_handles = receipt
        .provisioned_secrets
        .iter()
        .map(|secret| secret.vault_handle_sha256.clone())
        .collect::<BTreeSet<_>>();
    if manifest_handles != receipt_handles
        || manifest_handles.len() != injection.bootstrap_secret_handles.len()
        || manifest_handles.len() != receipt.secret_count as usize
    {
        bail!("session injection secret handles do not match the provider receipt");
    }

    for secret in &external.secrets {
        match &secret.delivery {
            ProviderDeliverySpec::Header { name, .. } => {
                if !injection.allowed_header_names.contains(name) {
                    bail!("provider header delivery is outside the injection allowlist");
                }
            }
            ProviderDeliverySpec::Cookie { cookie } => {
                if !injection.allowed_cookie_names.contains(&cookie.name) {
                    bail!("provider cookie delivery is outside the injection allowlist");
                }
            }
        }
    }
    if injection.created_at_epoch_seconds < receipt.completed_at_epoch_seconds
        || injection.expires_at_epoch_seconds > external.session_expires_at_epoch_seconds
    {
        bail!("session injection lifetime is outside the provisioned session lifetime");
    }
    Ok(())
}

fn verified_authenticated_paths(
    discovery: &DiscoverySessionPlan,
    injection: &SessionInjectionManifest,
) -> Result<BTreeSet<String>> {
    for path in &injection.allowed_path_prefixes {
        if !discovery
            .allowed_path_prefixes
            .iter()
            .any(|prefix| path_matches_prefix(path, prefix))
        {
            bail!("session injection path scope widens the discovery-session scope");
        }
    }
    Ok(injection.allowed_path_prefixes.clone())
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn activation_template(
    plan_path: &Path,
    activation_id: String,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    output: &Path,
    now: DateTime<Utc>,
) -> Result<()> {
    let plan: UnifiedOperatorPlan = read_json(plan_path)?;
    plan.verify(now.timestamp())?;
    let payload = UnifiedOperatorActivationPayload::template(
        activation_id,
        &plan,
        not_before.timestamp(),
        expires_at.timestamp(),
    )?;
    let signing_bytes = payload.signing_bytes()?;
    let document = ActivationTemplateDocument {
        signing_payload_hex: lower_hex(&signing_bytes),
        signing_payload_sha256: sha256_bytes(&signing_bytes),
        payload,
        signature_hex: String::new(),
    };
    write_json(output, &document)?;
    println!("unified_operator_activation_template: valid");
    println!(
        "signing_payload_sha256: {}",
        document.signing_payload_sha256
    );
    println!("network_activity: none");
    println!("output: {}", output.display());
    Ok(())
}

fn verify_activation(
    plan_path: &Path,
    activation_path: &Path,
    public_key_path: &Path,
    now: DateTime<Utc>,
) -> Result<()> {
    let plan: UnifiedOperatorPlan = read_json(plan_path)?;
    let certificate: UnifiedOperatorActivationCertificate = read_json(activation_path)?;
    let public_key = read_lower_hex_file(public_key_path)?;
    certificate.verify(&plan, &public_key, now.timestamp())?;
    println!("unified_operator_activation: valid");
    println!(
        "activation_certificate_sha256: {}",
        certificate.certificate_sha256()?
    );
    println!("network_activity: none");
    Ok(())
}

fn consume_activation(
    plan_path: &Path,
    activation_path: &Path,
    public_key_path: &Path,
    state_directory: &Path,
    confirm_consume: bool,
    now: DateTime<Utc>,
) -> Result<()> {
    if !confirm_consume {
        bail!("activation consumption requires --confirm-consume");
    }
    let plan: UnifiedOperatorPlan = read_json(plan_path)?;
    let certificate: UnifiedOperatorActivationCertificate = read_json(activation_path)?;
    let public_key = read_lower_hex_file(public_key_path)?;
    let consumed = consume_activation_once(
        state_directory,
        &plan,
        &certificate,
        &public_key,
        now.timestamp(),
    )?;
    println!("unified_operator_activation: consumed");
    println!("plan_sha256: {}", consumed.plan_sha256());
    println!("binding_sha256: {}", consumed.binding_sha256());
    println!(
        "activation_certificate_sha256: {}",
        consumed.activation_certificate_sha256()
    );
    println!("network_activity: none");
    println!("marker: {}", consumed.marker_path().display());
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = read_bounded_file(path, MAX_UNIFIED_ARTIFACT_BYTES)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("could not parse JSON {}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("could not create {}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("output path must end in a UTF-8 file name")?;
    if path.exists() {
        bail!("refusing to overwrite existing output {}", path.display());
    }
    let bytes = serde_json::to_vec_pretty(value).context("could not serialize JSON output")?;
    let temporary_path = parent.join(format!(".{file_name}.{}.nxb.tmp", std::process::id()));
    let publication = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .with_context(|| format!("could not create {}", temporary_path.display()))?;
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .with_context(|| format!("could not synchronize {}", temporary_path.display()))?;
        fs::hard_link(&temporary_path, path)
            .with_context(|| format!("could not atomically publish {}", path.display()))?;
        Ok(())
    })();
    if let Err(error) = publication {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    let _ = fs::remove_file(&temporary_path);
    Ok(())
}

fn read_lower_hex_file(path: &Path) -> Result<Vec<u8>> {
    let bytes = read_bounded_file(path, MAX_UNIFIED_KEY_FILE_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("hex file is not UTF-8: {}", path.display()))?;
    decode_lower_hex(text.trim())
}

fn read_bounded_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum_bytes {
        bail!(
            "input file is not a bounded regular file: {}",
            path.display()
        );
    }
    let expected_bytes = metadata.len();
    let capacity =
        usize::try_from(expected_bytes).context("input size does not fit memory index")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read {}", path.display()))?;
    if bytes.len() as u64 != expected_bytes {
        bail!("input file changed while being read: {}", path.display());
    }
    Ok(bytes)
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("hex input must be non-empty lower hexadecimal bytes");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).context("invalid hexadecimal byte")?;
            let low = hex_nibble(pair[1]).context("invalid hexadecimal byte")?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
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

fn sha256_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
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

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::json;

    use super::{path_matches_prefix, read_json, write_json, MAX_UNIFIED_ARTIFACT_BYTES};

    #[test]
    fn authenticated_prefix_must_not_widen_discovery_scope() {
        assert!(path_matches_prefix("/app/admin", "/app"));
        assert!(path_matches_prefix("/app", "/app"));
        assert!(!path_matches_prefix("/application", "/app"));
        assert!(!path_matches_prefix("/", "/app"));
    }

    #[test]
    fn oversized_artifact_is_rejected_before_parsing() {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let directory = std::env::temp_dir().join(format!(
            "nxb141-unified-input-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        let input = directory.join("oversized.json");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&input)
            .unwrap();
        file.set_len(MAX_UNIFIED_ARTIFACT_BYTES + 1).unwrap();
        assert!(read_json::<serde_json::Value>(&input).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn artifact_publication_is_complete_and_no_clobber() {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let directory = std::env::temp_dir().join(format!(
            "nxb141-unified-output-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        let output = directory.join("plan.json");
        write_json(&output, &json!({"version": 1, "state": "ready"})).unwrap();
        let bytes = fs::read(&output).unwrap();
        assert!(bytes.ends_with(b"\n"));
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["state"], "ready");
        assert!(write_json(&output, &json!({"state": "replaced"})).is_err());
        let unchanged: serde_json::Value =
            serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        assert_eq!(unchanged["state"], "ready");
        fs::remove_dir_all(directory).unwrap();
    }
}
