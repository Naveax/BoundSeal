#[path = "../live_orchestrator.rs"]
#[allow(dead_code, unused_imports)]
mod live_orchestrator;

#[path = "../discovery_session.rs"]
mod discovery_session;

use std::{collections::BTreeSet, fs, net::IpAddr, path::PathBuf};

#[cfg(feature = "live-network")]
use std::{
    collections::BTreeMap,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use discovery_session::{
    hash_bytes, lower_hex, validate_request_interval_against_policy,
    DiscoverySessionActivationCertificate, DiscoverySessionActivationPayload, DiscoverySessionPlan,
};
#[cfg(feature = "live-network")]
use discovery_session::{hash_serializable, method_from_code};
use live_orchestrator::{read_hex_file, read_json, write_json, PlannedMethod};
use bsl_policy::{CompiledPolicy, TargetPolicy};
use serde::Serialize;
use url::Url;

#[cfg(feature = "live-network")]
use discovery_session::consume_activation_once;
#[cfg(feature = "live-network")]
use live_orchestrator::{execute_discovery_session_request, DiscoverySessionRequestSpec};
#[cfg(feature = "live-network")]
use bsl_operator::{
    discover_response, write_report_bundle, CoverageSummary, DiscoveryCandidate,
    DiscoveryScheduler, OperatorConfig, OperatorFinding, OperatorReport, ReportBundle,
    SchedulerReceipt, StopReason,
};
#[cfg(feature = "live-network")]
use bsl_passive_analyzers::Finding;

#[derive(Debug, Parser)]
#[command(
    name = "bsl-discovery-session",
    version,
    about = "Signed bounded passive discovery-session utilities"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build a networkless signed-session plan.
    Plan {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        seed: String,
        #[arg(long, value_enum)]
        seed_method: PlannedMethod,
        #[arg(long)]
        selected_ip: IpAddr,
        #[arg(long = "resolved-ip", required = true)]
        resolved_ips: Vec<IpAddr>,
        #[arg(long = "allow-method", value_enum, required = true)]
        allowed_methods: Vec<PlannedMethod>,
        #[arg(long = "allow-path-prefix", required = true)]
        allowed_path_prefixes: Vec<String>,
        #[arg(long)]
        dns_context_id: String,
        #[arg(long)]
        dns_resolver_id: String,
        #[arg(long, default_value_t = 60)]
        dns_ttl_seconds: u32,
        #[arg(long, default_value_t = 16)]
        maximum_requests: u64,
        #[arg(long, default_value_t = 2)]
        maximum_depth: u16,
        #[arg(long, default_value_t = 2 * 1024 * 1024)]
        maximum_response_body_bytes: u64,
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        maximum_total_response_bytes: u64,
        #[arg(long, default_value_t = 1000)]
        minimum_request_interval_milliseconds: u64,
        #[arg(long)]
        activation_public_key: PathBuf,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    /// Verify a networkless discovery-session plan.
    VerifyPlan {
        path: PathBuf,
        #[arg(long)]
        now: Option<String>,
    },
    /// Emit canonical bytes for external Ed25519 signing.
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
    },
    /// Verify an externally signed discovery-session activation.
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
    /// Execute a signed bounded passive discovery session.
    #[cfg(feature = "live-network")]
    Run {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        activation: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        state_directory: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = "target/bsl-discovery-session")]
        output_directory: PathBuf,
        #[arg(long)]
        enable_live: bool,
        #[arg(long)]
        now: Option<String>,
    },
}

#[derive(Debug, Serialize)]
struct ActivationTemplateDocument {
    payload: DiscoverySessionActivationPayload,
    signing_payload_hex: String,
    signing_payload_sha256: String,
    signature_hex: String,
}

#[cfg(feature = "live-network")]
#[derive(Debug, Clone, Serialize)]
struct SessionRequestReceipt {
    sequence: u64,
    endpoint_sha256: String,
    method: String,
    depth: u16,
    response_status: u16,
    response_body_bytes: u64,
    response_body_sha256: String,
    live_receipt_sha256: String,
    redirect_observed: bool,
    finding_ids: Vec<String>,
    previous_receipt_sha256: String,
    receipt_sha256: String,
}

#[cfg(feature = "live-network")]
#[derive(Debug, Serialize)]
struct DiscoverySessionReceipt {
    version: u32,
    mode: String,
    session_id: String,
    plan_sha256: String,
    activation_certificate_sha256: String,
    policy_sha256: String,
    target_origin_sha256: String,
    selected_ip: String,
    request_budget: u64,
    response_byte_budget: u64,
    requests_issued: u64,
    total_response_bytes: u64,
    discovered_candidates: u64,
    passive_finding_count: u64,
    stop_reason: String,
    scheduler: SchedulerReceipt,
    coverage: CoverageSummary,
    request_receipts: Vec<SessionRequestReceipt>,
    request_receipt_chain_tail_sha256: String,
    report_sha256: String,
    export_manifest_sha256: String,
    body_retention: String,
    redirects_followed: bool,
    session_material_used: bool,
    active_probes_executed: bool,
    automatic_submission: bool,
    crash_recovery: String,
    completed_at_epoch_seconds: i64,
    receipt_sha256: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Plan {
            policy,
            seed,
            seed_method,
            selected_ip,
            resolved_ips,
            allowed_methods,
            allowed_path_prefixes,
            dns_context_id,
            dns_resolver_id,
            dns_ttl_seconds,
            maximum_requests,
            maximum_depth,
            maximum_response_body_bytes,
            maximum_total_response_bytes,
            minimum_request_interval_milliseconds,
            activation_public_key,
            session_id,
            expires_at,
            output,
            now,
        } => build_plan(
            policy,
            seed,
            seed_method,
            selected_ip,
            resolved_ips,
            allowed_methods,
            allowed_path_prefixes,
            dns_context_id,
            dns_resolver_id,
            dns_ttl_seconds,
            maximum_requests,
            maximum_depth,
            maximum_response_body_bytes,
            maximum_total_response_bytes,
            minimum_request_interval_milliseconds,
            activation_public_key,
            session_id,
            expires_at,
            output,
            now,
        ),
        Command::VerifyPlan { path, now } => verify_plan(path, now),
        Command::ActivationTemplate {
            plan,
            activation_id,
            not_before,
            expires_at,
            output,
        } => activation_template(plan, activation_id, not_before, expires_at, output),
        Command::VerifyActivation {
            plan,
            activation,
            public_key,
            now,
        } => verify_activation(plan, activation, public_key, now),
        #[cfg(feature = "live-network")]
        Command::Run {
            policy,
            plan,
            activation,
            public_key,
            state_directory,
            config,
            output_directory,
            enable_live,
            now,
        } => run_live_session(
            policy,
            plan,
            activation,
            public_key,
            state_directory,
            config,
            output_directory,
            enable_live,
            now,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_plan(
    policy_path: PathBuf,
    seed: String,
    seed_method: PlannedMethod,
    selected_ip: IpAddr,
    resolved_ips: Vec<IpAddr>,
    allowed_methods: Vec<PlannedMethod>,
    allowed_path_prefixes: Vec<String>,
    dns_context_id: String,
    dns_resolver_id: String,
    dns_ttl_seconds: u32,
    maximum_requests: u64,
    maximum_depth: u16,
    maximum_response_body_bytes: u64,
    maximum_total_response_bytes: u64,
    minimum_request_interval_milliseconds: u64,
    activation_public_key: PathBuf,
    session_id: String,
    expires_at: String,
    output: PathBuf,
    now: Option<String>,
) -> Result<()> {
    let policy_bytes = fs::read(&policy_path)
        .with_context(|| format!("could not read policy {}", policy_path.display()))?;
    let policy_text = std::str::from_utf8(&policy_bytes).context("policy file is not UTF-8")?;
    let now = parse_now(now)?;
    let compiled = TargetPolicy::from_toml(policy_text)?.compile(now)?;
    let expires_at = parse_timestamp(&expires_at)?;
    let public_key = read_hex_file(&activation_public_key, "activation_public_key")?;
    if public_key.len() != 32 {
        bail!("activation public key must contain 32 Ed25519 bytes");
    }
    let seed_url = Url::parse(&seed).context("seed URL is invalid")?;
    let allowed_methods = allowed_methods.into_iter().collect::<BTreeSet<_>>();
    for method in &allowed_methods {
        if !compiled.allows_request(&seed_url, method.code()) {
            bail!("program policy does not allow one of the signed session methods");
        }
    }
    if maximum_requests > compiled.maximum_total_requests() {
        bail!("session request budget exceeds program policy");
    }
    let mut resolved_ips = resolved_ips.into_iter().collect::<BTreeSet<_>>();
    resolved_ips.insert(selected_ip);
    let plan = DiscoverySessionPlan::build(
        session_id,
        now,
        expires_at,
        &policy_bytes,
        seed,
        seed_method,
        selected_ip,
        resolved_ips,
        allowed_methods,
        allowed_path_prefixes.into_iter().collect(),
        dns_context_id,
        dns_resolver_id,
        dns_ttl_seconds,
        maximum_requests,
        maximum_depth,
        maximum_response_body_bytes,
        maximum_total_response_bytes,
        minimum_request_interval_milliseconds,
        &public_key,
    )?;
    validate_request_interval_against_policy(&plan, compiled.maximum_requests_per_second())?;
    plan.verify(now)?;
    write_json(&output, &plan)?;
    println!("discovery_session_plan: valid");
    println!("plan_sha256: {}", plan.plan_sha256);
    println!("maximum_requests: {}", plan.maximum_requests);
    println!("maximum_depth: {}", plan.maximum_depth);
    println!("network_activity: none");
    println!("output: {}", output.display());
    Ok(())
}

fn verify_plan(path: PathBuf, now: Option<String>) -> Result<()> {
    let plan: DiscoverySessionPlan = read_json(&path)?;
    plan.verify(parse_now(now)?)?;
    println!("discovery_session_plan: valid");
    println!("plan_sha256: {}", plan.plan_sha256);
    println!("network_activity: none");
    Ok(())
}

fn activation_template(
    plan_path: PathBuf,
    activation_id: String,
    not_before: String,
    expires_at: String,
    output: PathBuf,
) -> Result<()> {
    let plan: DiscoverySessionPlan = read_json(&plan_path)?;
    plan.validate()?;
    let payload = DiscoverySessionActivationPayload::template(
        activation_id,
        &plan,
        parse_timestamp(&not_before)?,
        parse_timestamp(&expires_at)?,
    )?;
    let signing_bytes = payload.signing_bytes()?;
    let document = ActivationTemplateDocument {
        signing_payload_hex: lower_hex(&signing_bytes),
        signing_payload_sha256: hash_bytes(&signing_bytes),
        payload,
        signature_hex: String::new(),
    };
    write_json(&output, &document)?;
    println!("discovery_session_activation_template: valid");
    println!(
        "signing_payload_sha256: {}",
        document.signing_payload_sha256
    );
    println!("network_activity: none");
    println!("output: {}", output.display());
    Ok(())
}

fn verify_activation(
    plan_path: PathBuf,
    activation_path: PathBuf,
    public_key_path: PathBuf,
    now: Option<String>,
) -> Result<()> {
    let plan: DiscoverySessionPlan = read_json(&plan_path)?;
    let activation: DiscoverySessionActivationCertificate = read_json(&activation_path)?;
    let public_key = read_hex_file(&public_key_path, "public_key")?;
    activation.verify(&plan, &public_key, parse_now(now)?)?;
    println!("discovery_session_activation: valid");
    println!(
        "activation_certificate_sha256: {}",
        activation.certificate_sha256()?
    );
    println!("network_activity: none");
    Ok(())
}

#[cfg(feature = "live-network")]
#[allow(clippy::too_many_arguments)]
fn run_live_session(
    policy_path: PathBuf,
    plan_path: PathBuf,
    activation_path: PathBuf,
    public_key_path: PathBuf,
    state_directory: PathBuf,
    config_path: Option<PathBuf>,
    output_directory: PathBuf,
    enable_live: bool,
    now: Option<String>,
) -> Result<()> {
    if !enable_live {
        bail!("discovery-session execution requires the explicit --enable-live flag");
    }
    let now = parse_now(now)?;
    let policy_bytes = fs::read(&policy_path)
        .with_context(|| format!("could not read policy {}", policy_path.display()))?;
    let policy_text = std::str::from_utf8(&policy_bytes).context("policy file is not UTF-8")?;
    let compiled = TargetPolicy::from_toml(policy_text)?.compile(now)?;
    let plan: DiscoverySessionPlan = read_json(&plan_path)?;
    let activation: DiscoverySessionActivationCertificate = read_json(&activation_path)?;
    let public_key = read_hex_file(&public_key_path, "public_key")?;
    plan.verify(now)?;
    activation.verify(&plan, &public_key, now)?;
    if hash_bytes(&policy_bytes) != plan.policy_sha256 {
        bail!("policy file does not match the signed discovery-session plan");
    }
    validate_plan_against_policy(&plan, &compiled)?;
    let config = effective_operator_config(config_path.as_deref(), &plan)?;

    let activation_certificate_sha256 =
        consume_activation_once(&state_directory, &plan, &activation, now)?;
    let artifacts = execute_session(
        &policy_bytes,
        &compiled,
        &plan,
        activation.payload.expires_at_epoch_seconds,
        config,
        now,
    )?;
    let export_manifest = write_report_bundle(&output_directory, &artifacts.bundle)?;

    let mut receipt = DiscoverySessionReceipt {
        version: 1,
        mode: "signed_bounded_passive_discovery_session".into(),
        session_id: plan.session_id.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        activation_certificate_sha256,
        policy_sha256: plan.policy_sha256.clone(),
        target_origin_sha256: plan.target_origin_sha256.clone(),
        selected_ip: plan.selected_ip.to_string(),
        request_budget: artifacts.coverage.request_budget,
        response_byte_budget: plan.maximum_total_response_bytes,
        requests_issued: artifacts.coverage.requests_issued,
        total_response_bytes: artifacts.total_response_bytes,
        discovered_candidates: artifacts.discovered_candidates,
        passive_finding_count: artifacts.bundle.report.findings.len() as u64,
        stop_reason: artifacts.stop_reason,
        scheduler: artifacts.scheduler,
        coverage: artifacts.coverage,
        request_receipts: artifacts.request_receipts,
        request_receipt_chain_tail_sha256: artifacts
            .request_receipts
            .last()
            .map(|receipt| receipt.receipt_sha256.clone())
            .unwrap_or_else(|| plan.plan_sha256.clone()),
        report_sha256: artifacts.bundle.report.report_sha256.clone(),
        export_manifest_sha256: export_manifest.root_sha256,
        body_retention: "memory_only_not_exported".into(),
        redirects_followed: false,
        session_material_used: false,
        active_probes_executed: false,
        automatic_submission: false,
        crash_recovery: "fail_closed_fresh_plan_and_activation_required".into(),
        completed_at_epoch_seconds: now.timestamp(),
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = hash_serializable(&receipt)?;
    write_json(
        &output_directory.join("discovery-session-receipt.json"),
        &receipt,
    )?;

    println!("discovery_session: completed");
    println!("requests_issued: {}", receipt.requests_issued);
    println!("total_response_bytes: {}", receipt.total_response_bytes);
    println!("discovered_candidates: {}", receipt.discovered_candidates);
    println!("passive_findings: {}", receipt.passive_finding_count);
    println!("stop_reason: {}", receipt.stop_reason);
    println!("report_sha256: {}", receipt.report_sha256);
    println!("receipt_sha256: {}", receipt.receipt_sha256);
    println!("output_directory: {}", output_directory.display());
    Ok(())
}

#[cfg(feature = "live-network")]
struct SessionArtifacts {
    bundle: ReportBundle,
    scheduler: SchedulerReceipt,
    coverage: CoverageSummary,
    request_receipts: Vec<SessionRequestReceipt>,
    total_response_bytes: u64,
    discovered_candidates: u64,
    stop_reason: String,
}

#[cfg(feature = "live-network")]
fn execute_session(
    policy_bytes: &[u8],
    policy: &CompiledPolicy,
    plan: &DiscoverySessionPlan,
    activation_expires_at_epoch_seconds: i64,
    config: OperatorConfig,
    now: DateTime<Utc>,
) -> Result<SessionArtifacts> {
    let seed = plan.seed()?;
    let session_started = Instant::now();
    let mut scheduler = DiscoveryScheduler::new(config.clone())?;
    scheduler.enqueue(DiscoveryCandidate {
        canonical_url: seed.to_string(),
        canonical_url_sha256: hash_bytes(seed.as_str().as_bytes()),
        method: plan.seed_method.code().into(),
        depth: 0,
        source_kind: "signed_discovery_session_seed".into(),
    });

    let mut findings = BTreeMap::<String, Finding>::new();
    let mut request_receipts = Vec::new();
    let mut total_response_bytes = 0_u64;
    let mut discovered_candidates = 0_u64;
    let mut byte_budget_exhausted = false;
    let mut previous_receipt_sha256 = plan.plan_sha256.clone();

    while let Some(candidate) = scheduler.next_candidate() {
        let target = Url::parse(&candidate.canonical_url)
            .context("scheduler produced an invalid discovery-session URL")?;
        let method = method_from_code(&candidate.method)?;
        plan.authorize_candidate(&target, method, candidate.depth)?;
        if !policy.allows_request(&target, method.code()) {
            bail!("compiled program policy denied a signed discovery-session candidate");
        }
        let remaining_bytes = plan
            .maximum_total_response_bytes
            .saturating_sub(total_response_bytes);
        if remaining_bytes == 0 {
            byte_budget_exhausted = true;
            break;
        }
        if !request_receipts.is_empty() {
            thread::sleep(Duration::from_millis(
                plan.minimum_request_interval_milliseconds,
            ));
        }
        let elapsed = session_started.elapsed();
        let request_now = now
            + chrono::Duration::from_std(elapsed)
                .context("discovery-session elapsed time exceeded chrono bounds")?;
        plan.verify(request_now)?;
        if request_now.timestamp() > activation_expires_at_epoch_seconds {
            bail!("discovery-session activation expired before the next request");
        }
        let maximum_response_body_bytes = config
            .maximum_body_bytes
            .min(plan.maximum_response_body_bytes)
            .min(remaining_bytes);
        let observation = execute_discovery_session_request(
            policy_bytes,
            &DiscoverySessionRequestSpec {
                target_url: target.clone(),
                method,
                selected_ip: plan.selected_ip,
                resolved_ips: plan.resolved_ips.clone(),
                dns_context_id: plan.dns_context_id.clone(),
                dns_resolver_id: plan.dns_resolver_id.clone(),
                dns_ttl_seconds: plan.dns_ttl_seconds,
                dns_observation_elapsed: elapsed,
                maximum_response_body_bytes,
            },
            request_now,
        )?;
        total_response_bytes = total_response_bytes
            .checked_add(observation.response_body.len() as u64)
            .context("discovery-session response byte accounting overflowed")?;
        if total_response_bytes > plan.maximum_total_response_bytes {
            bail!("discovery-session exceeded its signed total response byte budget");
        }

        for finding in &observation.findings {
            findings
                .entry(finding.finding_id.clone())
                .or_insert_with(|| finding.clone());
        }
        let finding_ids = observation
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<Vec<_>>();
        let mut request_receipt = SessionRequestReceipt {
            sequence: request_receipts.len() as u64 + 1,
            endpoint_sha256: hash_bytes(target.as_str().as_bytes()),
            method: method.code().into(),
            depth: candidate.depth,
            response_status: observation.response_status,
            response_body_bytes: observation.response_body.len() as u64,
            response_body_sha256: observation.response_body_sha256.clone(),
            live_receipt_sha256: observation.live_receipt_sha256,
            redirect_observed: observation.redirect_observed,
            finding_ids,
            previous_receipt_sha256: previous_receipt_sha256.clone(),
            receipt_sha256: String::new(),
        };
        request_receipt.receipt_sha256 = hash_serializable(&request_receipt)?;
        previous_receipt_sha256 = request_receipt.receipt_sha256.clone();
        request_receipts.push(request_receipt);

        if method == PlannedMethod::Get
            && !observation.response_body.is_empty()
            && candidate.depth < config.maximum_depth
        {
            let mut batch = discover_response(
                &config,
                policy,
                &target,
                candidate.depth,
                observation.response_content_type.as_deref(),
                &observation.response_body,
            )?;
            batch.candidates.retain(|candidate| {
                let Ok(url) = Url::parse(&candidate.canonical_url) else {
                    return false;
                };
                let Ok(method) = method_from_code(&candidate.method) else {
                    return false;
                };
                plan.authorize_candidate(&url, method, candidate.depth)
                    .is_ok()
                    && policy.allows_request(&url, method.code())
            });
            discovered_candidates =
                discovered_candidates.saturating_add(batch.candidates.len() as u64);
            scheduler.enqueue_batch(batch);
        }
        if total_response_bytes == plan.maximum_total_response_bytes {
            byte_budget_exhausted = true;
            break;
        }
    }

    let scheduler_receipt = scheduler.receipt()?;
    let depth_reached = request_receipts
        .iter()
        .map(|receipt| receipt.depth)
        .max()
        .unwrap_or(0);
    let coverage = CoverageSummary {
        discovered_endpoints: scheduler_receipt
            .seen
            .saturating_add(scheduler_receipt.pending),
        tested_endpoints: request_receipts.len() as u64,
        requests_issued: request_receipts.len() as u64,
        request_budget: config.maximum_requests,
        depth_reached,
        maximum_depth: config.maximum_depth,
        saturation_reached: scheduler_receipt.pending == 0 && !byte_budget_exhausted,
    };
    let operator_findings = findings
        .values()
        .map(OperatorFinding::from_passive)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut untested_areas = vec![
        "Authenticated areas were not tested; BSL-137 does not inject session or vault material."
            .into(),
        "Active reflection, rate-limit and authorization-differential probes were not executed."
            .into(),
        "Redirects were observed but never followed.".into(),
        "Crash recovery is fail-closed and requires a fresh plan and activation.".into(),
    ];
    if byte_budget_exhausted {
        untested_areas.push(
            "Discovery stopped because the signed total response byte budget was exhausted.".into(),
        );
    }
    if scheduler_receipt.pending > 0 {
        untested_areas.push(
            "Eligible endpoints remained untested when a signed session budget was exhausted."
                .into(),
        );
    }
    let (report_stop_reason, stop_reason) = if byte_budget_exhausted {
        (StopReason::Saturated, "response_byte_budget_exhausted")
    } else if let Some(reason) = scheduler_receipt.stop_reason {
        (reason, stop_reason_code(reason))
    } else {
        (StopReason::Completed, "completed")
    };
    let report = OperatorReport::build(
        &plan.session_id,
        policy.program_name(),
        policy.policy_snapshot_sha256(),
        &seed,
        now.timestamp(),
        operator_findings,
        coverage.clone(),
        untested_areas,
        report_stop_reason,
    )?;
    let bundle = ReportBundle::build(report)?;
    Ok(SessionArtifacts {
        bundle,
        scheduler: scheduler_receipt,
        coverage,
        request_receipts,
        total_response_bytes,
        discovered_candidates,
        stop_reason: stop_reason.into(),
    })
}

#[cfg(feature = "live-network")]
fn effective_operator_config(
    path: Option<&Path>,
    plan: &DiscoverySessionPlan,
) -> Result<OperatorConfig> {
    let mut config = match path {
        Some(path) => {
            let bytes = fs::read(path)
                .with_context(|| format!("could not read operator config {}", path.display()))?;
            OperatorConfig::migrate_json(&bytes)?
        }
        None => OperatorConfig::default(),
    };
    if !config.passive_only {
        bail!("BSL-137 accepts only passive_only operator configurations");
    }
    config.maximum_requests = config
        .maximum_requests
        .min(config.maximum_endpoints)
        .min(plan.maximum_requests);
    config.maximum_depth = config.maximum_depth.min(plan.maximum_depth);
    config.maximum_body_bytes = config
        .maximum_body_bytes
        .min(plan.maximum_response_body_bytes);
    config.validate()?;
    Ok(config)
}

fn validate_plan_against_policy(
    plan: &DiscoverySessionPlan,
    policy: &CompiledPolicy,
) -> Result<()> {
    let seed = plan.seed()?;
    if plan.maximum_requests > policy.maximum_total_requests() {
        bail!("signed discovery-session request budget exceeds program policy");
    }
    for method in &plan.allowed_methods {
        if !policy.allows_request(&seed, method.code()) {
            bail!("signed discovery-session method is denied by program policy");
        }
    }
    validate_request_interval_against_policy(plan, policy.maximum_requests_per_second())
}

#[cfg(feature = "live-network")]
fn stop_reason_code(reason: StopReason) -> &'static str {
    match reason {
        StopReason::Completed => "completed",
        StopReason::RequestBudgetExhausted => "request_budget_exhausted",
        StopReason::EndpointLimitReached => "endpoint_limit_reached",
        StopReason::DepthLimitReached => "depth_limit_reached",
        StopReason::EmergencyStop => "emergency_stop",
        StopReason::Cancelled => "cancelled",
        StopReason::Saturated => "saturated",
        StopReason::OperatorDenied => "operator_denied",
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

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn template_document_binds_canonical_payload() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[17_u8; 32]).unwrap();
        let plan = DiscoverySessionPlan::build(
            "cli-session-test",
            DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            DateTime::from_timestamp(1_800_003_600, 0).unwrap(),
            b"policy",
            "https://example.com/app/",
            PlannedMethod::Get,
            "93.184.216.34".parse().unwrap(),
            BTreeSet::from(["93.184.216.34".parse().unwrap()]),
            BTreeSet::from([PlannedMethod::Get]),
            BTreeSet::from(["/app".into()]),
            "dns-context-cli-test",
            "signed-dns-observation",
            60,
            8,
            2,
            1024 * 1024,
            4 * 1024 * 1024,
            1000,
            key_pair.public_key().as_ref(),
        )
        .unwrap();
        let payload = DiscoverySessionActivationPayload::template(
            "cli-activation-test",
            &plan,
            DateTime::from_timestamp(1_800_000_010, 0).unwrap(),
            DateTime::from_timestamp(1_800_000_600, 0).unwrap(),
        )
        .unwrap();
        let bytes = payload.signing_bytes().unwrap();
        assert_eq!(hash_bytes(&bytes), hash_bytes(&bytes));
        assert!(!lower_hex(&bytes).is_empty());
    }
}
