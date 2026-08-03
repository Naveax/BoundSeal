use std::{fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::Args;
use nxb_operator::{
    authorize_probe, discover_response, write_report_bundle, CoverageSummary,
    DiscoveryCandidate, DiscoveryScheduler, OperatorConfig, OperatorFinding,
    OperatorReport, ProbeKind, ProbeRequest, ReportBundle, SchedulerReceipt,
    SessionManifest, StopReason,
};
use nxb_policy::TargetPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Authorized program scope/policy TOML.
    #[arg(long)]
    pub program: PathBuf,
    /// Exact HTTPS target to plan or analyze.
    #[arg(long)]
    pub target: String,
    /// Operator JSON configuration. Legacy schema 0 is migrated fail-closed.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Optional opaque vault-reference session manifest. Secret values are forbidden.
    #[arg(long)]
    pub session_manifest: Option<PathBuf>,
    /// Optional local response snapshot for passive discovery and report generation.
    #[arg(long)]
    pub response_snapshot: Option<PathBuf>,
    /// Output directory for plan, JSON, Markdown and HackerOne draft artifacts.
    #[arg(long, default_value = "target/nxb-scan")]
    pub output_directory: PathBuf,
    /// Stable run identifier used in receipts and reports.
    #[arg(long)]
    pub run_id: Option<String>,
    /// Override maximum discovery depth without broadening hard limits.
    #[arg(long)]
    pub maximum_depth: Option<u16>,
    /// Override maximum distinct endpoints without broadening hard limits.
    #[arg(long)]
    pub maximum_endpoints: Option<u64>,
    /// Override request budget without broadening hard limits.
    #[arg(long)]
    pub maximum_requests: Option<u64>,
    /// Networkless mode is mandatory for this command. Live execution uses signed live-run.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub dry_run: bool,
    /// Override current time using RFC3339 for deterministic fixtures.
    #[arg(long)]
    pub now: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseSnapshot {
    body_path: PathBuf,
    body_sha256: String,
    body_bytes: u64,
    content_type: Option<String>,
    #[serde(default)]
    current_depth: u16,
    #[serde(default)]
    findings: Vec<OperatorFinding>,
}

#[derive(Debug, Clone, Serialize)]
struct ScanPlanDocument {
    version: u32,
    run_id: String,
    program_name: String,
    policy_snapshot_sha256: String,
    policy_file_sha256: String,
    target_url: String,
    target_url_sha256: String,
    operator_config: OperatorConfig,
    dry_run: bool,
    network_activity: String,
    session_manifest_sha256: Option<String>,
    response_snapshot_sha256: Option<String>,
    scheduler: SchedulerReceipt,
    report_sha256: String,
    export_manifest_sha256: String,
    live_execution_boundary: String,
    plan_sha256: String,
}

pub fn run(args: ScanArgs) -> Result<()> {
    if !args.dry_run {
        bail!(
            "nxb scan never enables implicit network access; use live-plan, a signed activation, and live-run --enable-live"
        );
    }
    let now = parse_now(args.now)?;
    let policy_bytes = fs::read(&args.program)
        .with_context(|| format!("could not read policy {}", args.program.display()))?;
    let policy_text = std::str::from_utf8(&policy_bytes).context("policy is not UTF-8")?;
    let compiled = TargetPolicy::from_toml(policy_text)?.compile(now)?;
    let target = Url::parse(&args.target).context("target is not a valid absolute URL")?;

    let mut config = match args.config {
        Some(path) => {
            let bytes = fs::read(&path)
                .with_context(|| format!("could not read operator config {}", path.display()))?;
            OperatorConfig::migrate_json(&bytes)?
        }
        None => OperatorConfig::default(),
    };
    if let Some(value) = args.maximum_depth {
        config.maximum_depth = value;
    }
    if let Some(value) = args.maximum_endpoints {
        config.maximum_endpoints = value;
    }
    if let Some(value) = args.maximum_requests {
        config.maximum_requests = value;
    }
    config.validate()?;

    authorize_probe(
        &config,
        &compiled,
        &ProbeRequest {
            probe: ProbeKind::SecurityHeaders,
            endpoint: target.to_string(),
            method: "GET".into(),
            request_cost: 0,
            capability_reference: None,
            account_partition: None,
            tenant_partition: None,
        },
        config.maximum_requests,
    )?;

    let run_id = args
        .run_id
        .unwrap_or_else(|| format!("scan-{}", now.timestamp()));
    let session_manifest_sha256 = match args.session_manifest {
        Some(path) => {
            let bytes = fs::read(&path).with_context(|| {
                format!("could not read session manifest {}", path.display())
            })?;
            let manifest = SessionManifest::from_json(&bytes)?;
            manifest.validate_for_target(&target, now.timestamp())?;
            Some(hash_bytes(&bytes))
        }
        None => None,
    };

    let mut scheduler = DiscoveryScheduler::new(config.clone())?;
    scheduler.enqueue(DiscoveryCandidate {
        canonical_url: target.to_string(),
        canonical_url_sha256: hash_bytes(target.as_str().as_bytes()),
        method: "GET".into(),
        depth: 0,
        source_kind: "operator_seed".into(),
    });

    let mut findings = Vec::new();
    let mut discovered_endpoints = 1_u64;
    let mut tested_endpoints = 0_u64;
    let mut depth_reached = 0_u16;
    let mut untested_areas = Vec::new();
    let response_snapshot_sha256 = match args.response_snapshot {
        Some(path) => {
            let snapshot_bytes = fs::read(&path).with_context(|| {
                format!("could not read response snapshot {}", path.display())
            })?;
            let snapshot: ResponseSnapshot = serde_json::from_slice(&snapshot_bytes)
                .context("response snapshot JSON is invalid")?;
            let body = fs::read(&snapshot.body_path).with_context(|| {
                format!("could not read snapshot body {}", snapshot.body_path.display())
            })?;
            if snapshot.body_bytes != body.len() as u64
                || snapshot.body_sha256 != hash_bytes(&body)
            {
                bail!("response snapshot body length or SHA-256 does not match");
            }
            let root = scheduler
                .next_candidate()
                .context("root target was not available in the scheduler")?;
            if root.canonical_url != target.as_str() {
                bail!("scheduler root does not match the exact target");
            }
            tested_endpoints = 1;
            depth_reached = snapshot.current_depth;
            let batch = discover_response(
                &config,
                &compiled,
                &target,
                snapshot.current_depth,
                snapshot.content_type.as_deref().map(str::as_bytes),
                &body,
            )?;
            discovered_endpoints = discovered_endpoints
                .saturating_add(batch.candidates.len() as u64);
            depth_reached = depth_reached.max(
                batch
                    .candidates
                    .iter()
                    .map(|candidate| candidate.depth)
                    .max()
                    .unwrap_or(snapshot.current_depth),
            );
            scheduler.enqueue_batch(batch);
            for finding in &snapshot.findings {
                finding.validate()?;
            }
            findings = snapshot.findings;
            if scheduler.receipt()?.pending > 0 {
                untested_areas.push(
                    "Discovered endpoints were scheduled but not fetched by the networkless scan command."
                        .into(),
                );
            }
            Some(hash_bytes(&snapshot_bytes))
        }
        None => {
            untested_areas.push(
                "No response snapshot was supplied; HTTP discovery and passive probes were not executed."
                    .into(),
            );
            None
        }
    };
    if session_manifest_sha256.is_none() {
        untested_areas.push("Authenticated areas were not tested.".into());
    }
    untested_areas.push(
        "Active reflection, rate-limit and authorization-differential probes require a separately authorized live capability."
            .into(),
    );

    let scheduler_receipt = scheduler.receipt()?;
    let coverage = CoverageSummary {
        discovered_endpoints,
        tested_endpoints,
        requests_issued: scheduler_receipt.issued,
        request_budget: config.maximum_requests,
        depth_reached,
        maximum_depth: config.maximum_depth,
        saturation_reached: scheduler_receipt.pending == 0 && response_snapshot_sha256.is_some(),
    };
    let report = OperatorReport::build(
        run_id.clone(),
        compiled.program_name(),
        compiled.policy_snapshot_sha256(),
        &target,
        now.timestamp(),
        findings,
        coverage,
        untested_areas,
        scheduler_receipt.stop_reason.unwrap_or(StopReason::Completed),
    )?;
    let bundle = ReportBundle::build(report)?;
    let export_manifest = write_report_bundle(&args.output_directory, &bundle)?;

    let mut plan = ScanPlanDocument {
        version: 1,
        run_id,
        program_name: compiled.program_name().to_string(),
        policy_snapshot_sha256: compiled.policy_snapshot_sha256().to_string(),
        policy_file_sha256: hash_bytes(&policy_bytes),
        target_url: target.to_string(),
        target_url_sha256: hash_bytes(target.as_str().as_bytes()),
        operator_config: config,
        dry_run: true,
        network_activity: "none".into(),
        session_manifest_sha256,
        response_snapshot_sha256,
        scheduler: scheduler_receipt,
        report_sha256: bundle.report.report_sha256.clone(),
        export_manifest_sha256: export_manifest.root_sha256,
        live_execution_boundary:
            "signed live-plan + one-time Ed25519 activation + --enable-live required".into(),
        plan_sha256: String::new(),
    };
    plan.plan_sha256 = hash_serializable(&plan)?;
    write_json_atomic(&args.output_directory.join("scan-plan.json"), &plan)?;

    println!("scan: planned");
    println!("network_activity: none");
    println!("program: {}", plan.program_name);
    println!("target_sha256: {}", plan.target_url_sha256);
    println!("scheduled_pending: {}", plan.scheduler.pending);
    println!("findings: {}", bundle.report.findings.len());
    println!("report_sha256: {}", plan.report_sha256);
    println!("plan_sha256: {}", plan.plan_sha256);
    println!("output_directory: {}", args.output_directory.display());
    Ok(())
}

fn parse_now(value: Option<String>) -> Result<DateTime<Utc>> {
    match value {
        Some(value) => DateTime::parse_from_rfc3339(&value)
            .with_context(|| format!("invalid RFC3339 timestamp: {value}"))
            .map(|value| value.with_timezone(&Utc)),
        None => Ok(Utc::now()),
    }
}

fn write_json_atomic<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).context("could not serialize scan plan")?;
    let parent = path.parent().context("scan plan path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".scan-plan-{}.tmp",
        &hash_bytes(&bytes)[..16]
    ));
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    fs::write(&temporary, bytes)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).context("could not serialize hash material")?;
    Ok(hash_bytes(&bytes))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
