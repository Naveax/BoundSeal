#[cfg(feature = "live-network")]
#[path = "../live_orchestrator.rs"]
#[allow(dead_code, unused_imports)]
mod live_orchestrator;

#[cfg(feature = "live-network")]
mod enabled {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use anyhow::{bail, Context, Result};
    use chrono::{DateTime, Utc};
    use clap::Parser;
    use nxb_operator::{
        authorize_probe, discover_response, write_report_bundle, CoverageSummary,
        DiscoveryCandidate, DiscoveryScheduler, OperatorConfig, OperatorFinding, OperatorReport,
        ProbeKind, ProbeRequest, ReportBundle, SchedulerReceipt, StopReason,
    };
    use nxb_passive_analyzers::Finding;
    use nxb_policy::{CompiledPolicy, TargetPolicy};
    use serde::Serialize;
    use url::Url;

    use crate::live_orchestrator::{
        execute_live_run_observed, hash_bytes, read_hex_file, read_json, write_json,
        LiveActivationCertificate, LiveRunPlan, PlannedMethod,
    };

    #[derive(Debug, Parser)]
    #[command(
        name = "nxb-live-scan",
        version,
        about = "One signed HTTPS request bridged into the bounded NXB operator"
    )]
    struct Cli {
        /// Exact authorized program policy TOML used to create the signed plan.
        #[arg(long)]
        policy: PathBuf,
        /// Canonical single-request live plan.
        #[arg(long)]
        plan: PathBuf,
        /// One-use externally signed activation certificate.
        #[arg(long)]
        activation: PathBuf,
        /// Raw 32-byte Ed25519 public key encoded as lowercase hexadecimal.
        #[arg(long)]
        public_key: PathBuf,
        /// Durable one-use activation ledger directory.
        #[arg(long)]
        state_directory: PathBuf,
        /// Optional bounded operator configuration.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Report bundle and bridge receipt output directory.
        #[arg(long, default_value = "target/nxb-live-scan")]
        output_directory: PathBuf,
        /// Explicit live-network acknowledgement. No request is sent without this flag.
        #[arg(long)]
        enable_live: bool,
        /// Override current time using RFC3339, primarily for deterministic fixtures.
        #[arg(long)]
        now: Option<String>,
    }

    #[derive(Debug)]
    struct OperatorArtifacts {
        bundle: ReportBundle,
        scheduler: SchedulerReceipt,
        coverage: CoverageSummary,
        discovered_candidates: u64,
    }

    #[derive(Debug, Serialize)]
    struct LiveScanReceipt {
        version: u32,
        mode: String,
        run_id: String,
        plan_sha256: String,
        activation_certificate_sha256: String,
        live_orchestrator_receipt_sha256: String,
        policy_sha256: String,
        target_origin_sha256: String,
        method: String,
        response_status: u16,
        response_body_bytes: u64,
        response_body_sha256: String,
        response_content_type_sha256: Option<String>,
        passive_finding_count: u64,
        discovered_candidates: u64,
        scheduler: SchedulerReceipt,
        coverage: CoverageSummary,
        report_sha256: String,
        export_manifest_sha256: String,
        body_retention: String,
        followup_network_activity: String,
        session_material_used: bool,
        automatic_submission: bool,
        receipt_sha256: String,
    }

    pub fn run() -> Result<()> {
        let cli = Cli::parse();
        if !cli.enable_live {
            bail!("signed live operator execution requires the explicit --enable-live flag");
        }

        let now = parse_now(cli.now)?;
        let policy_bytes = fs::read(&cli.policy)
            .with_context(|| format!("could not read policy {}", cli.policy.display()))?;
        let policy_text = std::str::from_utf8(&policy_bytes).context("policy file is not UTF-8")?;
        let compiled = TargetPolicy::from_toml(policy_text)?.compile(now)?;

        let plan: LiveRunPlan = read_json(&cli.plan)?;
        let activation: LiveActivationCertificate = read_json(&cli.activation)?;
        let public_key = read_hex_file(&cli.public_key, "public_key")?;
        plan.verify(now)?;
        activation.verify(&plan, &public_key, now)?;
        if hash_bytes(&policy_bytes) != plan.policy_sha256 {
            bail!("policy file does not match the signed live-plan");
        }
        let target = plan.parsed_url()?;

        let mut config = load_operator_config(cli.config.as_deref())?;
        if !config.passive_only {
            bail!("NXB-136 live operator bridge accepts only passive_only operator configs");
        }
        config.maximum_requests = plan.maximum_requests;
        config.validate()?;
        authorize_passive_probes(&config, &compiled, &target, plan.method)?;

        let activation_certificate_sha256 = activation.certificate_sha256()?;
        let observation = execute_live_run_observed(
            &policy_bytes,
            &plan,
            &activation,
            &public_key,
            &cli.state_directory,
            now,
        )?;
        if observation.receipt.activation_certificate_sha256 != activation_certificate_sha256 {
            bail!("live orchestrator receipt is not bound to the supplied activation");
        }

        let artifacts = build_operator_artifacts(
            config,
            &compiled,
            &target,
            &plan.run_id,
            now,
            plan.method,
            observation.response_content_type.as_deref(),
            &observation.response_body,
            &observation.findings,
        )?;
        let export_manifest = write_report_bundle(&cli.output_directory, &artifacts.bundle)?;

        let mut receipt = LiveScanReceipt {
            version: 1,
            mode: "signed_single_request_operator_bridge".into(),
            run_id: plan.run_id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            activation_certificate_sha256,
            live_orchestrator_receipt_sha256: observation.receipt.receipt_sha256.clone(),
            policy_sha256: plan.policy_sha256.clone(),
            target_origin_sha256: plan.target_origin_sha256.clone(),
            method: plan.method.code().into(),
            response_status: observation.response_status,
            response_body_bytes: observation.response_body.len() as u64,
            response_body_sha256: hash_bytes(&observation.response_body),
            response_content_type_sha256: observation
                .response_content_type
                .as_deref()
                .map(hash_bytes),
            passive_finding_count: observation.findings.len() as u64,
            discovered_candidates: artifacts.discovered_candidates,
            scheduler: artifacts.scheduler,
            coverage: artifacts.coverage,
            report_sha256: artifacts.bundle.report.report_sha256.clone(),
            export_manifest_sha256: export_manifest.root_sha256,
            body_retention: "memory_only_not_exported".into(),
            followup_network_activity:
                "none_each_followup_requires_a_new_exact_plan_and_one_use_activation".into(),
            session_material_used: false,
            automatic_submission: false,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = hash_serializable(&receipt)?;
        let receipt_path = cli.output_directory.join("live-scan-receipt.json");
        write_json(&receipt_path, &receipt)?;

        println!("live_scan: completed");
        println!("requests_issued: {}", receipt.coverage.requests_issued);
        println!("passive_findings: {}", receipt.passive_finding_count);
        println!("discovered_candidates: {}", receipt.discovered_candidates);
        println!("followup_network_activity: none");
        println!("report_sha256: {}", receipt.report_sha256);
        println!("receipt_sha256: {}", receipt.receipt_sha256);
        println!("output_directory: {}", cli.output_directory.display());
        Ok(())
    }

    fn load_operator_config(path: Option<&Path>) -> Result<OperatorConfig> {
        let mut config = match path {
            Some(path) => {
                let bytes = fs::read(path).with_context(|| {
                    format!("could not read operator config {}", path.display())
                })?;
                OperatorConfig::migrate_json(&bytes)?
            }
            None => OperatorConfig::default(),
        };
        config.maximum_requests = 1;
        config.validate()?;
        Ok(config)
    }

    fn authorize_passive_probes(
        config: &OperatorConfig,
        policy: &CompiledPolicy,
        target: &Url,
        method: PlannedMethod,
    ) -> Result<()> {
        for probe in [
            ProbeKind::SecurityHeaders,
            ProbeKind::CookieFlags,
            ProbeKind::CachePolicy,
        ] {
            authorize_probe(
                config,
                policy,
                &ProbeRequest {
                    probe,
                    endpoint: target.to_string(),
                    method: method.code().into(),
                    request_cost: probe.default_request_cost(),
                    capability_reference: None,
                    account_partition: None,
                    tenant_partition: None,
                },
                1,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_operator_artifacts(
        config: OperatorConfig,
        policy: &CompiledPolicy,
        target: &Url,
        run_id: &str,
        now: DateTime<Utc>,
        method: PlannedMethod,
        content_type: Option<&[u8]>,
        body: &[u8],
        passive_findings: &[Finding],
    ) -> Result<OperatorArtifacts> {
        let mut scheduler = DiscoveryScheduler::new(config.clone())?;
        scheduler.enqueue(DiscoveryCandidate {
            canonical_url: target.to_string(),
            canonical_url_sha256: hash_bytes(target.as_str().as_bytes()),
            method: method.code().into(),
            depth: 0,
            source_kind: "signed_live_seed".into(),
        });
        let root = scheduler
            .next_candidate()
            .context("signed live target was not available in the scheduler")?;
        if root.canonical_url != target.as_str() || root.method != method.code() {
            bail!("operator scheduler root does not match the signed live target");
        }

        let mut discovered_candidates = 0_u64;
        let mut depth_reached = 0_u16;
        let mut untested_areas = Vec::new();
        let discovery_attempted = method == PlannedMethod::Get && !body.is_empty();
        if discovery_attempted {
            let batch = discover_response(&config, policy, target, 0, content_type, body)?;
            discovered_candidates = batch.candidates.len() as u64;
            depth_reached = batch
                .candidates
                .iter()
                .map(|candidate| candidate.depth)
                .max()
                .unwrap_or(0);
            scheduler.enqueue_batch(batch);
        } else {
            untested_areas.push(
                "The signed response did not contain a GET body suitable for passive endpoint discovery."
                    .into(),
            );
        }

        let before_stop = scheduler.receipt()?;
        if before_stop.pending > 0 {
            let _ = scheduler.next_candidate();
            untested_areas.push(
                "Discovered endpoints were not fetched; every follow-up requires a new exact signed plan and one-use activation."
                    .into(),
            );
        }
        untested_areas.push(
            "Authenticated areas were not tested; NXB-136 does not inject session or vault material."
                .into(),
        );
        untested_areas.push(
            "Active reflection, rate-limit and authorization-differential probes were not executed."
                .into(),
        );
        untested_areas.push("Redirects were observed but never followed.".into());

        let scheduler_receipt = scheduler.receipt()?;
        let coverage = CoverageSummary {
            discovered_endpoints: 1_u64.saturating_add(discovered_candidates),
            tested_endpoints: 1,
            requests_issued: scheduler_receipt.issued,
            request_budget: config.maximum_requests,
            depth_reached,
            maximum_depth: config.maximum_depth,
            saturation_reached: discovery_attempted && scheduler_receipt.pending == 0,
        };
        let findings = passive_findings
            .iter()
            .map(OperatorFinding::from_passive)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let stop_reason = scheduler_receipt.stop_reason.unwrap_or({
            if scheduler_receipt.pending > 0 {
                StopReason::RequestBudgetExhausted
            } else {
                StopReason::Completed
            }
        });
        let report = OperatorReport::build(
            run_id,
            policy.program_name(),
            policy.policy_snapshot_sha256(),
            target,
            now.timestamp(),
            findings,
            coverage.clone(),
            untested_areas,
            stop_reason,
        )?;
        let bundle = ReportBundle::build(report)?;
        Ok(OperatorArtifacts {
            bundle,
            scheduler: scheduler_receipt,
            coverage,
            discovered_candidates,
        })
    }

    fn parse_now(value: Option<String>) -> Result<DateTime<Utc>> {
        match value {
            Some(value) => DateTime::parse_from_rfc3339(&value)
                .with_context(|| format!("invalid RFC3339 timestamp: {value}"))
                .map(|value| value.with_timezone(&Utc)),
            None => Ok(Utc::now()),
        }
    }

    fn hash_serializable<T: Serialize>(value: &T) -> Result<String> {
        let bytes = serde_json::to_vec(value).context("could not serialize bridge receipt")?;
        Ok(hash_bytes(&bytes))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn policy(now: DateTime<Utc>) -> CompiledPolicy {
            let snapshot = "a".repeat(64);
            let source = format!(
                r#"
schema_version = 1

[program]
name = "NXB test program"
platform = "local"
policy_url = "https://example.com/policy"

[scope]
include_hosts = ["example.com"]
exclude_hosts = []
allowed_schemes = ["https"]
allowed_methods = ["GET", "HEAD"]
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
researcher = "nxb-test"
policy_snapshot_sha256 = "{snapshot}"
expires_at = "2035-01-01T00:00:00Z"
"#
            );
            TargetPolicy::from_toml(&source)
                .unwrap()
                .compile(now)
                .unwrap()
        }

        #[test]
        fn followup_is_scheduled_but_never_fetched() {
            let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
            let policy = policy(now);
            let target = Url::parse("https://example.com/").unwrap();
            let mut config = OperatorConfig::default();
            config.maximum_requests = 1;
            let artifacts = build_operator_artifacts(
                config,
                &policy,
                &target,
                "nxb-136-test",
                now,
                PlannedMethod::Get,
                Some(b"text/html"),
                br#"<html><a href="/health">health</a></html>"#,
                &[],
            )
            .unwrap();

            assert_eq!(artifacts.coverage.requests_issued, 1);
            assert_eq!(artifacts.coverage.tested_endpoints, 1);
            assert_eq!(artifacts.discovered_candidates, 1);
            assert_eq!(artifacts.scheduler.pending, 1);
            assert_eq!(
                artifacts.scheduler.stop_reason,
                Some(StopReason::RequestBudgetExhausted)
            );
            assert!(!artifacts.bundle.report.automatic_submission);
        }

        #[test]
        fn head_response_does_not_attempt_body_discovery() {
            let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
            let policy = policy(now);
            let target = Url::parse("https://example.com/").unwrap();
            let mut config = OperatorConfig::default();
            config.maximum_requests = 1;
            let artifacts = build_operator_artifacts(
                config,
                &policy,
                &target,
                "nxb-136-head-test",
                now,
                PlannedMethod::Head,
                None,
                &[],
                &[],
            )
            .unwrap();

            assert_eq!(artifacts.discovered_candidates, 0);
            assert_eq!(artifacts.coverage.requests_issued, 1);
            assert!(!artifacts.coverage.saturation_reached);
            assert_eq!(artifacts.scheduler.pending, 0);
        }
    }
}

#[cfg(feature = "live-network")]
fn main() -> anyhow::Result<()> {
    enabled::run()
}

#[cfg(not(feature = "live-network"))]
fn main() {
    eprintln!("nxb-live-scan is disabled; rebuild nxb-core with --features live-network");
    std::process::exit(2);
}
