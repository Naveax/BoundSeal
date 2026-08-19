use std::{collections::BTreeSet, fs, net::IpAddr, path::PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;

use bsl_operator::{
    authorize_probe, discover_response, write_report_bundle, CoverageSummary, DiscoveryCandidate,
    DiscoveryScheduler, OperatorConfig, OperatorFinding, OperatorReport, ProbeKind, ProbeRequest,
    ReportBundle, SchedulerReceipt, SessionManifest, StopReason,
};
use bsl_passive_analyzers::Finding;
use bsl_policy::TargetPolicy;

#[derive(Debug, Parser)]
#[command(name = "bsl-live-scan", version, about = "Explicitly authorized bounded passive live scan")]
struct Cli {
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    target: String,
    #[arg(long)]
    selected_ip: IpAddr,
    #[arg(long = "resolved-ip", required = true)]
    resolved_ips: Vec<IpAddr>,
    #[arg(long)]
    session_manifest: Option<PathBuf>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "target/bsl-live-scan")]
    output_directory: PathBuf,
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
    run_id: String,
    #[arg(long)]
    expires_at: String,
    #[arg(long)]
    enable_live: bool,
    #[arg(long)]
    now: Option<String>,
}

#[derive(Debug, Serialize)]
struct LiveScanSummary {
    version: u32,
    run_id: String,
    policy_sha256: String,
    target_origin_sha256: String,
    selected_ip: String,
    requests_issued: u64,
    discovered_candidates: u64,
    finding_count: u64,
    total_response_bytes: u64,
    stop_reason: String,
    scheduler: SchedulerReceipt,
    coverage: CoverageSummary,
    report_sha256: String,
    export_manifest_sha256: String,
    session_manifest_sha256: Option<String>,
    redirects_followed: bool,
    active_probes_executed: bool,
    automatic_submission: bool,
    network_mode: String,
    completed_at_epoch_seconds: i64,
    summary_sha256: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if !cli.enable_live {
        bail!("live scan requires the explicit --enable-live flag");
    }
    let now = parse_now(cli.now)?;
    let expires_at = parse_timestamp(&cli.expires_at)?;
    if expires_at <= now || expires_at.timestamp().saturating_sub(now.timestamp()) > 4 * 60 * 60 {
        bail!("live scan expiry must be in the future and within four hours");
    }

    let policy_bytes = fs::read(&cli.policy)
        .with_context(|| format!("could not read policy {}", cli.policy.display()))?;
    let policy_text = std::str::from_utf8(&policy_bytes).context("policy is not UTF-8")?;
    let compiled = TargetPolicy::from_toml(policy_text)?.compile(now)?;
    let target = Url::parse(&cli.target).context("target URL is invalid")?;
    if target.scheme() != "https"
        || target.port_or_known_default() != Some(443)
        || target.query().is_some()
        || target.fragment().is_some()
        || !target.username().is_empty()
        || target.password().is_some()
    {
        bail!("live scan target must be credential-free HTTPS/443 without query or fragment");
    }
    let host = target.host_str().context("target URL has no host")?;
    if !compiled.allows_host(host) || !compiled.allows_request(&target, "GET") {
        bail!("target is outside the supplied policy");
    }
    if !bsl_policy::is_public_destination(cli.selected_ip) {
        bail!("selected IP is not public");
    }
    let mut resolved_ips = cli.resolved_ips.into_iter().collect::<BTreeSet<_>>();
    resolved_ips.insert(cli.selected_ip);
    if resolved_ips.iter().any(|ip| !bsl_policy::is_public_destination(*ip)) {
        bail!("resolved IP set contains a non-public destination");
    }

    let mut config = match cli.config.as_ref() {
        Some(path) => OperatorConfig::migrate_json(&fs::read(path)?)?,
        None => OperatorConfig::default(),
    };
    config.maximum_requests = config.maximum_requests.min(cli.maximum_requests);
    config.maximum_depth = config.maximum_depth.min(cli.maximum_depth);
    config.maximum_body_bytes = config.maximum_body_bytes.min(cli.maximum_response_body_bytes);
    if !config.passive_only {
        bail!("bsl-live-scan requires passive_only operator configuration");
    }
    config.validate()?;
    authorize_probe(
        &config,
        &compiled,
        &ProbeRequest {
            probe: ProbeKind::SecurityHeaders,
            endpoint: target.to_string(),
            method: "GET".into(),
            request_cost: 1,
            capability_reference: None,
            account_partition: None,
            tenant_partition: None,
        },
        config.maximum_requests,
    )?;

    let session_manifest_sha256 = match cli.session_manifest.as_ref() {
        Some(path) => {
            let bytes = fs::read(path)?;
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
        source_kind: "bsl_live_scan_seed".into(),
    });

    let mut findings = Vec::<Finding>::new();
    let mut requests_issued = 0_u64;
    let mut total_response_bytes = 0_u64;
    let mut discovered_candidates = 0_u64;
    let mut depth_reached = 0_u16;
    let mut stop_reason = "completed".to_string();

    while let Some(candidate) = scheduler.next_candidate() {
        if requests_issued >= config.maximum_requests {
            stop_reason = "request_budget_exhausted".into();
            break;
        }
        if total_response_bytes >= cli.maximum_total_response_bytes {
            stop_reason = "response_byte_budget_exhausted".into();
            break;
        }
        let url = Url::parse(&candidate.canonical_url)?;
        let remaining = cli.maximum_total_response_bytes.saturating_sub(total_response_bytes);
        let body_limit = config.maximum_body_bytes.min(remaining);
        if body_limit == 0 {
            stop_reason = "response_byte_budget_exhausted".into();
            break;
        }

        let observation = bsl_core_live_request::execute(
            &policy_bytes,
            &url,
            cli.selected_ip,
            &resolved_ips,
            body_limit,
            now,
        )?;
        requests_issued = requests_issued.saturating_add(1);
        total_response_bytes = total_response_bytes.saturating_add(observation.body.len() as u64);
        depth_reached = depth_reached.max(candidate.depth);
        findings.extend(observation.findings);

        if candidate.depth < config.maximum_depth && !observation.body.is_empty() {
            let batch = discover_response(
                &config,
                &compiled,
                &url,
                candidate.depth,
                observation.content_type.as_deref(),
                &observation.body,
            )?;
            discovered_candidates = discovered_candidates.saturating_add(batch.candidates.len() as u64);
            scheduler.enqueue_batch(batch);
        }
    }

    let scheduler_receipt = scheduler.receipt()?;
    let coverage = CoverageSummary {
        discovered_endpoints: scheduler_receipt.seen.saturating_add(scheduler_receipt.pending),
        tested_endpoints: requests_issued,
        requests_issued,
        request_budget: config.maximum_requests,
        depth_reached,
        maximum_depth: config.maximum_depth,
        saturation_reached: scheduler_receipt.pending == 0,
    };
    let operator_findings = findings
        .iter()
        .map(OperatorFinding::from_passive)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let report = OperatorReport::build(
        &cli.run_id,
        compiled.program_name(),
        compiled.policy_snapshot_sha256(),
        &target,
        now.timestamp(),
        operator_findings,
        coverage.clone(),
        vec![
            "Only bounded passive GET/HEAD-safe discovery was executed.".into(),
            "Redirects were not followed.".into(),
            "Active probes and automatic submission remained disabled.".into(),
        ],
        StopReason::Completed,
    )?;
    let bundle = ReportBundle::build(report)?;
    let export = write_report_bundle(&cli.output_directory, &bundle)?;

    let target_origin_sha256 = hash_bytes(
        format!("https://{}:443", target.host_str().unwrap_or_default()).as_bytes(),
    );
    let mut summary = LiveScanSummary {
        version: 1,
        run_id: cli.run_id,
        policy_sha256: hash_bytes(&policy_bytes),
        target_origin_sha256,
        selected_ip: cli.selected_ip.to_string(),
        requests_issued,
        discovered_candidates,
        finding_count: findings.len() as u64,
        total_response_bytes,
        stop_reason,
        scheduler: scheduler_receipt,
        coverage,
        report_sha256: bundle.report.report_sha256.clone(),
        export_manifest_sha256: export.root_sha256,
        session_manifest_sha256,
        redirects_followed: false,
        active_probes_executed: false,
        automatic_submission: false,
        network_mode: "explicit_bounded_https".into(),
        completed_at_epoch_seconds: now.timestamp(),
        summary_sha256: String::new(),
    };
    summary.summary_sha256 = hash_serializable(&summary)?;
    fs::create_dir_all(&cli.output_directory)?;
    fs::write(
        cli.output_directory.join("live-scan-summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    println!("live_scan: completed");
    println!("requests_issued: {}", summary.requests_issued);
    println!("findings: {}", summary.finding_count);
    println!("report_sha256: {}", summary.report_sha256);
    println!("summary_sha256: {}", summary.summary_sha256);
    Ok(())
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

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String> {
    Ok(hash_bytes(&serde_json::to_vec(value)?))
}

mod bsl_core_live_request {
    use super::*;
    use bsl_executor::ExecutionControl;
    use bsl_gateway::{DecisionOutcome, RequestIntent, ScopeGateway};
    use bsl_live_adapter::{LiveAdapterConfig, LivePassivePipeline, LivePassiveRequest, PassiveMethod};
    use bsl_passive_analyzers::{
        CachePolicyAnalyzer, CookieSecurityAnalyzer, HeaderSecurityAnalyzer, ObservedHeader,
        PassiveAnalyzer, ResponseObservation,
    };
    use bsl_pinned_transport::PinnedTransportCoordinator;
    use bsl_stream::StreamControl;
    use bsl_transport::{ConnectionAttempt, TransportScheme};
    use std::time::Duration;

    pub struct Observation {
        pub findings: Vec<Finding>,
        pub content_type: Option<String>,
        pub body: Vec<u8>,
    }

    pub fn execute(
        policy_bytes: &[u8],
        target: &Url,
        selected_ip: IpAddr,
        resolved_ips: &BTreeSet<IpAddr>,
        maximum_body_bytes: u64,
        now: DateTime<Utc>,
    ) -> Result<Observation> {
        let policy_text = std::str::from_utf8(policy_bytes)?;
        let compiled = TargetPolicy::from_toml(policy_text)?.compile(now)?;
        let gateway = ScopeGateway::new(compiled, 1)?;
        let mut transport = PinnedTransportCoordinator::new(gateway);
        let intent = RequestIntent {
            url: target.clone(),
            method: "GET".into(),
            resolved_ips: resolved_ips.iter().copied().collect(),
            redirect_depth: 0,
            dns_context_id: "bsl-live-scan-dns".into(),
            dns_resolver_id: "operator-pinned".into(),
            dns_ttl_seconds: 60,
        };
        let authorization = transport.authorize_connection(&intent, selected_ip, Duration::ZERO)?;
        if authorization.decision.outcome != DecisionOutcome::Allow {
            bail!("scope gateway denied live-scan request");
        }
        let ticket = authorization.ticket.context("authorized request produced no ticket")?;
        let attempt = ConnectionAttempt {
            ticket_id: ticket.ticket_id.clone(),
            dns_context_id: ticket.dns_context_id.clone(),
            scheme: TransportScheme::Https,
            remote_ip: ticket.selected_ip,
            port: ticket.port,
            sni: ticket.sni.clone(),
            http_host: ticket.http_host.clone(),
            redirect_depth: ticket.redirect_depth,
        };
        let mut config = LiveAdapterConfig::conservative("bsl-live-scan")?;
        config.limits.http.maximum_response_body_bytes = maximum_body_bytes;
        config.validate()?;
        let mut pipeline = LivePassivePipeline::new(transport, config)?;
        let request = LivePassiveRequest::new(PassiveMethod::Get, target.path().to_string())?;
        let result = pipeline.execute(
            attempt,
            Duration::ZERO,
            request,
            ExecutionControl::default(),
            StreamControl::default(),
        )?;
        let exchange = result.exchange.context("live scan produced no HTTP exchange")?;
        let headers = exchange
            .response
            .headers
            .iter()
            .map(|header| ObservedHeader::new(header.name.clone(), header.value.clone()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let observation = ResponseObservation {
            url: target.clone(),
            status: exchange.response.status_code,
            authenticated: false,
            headers,
            body_sha256: hash_bytes(&exchange.response.body),
            body_bytes: exchange.response.body.len() as u64,
            tls: None,
        };
        observation.validate()?;
        let mut findings = Vec::new();
        for analyzer in [
            &HeaderSecurityAnalyzer as &dyn PassiveAnalyzer,
            &CookieSecurityAnalyzer,
            &CachePolicyAnalyzer,
        ] {
            findings.extend(analyzer.analyze(&observation)?);
        }
        let content_type = exchange
            .response
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .and_then(|header| String::from_utf8(header.value.clone()).ok());
        Ok(Observation { findings, content_type, body: exchange.response.body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_fixture_is_available_for_signed_live_testing() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[31_u8; 32]).unwrap();
        assert_eq!(key_pair.public_key().as_ref().len(), 32);
    }
}
