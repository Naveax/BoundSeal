use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use nxb_executor::ExecutionControl;
use nxb_gateway::{DecisionOutcome, RequestIntent, ScopeGateway};
use nxb_live_adapter::{
    LiveAdapterConfig, LivePassivePipeline, LivePassiveRequest, PassiveMethod,
};
use nxb_passive_analyzers::{
    CachePolicyAnalyzer, CookieSecurityAnalyzer, Finding, HeaderSecurityAnalyzer, ObservedHeader,
    PassiveAnalyzer, ResponseObservation,
};
use nxb_pinned_transport::PinnedTransportCoordinator;
use nxb_policy::TargetPolicy;
use nxb_stream::StreamControl;
use nxb_transport::{ConnectionAttempt, TransportScheme};
use url::Url;

use super::{hash_bytes, validate_request_target, validate_target_url, PlannedMethod};

#[derive(Debug, Clone)]
pub struct DiscoverySessionRequestSpec {
    pub target_url: Url,
    pub method: PlannedMethod,
    pub selected_ip: IpAddr,
    pub resolved_ips: BTreeSet<IpAddr>,
    pub dns_context_id: String,
    pub dns_resolver_id: String,
    pub dns_ttl_seconds: u32,
    pub maximum_response_body_bytes: u64,
}

impl DiscoverySessionRequestSpec {
    pub fn validate(&self) -> Result<()> {
        let validated = validate_target_url(self.target_url.as_str())?;
        if validated != self.target_url {
            bail!("discovery-session request URL is not canonical");
        }
        if self.resolved_ips.is_empty()
            || !self.resolved_ips.contains(&self.selected_ip)
            || self
                .resolved_ips
                .iter()
                .any(|ip| !nxb_policy::is_public_destination(*ip))
        {
            bail!("discovery-session DNS binding is empty, non-public, or inconsistent");
        }
        if self.dns_context_id.is_empty()
            || self.dns_resolver_id.is_empty()
            || self.dns_ttl_seconds == 0
            || self.dns_ttl_seconds > 86_400
        {
            bail!("discovery-session DNS metadata is invalid");
        }
        if self.maximum_response_body_bytes == 0
            || self.maximum_response_body_bytes > 8 * 1024 * 1024
        {
            bail!("discovery-session response body limit is invalid");
        }
        validate_request_target(if self.target_url.path().is_empty() {
            "/"
        } else {
            self.target_url.path()
        })?;
        Ok(())
    }

    fn request_target(&self) -> Result<String> {
        self.validate()?;
        Ok(if self.target_url.path().is_empty() {
            "/".to_string()
        } else {
            self.target_url.path().to_string()
        })
    }
}

#[derive(Debug)]
pub struct DiscoverySessionRequestObservation {
    pub findings: Vec<Finding>,
    pub response_status: u16,
    pub response_content_type: Option<Vec<u8>>,
    pub response_body: Vec<u8>,
    pub response_body_sha256: String,
    pub live_receipt_sha256: String,
    pub redirect_observed: bool,
}

pub fn execute_discovery_session_request(
    policy_bytes: &[u8],
    spec: &DiscoverySessionRequestSpec,
    now: DateTime<Utc>,
) -> Result<DiscoverySessionRequestObservation> {
    spec.validate()?;
    let policy_text = std::str::from_utf8(policy_bytes).context("policy file is not UTF-8")?;
    let compiled = TargetPolicy::from_toml(policy_text)?
        .compile(now)
        .context("policy could not be compiled for discovery-session request")?;

    let gateway = ScopeGateway::new(compiled, 1)?;
    let mut transport = PinnedTransportCoordinator::new(gateway);
    let intent = RequestIntent {
        url: spec.target_url.clone(),
        method: spec.method.code().to_string(),
        resolved_ips: spec.resolved_ips.iter().copied().collect(),
        redirect_depth: 0,
        dns_context_id: spec.dns_context_id.clone(),
        dns_resolver_id: spec.dns_resolver_id.clone(),
        dns_ttl_seconds: spec.dns_ttl_seconds,
    };
    let authorization = transport.authorize_connection(&intent, spec.selected_ip, Duration::ZERO)?;
    if authorization.decision.outcome != DecisionOutcome::Allow {
        bail!(
            "scope gateway denied discovery-session request: {:?}",
            authorization.decision.reason
        );
    }
    let ticket = authorization
        .ticket
        .context("authorized discovery-session request did not produce a ticket")?;
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

    let mut config = LiveAdapterConfig::conservative("nxb-discovery-session")?;
    config.limits.http.maximum_response_body_bytes = spec.maximum_response_body_bytes;
    config.limits.http.maximum_chunk_bytes = config
        .limits
        .http
        .maximum_chunk_bytes
        .min(spec.maximum_response_body_bytes);
    config.limits.http.maximum_response_wire_bytes = spec
        .maximum_response_body_bytes
        .saturating_add(config.limits.http.maximum_response_header_bytes)
        .saturating_add(config.limits.http.maximum_trailer_bytes)
        .saturating_add(64 * 1024);
    config.validate()?;

    let mut pipeline = LivePassivePipeline::new(transport, config)?;
    let method = match spec.method {
        PlannedMethod::Get => PassiveMethod::Get,
        PlannedMethod::Head => PassiveMethod::Head,
    };
    let request = LivePassiveRequest::new(method, spec.request_target()?)?;
    let result = pipeline.execute(
        attempt,
        Duration::ZERO,
        request,
        ExecutionControl::default(),
        StreamControl::default(),
    )?;
    let live_receipt = result
        .receipt
        .as_ref()
        .context("discovery-session request did not produce a completed receipt")?;
    live_receipt.verify()?;
    let exchange = result
        .exchange
        .as_ref()
        .context("discovery-session request did not produce an HTTP exchange")?;

    let response_body = exchange.response.body.clone();
    if response_body.len() as u64 != live_receipt.response_body_bytes
        || response_body.len() as u64 > spec.maximum_response_body_bytes
        || hash_bytes(&response_body) != live_receipt.response_body_sha256
    {
        bail!("discovery-session response does not match its bounded HTTP receipt");
    }
    let mut content_types = exchange
        .response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-type"));
    let response_content_type = content_types.next().map(|header| header.value.clone());
    if content_types.next().is_some() {
        bail!("multiple Content-Type headers are outside the discovery-session contract");
    }

    let headers = exchange
        .response
        .headers
        .iter()
        .map(|header| ObservedHeader::new(header.name.clone(), header.value.clone()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let observation = ResponseObservation {
        url: spec.target_url.clone(),
        status: exchange.response.status_code,
        authenticated: false,
        headers,
        body_sha256: live_receipt.response_body_sha256.clone(),
        body_bytes: live_receipt.response_body_bytes,
        tls: None,
    };
    observation.validate()?;

    let mut findings = BTreeMap::new();
    for analyzer in [
        &HeaderSecurityAnalyzer as &dyn PassiveAnalyzer,
        &CookieSecurityAnalyzer,
        &CachePolicyAnalyzer,
    ] {
        for finding in analyzer.analyze(&observation)? {
            findings
                .entry(finding.finding_id.clone())
                .or_insert(finding);
        }
    }

    Ok(DiscoverySessionRequestObservation {
        findings: findings.into_values().collect(),
        response_status: exchange.response.status_code,
        response_content_type,
        response_body,
        response_body_sha256: live_receipt.response_body_sha256.clone(),
        live_receipt_sha256: live_receipt.receipt_sha256.clone(),
        redirect_observed: live_receipt.redirect_observed,
    })
}
