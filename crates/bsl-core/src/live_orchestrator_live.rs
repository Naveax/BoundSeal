#[cfg(feature = "live-network")]
mod live_execution {
    use std::{
        collections::BTreeMap,
        fs::{self, OpenOptions},
        io::Write,
        path::Path,
        time::Duration,
    };

    use anyhow::{bail, Context, Result};
    use chrono::{DateTime, Utc};
    use bsl_executor::ExecutionControl;
    use bsl_gateway::{DecisionOutcome, RequestIntent, ScopeGateway};
    use bsl_live_adapter::{
        LiveAdapterConfig, LivePassivePipeline, LivePassiveRequest, PassiveMethod,
    };
    use bsl_passive_analyzers::{
        CachePolicyAnalyzer, CookieSecurityAnalyzer, Finding, HeaderSecurityAnalyzer,
        ObservedHeader, PassiveAnalyzer, ResponseObservation,
    };
    use bsl_pinned_transport::PinnedTransportCoordinator;
    use bsl_policy::TargetPolicy;
    use bsl_stream::StreamControl;
    use bsl_transport::{ConnectionAttempt, TransportScheme};

    use super::{
        hash_bytes, hash_serializable, LiveActivationCertificate, LiveOrchestratorReceipt,
        LiveRunPlan, PlannedMethod,
    };

    #[derive(Debug, serde::Serialize)]
    struct ActivationUseMarker {
        activation_id_sha256: String,
        activation_certificate_sha256: String,
        plan_sha256: String,
        consumed_at_epoch_seconds: i64,
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct LiveRunObservation {
        pub receipt: LiveOrchestratorReceipt,
        pub findings: Vec<Finding>,
        pub response_status: u16,
        pub response_content_type: Option<Vec<u8>>,
        pub response_body: Vec<u8>,
    }

    #[allow(dead_code)]
    pub fn execute_live_run(
        policy_bytes: &[u8],
        plan: &LiveRunPlan,
        activation: &LiveActivationCertificate,
        public_key: &[u8],
        state_directory: &Path,
        now: DateTime<Utc>,
    ) -> Result<(LiveOrchestratorReceipt, Vec<Finding>)> {
        let observation = execute_live_run_observed(
            policy_bytes,
            plan,
            activation,
            public_key,
            state_directory,
            now,
        )?;
        Ok((observation.receipt, observation.findings))
    }

    pub fn execute_live_run_observed(
        policy_bytes: &[u8],
        plan: &LiveRunPlan,
        activation: &LiveActivationCertificate,
        public_key: &[u8],
        state_directory: &Path,
        now: DateTime<Utc>,
    ) -> Result<LiveRunObservation> {
        plan.verify(now)?;
        activation.verify(plan, public_key, now)?;
        if hash_bytes(policy_bytes) != plan.policy_sha256 {
            bail!("policy file does not match signed live-plan");
        }

        let policy_text =
            std::str::from_utf8(policy_bytes).context("policy file is not UTF-8")?;
        let compiled = TargetPolicy::from_toml(policy_text)?
            .compile(now)
            .context("policy could not be compiled for live run")?;
        let target_url = plan.parsed_url()?;

        let activation_certificate_sha256 = activation.certificate_sha256()?;
        consume_activation_once(
            state_directory,
            activation,
            &activation_certificate_sha256,
            plan,
            now,
        )?;

        let gateway = ScopeGateway::new(compiled, 1)?;
        let mut transport = PinnedTransportCoordinator::new(gateway);
        let intent = RequestIntent {
            url: target_url.clone(),
            method: plan.method.code().to_string(),
            resolved_ips: plan.resolved_ips.iter().copied().collect(),
            redirect_depth: 0,
            dns_context_id: plan.dns_context_id.clone(),
            dns_resolver_id: plan.dns_resolver_id.clone(),
            dns_ttl_seconds: plan.dns_ttl_seconds,
        };
        let authorization =
            transport.authorize_connection(&intent, plan.selected_ip, Duration::ZERO)?;
        if authorization.decision.outcome != DecisionOutcome::Allow {
            bail!(
                "scope gateway denied live request: {:?}",
                authorization.decision.reason
            );
        }
        let ticket = authorization
            .ticket
            .context("authorized request did not produce a ticket")?;
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

        let config = LiveAdapterConfig::conservative("bsl-cli-live-orchestrator")?;
        let mut pipeline = LivePassivePipeline::new(transport, config)?;
        let method = match plan.method {
            PlannedMethod::Get => PassiveMethod::Get,
            PlannedMethod::Head => PassiveMethod::Head,
        };
        let request = LivePassiveRequest::new(method, plan.request_target()?)?;
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
            .context("live adapter did not produce a completed receipt")?;
        live_receipt.verify()?;
        let exchange = result
            .exchange
            .as_ref()
            .context("live adapter did not produce an HTTP exchange")?;

        let response_body = exchange.response.body.clone();
        if response_body.len() as u64 != live_receipt.response_body_bytes
            || hash_bytes(&response_body) != live_receipt.response_body_sha256
        {
            bail!("live response body does not match the verified HTTP receipt");
        }
        let mut content_types = exchange
            .response
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("content-type"));
        let response_content_type = content_types.next().map(|header| header.value.clone());
        if content_types.next().is_some() {
            bail!("multiple Content-Type headers are outside the live operator bridge contract");
        }

        let headers = exchange
            .response
            .headers
            .iter()
            .map(|header| ObservedHeader::new(header.name.clone(), header.value.clone()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let observation = ResponseObservation {
            url: target_url,
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
        let findings = findings.into_values().collect::<Vec<_>>();
        let finding_ids = findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<Vec<_>>();

        let mut receipt = LiveOrchestratorReceipt {
            version: 1,
            run_id: plan.run_id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            activation_id: activation.payload.activation_id.clone(),
            activation_certificate_sha256,
            policy_sha256: plan.policy_sha256.clone(),
            target_origin_sha256: plan.target_origin_sha256.clone(),
            selected_ip: plan.selected_ip.to_string(),
            method: plan.method.code().to_string(),
            live_receipt_sha256: live_receipt.receipt_sha256.clone(),
            finding_count: finding_ids.len() as u64,
            finding_ids,
            redirect_observed: live_receipt.redirect_observed,
            completed_at_epoch_seconds: now.timestamp(),
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = hash_serializable(&receipt)?;
        receipt.verify()?;
        Ok(LiveRunObservation {
            receipt,
            findings,
            response_status: exchange.response.status_code,
            response_content_type,
            response_body,
        })
    }

    fn consume_activation_once(
        state_directory: &Path,
        activation: &LiveActivationCertificate,
        certificate_sha256: &str,
        plan: &LiveRunPlan,
        now: DateTime<Utc>,
    ) -> Result<()> {
        fs::create_dir_all(state_directory).with_context(|| {
            format!(
                "could not create live state directory {}",
                state_directory.display()
            )
        })?;
        let activation_id_sha256 = hash_bytes(activation.payload.activation_id.as_bytes());
        let marker_path = state_directory.join(format!(
            "activation-{activation_id_sha256}.used.json"
        ));
        let marker = ActivationUseMarker {
            activation_id_sha256,
            activation_certificate_sha256: certificate_sha256.to_string(),
            plan_sha256: plan.plan_sha256.clone(),
            consumed_at_epoch_seconds: now.timestamp(),
        };
        let bytes = serde_json::to_vec_pretty(&marker)
            .context("could not serialize activation-use marker")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker_path)
            .with_context(|| {
                format!(
                    "activation was already used or marker could not be created: {}",
                    marker_path.display()
                )
            })?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
}

#[cfg(feature = "live-network")]
#[allow(unused_imports)]
pub use live_execution::{execute_live_run, execute_live_run_observed, LiveRunObservation};
