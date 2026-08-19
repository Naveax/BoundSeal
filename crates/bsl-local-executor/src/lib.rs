use std::time::Duration;

use bsl_executor::{
    ExecutionControl, ExecutionLimits, ExecutionReceipt, ExecutorError, PermitBackend,
    PermitExecutor,
};
use bsl_pinned_transport::{PinnedTransportCoordinator, PinnedTransportError};
use bsl_transport::{ConnectionAttempt, TicketUseOutcome, TicketUseResult};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalExecutionResult {
    pub ticket_use: TicketUseResult,
    pub execution_receipt: Option<ExecutionReceipt>,
    pub transport_audit_anchor: String,
}

#[derive(Debug)]
pub struct LocalExecutionPipeline<B> {
    transport: PinnedTransportCoordinator,
    executor: PermitExecutor<B>,
}

impl<B: PermitBackend> LocalExecutionPipeline<B> {
    pub fn new(transport: PinnedTransportCoordinator, executor: PermitExecutor<B>) -> Self {
        Self {
            transport,
            executor,
        }
    }

    pub fn consume_and_execute(
        &mut self,
        attempt: ConnectionAttempt,
        elapsed: Duration,
        limits: ExecutionLimits,
        control: ExecutionControl,
    ) -> Result<LocalExecutionResult, LocalExecutionError> {
        let ticket_use = self.transport.consume_connection_ticket(attempt, elapsed)?;
        let transport_audit_anchor = self.transport.transport_audit().tail_hash().to_string();

        if ticket_use.outcome != TicketUseOutcome::Consumed {
            return Ok(LocalExecutionResult {
                ticket_use,
                execution_receipt: None,
                transport_audit_anchor,
            });
        }

        let Some(permit) = ticket_use.permit.as_ref() else {
            self.transport.complete_request();
            return Err(LocalExecutionError::ConsumedTicketMissingPermit);
        };

        let execution = self
            .executor
            .execute(permit, &transport_audit_anchor, limits, control);

        // A successful ticket consumption owns exactly one in-flight gateway budget slot.
        // Every terminal executor result, including an executor error, releases it once.
        self.transport.complete_request();

        let execution_receipt = execution?;
        Ok(LocalExecutionResult {
            ticket_use,
            execution_receipt: Some(execution_receipt),
            transport_audit_anchor,
        })
    }

    pub fn transport(&self) -> &PinnedTransportCoordinator {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut PinnedTransportCoordinator {
        &mut self.transport
    }

    pub fn executor(&self) -> &PermitExecutor<B> {
        &self.executor
    }

    pub fn executor_mut(&mut self) -> &mut PermitExecutor<B> {
        &mut self.executor
    }

    pub fn into_parts(self) -> (PinnedTransportCoordinator, PermitExecutor<B>) {
        (self.transport, self.executor)
    }
}

#[derive(Debug, Error)]
pub enum LocalExecutionError {
    #[error("pinned transport rejected local execution: {0}")]
    Transport(#[from] PinnedTransportError),
    #[error("permit executor rejected local execution: {0}")]
    Executor(#[from] ExecutorError),
    #[error("a consumed ticket did not contain a transport permit")]
    ConsumedTicketMissingPermit,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bsl_executor::{ExecutionOutcome, ExecutorConfig, SyntheticBackend, SyntheticScenario};
    use bsl_gateway::{RequestIntent, ScopeGateway};
    use bsl_policy::{
        AuthorizationPolicy, AutomationPolicy, ProgramPolicy, ScopePolicy, TargetPolicy,
    };
    use bsl_transport::{ConnectionAttempt, ConnectionTicket, TicketUseOutcome};
    use chrono::{Duration as ChronoDuration, Utc};

    use super::*;

    fn transport() -> PinnedTransportCoordinator {
        let policy = TargetPolicy {
            schema_version: 1,
            program: ProgramPolicy {
                name: "Example".into(),
                platform: "hackerone".into(),
                policy_url: None,
            },
            scope: ScopePolicy {
                include_hosts: BTreeSet::from(["app.example.com".into()]),
                exclude_hosts: BTreeSet::new(),
                allowed_schemes: BTreeSet::from(["https".into()]),
                allowed_methods: BTreeSet::from(["GET".into()]),
                allow_subdomains: false,
            },
            automation: AutomationPolicy {
                active_testing: false,
                credential_bruteforce: false,
                destructive_testing: false,
                oob_callbacks: false,
                max_requests_per_second: 4.0,
                max_concurrency: 4,
                max_total_requests: 10,
            },
            authorization: AuthorizationPolicy {
                confirmed: true,
                researcher: "naveax".into(),
                policy_snapshot_sha256: "a".repeat(64),
                expires_at: Utc::now() + ChronoDuration::days(1),
            },
        }
        .compile(Utc::now())
        .unwrap();
        PinnedTransportCoordinator::new(ScopeGateway::new(policy, 5).unwrap())
    }

    fn intent() -> RequestIntent {
        RequestIntent {
            url: url::Url::parse("https://app.example.com/api/me").unwrap(),
            method: "GET".into(),
            resolved_ips: vec!["1.1.1.1".parse().unwrap()],
            redirect_depth: 0,
            dns_context_id: "navigation-1".into(),
            dns_resolver_id: "system-resolver".into(),
            dns_ttl_seconds: 60,
        }
    }

    fn attempt(ticket: &ConnectionTicket) -> ConnectionAttempt {
        ConnectionAttempt {
            ticket_id: ticket.ticket_id.clone(),
            dns_context_id: ticket.dns_context_id.clone(),
            scheme: ticket.scheme,
            remote_ip: ticket.selected_ip,
            port: ticket.port,
            sni: ticket.sni.clone(),
            http_host: ticket.http_host.clone(),
            redirect_depth: ticket.redirect_depth,
        }
    }

    fn pipeline(scenario: SyntheticScenario) -> LocalExecutionPipeline<SyntheticBackend> {
        let executor = PermitExecutor::new(
            ExecutorConfig {
                executor_id: "local-fixture-1".into(),
            },
            SyntheticBackend::new([scenario]),
        )
        .unwrap();
        LocalExecutionPipeline::new(transport(), executor)
    }

    fn authorize_ticket(
        pipeline: &mut LocalExecutionPipeline<SyntheticBackend>,
    ) -> ConnectionTicket {
        pipeline
            .transport_mut()
            .authorize_connection(&intent(), "1.1.1.1".parse().unwrap(), Duration::ZERO)
            .unwrap()
            .ticket
            .unwrap()
    }

    #[test]
    fn successful_execution_releases_gateway_budget_once() {
        let mut pipeline = pipeline(SyntheticScenario::success(1, 5, 32, 8));
        let ticket = authorize_ticket(&mut pipeline);
        assert_eq!(pipeline.transport().gateway().in_flight_requests(), 1);

        let result = pipeline
            .consume_and_execute(
                attempt(&ticket),
                Duration::from_millis(1),
                ExecutionLimits::default(),
                ExecutionControl::default(),
            )
            .unwrap();

        assert_eq!(
            result.execution_receipt.unwrap().outcome,
            ExecutionOutcome::Completed
        );
        assert_eq!(pipeline.transport().gateway().in_flight_requests(), 0);
        pipeline.executor().audit().verify().unwrap();
    }

    #[test]
    fn backend_failure_still_releases_gateway_budget() {
        let mut pipeline = pipeline(SyntheticScenario::failure("connection_reset", 3));
        let ticket = authorize_ticket(&mut pipeline);
        let result = pipeline
            .consume_and_execute(
                attempt(&ticket),
                Duration::from_millis(1),
                ExecutionLimits::default(),
                ExecutionControl::default(),
            )
            .unwrap();

        assert!(matches!(
            result.execution_receipt.unwrap().outcome,
            ExecutionOutcome::BackendFailure { .. }
        ));
        assert_eq!(pipeline.transport().gateway().in_flight_requests(), 0);
    }

    #[test]
    fn cancellation_releases_budget_without_backend_use() {
        let mut pipeline = pipeline(SyntheticScenario::success(1, 1, 1, 1));
        let ticket = authorize_ticket(&mut pipeline);
        let result = pipeline
            .consume_and_execute(
                attempt(&ticket),
                Duration::from_millis(1),
                ExecutionLimits::default(),
                ExecutionControl {
                    cancel_requested: true,
                    emergency_stop_requested: false,
                },
            )
            .unwrap();

        assert_eq!(
            result.execution_receipt.unwrap().outcome,
            ExecutionOutcome::Cancelled
        );
        assert_eq!(pipeline.transport().gateway().in_flight_requests(), 0);
        assert!(pipeline
            .executor()
            .backend()
            .observed_endpoints()
            .is_empty());
    }

    #[test]
    fn mismatched_ticket_does_not_invoke_executor_or_double_release() {
        let mut pipeline = pipeline(SyntheticScenario::success(1, 1, 1, 1));
        let ticket = authorize_ticket(&mut pipeline);
        let mut wrong = attempt(&ticket);
        wrong.port = 444;

        let result = pipeline
            .consume_and_execute(
                wrong,
                Duration::from_millis(1),
                ExecutionLimits::default(),
                ExecutionControl::default(),
            )
            .unwrap();

        assert!(matches!(
            result.ticket_use.outcome,
            TicketUseOutcome::BindingMismatch { .. }
        ));
        assert!(result.execution_receipt.is_none());
        assert_eq!(pipeline.transport().gateway().in_flight_requests(), 0);
        assert!(pipeline
            .executor()
            .backend()
            .observed_endpoints()
            .is_empty());
    }

    #[test]
    fn executor_audit_is_anchored_to_transport_consumption_record() {
        let mut pipeline = pipeline(SyntheticScenario::success(1, 2, 3, 4));
        let ticket = authorize_ticket(&mut pipeline);
        let result = pipeline
            .consume_and_execute(
                attempt(&ticket),
                Duration::from_millis(1),
                ExecutionLimits::default(),
                ExecutionControl::default(),
            )
            .unwrap();

        let receipt = result.execution_receipt.unwrap();
        assert_eq!(
            receipt.transport_audit_anchor,
            result.transport_audit_anchor
        );
        assert_eq!(
            pipeline.executor().audit().records()[0]
                .event
                .transport_audit_anchor,
            pipeline.transport().transport_audit().tail_hash()
        );
    }
}
