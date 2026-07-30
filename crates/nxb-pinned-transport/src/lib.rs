use std::{collections::BTreeSet, net::IpAddr, time::Duration};

use nxb_gateway::{DecisionOutcome, GatewayDecision, GatewayError, RequestIntent, ScopeGateway};
use nxb_transport::{
    expected_http_host, ConnectionAttempt, ConnectionTicket, TicketAuthority, TicketBinding,
    TicketIssueError, TicketIssueRequest, TicketUseOutcome, TicketUseResult, TransportScheme,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const DEFAULT_TICKET_TTL_MILLISECONDS: u64 = 5_000;
pub const TRANSPORT_AUDIT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionAuthorization {
    pub decision: GatewayDecision,
    pub ticket: Option<ConnectionTicket>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportAuditEvent {
    pub event_id: String,
    pub action: String,
    pub status: String,
    pub reason: String,
    pub gateway_audit_anchor: String,
    pub ticket_id: Option<String>,
    pub decision_id: Option<String>,
    pub binding_hash: Option<String>,
    pub dns_context_id: String,
    pub host: String,
    pub scheme: String,
    pub selected_ip: String,
    pub port: u16,
    pub sni: Option<String>,
    pub http_host: String,
    pub redirect_depth: u8,
    pub elapsed_milliseconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: TransportAuditEvent,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct TransportAuditChain {
    records: Vec<TransportAuditRecord>,
    tail_hash: String,
    next_event_id: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransportAuditError {
    #[error("transport audit material could not be serialized: {0}")]
    Serialization(String),
    #[error("transport audit sequence mismatch at record {record_index}")]
    SequenceMismatch { record_index: usize },
    #[error("transport audit previous-hash mismatch at record {record_index}")]
    PreviousHashMismatch { record_index: usize },
    #[error("transport audit record-hash mismatch at record {record_index}")]
    RecordHashMismatch { record_index: usize },
    #[error("transport audit tail hash does not match the final record")]
    TailHashMismatch,
}

#[derive(Debug, Error)]
pub enum PinnedTransportError {
    #[error("gateway rejected the coordinator operation: {0}")]
    Gateway(#[from] GatewayError),
    #[error("transport ticket could not be issued: {0}")]
    Ticket(#[from] TicketIssueError),
    #[error("transport audit record could not be committed: {0}")]
    Audit(#[from] TransportAuditError),
    #[error("selected transport IP was not present in the gateway DNS observation")]
    SelectedIpNotResolved,
    #[error("authorized URL did not contain a DNS host")]
    MissingHost,
    #[error("authorized URL did not contain a usable port")]
    MissingPort,
    #[error("authorized URL used an unsupported transport scheme")]
    UnsupportedScheme,
}

#[derive(Debug)]
pub struct PinnedTransportCoordinator {
    gateway: ScopeGateway,
    tickets: TicketAuthority,
    audit: TransportAuditChain,
    ticket_ttl_milliseconds: u64,
}

impl Default for TransportAuditChain {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportAuditChain {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            tail_hash: TRANSPORT_AUDIT_GENESIS_HASH.into(),
            next_event_id: 1,
        }
    }

    pub fn allocate_event_id(&mut self) -> String {
        let value = self.next_event_id;
        self.next_event_id = self.next_event_id.saturating_add(1);
        format!("transport-event-{value:020}")
    }

    pub fn append(
        &mut self,
        event: TransportAuditEvent,
    ) -> Result<&TransportAuditRecord, TransportAuditError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = transport_record_hash(sequence, &previous_hash, &event)?;
        self.records.push(TransportAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self
            .records
            .last()
            .expect("a transport audit record was appended before lookup"))
    }

    pub fn records(&self) -> &[TransportAuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn verify(&self) -> Result<(), TransportAuditError> {
        let mut expected_previous = TRANSPORT_AUDIT_GENESIS_HASH.to_string();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(TransportAuditError::SequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != expected_previous {
                return Err(TransportAuditError::PreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected_hash =
                transport_record_hash(record.sequence, &record.previous_hash, &record.event)?;
            if record.record_hash != expected_hash {
                return Err(TransportAuditError::RecordHashMismatch {
                    record_index: index,
                });
            }
            expected_previous = expected_hash;
        }
        if self.tail_hash != expected_previous {
            return Err(TransportAuditError::TailHashMismatch);
        }
        Ok(())
    }
}

impl PinnedTransportCoordinator {
    pub fn new(gateway: ScopeGateway) -> Self {
        Self {
            gateway,
            tickets: TicketAuthority::new(),
            audit: TransportAuditChain::new(),
            ticket_ttl_milliseconds: DEFAULT_TICKET_TTL_MILLISECONDS,
        }
    }

    pub fn authorize_connection(
        &mut self,
        intent: &RequestIntent,
        selected_ip: IpAddr,
        elapsed: Duration,
    ) -> Result<ConnectionAuthorization, PinnedTransportError> {
        if !intent.resolved_ips.contains(&selected_ip) {
            let anchor = self.gateway.audit_chain().tail_hash().to_string();
            let event_id = self.audit.allocate_event_id();
            self.audit.append(TransportAuditEvent {
                event_id,
                action: "issue".into(),
                status: "rejected".into(),
                reason: "selected_ip_not_resolved".into(),
                gateway_audit_anchor: anchor,
                ticket_id: None,
                decision_id: None,
                binding_hash: None,
                dns_context_id: sanitize_identifier(&intent.dns_context_id),
                host: intent
                    .url
                    .host_str()
                    .unwrap_or("[missing]")
                    .to_ascii_lowercase(),
                scheme: intent.url.scheme().to_ascii_lowercase(),
                selected_ip: selected_ip.to_string(),
                port: intent.url.port_or_known_default().unwrap_or(0),
                sni: None,
                http_host: "[not_issued]".into(),
                redirect_depth: intent.redirect_depth,
                elapsed_milliseconds: duration_milliseconds_saturated(elapsed),
            })?;
            return Err(PinnedTransportError::SelectedIpNotResolved);
        }

        let decision = self.gateway.authorize(intent, elapsed)?;
        if decision.outcome == DecisionOutcome::Deny {
            return Ok(ConnectionAuthorization {
                decision,
                ticket: None,
            });
        }

        let host = intent
            .url
            .host_str()
            .ok_or(PinnedTransportError::MissingHost)?
            .to_ascii_lowercase();
        let scheme = match intent.url.scheme() {
            "http" => TransportScheme::Http,
            "https" => TransportScheme::Https,
            _ => {
                self.gateway.complete_request();
                return Err(PinnedTransportError::UnsupportedScheme);
            }
        };
        let port = intent
            .url
            .port_or_known_default()
            .ok_or(PinnedTransportError::MissingPort)?;
        let sni = match scheme {
            TransportScheme::Http => None,
            TransportScheme::Https => Some(host.clone()),
        };
        let audit_anchor = self.gateway.audit_chain().tail_hash().to_string();
        let issue = TicketIssueRequest {
            binding: TicketBinding {
                decision_id: decision.decision_id.clone(),
                dns_context_id: intent.dns_context_id.clone(),
                host: host.clone(),
                scheme,
                port,
                sni: sni.clone(),
                http_host: expected_http_host(&host, scheme, port),
                pinned_addresses: intent.resolved_ips.iter().copied().collect::<BTreeSet<_>>(),
                selected_ip,
                redirect_depth: intent.redirect_depth,
            },
            issued_at_milliseconds: duration_milliseconds_saturated(elapsed),
            ttl_milliseconds: self.ticket_ttl_milliseconds,
            audit_anchor: audit_anchor.clone(),
        };

        let ticket = match self.tickets.issue(issue) {
            Ok(ticket) => ticket,
            Err(error) => {
                self.gateway.complete_request();
                return Err(error.into());
            }
        };
        self.append_issue_event(intent, &ticket, audit_anchor, elapsed)?;
        Ok(ConnectionAuthorization {
            decision,
            ticket: Some(ticket),
        })
    }

    pub fn consume_connection_ticket(
        &mut self,
        attempt: ConnectionAttempt,
        elapsed: Duration,
    ) -> Result<TicketUseResult, PinnedTransportError> {
        let result = self
            .tickets
            .consume(attempt, duration_milliseconds_saturated(elapsed));
        self.append_use_event(&result, elapsed)?;
        if matches!(
            result.outcome,
            TicketUseOutcome::Expired
                | TicketUseOutcome::ClockRegression
                | TicketUseOutcome::BindingMismatch { .. }
        ) {
            self.gateway.complete_request();
        }
        Ok(result)
    }

    pub fn complete_request(&mut self) {
        self.gateway.complete_request();
    }

    pub fn release_context(&mut self, context_id: &str) -> (usize, usize) {
        let revoked = self.tickets.revoke_context(context_id);
        for _ in 0..revoked {
            self.gateway.complete_request();
        }
        let dns_pins = self.gateway.release_dns_context(context_id);
        (dns_pins, revoked)
    }

    pub fn gateway(&self) -> &ScopeGateway {
        &self.gateway
    }

    pub fn transport_audit(&self) -> &TransportAuditChain {
        &self.audit
    }

    pub fn ticket(&self, ticket_id: &str) -> Option<&ConnectionTicket> {
        self.tickets.ticket(ticket_id)
    }

    fn append_issue_event(
        &mut self,
        intent: &RequestIntent,
        ticket: &ConnectionTicket,
        gateway_audit_anchor: String,
        elapsed: Duration,
    ) -> Result<(), TransportAuditError> {
        let event_id = self.audit.allocate_event_id();
        self.audit.append(TransportAuditEvent {
            event_id,
            action: "issue".into(),
            status: "issued".into(),
            reason: "gateway_authorized".into(),
            gateway_audit_anchor,
            ticket_id: Some(ticket.ticket_id.clone()),
            decision_id: Some(ticket.decision_id.clone()),
            binding_hash: Some(ticket.binding_hash.clone()),
            dns_context_id: ticket.dns_context_id.clone(),
            host: ticket.host.clone(),
            scheme: ticket.scheme.code().into(),
            selected_ip: ticket.selected_ip.to_string(),
            port: ticket.port,
            sni: ticket.sni.clone(),
            http_host: ticket.http_host.clone(),
            redirect_depth: ticket.redirect_depth,
            elapsed_milliseconds: duration_milliseconds_saturated(elapsed),
        })?;
        debug_assert_eq!(intent.redirect_depth, ticket.redirect_depth);
        Ok(())
    }

    fn append_use_event(
        &mut self,
        result: &TicketUseResult,
        elapsed: Duration,
    ) -> Result<(), TransportAuditError> {
        let ticket = result.ticket.as_ref();
        let reason = match &result.outcome {
            TicketUseOutcome::BindingMismatch { field } => {
                format!("binding_mismatch:{}", field.code())
            }
            other => other.code().into(),
        };
        let event_id = self.audit.allocate_event_id();
        self.audit.append(TransportAuditEvent {
            event_id,
            action: "consume".into(),
            status: result.outcome.code().into(),
            reason,
            gateway_audit_anchor: ticket
                .map(|value| value.audit_anchor.clone())
                .unwrap_or_else(|| self.gateway.audit_chain().tail_hash().to_string()),
            ticket_id: Some(result.attempt.ticket_id.clone()),
            decision_id: ticket.map(|value| value.decision_id.clone()),
            binding_hash: ticket.map(|value| value.binding_hash.clone()),
            dns_context_id: ticket
                .map(|value| value.dns_context_id.clone())
                .unwrap_or_else(|| sanitize_identifier(&result.attempt.dns_context_id)),
            host: ticket
                .map(|value| value.host.clone())
                .unwrap_or_else(|| "[unknown]".into()),
            scheme: result.attempt.scheme.code().into(),
            selected_ip: result.attempt.remote_ip.to_string(),
            port: result.attempt.port,
            sni: result
                .attempt
                .sni
                .clone()
                .map(|value| sanitize_host(&value)),
            http_host: sanitize_authority(&result.attempt.http_host),
            redirect_depth: result.attempt.redirect_depth,
            elapsed_milliseconds: duration_milliseconds_saturated(elapsed),
        })?;
        Ok(())
    }
}

fn transport_record_hash(
    sequence: u64,
    previous_hash: &str,
    event: &TransportAuditEvent,
) -> Result<String, TransportAuditError> {
    #[derive(Serialize)]
    struct Material<'a> {
        sequence: u64,
        previous_hash: &'a str,
        event: &'a TransportAuditEvent,
    }

    let bytes = serde_json::to_vec(&Material {
        sequence,
        previous_hash,
        event,
    })
    .map_err(|error| TransportAuditError::Serialization(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(to_lower_hex(&digest))
}

fn sanitize_identifier(value: &str) -> String {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return "[invalid]".into();
    }
    value.to_ascii_lowercase()
}

fn sanitize_host(value: &str) -> String {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value.contains('/')
        || value.contains('\\')
        || value.contains('@')
    {
        "[invalid]".into()
    } else {
        value
    }
}

fn sanitize_authority(value: &str) -> String {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 260
        || value.contains('/')
        || value.contains('\\')
        || value.contains('@')
    {
        "[invalid]".into()
    } else {
        value
    }
}

fn duration_milliseconds_saturated(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn to_lower_hex(bytes: &[u8]) -> String {
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
    use std::collections::BTreeSet;

    use chrono::{Duration as ChronoDuration, Utc};
    use nxb_policy::{
        AuthorizationPolicy, AutomationPolicy, ProgramPolicy, ScopePolicy, TargetPolicy,
    };

    use super::*;

    fn coordinator() -> PinnedTransportCoordinator {
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

    fn intent(depth: u8, context: &str) -> RequestIntent {
        RequestIntent {
            url: url::Url::parse("https://app.example.com/api/me").unwrap(),
            method: "GET".into(),
            resolved_ips: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
            redirect_depth: depth,
            dns_context_id: context.into(),
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

    #[test]
    fn gateway_allow_issues_ticket_anchored_to_gateway_audit() {
        let mut coordinator = coordinator();
        let authorization = coordinator
            .authorize_connection(
                &intent(0, "navigation-1"),
                "8.8.8.8".parse().unwrap(),
                Duration::ZERO,
            )
            .unwrap();
        let ticket = authorization.ticket.unwrap();
        assert_eq!(
            ticket.audit_anchor,
            coordinator.gateway().audit_chain().tail_hash()
        );
        assert_eq!(
            coordinator.transport_audit().records()[0].event.status,
            "issued"
        );
        coordinator.transport_audit().verify().unwrap();
    }

    #[test]
    fn exact_attempt_consumes_ticket_once() {
        let mut coordinator = coordinator();
        let ticket = coordinator
            .authorize_connection(
                &intent(0, "navigation-1"),
                "8.8.8.8".parse().unwrap(),
                Duration::ZERO,
            )
            .unwrap()
            .ticket
            .unwrap();
        let first = coordinator
            .consume_connection_ticket(attempt(&ticket), Duration::from_millis(1))
            .unwrap();
        assert_eq!(first.outcome, TicketUseOutcome::Consumed);
        assert!(first.permit.is_some());
        coordinator.complete_request();

        let replay = coordinator
            .consume_connection_ticket(attempt(&ticket), Duration::from_millis(2))
            .unwrap();
        assert_eq!(replay.outcome, TicketUseOutcome::AlreadyConsumed);
    }

    #[test]
    fn unresolved_selected_ip_is_rejected_without_budget_spend() {
        let mut coordinator = coordinator();
        let before = coordinator.gateway().remaining_requests();
        assert!(matches!(
            coordinator.authorize_connection(
                &intent(0, "navigation-1"),
                "9.9.9.9".parse().unwrap(),
                Duration::ZERO,
            ),
            Err(PinnedTransportError::SelectedIpNotResolved)
        ));
        assert_eq!(coordinator.gateway().remaining_requests(), before);
        assert_eq!(
            coordinator.transport_audit().records()[0].event.status,
            "rejected"
        );
    }

    #[test]
    fn redirect_depth_mismatch_burns_old_ticket_and_new_hop_gets_new_ticket() {
        let mut coordinator = coordinator();
        let old = coordinator
            .authorize_connection(
                &intent(0, "navigation-1"),
                "8.8.8.8".parse().unwrap(),
                Duration::ZERO,
            )
            .unwrap()
            .ticket
            .unwrap();
        let mut wrong_hop = attempt(&old);
        wrong_hop.redirect_depth = 1;
        let mismatch = coordinator
            .consume_connection_ticket(wrong_hop, Duration::from_millis(1))
            .unwrap();
        assert!(matches!(
            mismatch.outcome,
            TicketUseOutcome::BindingMismatch { .. }
        ));

        let new = coordinator
            .authorize_connection(
                &intent(1, "navigation-1"),
                "8.8.8.8".parse().unwrap(),
                Duration::from_secs(1),
            )
            .unwrap()
            .ticket
            .unwrap();
        assert_ne!(old.ticket_id, new.ticket_id);
        assert_eq!(new.redirect_depth, 1);
    }

    #[test]
    fn releasing_context_revokes_ticket_and_dns_pin() {
        let mut coordinator = coordinator();
        let ticket = coordinator
            .authorize_connection(
                &intent(0, "navigation-1"),
                "8.8.8.8".parse().unwrap(),
                Duration::ZERO,
            )
            .unwrap()
            .ticket
            .unwrap();
        assert_eq!(coordinator.release_context("navigation-1"), (1, 1));
        assert_eq!(
            coordinator
                .consume_connection_ticket(attempt(&ticket), Duration::from_millis(1))
                .unwrap()
                .outcome,
            TicketUseOutcome::Revoked
        );
    }
}
