use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_TICKET_TTL_MILLISECONDS: u64 = 30_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportScheme {
    Http,
    Https,
}

impl TransportScheme {
    pub fn code(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TicketBinding {
    pub decision_id: String,
    pub dns_context_id: String,
    pub host: String,
    pub scheme: TransportScheme,
    pub port: u16,
    pub sni: Option<String>,
    pub http_host: String,
    pub pinned_addresses: BTreeSet<IpAddr>,
    pub selected_ip: IpAddr,
    pub redirect_depth: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TicketIssueRequest {
    pub binding: TicketBinding,
    pub issued_at_milliseconds: u64,
    pub ttl_milliseconds: u64,
    pub audit_anchor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionTicket {
    pub ticket_id: String,
    pub decision_id: String,
    pub dns_context_id: String,
    pub host: String,
    pub scheme: TransportScheme,
    pub port: u16,
    pub sni: Option<String>,
    pub http_host: String,
    pub pinned_addresses: BTreeSet<IpAddr>,
    pub selected_ip: IpAddr,
    pub redirect_depth: u8,
    pub issued_at_milliseconds: u64,
    pub expires_at_milliseconds: u64,
    pub audit_anchor: String,
    pub binding_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionAttempt {
    pub ticket_id: String,
    pub dns_context_id: String,
    pub scheme: TransportScheme,
    pub remote_ip: IpAddr,
    pub port: u16,
    pub sni: Option<String>,
    pub http_host: String,
    pub redirect_depth: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportPermit {
    pub ticket_id: String,
    pub decision_id: String,
    pub dns_context_id: String,
    pub scheme: TransportScheme,
    pub remote_ip: IpAddr,
    pub port: u16,
    pub sni: Option<String>,
    pub http_host: String,
    pub redirect_depth: u8,
    pub binding_hash: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BindingField {
    DnsContextId,
    Scheme,
    RemoteIp,
    Port,
    Sni,
    HttpHost,
    RedirectDepth,
}

impl BindingField {
    pub fn code(self) -> &'static str {
        match self {
            Self::DnsContextId => "dns_context_id",
            Self::Scheme => "scheme",
            Self::RemoteIp => "remote_ip",
            Self::Port => "port",
            Self::Sni => "sni",
            Self::HttpHost => "http_host",
            Self::RedirectDepth => "redirect_depth",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TicketUseOutcome {
    Consumed,
    UnknownTicket,
    AlreadyConsumed,
    Revoked,
    Expired,
    ClockRegression,
    BindingMismatch { field: BindingField },
}

impl TicketUseOutcome {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Consumed => "consumed",
            Self::UnknownTicket => "unknown_ticket",
            Self::AlreadyConsumed => "already_consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::ClockRegression => "clock_regression",
            Self::BindingMismatch { .. } => "binding_mismatch",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TicketUseResult {
    pub outcome: TicketUseOutcome,
    pub ticket: Option<ConnectionTicket>,
    pub attempt: ConnectionAttempt,
    pub permit: Option<TransportPermit>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TicketIssueError {
    #[error("transport decision_id is invalid")]
    InvalidDecisionId,
    #[error("transport DNS context_id is invalid")]
    InvalidDnsContextId,
    #[error("transport host is invalid")]
    InvalidHost,
    #[error("transport port must be non-zero")]
    InvalidPort,
    #[error("transport pinned address set is empty")]
    EmptyPinnedAddressSet,
    #[error("selected transport IP is not in the pinned address set")]
    SelectedIpNotPinned,
    #[error("HTTPS transport requires SNI equal to the normalized host")]
    InvalidTlsSni,
    #[error("HTTP transport must not carry TLS SNI")]
    UnexpectedTlsSni,
    #[error("HTTP Host authority does not match the normalized ticket authority")]
    InvalidHttpHost,
    #[error(
        "transport ticket TTL must be between 1 and {MAX_TICKET_TTL_MILLISECONDS} milliseconds"
    )]
    InvalidTtl,
    #[error("transport ticket expiry overflowed")]
    ExpiryOverflow,
    #[error("transport audit anchor must be a lowercase SHA-256 value")]
    InvalidAuditAnchor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredTicketState {
    Issued,
    Consumed,
    Revoked,
}

#[derive(Debug, Clone)]
struct StoredTicket {
    ticket: ConnectionTicket,
    state: StoredTicketState,
}

#[derive(Debug)]
pub struct TicketAuthority {
    tickets: BTreeMap<String, StoredTicket>,
    next_ticket_id: u64,
}

impl Default for TicketAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl TicketAuthority {
    pub fn new() -> Self {
        Self {
            tickets: BTreeMap::new(),
            next_ticket_id: 1,
        }
    }

    pub fn issue(
        &mut self,
        request: TicketIssueRequest,
    ) -> Result<ConnectionTicket, TicketIssueError> {
        let binding = normalize_and_validate_binding(request.binding)?;
        if request.ttl_milliseconds == 0 || request.ttl_milliseconds > MAX_TICKET_TTL_MILLISECONDS {
            return Err(TicketIssueError::InvalidTtl);
        }
        if !is_lower_hex_sha256(&request.audit_anchor) {
            return Err(TicketIssueError::InvalidAuditAnchor);
        }

        let expires_at_milliseconds = request
            .issued_at_milliseconds
            .checked_add(request.ttl_milliseconds)
            .ok_or(TicketIssueError::ExpiryOverflow)?;
        let ticket_id = self.allocate_ticket_id();
        let binding_hash = binding_hash(
            &ticket_id,
            &binding,
            request.issued_at_milliseconds,
            expires_at_milliseconds,
            &request.audit_anchor,
        );

        let ticket = ConnectionTicket {
            ticket_id: ticket_id.clone(),
            decision_id: binding.decision_id,
            dns_context_id: binding.dns_context_id,
            host: binding.host,
            scheme: binding.scheme,
            port: binding.port,
            sni: binding.sni,
            http_host: binding.http_host,
            pinned_addresses: binding.pinned_addresses,
            selected_ip: binding.selected_ip,
            redirect_depth: binding.redirect_depth,
            issued_at_milliseconds: request.issued_at_milliseconds,
            expires_at_milliseconds,
            audit_anchor: request.audit_anchor,
            binding_hash,
        };

        self.tickets.insert(
            ticket_id,
            StoredTicket {
                ticket: ticket.clone(),
                state: StoredTicketState::Issued,
            },
        );
        Ok(ticket)
    }

    pub fn consume(
        &mut self,
        attempt: ConnectionAttempt,
        now_milliseconds: u64,
    ) -> TicketUseResult {
        let Some(stored) = self.tickets.get_mut(&attempt.ticket_id) else {
            return TicketUseResult {
                outcome: TicketUseOutcome::UnknownTicket,
                ticket: None,
                attempt,
                permit: None,
            };
        };

        let ticket = stored.ticket.clone();
        match stored.state {
            StoredTicketState::Consumed => {
                return TicketUseResult {
                    outcome: TicketUseOutcome::AlreadyConsumed,
                    ticket: Some(ticket),
                    attempt,
                    permit: None,
                }
            }
            StoredTicketState::Revoked => {
                return TicketUseResult {
                    outcome: TicketUseOutcome::Revoked,
                    ticket: Some(ticket),
                    attempt,
                    permit: None,
                }
            }
            StoredTicketState::Issued => {}
        }

        // Any first use attempt burns the ticket, including malformed or mismatched attempts.
        stored.state = StoredTicketState::Consumed;

        if now_milliseconds < ticket.issued_at_milliseconds {
            return failed_use(TicketUseOutcome::ClockRegression, ticket, attempt);
        }
        if now_milliseconds > ticket.expires_at_milliseconds {
            return failed_use(TicketUseOutcome::Expired, ticket, attempt);
        }

        for (matches, field) in [
            (
                normalize_identifier(&attempt.dns_context_id) == ticket.dns_context_id,
                BindingField::DnsContextId,
            ),
            (attempt.scheme == ticket.scheme, BindingField::Scheme),
            (
                attempt.remote_ip == ticket.selected_ip,
                BindingField::RemoteIp,
            ),
            (attempt.port == ticket.port, BindingField::Port),
            (
                attempt.sni.as_deref().map(normalize_host) == ticket.sni,
                BindingField::Sni,
            ),
            (
                normalize_authority(&attempt.http_host) == ticket.http_host,
                BindingField::HttpHost,
            ),
            (
                attempt.redirect_depth == ticket.redirect_depth,
                BindingField::RedirectDepth,
            ),
        ] {
            if !matches {
                return failed_use(TicketUseOutcome::BindingMismatch { field }, ticket, attempt);
            }
        }

        let permit = TransportPermit {
            ticket_id: ticket.ticket_id.clone(),
            decision_id: ticket.decision_id.clone(),
            dns_context_id: ticket.dns_context_id.clone(),
            scheme: ticket.scheme,
            remote_ip: ticket.selected_ip,
            port: ticket.port,
            sni: ticket.sni.clone(),
            http_host: ticket.http_host.clone(),
            redirect_depth: ticket.redirect_depth,
            binding_hash: ticket.binding_hash.clone(),
        };
        TicketUseResult {
            outcome: TicketUseOutcome::Consumed,
            ticket: Some(ticket),
            attempt,
            permit: Some(permit),
        }
    }

    pub fn revoke_context(&mut self, context_id: &str) -> usize {
        let normalized = normalize_identifier(context_id);
        let mut revoked = 0;
        for stored in self.tickets.values_mut() {
            if stored.ticket.dns_context_id == normalized
                && stored.state == StoredTicketState::Issued
            {
                stored.state = StoredTicketState::Revoked;
                revoked += 1;
            }
        }
        revoked
    }

    pub fn ticket(&self, ticket_id: &str) -> Option<&ConnectionTicket> {
        self.tickets.get(ticket_id).map(|stored| &stored.ticket)
    }

    pub fn issued_count(&self) -> usize {
        self.tickets
            .values()
            .filter(|stored| stored.state == StoredTicketState::Issued)
            .count()
    }

    pub fn consumed_count(&self) -> usize {
        self.tickets
            .values()
            .filter(|stored| stored.state == StoredTicketState::Consumed)
            .count()
    }

    fn allocate_ticket_id(&mut self) -> String {
        let value = self.next_ticket_id;
        self.next_ticket_id = self.next_ticket_id.saturating_add(1);
        format!("ticket-{value:020}")
    }
}

fn failed_use(
    outcome: TicketUseOutcome,
    ticket: ConnectionTicket,
    attempt: ConnectionAttempt,
) -> TicketUseResult {
    TicketUseResult {
        outcome,
        ticket: Some(ticket),
        attempt,
        permit: None,
    }
}

fn normalize_and_validate_binding(
    mut binding: TicketBinding,
) -> Result<TicketBinding, TicketIssueError> {
    if !is_valid_identifier(&binding.decision_id) {
        return Err(TicketIssueError::InvalidDecisionId);
    }
    if !is_valid_identifier(&binding.dns_context_id) {
        return Err(TicketIssueError::InvalidDnsContextId);
    }
    binding.decision_id = normalize_identifier(&binding.decision_id);
    binding.dns_context_id = normalize_identifier(&binding.dns_context_id);
    binding.host = normalize_host(&binding.host);
    if !is_valid_host(&binding.host) {
        return Err(TicketIssueError::InvalidHost);
    }
    if binding.port == 0 {
        return Err(TicketIssueError::InvalidPort);
    }
    if binding.pinned_addresses.is_empty() {
        return Err(TicketIssueError::EmptyPinnedAddressSet);
    }
    if !binding.pinned_addresses.contains(&binding.selected_ip) {
        return Err(TicketIssueError::SelectedIpNotPinned);
    }

    binding.sni = binding.sni.as_deref().map(normalize_host);
    match binding.scheme {
        TransportScheme::Https if binding.sni.as_deref() != Some(binding.host.as_str()) => {
            return Err(TicketIssueError::InvalidTlsSni)
        }
        TransportScheme::Http if binding.sni.is_some() => {
            return Err(TicketIssueError::UnexpectedTlsSni)
        }
        TransportScheme::Http | TransportScheme::Https => {}
    }

    let expected_authority = expected_http_host(&binding.host, binding.scheme, binding.port);
    binding.http_host = normalize_authority(&binding.http_host);
    if binding.http_host != expected_authority {
        return Err(TicketIssueError::InvalidHttpHost);
    }
    Ok(binding)
}

pub fn expected_http_host(host: &str, scheme: TransportScheme, port: u16) -> String {
    let host = normalize_host(host);
    if port == scheme.default_port() {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn binding_hash(
    ticket_id: &str,
    binding: &TicketBinding,
    issued_at_milliseconds: u64,
    expires_at_milliseconds: u64,
    audit_anchor: &str,
) -> String {
    let pinned = binding
        .pinned_addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let material = format!(
        "bsl.transport.v1\n{ticket_id}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{pinned}\n{}\n{}\n{issued_at_milliseconds}\n{expires_at_milliseconds}\n{audit_anchor}",
        binding.decision_id,
        binding.dns_context_id,
        binding.host,
        binding.scheme.code(),
        binding.port,
        binding.sni.as_deref().unwrap_or(""),
        binding.http_host,
        binding.selected_ip,
        binding.redirect_depth,
    );
    let digest = Sha256::digest(material.as_bytes());
    to_lower_hex(&digest)
}

fn normalize_identifier(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn is_valid_identifier(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn normalize_host(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_authority(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn is_valid_host(value: &str) -> bool {
    let host = normalize_host(value);
    if host.is_empty()
        || host.len() > 253
        || host.contains(':')
        || host.contains('/')
        || host.contains('\\')
    {
        return false;
    }

    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    use super::*;

    fn binding() -> TicketBinding {
        TicketBinding {
            decision_id: "decision-0001".into(),
            dns_context_id: "navigation-1".into(),
            host: "app.example.com".into(),
            scheme: TransportScheme::Https,
            port: 443,
            sni: Some("app.example.com".into()),
            http_host: "app.example.com".into(),
            pinned_addresses: BTreeSet::from([
                "1.1.1.1".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
            ]),
            selected_ip: "8.8.8.8".parse().unwrap(),
            redirect_depth: 0,
        }
    }

    fn issue(authority: &mut TicketAuthority) -> ConnectionTicket {
        authority
            .issue(TicketIssueRequest {
                binding: binding(),
                issued_at_milliseconds: 100,
                ttl_milliseconds: 5_000,
                audit_anchor: "a".repeat(64),
            })
            .unwrap()
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
    fn issues_and_consumes_exact_binding_once() {
        let mut authority = TicketAuthority::new();
        let ticket = issue(&mut authority);
        let first = authority.consume(attempt(&ticket), 200);
        assert_eq!(first.outcome, TicketUseOutcome::Consumed);
        assert!(first.permit.is_some());

        let replay = authority.consume(attempt(&ticket), 201);
        assert_eq!(replay.outcome, TicketUseOutcome::AlreadyConsumed);
        assert!(replay.permit.is_none());
    }

    #[test]
    fn mismatch_burns_ticket() {
        let mut authority = TicketAuthority::new();
        let ticket = issue(&mut authority);
        let mut wrong = attempt(&ticket);
        wrong.remote_ip = "1.1.1.1".parse().unwrap();
        let result = authority.consume(wrong, 200);
        assert_eq!(
            result.outcome,
            TicketUseOutcome::BindingMismatch {
                field: BindingField::RemoteIp
            }
        );

        let replay = authority.consume(attempt(&ticket), 201);
        assert_eq!(replay.outcome, TicketUseOutcome::AlreadyConsumed);
    }

    #[test]
    fn redirect_depth_requires_a_new_ticket() {
        let mut authority = TicketAuthority::new();
        let ticket = issue(&mut authority);
        let mut redirected = attempt(&ticket);
        redirected.redirect_depth = 1;
        let result = authority.consume(redirected, 200);
        assert_eq!(
            result.outcome,
            TicketUseOutcome::BindingMismatch {
                field: BindingField::RedirectDepth
            }
        );
    }

    #[test]
    fn expired_ticket_is_rejected_and_burned() {
        let mut authority = TicketAuthority::new();
        let ticket = issue(&mut authority);
        let result = authority.consume(attempt(&ticket), 5_101);
        assert_eq!(result.outcome, TicketUseOutcome::Expired);
        assert_eq!(
            authority.consume(attempt(&ticket), 5_102).outcome,
            TicketUseOutcome::AlreadyConsumed
        );
    }

    #[test]
    fn selected_ip_must_be_pinned() {
        let mut authority = TicketAuthority::new();
        let mut request = TicketIssueRequest {
            binding: binding(),
            issued_at_milliseconds: 100,
            ttl_milliseconds: 5_000,
            audit_anchor: "a".repeat(64),
        };
        request.binding.selected_ip = "9.9.9.9".parse().unwrap();
        assert_eq!(
            authority.issue(request),
            Err(TicketIssueError::SelectedIpNotPinned)
        );
    }

    #[test]
    fn https_requires_exact_sni() {
        let mut authority = TicketAuthority::new();
        let mut request = TicketIssueRequest {
            binding: binding(),
            issued_at_milliseconds: 100,
            ttl_milliseconds: 5_000,
            audit_anchor: "a".repeat(64),
        };
        request.binding.sni = Some("other.example.com".into());
        assert_eq!(
            authority.issue(request),
            Err(TicketIssueError::InvalidTlsSni)
        );
    }

    #[test]
    fn revoking_context_invalidates_unconsumed_tickets() {
        let mut authority = TicketAuthority::new();
        let ticket = issue(&mut authority);
        assert_eq!(authority.revoke_context("navigation-1"), 1);
        assert_eq!(
            authority.consume(attempt(&ticket), 200).outcome,
            TicketUseOutcome::Revoked
        );
    }
}
