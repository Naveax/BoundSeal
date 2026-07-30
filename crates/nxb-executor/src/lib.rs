use std::{
    collections::{BTreeMap, VecDeque},
    net::IpAddr,
};

use nxb_transport::{TransportPermit, TransportScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_CONNECT_TIMEOUT_MILLISECONDS: u64 = 30_000;
pub const MAX_TOTAL_TIMEOUT_MILLISECONDS: u64 = 120_000;
pub const MAX_DIRECTION_BYTES: u64 = 64 * 1024 * 1024;
pub const EXECUTOR_AUDIT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutorConfig {
    pub executor_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionLimits {
    pub connect_timeout_milliseconds: u64,
    pub total_timeout_milliseconds: u64,
    pub maximum_read_bytes: u64,
    pub maximum_write_bytes: u64,
}

impl ExecutionLimits {
    pub fn conservative_default() -> Self {
        Self {
            connect_timeout_milliseconds: 5_000,
            total_timeout_milliseconds: 15_000,
            maximum_read_bytes: 2 * 1024 * 1024,
            maximum_write_bytes: 256 * 1024,
        }
    }

    pub fn validate(self) -> Result<Self, ExecutorError> {
        if self.connect_timeout_milliseconds == 0
            || self.connect_timeout_milliseconds > MAX_CONNECT_TIMEOUT_MILLISECONDS
        {
            return Err(ExecutorError::InvalidLimits(
                "connect timeout is outside the supported range".into(),
            ));
        }
        if self.total_timeout_milliseconds < self.connect_timeout_milliseconds
            || self.total_timeout_milliseconds > MAX_TOTAL_TIMEOUT_MILLISECONDS
        {
            return Err(ExecutorError::InvalidLimits(
                "total timeout must cover connect timeout and remain bounded".into(),
            ));
        }
        if self.maximum_read_bytes == 0 || self.maximum_read_bytes > MAX_DIRECTION_BYTES {
            return Err(ExecutorError::InvalidLimits(
                "read byte budget is outside the supported range".into(),
            ));
        }
        if self.maximum_write_bytes == 0 || self.maximum_write_bytes > MAX_DIRECTION_BYTES {
            return Err(ExecutorError::InvalidLimits(
                "write byte budget is outside the supported range".into(),
            ));
        }
        Ok(self)
    }
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self::conservative_default()
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControl {
    pub cancel_requested: bool,
    pub emergency_stop_requested: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Prepared,
    Connecting,
    Connected,
    Completed,
    Cancelled,
    EmergencyStopped,
    TimedOut,
    BudgetRejected,
    BackendFailed,
    PermitRejected,
}

impl ExecutionState {
    pub fn code(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::EmergencyStopped => "emergency_stopped",
            Self::TimedOut => "timed_out",
            Self::BudgetRejected => "budget_rejected",
            Self::BackendFailed => "backend_failed",
            Self::PermitRejected => "permit_rejected",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Completed,
    Cancelled,
    EmergencyStopped,
    ConnectTimeout,
    TotalTimeout,
    ReadBudgetExceeded,
    WriteBudgetExceeded,
    BackendFailure { backend_code: String },
    PermitIntegrityRejected { reason: String },
}

impl ExecutionOutcome {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::EmergencyStopped => "emergency_stopped",
            Self::ConnectTimeout => "connect_timeout",
            Self::TotalTimeout => "total_timeout",
            Self::ReadBudgetExceeded => "read_budget_exceeded",
            Self::WriteBudgetExceeded => "write_budget_exceeded",
            Self::BackendFailure { .. } => "backend_failure",
            Self::PermitIntegrityRejected { .. } => "permit_integrity_rejected",
        }
    }

    fn terminal_state(&self) -> ExecutionState {
        match self {
            Self::Completed => ExecutionState::Completed,
            Self::Cancelled => ExecutionState::Cancelled,
            Self::EmergencyStopped => ExecutionState::EmergencyStopped,
            Self::ConnectTimeout | Self::TotalTimeout => ExecutionState::TimedOut,
            Self::ReadBudgetExceeded | Self::WriteBudgetExceeded => ExecutionState::BudgetRejected,
            Self::BackendFailure { .. } => ExecutionState::BackendFailed,
            Self::PermitIntegrityRejected { .. } => ExecutionState::PermitRejected,
        }
    }

    fn details(&self) -> BTreeMap<String, String> {
        let mut details = BTreeMap::new();
        match self {
            Self::BackendFailure { backend_code } => {
                details.insert("backend_code".into(), backend_code.clone());
            }
            Self::PermitIntegrityRejected { reason } => {
                details.insert("reason".into(), reason.clone());
            }
            _ => {}
        }
        details
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendReport {
    pub connected_after_milliseconds: Option<u64>,
    pub elapsed_milliseconds: u64,
    pub read_bytes: u64,
    pub written_bytes: u64,
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct PermitEndpoint<'a> {
    pub ticket_id: &'a str,
    pub decision_id: &'a str,
    pub dns_context_id: &'a str,
    pub scheme: TransportScheme,
    pub remote_ip: IpAddr,
    pub port: u16,
    pub sni: Option<&'a str>,
    pub http_host: &'a str,
    pub redirect_depth: u8,
    pub binding_hash: &'a str,
}

pub trait PermitBackend {
    fn execute(
        &mut self,
        endpoint: PermitEndpoint<'_>,
        limits: &ExecutionLimits,
        control: &ExecutionControl,
    ) -> BackendReport;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyntheticScenario {
    pub connected_after_milliseconds: Option<u64>,
    pub elapsed_milliseconds: u64,
    pub read_bytes: u64,
    pub written_bytes: u64,
    pub failure_code: Option<String>,
}

impl SyntheticScenario {
    pub fn success(
        connected_after_milliseconds: u64,
        elapsed_milliseconds: u64,
        read_bytes: u64,
        written_bytes: u64,
    ) -> Self {
        Self {
            connected_after_milliseconds: Some(connected_after_milliseconds),
            elapsed_milliseconds,
            read_bytes,
            written_bytes,
            failure_code: None,
        }
    }

    pub fn failure(code: impl Into<String>, elapsed_milliseconds: u64) -> Self {
        Self {
            connected_after_milliseconds: None,
            elapsed_milliseconds,
            read_bytes: 0,
            written_bytes: 0,
            failure_code: Some(code.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyntheticEndpointObservation {
    pub ticket_id: String,
    pub decision_id: String,
    pub dns_context_id: String,
    pub scheme: String,
    pub remote_ip: String,
    pub port: u16,
    pub sni: Option<String>,
    pub http_host: String,
    pub redirect_depth: u8,
    pub binding_hash: String,
}

#[derive(Debug, Default)]
pub struct SyntheticBackend {
    scenarios: VecDeque<SyntheticScenario>,
    observed_endpoints: Vec<SyntheticEndpointObservation>,
}

impl SyntheticBackend {
    pub fn new(scenarios: impl IntoIterator<Item = SyntheticScenario>) -> Self {
        Self {
            scenarios: scenarios.into_iter().collect(),
            observed_endpoints: Vec::new(),
        }
    }

    pub fn observed_endpoints(&self) -> &[SyntheticEndpointObservation] {
        &self.observed_endpoints
    }
}

impl PermitBackend for SyntheticBackend {
    fn execute(
        &mut self,
        endpoint: PermitEndpoint<'_>,
        _limits: &ExecutionLimits,
        _control: &ExecutionControl,
    ) -> BackendReport {
        self.observed_endpoints.push(SyntheticEndpointObservation {
            ticket_id: endpoint.ticket_id.into(),
            decision_id: endpoint.decision_id.into(),
            dns_context_id: endpoint.dns_context_id.into(),
            scheme: endpoint.scheme.code().into(),
            remote_ip: endpoint.remote_ip.to_string(),
            port: endpoint.port,
            sni: endpoint.sni.map(str::to_string),
            http_host: endpoint.http_host.into(),
            redirect_depth: endpoint.redirect_depth,
            binding_hash: endpoint.binding_hash.into(),
        });

        let scenario = self
            .scenarios
            .pop_front()
            .unwrap_or_else(|| SyntheticScenario::failure("synthetic_scenario_exhausted", 0));
        BackendReport {
            connected_after_milliseconds: scenario.connected_after_milliseconds,
            elapsed_milliseconds: scenario.elapsed_milliseconds,
            read_bytes: scenario.read_bytes,
            written_bytes: scenario.written_bytes,
            failure_code: scenario.failure_code,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionReceipt {
    pub execution_id: String,
    pub executor_id: String,
    pub ticket_id: String,
    pub decision_id: String,
    pub dns_context_id: String,
    pub transport_audit_anchor: String,
    pub binding_hash: String,
    pub endpoint_fingerprint: String,
    pub outcome: ExecutionOutcome,
    pub state_history: Vec<ExecutionState>,
    pub connected_after_milliseconds: Option<u64>,
    pub elapsed_milliseconds: u64,
    pub read_bytes: u64,
    pub written_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutorAuditEvent {
    pub execution_id: String,
    pub executor_id: String,
    pub ticket_id: String,
    pub decision_id: String,
    pub dns_context_id: String,
    pub transport_audit_anchor: String,
    pub binding_hash: String,
    pub endpoint_fingerprint: String,
    pub remote_ip: String,
    pub port: u16,
    pub scheme: String,
    pub sni: Option<String>,
    pub http_host: String,
    pub redirect_depth: u8,
    pub outcome: String,
    pub outcome_details: BTreeMap<String, String>,
    pub state_history: Vec<String>,
    pub connected_after_milliseconds: Option<u64>,
    pub elapsed_milliseconds: u64,
    pub read_bytes: u64,
    pub written_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutorAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: ExecutorAuditEvent,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct ExecutorAuditChain {
    records: Vec<ExecutorAuditRecord>,
    tail_hash: String,
}

impl Default for ExecutorAuditChain {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutorAuditChain {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            tail_hash: EXECUTOR_AUDIT_GENESIS_HASH.into(),
        }
    }

    pub fn append(
        &mut self,
        event: ExecutorAuditEvent,
    ) -> Result<&ExecutorAuditRecord, ExecutorAuditError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = executor_record_hash(sequence, &previous_hash, &event)?;
        self.records.push(ExecutorAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self
            .records
            .last()
            .expect("an executor audit record was appended before lookup"))
    }

    pub fn records(&self) -> &[ExecutorAuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), ExecutorAuditError> {
        let mut expected_previous = EXECUTOR_AUDIT_GENESIS_HASH.to_string();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(ExecutorAuditError::SequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != expected_previous {
                return Err(ExecutorAuditError::PreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected_hash =
                executor_record_hash(record.sequence, &record.previous_hash, &record.event)?;
            if record.record_hash != expected_hash {
                return Err(ExecutorAuditError::RecordHashMismatch {
                    record_index: index,
                });
            }
            expected_previous = expected_hash;
        }
        if self.tail_hash != expected_previous {
            return Err(ExecutorAuditError::TailHashMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PermitExecutor<B> {
    config: ExecutorConfig,
    backend: B,
    audit: ExecutorAuditChain,
    next_execution_id: u64,
}

impl<B: PermitBackend> PermitExecutor<B> {
    pub fn new(config: ExecutorConfig, backend: B) -> Result<Self, ExecutorError> {
        if !is_valid_identifier(&config.executor_id) {
            return Err(ExecutorError::InvalidExecutorId);
        }
        Ok(Self {
            config,
            backend,
            audit: ExecutorAuditChain::new(),
            next_execution_id: 1,
        })
    }

    pub fn execute(
        &mut self,
        permit: &TransportPermit,
        transport_audit_anchor: &str,
        limits: ExecutionLimits,
        control: ExecutionControl,
    ) -> Result<ExecutionReceipt, ExecutorError> {
        let limits = limits.validate()?;
        if !is_lower_hex_sha256(transport_audit_anchor) {
            return Err(ExecutorError::InvalidTransportAuditAnchor);
        }

        let execution_id = self.allocate_execution_id();
        let endpoint_fingerprint = endpoint_fingerprint(permit, transport_audit_anchor);
        let mut states = vec![ExecutionState::Prepared];
        let report;
        let outcome;

        if let Err(reason) = validate_permit(permit) {
            outcome = ExecutionOutcome::PermitIntegrityRejected { reason };
            report = empty_report();
        } else if control.emergency_stop_requested {
            outcome = ExecutionOutcome::EmergencyStopped;
            report = empty_report();
        } else if control.cancel_requested {
            outcome = ExecutionOutcome::Cancelled;
            report = empty_report();
        } else {
            states.push(ExecutionState::Connecting);
            report = self
                .backend
                .execute(endpoint_from_permit(permit), &limits, &control);
            if report.connected_after_milliseconds.is_some() {
                states.push(ExecutionState::Connected);
            }
            outcome = classify_report(&report, limits);
        }

        states.push(outcome.terminal_state());
        let receipt = ExecutionReceipt {
            execution_id,
            executor_id: self.config.executor_id.clone(),
            ticket_id: permit.ticket_id.clone(),
            decision_id: permit.decision_id.clone(),
            dns_context_id: permit.dns_context_id.clone(),
            transport_audit_anchor: transport_audit_anchor.into(),
            binding_hash: permit.binding_hash.clone(),
            endpoint_fingerprint,
            outcome: outcome.clone(),
            state_history: states,
            connected_after_milliseconds: report.connected_after_milliseconds,
            elapsed_milliseconds: report.elapsed_milliseconds,
            read_bytes: report.read_bytes,
            written_bytes: report.written_bytes,
        };
        self.append_receipt(permit, &receipt)?;
        Ok(receipt)
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn audit(&self) -> &ExecutorAuditChain {
        &self.audit
    }

    fn allocate_execution_id(&mut self) -> String {
        let value = self.next_execution_id;
        self.next_execution_id = self.next_execution_id.saturating_add(1);
        format!("execution-{value:020}")
    }

    fn append_receipt(
        &mut self,
        permit: &TransportPermit,
        receipt: &ExecutionReceipt,
    ) -> Result<(), ExecutorAuditError> {
        self.audit.append(ExecutorAuditEvent {
            execution_id: receipt.execution_id.clone(),
            executor_id: receipt.executor_id.clone(),
            ticket_id: receipt.ticket_id.clone(),
            decision_id: receipt.decision_id.clone(),
            dns_context_id: receipt.dns_context_id.clone(),
            transport_audit_anchor: receipt.transport_audit_anchor.clone(),
            binding_hash: receipt.binding_hash.clone(),
            endpoint_fingerprint: receipt.endpoint_fingerprint.clone(),
            remote_ip: permit.remote_ip.to_string(),
            port: permit.port,
            scheme: permit.scheme.code().into(),
            sni: permit.sni.clone(),
            http_host: permit.http_host.clone(),
            redirect_depth: permit.redirect_depth,
            outcome: receipt.outcome.code().into(),
            outcome_details: receipt.outcome.details(),
            state_history: receipt
                .state_history
                .iter()
                .map(|state| state.code().into())
                .collect(),
            connected_after_milliseconds: receipt.connected_after_milliseconds,
            elapsed_milliseconds: receipt.elapsed_milliseconds,
            read_bytes: receipt.read_bytes,
            written_bytes: receipt.written_bytes,
        })?;
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExecutorError {
    #[error("executor_id is invalid")]
    InvalidExecutorId,
    #[error("executor limits are invalid: {0}")]
    InvalidLimits(String),
    #[error("transport audit anchor must be a lowercase SHA-256 value")]
    InvalidTransportAuditAnchor,
    #[error("executor audit record could not be committed: {0}")]
    Audit(#[from] ExecutorAuditError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExecutorAuditError {
    #[error("executor audit material could not be serialized: {0}")]
    Serialization(String),
    #[error("executor audit sequence mismatch at record {record_index}")]
    SequenceMismatch { record_index: usize },
    #[error("executor audit previous-hash mismatch at record {record_index}")]
    PreviousHashMismatch { record_index: usize },
    #[error("executor audit record-hash mismatch at record {record_index}")]
    RecordHashMismatch { record_index: usize },
    #[error("executor audit tail hash does not match the final record")]
    TailHashMismatch,
}

fn empty_report() -> BackendReport {
    BackendReport {
        connected_after_milliseconds: None,
        elapsed_milliseconds: 0,
        read_bytes: 0,
        written_bytes: 0,
        failure_code: None,
    }
}

fn endpoint_from_permit(permit: &TransportPermit) -> PermitEndpoint<'_> {
    PermitEndpoint {
        ticket_id: &permit.ticket_id,
        decision_id: &permit.decision_id,
        dns_context_id: &permit.dns_context_id,
        scheme: permit.scheme,
        remote_ip: permit.remote_ip,
        port: permit.port,
        sni: permit.sni.as_deref(),
        http_host: &permit.http_host,
        redirect_depth: permit.redirect_depth,
        binding_hash: &permit.binding_hash,
    }
}

fn validate_permit(permit: &TransportPermit) -> Result<(), String> {
    if !is_valid_identifier(&permit.ticket_id) {
        return Err("invalid_ticket_id".into());
    }
    if !is_valid_identifier(&permit.decision_id) {
        return Err("invalid_decision_id".into());
    }
    if !is_valid_identifier(&permit.dns_context_id) {
        return Err("invalid_dns_context_id".into());
    }
    if permit.port == 0 {
        return Err("zero_port".into());
    }
    if !is_lower_hex_sha256(&permit.binding_hash) {
        return Err("invalid_binding_hash".into());
    }
    if permit.http_host.trim().is_empty()
        || permit.http_host.contains('/')
        || permit.http_host.contains('\\')
        || permit.http_host.contains('@')
    {
        return Err("invalid_http_host".into());
    }
    match permit.scheme {
        TransportScheme::Http => {
            if permit.sni.is_some() {
                Err("unexpected_http_sni".into())
            } else {
                Ok(())
            }
        }
        TransportScheme::Https => match permit.sni.as_deref() {
            Some(value) if !value.trim().is_empty() => Ok(()),
            _ => Err("missing_https_sni".into()),
        },
    }
}

fn classify_report(report: &BackendReport, limits: ExecutionLimits) -> ExecutionOutcome {
    if let Some(code) = &report.failure_code {
        return ExecutionOutcome::BackendFailure {
            backend_code: sanitize_backend_code(code),
        };
    }
    let Some(connected_after) = report.connected_after_milliseconds else {
        return ExecutionOutcome::BackendFailure {
            backend_code: "backend_did_not_connect".into(),
        };
    };
    if connected_after > limits.connect_timeout_milliseconds {
        return ExecutionOutcome::ConnectTimeout;
    }
    if report.elapsed_milliseconds > limits.total_timeout_milliseconds {
        return ExecutionOutcome::TotalTimeout;
    }
    if report.read_bytes > limits.maximum_read_bytes {
        return ExecutionOutcome::ReadBudgetExceeded;
    }
    if report.written_bytes > limits.maximum_write_bytes {
        return ExecutionOutcome::WriteBudgetExceeded;
    }
    ExecutionOutcome::Completed
}

fn endpoint_fingerprint(permit: &TransportPermit, transport_audit_anchor: &str) -> String {
    #[derive(Serialize)]
    struct Material<'a> {
        ticket_id: &'a str,
        decision_id: &'a str,
        dns_context_id: &'a str,
        scheme: &'a str,
        remote_ip: IpAddr,
        port: u16,
        sni: Option<&'a str>,
        http_host: &'a str,
        redirect_depth: u8,
        binding_hash: &'a str,
        transport_audit_anchor: &'a str,
    }

    let material = Material {
        ticket_id: &permit.ticket_id,
        decision_id: &permit.decision_id,
        dns_context_id: &permit.dns_context_id,
        scheme: permit.scheme.code(),
        remote_ip: permit.remote_ip,
        port: permit.port,
        sni: permit.sni.as_deref(),
        http_host: &permit.http_host,
        redirect_depth: permit.redirect_depth,
        binding_hash: &permit.binding_hash,
        transport_audit_anchor,
    };
    let bytes =
        serde_json::to_vec(&material).expect("endpoint fingerprint material is serializable");
    to_lower_hex(&Sha256::digest(bytes))
}

fn executor_record_hash(
    sequence: u64,
    previous_hash: &str,
    event: &ExecutorAuditEvent,
) -> Result<String, ExecutorAuditError> {
    #[derive(Serialize)]
    struct Material<'a> {
        sequence: u64,
        previous_hash: &'a str,
        event: &'a ExecutorAuditEvent,
    }

    let bytes = serde_json::to_vec(&Material {
        sequence,
        previous_hash,
        event,
    })
    .map_err(|error| ExecutorAuditError::Serialization(error.to_string()))?;
    Ok(to_lower_hex(&Sha256::digest(bytes)))
}

fn is_valid_identifier(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sanitize_backend_code(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    if is_valid_identifier(&normalized) {
        normalized
    } else {
        "invalid_backend_code".into()
    }
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

    fn permit() -> TransportPermit {
        TransportPermit {
            ticket_id: "ticket-0001".into(),
            decision_id: "decision-0001".into(),
            dns_context_id: "navigation-1".into(),
            scheme: TransportScheme::Https,
            remote_ip: "1.1.1.1".parse().unwrap(),
            port: 443,
            sni: Some("app.example.com".into()),
            http_host: "app.example.com".into(),
            redirect_depth: 0,
            binding_hash: "a".repeat(64),
        }
    }

    fn executor(scenario: SyntheticScenario) -> PermitExecutor<SyntheticBackend> {
        PermitExecutor::new(
            ExecutorConfig {
                executor_id: "local-fixture-1".into(),
            },
            SyntheticBackend::new([scenario]),
        )
        .unwrap()
    }

    #[test]
    fn completes_a_bounded_synthetic_execution() {
        let mut executor = executor(SyntheticScenario::success(10, 25, 128, 32));
        let receipt = executor
            .execute(
                &permit(),
                &"b".repeat(64),
                ExecutionLimits::default(),
                ExecutionControl::default(),
            )
            .unwrap();

        assert_eq!(receipt.outcome, ExecutionOutcome::Completed);
        assert_eq!(
            receipt.state_history.last(),
            Some(&ExecutionState::Completed)
        );
        assert_eq!(executor.backend().observed_endpoints().len(), 1);
        executor.audit().verify().unwrap();
    }

    #[test]
    fn rejects_malformed_permit_before_backend_use() {
        let mut invalid = permit();
        invalid.binding_hash = "not-a-hash".into();
        let mut executor = executor(SyntheticScenario::success(1, 1, 1, 1));
        let receipt = executor
            .execute(
                &invalid,
                &"b".repeat(64),
                ExecutionLimits::default(),
                ExecutionControl::default(),
            )
            .unwrap();

        assert!(matches!(
            receipt.outcome,
            ExecutionOutcome::PermitIntegrityRejected { .. }
        ));
        assert!(executor.backend().observed_endpoints().is_empty());
    }

    #[test]
    fn enforces_connect_and_direction_budgets() {
        let limits = ExecutionLimits {
            connect_timeout_milliseconds: 100,
            total_timeout_milliseconds: 1_000,
            maximum_read_bytes: 10,
            maximum_write_bytes: 10,
        };
        let mut connect_timeout = executor(SyntheticScenario::success(101, 101, 0, 0));
        assert_eq!(
            connect_timeout
                .execute(
                    &permit(),
                    &"b".repeat(64),
                    limits,
                    ExecutionControl::default(),
                )
                .unwrap()
                .outcome,
            ExecutionOutcome::ConnectTimeout
        );

        let mut read_limit = executor(SyntheticScenario::success(1, 2, 11, 0));
        assert_eq!(
            read_limit
                .execute(
                    &permit(),
                    &"b".repeat(64),
                    limits,
                    ExecutionControl::default(),
                )
                .unwrap()
                .outcome,
            ExecutionOutcome::ReadBudgetExceeded
        );
    }

    #[test]
    fn cancellation_and_emergency_stop_do_not_call_backend() {
        let mut cancelled = executor(SyntheticScenario::success(1, 1, 1, 1));
        let receipt = cancelled
            .execute(
                &permit(),
                &"b".repeat(64),
                ExecutionLimits::default(),
                ExecutionControl {
                    cancel_requested: true,
                    emergency_stop_requested: false,
                },
            )
            .unwrap();
        assert_eq!(receipt.outcome, ExecutionOutcome::Cancelled);
        assert!(cancelled.backend().observed_endpoints().is_empty());

        let mut stopped = executor(SyntheticScenario::success(1, 1, 1, 1));
        let receipt = stopped
            .execute(
                &permit(),
                &"b".repeat(64),
                ExecutionLimits::default(),
                ExecutionControl {
                    cancel_requested: true,
                    emergency_stop_requested: true,
                },
            )
            .unwrap();
        assert_eq!(receipt.outcome, ExecutionOutcome::EmergencyStopped);
        assert!(stopped.backend().observed_endpoints().is_empty());
    }

    #[test]
    fn records_backend_failure_without_unbounded_text() {
        let mut executor = executor(SyntheticScenario::failure("Connection_Reset", 4));
        let receipt = executor
            .execute(
                &permit(),
                &"b".repeat(64),
                ExecutionLimits::default(),
                ExecutionControl::default(),
            )
            .unwrap();
        assert_eq!(
            receipt.outcome,
            ExecutionOutcome::BackendFailure {
                backend_code: "connection_reset".into()
            }
        );
    }

    #[test]
    fn audit_detects_modified_execution_data() {
        let mut executor = executor(SyntheticScenario::success(1, 2, 3, 4));
        executor
            .execute(
                &permit(),
                &"b".repeat(64),
                ExecutionLimits::default(),
                ExecutionControl::default(),
            )
            .unwrap();
        executor.audit.records[0].event.read_bytes = 999;
        assert_eq!(
            executor.audit.verify(),
            Err(ExecutorAuditError::RecordHashMismatch { record_index: 0 })
        );
    }

    #[test]
    fn limit_validation_rejects_unbounded_values() {
        let result = ExecutionLimits {
            connect_timeout_milliseconds: 1,
            total_timeout_milliseconds: 2,
            maximum_read_bytes: MAX_DIRECTION_BYTES + 1,
            maximum_write_bytes: 1,
        }
        .validate();
        assert!(matches!(result, Err(ExecutorError::InvalidLimits(_))));
    }

    #[test]
    fn backend_observes_only_permit_derived_endpoint_fields() {
        let mut executor = executor(SyntheticScenario::success(1, 1, 0, 0));
        executor
            .execute(
                &permit(),
                &"b".repeat(64),
                ExecutionLimits::default(),
                ExecutionControl::default(),
            )
            .unwrap();
        let observed = &executor.backend().observed_endpoints()[0];
        assert_eq!(observed.remote_ip, "1.1.1.1");
        assert_eq!(observed.port, 443);
        assert_eq!(observed.sni.as_deref(), Some("app.example.com"));
    }
}
