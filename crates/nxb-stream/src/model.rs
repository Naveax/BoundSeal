use std::collections::BTreeMap;

use nxb_executor::ExecutorAuditError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::audit::StreamAuditError;

pub const MAX_STREAM_DIRECTION_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_STREAM_OPERATION_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_STREAM_DEADLINE_MILLISECONDS: u64 = 120_000;
pub const MAX_STREAM_OPERATIONS: u64 = 100_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamLimits {
    pub maximum_read_bytes: u64,
    pub maximum_write_bytes: u64,
    pub maximum_operation_bytes: u64,
    pub read_deadline_milliseconds: u64,
    pub write_deadline_milliseconds: u64,
    pub total_deadline_milliseconds: u64,
    pub maximum_operations: u64,
}

impl StreamLimits {
    pub fn conservative_default() -> Self {
        Self {
            maximum_read_bytes: 2 * 1024 * 1024,
            maximum_write_bytes: 256 * 1024,
            maximum_operation_bytes: 64 * 1024,
            read_deadline_milliseconds: 5_000,
            write_deadline_milliseconds: 5_000,
            total_deadline_milliseconds: 30_000,
            maximum_operations: 4_096,
        }
    }

    pub fn validate(self) -> Result<Self, StreamOpenError> {
        if self.maximum_read_bytes == 0 || self.maximum_read_bytes > MAX_STREAM_DIRECTION_BYTES {
            return Err(StreamOpenError::InvalidLimits(
                "read budget is outside the supported range".into(),
            ));
        }
        if self.maximum_write_bytes == 0 || self.maximum_write_bytes > MAX_STREAM_DIRECTION_BYTES {
            return Err(StreamOpenError::InvalidLimits(
                "write budget is outside the supported range".into(),
            ));
        }
        if self.maximum_operation_bytes == 0
            || self.maximum_operation_bytes > MAX_STREAM_OPERATION_BYTES
            || self.maximum_operation_bytes > self.maximum_read_bytes.max(self.maximum_write_bytes)
        {
            return Err(StreamOpenError::InvalidLimits(
                "operation byte budget is outside the supported range".into(),
            ));
        }
        if self.read_deadline_milliseconds == 0
            || self.read_deadline_milliseconds > MAX_STREAM_DEADLINE_MILLISECONDS
        {
            return Err(StreamOpenError::InvalidLimits(
                "read deadline is outside the supported range".into(),
            ));
        }
        if self.write_deadline_milliseconds == 0
            || self.write_deadline_milliseconds > MAX_STREAM_DEADLINE_MILLISECONDS
        {
            return Err(StreamOpenError::InvalidLimits(
                "write deadline is outside the supported range".into(),
            ));
        }
        if self.total_deadline_milliseconds
            < self
                .read_deadline_milliseconds
                .max(self.write_deadline_milliseconds)
            || self.total_deadline_milliseconds > MAX_STREAM_DEADLINE_MILLISECONDS
        {
            return Err(StreamOpenError::InvalidLimits(
                "total deadline must cover operation deadlines and remain bounded".into(),
            ));
        }
        if self.maximum_operations == 0 || self.maximum_operations > MAX_STREAM_OPERATIONS {
            return Err(StreamOpenError::InvalidLimits(
                "operation count is outside the supported range".into(),
            ));
        }
        Ok(self)
    }
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self::conservative_default()
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamControl {
    pub cancel_requested: bool,
    pub emergency_stop_requested: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamDirection {
    Read,
    Write,
}

impl StreamDirection {
    pub fn code(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    Open,
    ReadClosed,
    WriteClosed,
    Closed,
    Cancelled,
    EmergencyStopped,
    TimedOut,
    BudgetExceeded,
    Reset,
    Truncated,
    BackendFailed,
}

impl StreamState {
    pub fn code(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ReadClosed => "read_closed",
            Self::WriteClosed => "write_closed",
            Self::Closed => "closed",
            Self::Cancelled => "cancelled",
            Self::EmergencyStopped => "emergency_stopped",
            Self::TimedOut => "timed_out",
            Self::BudgetExceeded => "budget_exceeded",
            Self::Reset => "reset",
            Self::Truncated => "truncated",
            Self::BackendFailed => "backend_failed",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Closed
                | Self::Cancelled
                | Self::EmergencyStopped
                | Self::TimedOut
                | Self::BudgetExceeded
                | Self::Reset
                | Self::Truncated
                | Self::BackendFailed
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum StreamOperationOutcome {
    Opened,
    Data,
    Written,
    PartialWrite,
    Backpressure,
    Eof,
    Closed,
    Cancelled,
    EmergencyStopped,
    ReadTimeout,
    WriteTimeout,
    TotalTimeout,
    ReadBudgetExceeded,
    WriteBudgetExceeded,
    OperationBudgetExceeded,
    Reset,
    Truncated,
    BackendFailure { backend_code: String },
}

impl StreamOperationOutcome {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Data => "data",
            Self::Written => "written",
            Self::PartialWrite => "partial_write",
            Self::Backpressure => "backpressure",
            Self::Eof => "eof",
            Self::Closed => "closed",
            Self::Cancelled => "cancelled",
            Self::EmergencyStopped => "emergency_stopped",
            Self::ReadTimeout => "read_timeout",
            Self::WriteTimeout => "write_timeout",
            Self::TotalTimeout => "total_timeout",
            Self::ReadBudgetExceeded => "read_budget_exceeded",
            Self::WriteBudgetExceeded => "write_budget_exceeded",
            Self::OperationBudgetExceeded => "operation_budget_exceeded",
            Self::Reset => "reset",
            Self::Truncated => "truncated",
            Self::BackendFailure { .. } => "backend_failure",
        }
    }

    pub(crate) fn details(&self) -> BTreeMap<String, String> {
        let mut details = BTreeMap::new();
        if let Self::BackendFailure { backend_code } = self {
            details.insert("backend_code".into(), backend_code.clone());
        }
        details
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendReadStatus {
    Data(Vec<u8>),
    Eof,
    Backpressure,
    Timeout,
    Reset,
    Truncated(Vec<u8>),
    Failure(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendReadReport {
    pub elapsed_milliseconds: u64,
    pub status: BackendReadStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendWriteStatus {
    Written(u64),
    Backpressure,
    Timeout,
    Reset,
    Closed,
    Failure(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendWriteReport {
    pub elapsed_milliseconds: u64,
    pub status: BackendWriteStatus,
}

pub trait ByteStreamBackend {
    fn read(&mut self, maximum_bytes: u64, deadline_milliseconds: u64) -> BackendReadReport;

    fn write(&mut self, bytes: &[u8], deadline_milliseconds: u64) -> BackendWriteReport;

    fn close(&mut self);
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamGrant {
    pub(crate) stream_id: String,
    pub(crate) execution_id: String,
    pub(crate) executor_id: String,
    pub(crate) ticket_id: String,
    pub(crate) decision_id: String,
    pub(crate) dns_context_id: String,
    pub(crate) binding_hash: String,
    pub(crate) endpoint_fingerprint: String,
    pub(crate) executor_audit_anchor: String,
    pub(crate) remote_ip: String,
    pub(crate) port: u16,
    pub(crate) scheme: String,
    pub(crate) sni: Option<String>,
    pub(crate) http_host: String,
    pub(crate) redirect_depth: u8,
}

impl StreamGrant {
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn ticket_id(&self) -> &str {
        &self.ticket_id
    }

    pub fn executor_audit_anchor(&self) -> &str {
        &self.executor_audit_anchor
    }

    pub fn binding_hash(&self) -> &str {
        &self.binding_hash
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamOperationReceipt {
    pub operation_id: String,
    pub stream_id: String,
    pub direction: Option<StreamDirection>,
    pub outcome: StreamOperationOutcome,
    pub requested_bytes: u64,
    pub transferred_bytes: u64,
    pub payload_sha256: Option<String>,
    pub elapsed_milliseconds: u64,
    pub cumulative_read_bytes: u64,
    pub cumulative_written_bytes: u64,
    pub state_before: StreamState,
    pub state_after: StreamState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamReadResult {
    pub bytes: Vec<u8>,
    pub receipt: StreamOperationReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamWriteResult {
    pub receipt: StreamOperationReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamReceipt {
    pub stream_id: String,
    pub execution_id: String,
    pub executor_id: String,
    pub ticket_id: String,
    pub decision_id: String,
    pub dns_context_id: String,
    pub binding_hash: String,
    pub endpoint_fingerprint: String,
    pub executor_audit_anchor: String,
    pub stream_audit_tail: String,
    pub state: StreamState,
    pub read_bytes: u64,
    pub written_bytes: u64,
    pub elapsed_milliseconds: u64,
    pub operation_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamAuditEvent {
    pub operation_id: String,
    pub stream_id: String,
    pub execution_id: String,
    pub executor_id: String,
    pub ticket_id: String,
    pub decision_id: String,
    pub dns_context_id: String,
    pub binding_hash: String,
    pub endpoint_fingerprint: String,
    pub executor_audit_anchor: String,
    pub remote_ip: String,
    pub port: u16,
    pub scheme: String,
    pub sni: Option<String>,
    pub http_host: String,
    pub redirect_depth: u8,
    pub direction: Option<String>,
    pub outcome: String,
    pub outcome_details: BTreeMap<String, String>,
    pub requested_bytes: u64,
    pub transferred_bytes: u64,
    pub payload_sha256: Option<String>,
    pub elapsed_milliseconds: u64,
    pub cumulative_read_bytes: u64,
    pub cumulative_written_bytes: u64,
    pub state_before: String,
    pub state_after: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StreamOpenError {
    #[error("stream limits are invalid: {0}")]
    InvalidLimits(String),
    #[error("executor audit chain is invalid: {0}")]
    InvalidExecutorAudit(ExecutorAuditError),
    #[error("executor audit record for the receipt was not found")]
    MissingExecutorAuditRecord,
    #[error("executor receipt did not complete successfully")]
    ExecutionNotCompleted,
    #[error("permit, execution receipt and executor audit record do not match: {0}")]
    BindingMismatch(String),
    #[error("executor audit anchor is not a lowercase SHA-256 value")]
    InvalidExecutorAuditAnchor,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StreamError {
    #[error("stream operation size is zero or exceeds the configured per-operation limit")]
    InvalidOperationSize,
    #[error("stream read side is closed")]
    ReadSideClosed,
    #[error("stream write side is closed")]
    WriteSideClosed,
    #[error("stream is in terminal state {0:?}")]
    TerminalState(StreamState),
    #[error("stream audit record could not be committed: {0}")]
    Audit(#[from] StreamAuditError),
}
