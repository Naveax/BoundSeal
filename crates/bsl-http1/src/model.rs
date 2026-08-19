use std::collections::BTreeMap;

use nxb_stream::{StreamAuditError, StreamError, StreamOperationOutcome, StreamState};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::audit::Http1AuditError;

pub const MAX_HTTP_HEADER_BYTES: u64 = 256 * 1024;
pub const MAX_HTTP_HEADERS: u64 = 512;
pub const MAX_HTTP_BODY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_HTTP_CHUNKS: u64 = 65_536;
pub const MAX_HTTP_TRAILER_BYTES: u64 = 64 * 1024;
pub const MAX_HTTP_INTERIM_RESPONSES: u64 = 32;
const MAX_HTTP_OPERATION_BYTES: u64 = 64 * 1024;
const MAX_HTTP_BACKPRESSURE_EVENTS: u64 = 1_024;
const MAX_HTTP_WIRE_BYTES: u64 = 96 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http1Limits {
    pub maximum_request_header_bytes: u64,
    pub maximum_response_header_bytes: u64,
    pub maximum_header_count: u64,
    pub maximum_header_name_bytes: u64,
    pub maximum_header_value_bytes: u64,
    pub maximum_request_body_bytes: u64,
    pub maximum_response_body_bytes: u64,
    pub maximum_chunk_bytes: u64,
    pub maximum_chunk_count: u64,
    pub maximum_trailer_bytes: u64,
    pub maximum_trailer_count: u64,
    pub maximum_interim_responses: u64,
    pub io_operation_bytes: u64,
    pub maximum_backpressure_events: u64,
    pub maximum_response_wire_bytes: u64,
}

impl Http1Limits {
    pub fn conservative_default() -> Self {
        Self {
            maximum_request_header_bytes: 32 * 1024,
            maximum_response_header_bytes: 64 * 1024,
            maximum_header_count: 128,
            maximum_header_name_bytes: 128,
            maximum_header_value_bytes: 8 * 1024,
            maximum_request_body_bytes: 2 * 1024 * 1024,
            maximum_response_body_bytes: 8 * 1024 * 1024,
            maximum_chunk_bytes: 1024 * 1024,
            maximum_chunk_count: 4_096,
            maximum_trailer_bytes: 16 * 1024,
            maximum_trailer_count: 32,
            maximum_interim_responses: 8,
            io_operation_bytes: 16 * 1024,
            maximum_backpressure_events: 32,
            maximum_response_wire_bytes: 16 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<Self, Http1Error> {
        validate_nonzero_cap(
            self.maximum_request_header_bytes,
            MAX_HTTP_HEADER_BYTES,
            "request_header_bytes",
        )?;
        validate_nonzero_cap(
            self.maximum_response_header_bytes,
            MAX_HTTP_HEADER_BYTES,
            "response_header_bytes",
        )?;
        validate_nonzero_cap(self.maximum_header_count, MAX_HTTP_HEADERS, "header_count")?;
        validate_nonzero_cap(self.maximum_header_name_bytes, 1024, "header_name_bytes")?;
        validate_nonzero_cap(
            self.maximum_header_value_bytes,
            MAX_HTTP_HEADER_BYTES,
            "header_value_bytes",
        )?;
        validate_nonzero_cap(
            self.maximum_request_body_bytes,
            MAX_HTTP_BODY_BYTES,
            "request_body_bytes",
        )?;
        validate_nonzero_cap(
            self.maximum_response_body_bytes,
            MAX_HTTP_BODY_BYTES,
            "response_body_bytes",
        )?;
        validate_nonzero_cap(
            self.maximum_chunk_bytes,
            self.maximum_response_body_bytes,
            "chunk_bytes",
        )?;
        validate_nonzero_cap(self.maximum_chunk_count, MAX_HTTP_CHUNKS, "chunk_count")?;
        validate_nonzero_cap(
            self.maximum_trailer_bytes,
            MAX_HTTP_TRAILER_BYTES,
            "trailer_bytes",
        )?;
        validate_nonzero_cap(
            self.maximum_trailer_count,
            self.maximum_header_count,
            "trailer_count",
        )?;
        validate_nonzero_cap(
            self.maximum_interim_responses,
            MAX_HTTP_INTERIM_RESPONSES,
            "interim_responses",
        )?;
        validate_nonzero_cap(
            self.io_operation_bytes,
            MAX_HTTP_OPERATION_BYTES,
            "io_operation_bytes",
        )?;
        validate_nonzero_cap(
            self.maximum_backpressure_events,
            MAX_HTTP_BACKPRESSURE_EVENTS,
            "backpressure_events",
        )?;
        validate_nonzero_cap(
            self.maximum_response_wire_bytes,
            MAX_HTTP_WIRE_BYTES,
            "response_wire_bytes",
        )?;
        if self.maximum_response_wire_bytes < self.maximum_response_body_bytes {
            return Err(Http1Error::InvalidLimits(
                "response wire budget must cover response body budget".into(),
            ));
        }
        Ok(self)
    }
}

impl Default for Http1Limits {
    fn default() -> Self {
        Self::conservative_default()
    }
}

fn validate_nonzero_cap(value: u64, cap: u64, name: &str) -> Result<(), Http1Error> {
    if value == 0 || value > cap {
        return Err(Http1Error::InvalidLimits(format!(
            "{name} is outside the supported range"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1Header {
    pub name: String,
    pub value: Vec<u8>,
}

impl Http1Header {
    pub fn new(name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1Request {
    pub method: String,
    pub target: String,
    pub headers: Vec<Http1Header>,
    pub body: Vec<u8>,
}

impl Http1Request {
    pub fn new(method: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            target: target.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Http1Version {
    Http10,
    Http11,
}

impl Http1Version {
    pub fn code(self) -> &'static str {
        match self {
            Self::Http10 => "http_1_0",
            Self::Http11 => "http_1_1",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "length", rename_all = "snake_case")]
pub enum Http1Framing {
    NoBody,
    ContentLength(u64),
    Chunked,
    ConnectionClose,
}

impl Http1Framing {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoBody => "no_body",
            Self::ContentLength(_) => "content_length",
            Self::Chunked => "chunked",
            Self::ConnectionClose => "connection_close",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1Response {
    pub version: Http1Version,
    pub status_code: u16,
    pub reason: Vec<u8>,
    pub headers: Vec<Http1Header>,
    pub trailers: Vec<Http1Header>,
    pub body: Vec<u8>,
    pub framing: Http1Framing,
    pub interim_responses: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http1ExchangeReceipt {
    pub exchange_id: String,
    pub stream_id: String,
    pub execution_id: String,
    pub request_method: String,
    pub request_target_sha256: String,
    pub request_wire_sha256: String,
    pub request_body_sha256: String,
    pub request_header_count: u64,
    pub request_body_bytes: u64,
    pub response_wire_sha256: String,
    pub response_body_sha256: String,
    pub response_status: u16,
    pub response_version: String,
    pub response_framing: String,
    pub response_header_count: u64,
    pub response_trailer_count: u64,
    pub response_body_bytes: u64,
    pub interim_responses: u64,
    pub stream_audit_before: String,
    pub stream_audit_after: String,
    pub http_audit_tail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http1Exchange {
    pub response: Http1Response,
    pub receipt: Http1ExchangeReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http1AuditEvent {
    pub exchange_id: String,
    pub stream_id: String,
    pub execution_id: String,
    pub request_method: String,
    pub request_target_sha256: String,
    pub request_wire_sha256: String,
    pub request_body_sha256: String,
    pub request_header_count: u64,
    pub request_body_bytes: u64,
    pub response_wire_sha256: String,
    pub response_body_sha256: String,
    pub response_status: u16,
    pub response_version: String,
    pub response_framing: String,
    pub response_header_count: u64,
    pub response_trailer_count: u64,
    pub response_body_bytes: u64,
    pub interim_responses: u64,
    pub stream_audit_before: String,
    pub stream_audit_after: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Http1Error {
    #[error("HTTP/1 limits are invalid: {0}")]
    InvalidLimits(String),
    #[error("HTTP/1 request is invalid: {0}")]
    InvalidRequest(String),
    #[error("HTTP/1 response framing is invalid: {0}")]
    InvalidResponse(String),
    #[error("HTTP/1 response is incomplete: {0}")]
    TruncatedResponse(String),
    #[error("HTTP/1 stream operation failed: {0}")]
    Stream(#[from] StreamError),
    #[error("HTTP/1 stream entered an unusable state: {state:?}")]
    StreamState { state: StreamState },
    #[error("HTTP/1 stream produced an unusable operation outcome: {outcome:?}")]
    StreamOutcome { outcome: StreamOperationOutcome },
    #[error("HTTP/1 backpressure retry budget was exceeded")]
    BackpressureBudgetExceeded,
    #[error("HTTP/1 codec can perform only one connection-close exchange")]
    ExchangeAlreadyCompleted,
    #[error("HTTP/1 secret-header lease failed: {0}")]
    SecretHeaders(#[from] nxb_vault::VaultError),
    #[error("HTTP/1 audit chain is invalid: {0}")]
    Audit(#[from] Http1AuditError),
    #[error("HTTP/1 stream audit chain is invalid: {0}")]
    StreamAudit(#[from] StreamAuditError),
}
