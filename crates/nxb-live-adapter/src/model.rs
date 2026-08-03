use nxb_executor::{ExecutionLimits, ExecutionReceipt};
use nxb_http1::{Http1Exchange, Http1Header, Http1Limits, Http1Request};
use nxb_stream::{StreamLimits, StreamReceipt};
use nxb_tls::{LibraryVerifiedTlsObservation, TlsProtocolVersion};
use nxb_transport::TicketUseResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_LIVE_REQUEST_TARGET_BYTES: usize = 4 * 1024;
const DENIED_PATH_SEGMENTS: &[&str] = &[
    "delete",
    "destroy",
    "disable",
    "drop",
    "logoff",
    "logout",
    "remove",
    "reset",
    "revoke",
    "shutdown",
    "signout",
    "terminate",
    "unsubscribe",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PassiveMethod {
    Get,
    Head,
}

impl PassiveMethod {
    pub fn code(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LivePassiveRequest {
    pub method: PassiveMethod,
    pub target: String,
}

impl LivePassiveRequest {
    pub fn new(method: PassiveMethod, target: impl Into<String>) -> Result<Self, LiveAdapterError> {
        let request = Self {
            method,
            target: target.into(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn root_get() -> Self {
        Self {
            method: PassiveMethod::Get,
            target: "/".into(),
        }
    }

    pub fn validate(&self) -> Result<(), LiveAdapterError> {
        if self.target.is_empty()
            || self.target.len() > MAX_LIVE_REQUEST_TARGET_BYTES
            || !self.target.starts_with('/')
            || self.target.starts_with("//")
            || self.target.contains('?')
            || self.target.contains('#')
            || self.target.contains('%')
            || self.target.contains('\\')
            || self
                .target
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(LiveAdapterError::InvalidRequestTarget);
        }

        for segment in self.target.split('/') {
            if DENIED_PATH_SEGMENTS
                .iter()
                .any(|denied| segment.eq_ignore_ascii_case(denied))
            {
                return Err(LiveAdapterError::DeniedRequestTarget);
            }
        }
        Ok(())
    }

    pub(crate) fn to_http1(&self) -> Http1Request {
        let mut request = Http1Request::new(self.method.code(), self.target.clone());
        request
            .headers
            .push(Http1Header::new("Accept", b"*/*".to_vec()));
        request
            .headers
            .push(Http1Header::new("Accept-Encoding", b"identity".to_vec()));
        request.headers.push(Http1Header::new(
            "User-Agent",
            b"NXB/0.1 passive-security-research".to_vec(),
        ));
        request
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveAdapterLimits {
    pub execution: ExecutionLimits,
    pub stream: StreamLimits,
    pub http: Http1Limits,
}

impl LiveAdapterLimits {
    pub fn conservative_default() -> Self {
        let execution = ExecutionLimits::conservative_default();
        let stream = StreamLimits {
            maximum_read_bytes: 16 * 1024 * 1024,
            maximum_write_bytes: 128 * 1024,
            maximum_operation_bytes: 64 * 1024,
            read_deadline_milliseconds: 10_000,
            write_deadline_milliseconds: 10_000,
            total_deadline_milliseconds: 30_000,
            maximum_operations: 4_096,
        };
        let http = Http1Limits::conservative_default();
        Self {
            execution,
            stream,
            http,
        }
    }

    pub fn validate(self) -> Result<Self, LiveAdapterError> {
        self.execution
            .validate()
            .map_err(|error| LiveAdapterError::InvalidLimits(error.to_string()))?;
        self.stream
            .validate()
            .map_err(|error| LiveAdapterError::InvalidLimits(error.to_string()))?;
        self.http
            .validate()
            .map_err(|error| LiveAdapterError::InvalidLimits(error.to_string()))?;
        if self.stream.maximum_read_bytes < self.http.maximum_response_wire_bytes
            || self.stream.maximum_write_bytes < self.http.maximum_request_header_bytes
        {
            return Err(LiveAdapterError::InvalidLimits(
                "stream budgets must cover HTTP wire budgets".into(),
            ));
        }
        Ok(self)
    }
}

impl Default for LiveAdapterLimits {
    fn default() -> Self {
        Self::conservative_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveAdapterConfig {
    pub executor_id: String,
    pub limits: LiveAdapterLimits,
}

impl LiveAdapterConfig {
    pub fn conservative(executor_id: impl Into<String>) -> Result<Self, LiveAdapterError> {
        let config = Self {
            executor_id: executor_id.into(),
            limits: LiveAdapterLimits::conservative_default(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), LiveAdapterError> {
        if self.executor_id.is_empty()
            || self.executor_id.len() > 128
            || !self.executor_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(LiveAdapterError::InvalidExecutorId);
        }
        self.limits.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveTlsObservation {
    pub remote_ip: String,
    pub server_name: String,
    pub protocol_version: String,
    pub alpn_protocol: Option<String>,
    pub cipher_suite: String,
    pub handshake_kind: String,
    pub certificate_chain_length: u64,
    pub certificate_chain_sha256: String,
    pub leaf_certificate_sha256: String,
    pub trust_store_sha256: String,
    pub connected_after_milliseconds: u64,
    pub handshake_elapsed_milliseconds: u64,
    pub tls_read_bytes: u64,
    pub tls_written_bytes: u64,
    pub early_data_accepted: bool,
    pub renegotiation_observed: bool,
    pub session_resumed: bool,
}

impl LiveTlsObservation {
    pub(crate) fn library_verified(
        &self,
        verifier_id: impl Into<String>,
    ) -> Result<LibraryVerifiedTlsObservation, LiveAdapterError> {
        let protocol_version = match self.protocol_version.as_str() {
            "tls_1_2" => TlsProtocolVersion::Tls12,
            "tls_1_3" => TlsProtocolVersion::Tls13,
            _ => {
                return Err(LiveAdapterError::TlsConfiguration(
                    "live TLS observation has an unsupported protocol version".into(),
                ))
            }
        };
        let alpn = self.alpn_protocol.clone().ok_or_else(|| {
            LiveAdapterError::TlsConfiguration(
                "live TLS observation is missing the required HTTP/1.1 ALPN".into(),
            )
        })?;
        let chain_depth = usize::try_from(self.certificate_chain_length).map_err(|_| {
            LiveAdapterError::TlsConfiguration(
                "certificate chain length does not fit the platform".into(),
            )
        })?;
        Ok(LibraryVerifiedTlsObservation {
            verifier_id: verifier_id.into(),
            server_name: self.server_name.clone(),
            protocol_version,
            alpn,
            handshake_read_bytes: self.tls_read_bytes,
            handshake_write_bytes: self.tls_written_bytes,
            elapsed_milliseconds: self.handshake_elapsed_milliseconds,
            chain_depth,
            chain_fingerprint_sha256: self.certificate_chain_sha256.clone(),
            leaf_fingerprint_sha256: self.leaf_certificate_sha256.clone(),
            trust_anchor_sha256: self.trust_store_sha256.clone(),
            early_data_accepted: self.early_data_accepted,
            renegotiation_observed: self.renegotiation_observed,
            session_resumed: self.session_resumed,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LivePassiveReceipt {
    pub ticket_id: String,
    pub decision_id: String,
    pub dns_context_id: String,
    pub execution_id: String,
    pub stream_id: String,
    pub exchange_id: String,
    pub request_method: String,
    pub request_target_sha256: String,
    pub remote_ip: String,
    pub server_name_sha256: String,
    pub tls_protocol: String,
    pub tls_alpn: Option<String>,
    pub tls_cipher_suite: String,
    pub leaf_certificate_sha256: String,
    pub response_status: u16,
    pub response_framing: String,
    pub response_header_count: u64,
    pub response_trailer_count: u64,
    pub response_body_bytes: u64,
    pub response_body_sha256: String,
    pub redirect_observed: bool,
    pub transport_audit_anchor: String,
    pub executor_audit_tail: String,
    pub stream_audit_tail: String,
    pub http_audit_tail: String,
    pub receipt_sha256: String,
}

impl LivePassiveReceipt {
    pub fn verify(&self) -> Result<(), LiveAdapterError> {
        let mut material = self.clone();
        material.receipt_sha256.clear();
        if live_hash_serializable(&material)? != self.receipt_sha256 {
            return Err(LiveAdapterError::ReceiptDigest);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct LivePassiveResult {
    pub ticket_use: TicketUseResult,
    pub execution_receipt: Option<ExecutionReceipt>,
    pub tls_observation: Option<LiveTlsObservation>,
    pub stream_receipt: Option<StreamReceipt>,
    pub exchange: Option<Http1Exchange>,
    pub receipt: Option<LivePassiveReceipt>,
    pub transport_audit_anchor: String,
}

#[derive(Debug, Error)]
pub enum LiveAdapterError {
    #[error("live adapter executor_id is invalid")]
    InvalidExecutorId,
    #[error("live adapter limits are invalid: {0}")]
    InvalidLimits(String),
    #[error("live TLS configuration is invalid: {0}")]
    TlsConfiguration(String),
    #[error("live passive request target is invalid")]
    InvalidRequestTarget,
    #[error("live passive request target contains a denied action segment")]
    DeniedRequestTarget,
    #[error("a consumed ticket did not contain a permit")]
    ConsumedTicketMissingPermit,
    #[error("live connection completed without a TLS stream")]
    MissingTlsStream,
    #[error("live connection completed without TLS metadata")]
    MissingTlsObservation,
    #[error("live execution did not complete successfully")]
    ExecutionNotCompleted,
    #[error("pinned transport rejected live execution: {0}")]
    Transport(#[from] nxb_pinned_transport::PinnedTransportError),
    #[error("permit executor rejected live execution: {0}")]
    Executor(#[from] nxb_executor::ExecutorError),
    #[error("bounded stream rejected live execution: {0}")]
    StreamOpen(#[from] nxb_stream::StreamOpenError),
    #[error("verified TLS stream binding failed: {0}")]
    TlsBinding(#[from] nxb_tls::LibraryVerifiedTlsError),
    #[error("HTTP/1 exchange rejected live execution: {0}")]
    Http(#[from] nxb_http1::Http1Error),
    #[error("live receipt serialization failed: {0}")]
    Serialization(String),
    #[error("live receipt digest mismatch")]
    ReceiptDigest,
}

pub(crate) fn build_live_receipt(
    tls: &LiveTlsObservation,
    exchange: &Http1Exchange,
    stream: &StreamReceipt,
    execution: &ExecutionReceipt,
    transport_audit_anchor: &str,
    executor_audit_tail: &str,
) -> Result<LivePassiveReceipt, LiveAdapterError> {
    let redirect_observed = (300..400).contains(&exchange.response.status_code);
    let mut receipt = LivePassiveReceipt {
        ticket_id: execution.ticket_id.clone(),
        decision_id: execution.decision_id.clone(),
        dns_context_id: execution.dns_context_id.clone(),
        execution_id: execution.execution_id.clone(),
        stream_id: stream.stream_id.clone(),
        exchange_id: exchange.receipt.exchange_id.clone(),
        request_method: exchange.receipt.request_method.clone(),
        request_target_sha256: exchange.receipt.request_target_sha256.clone(),
        remote_ip: tls.remote_ip.clone(),
        server_name_sha256: live_hash_bytes(tls.server_name.as_bytes()),
        tls_protocol: tls.protocol_version.clone(),
        tls_alpn: tls.alpn_protocol.clone(),
        tls_cipher_suite: tls.cipher_suite.clone(),
        leaf_certificate_sha256: tls.leaf_certificate_sha256.clone(),
        response_status: exchange.receipt.response_status,
        response_framing: exchange.receipt.response_framing.clone(),
        response_header_count: exchange.receipt.response_header_count,
        response_trailer_count: exchange.receipt.response_trailer_count,
        response_body_bytes: exchange.receipt.response_body_bytes,
        response_body_sha256: exchange.receipt.response_body_sha256.clone(),
        redirect_observed,
        transport_audit_anchor: transport_audit_anchor.into(),
        executor_audit_tail: executor_audit_tail.into(),
        stream_audit_tail: stream.stream_audit_tail.clone(),
        http_audit_tail: exchange.receipt.http_audit_tail.clone(),
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = live_hash_serializable(&receipt)?;
    Ok(receipt)
}

pub(crate) fn live_hash_serializable<T: Serialize>(value: &T) -> Result<String, LiveAdapterError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| LiveAdapterError::Serialization(error.to_string()))?;
    Ok(live_hash_bytes(&bytes))
}

pub(crate) fn live_hash_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
