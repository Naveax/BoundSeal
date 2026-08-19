use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use bsl_stream::StreamGrant;
use bsl_tls::TlsSessionGrant;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CHANNEL_AUDIT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const MAX_REQUEST_HEADER_COUNT: usize = 128;
pub const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_BODY_CHUNKS: usize = 4096;
pub const MAX_RESPONSE_HEADER_COUNT: usize = 512;
pub const MAX_RESPONSE_HEADER_BYTES: usize = 256 * 1024;
pub const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RESPONSE_PREVIEW_BYTES: usize = 4096;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChannelError {
    #[error("channel identifier is invalid")]
    InvalidIdentifier,
    #[error("stream binding metadata is invalid: {0}")]
    InvalidStreamBinding(String),
    #[error("TLS binding metadata is invalid: {0}")]
    InvalidTlsBinding(String),
    #[error("plain HTTP channel requires an HTTP stream without TLS SNI")]
    PlainChannelRequiresHttp,
    #[error("verified TLS channel requires an HTTPS stream")]
    TlsChannelRequiresHttps,
    #[error("TLS grant does not match the stream: {0}")]
    TlsBindingMismatch(&'static str),
    #[error("TLS ALPN must be exactly http/1.1")]
    InvalidAlpn,
    #[error("channel grant has already been consumed")]
    ChannelReplay,
    #[error("request method is invalid or unsupported")]
    InvalidMethod,
    #[error("request target is invalid: {0}")]
    InvalidTarget(String),
    #[error("request header is invalid: {0}")]
    InvalidHeader(String),
    #[error("request limits are exceeded: {0}")]
    RequestLimit(String),
    #[error("request body is invalid: {0}")]
    InvalidBody(String),
    #[error("sensitive headers require a verified TLS channel")]
    SensitiveHeadersRequireTls,
    #[error("response envelope is invalid: {0}")]
    InvalidResponse(String),
    #[error("channel audit material could not be serialized: {0}")]
    AuditSerialization(String),
    #[error("channel audit sequence mismatch at record {record_index}")]
    AuditSequenceMismatch { record_index: usize },
    #[error("channel audit previous hash mismatch at record {record_index}")]
    AuditPreviousHashMismatch { record_index: usize },
    #[error("channel audit record hash mismatch at record {record_index}")]
    AuditRecordHashMismatch { record_index: usize },
    #[error("channel audit tail hash mismatch")]
    AuditTailMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    PlainHttp,
    VerifiedTls,
}

impl ChannelKind {
    pub fn code(&self) -> &'static str {
        match self {
            Self::PlainHttp => "plain_http",
            Self::VerifiedTls => "verified_tls",
        }
    }

    pub fn permits_sensitive_headers(&self) -> bool {
        matches!(self, Self::VerifiedTls)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamBindingSnapshot {
    pub stream_id: String,
    pub execution_id: String,
    pub ticket_id: String,
    pub binding_hash: String,
    pub stream_audit_anchor: String,
    pub scheme: String,
    pub sni: Option<String>,
    pub http_host: String,
    pub port: u16,
    pub redirect_depth: u8,
}

impl StreamBindingSnapshot {
    pub fn from_grant(grant: &StreamGrant, stream_audit_anchor: impl Into<String>) -> Self {
        Self {
            stream_id: grant.stream_id().into(),
            execution_id: grant.execution_id().into(),
            ticket_id: grant.ticket_id().into(),
            binding_hash: grant.binding_hash().into(),
            stream_audit_anchor: stream_audit_anchor.into(),
            scheme: grant.scheme().to_ascii_lowercase(),
            sni: grant.sni().map(str::to_ascii_lowercase),
            http_host: grant.http_host().to_ascii_lowercase(),
            port: grant.port(),
            redirect_depth: grant.redirect_depth(),
        }
    }

    pub fn validate(&self) -> Result<(), ChannelError> {
        validate_identifier(&self.stream_id)?;
        validate_identifier(&self.execution_id)?;
        validate_identifier(&self.ticket_id)?;
        validate_sha256(&self.binding_hash, "binding_hash")?;
        validate_sha256(&self.stream_audit_anchor, "stream_audit_anchor")?;
        if !matches!(self.scheme.as_str(), "http" | "https") {
            return Err(ChannelError::InvalidStreamBinding(
                "unsupported scheme".into(),
            ));
        }
        validate_authority(&self.http_host)?;
        if self.port == 0 {
            return Err(ChannelError::InvalidStreamBinding(
                "port must be non-zero".into(),
            ));
        }
        match self.scheme.as_str() {
            "http" if self.sni.is_some() => Err(ChannelError::InvalidStreamBinding(
                "HTTP stream must not carry SNI".into(),
            )),
            "https" if self.sni.as_deref().is_none_or(str::is_empty) => {
                Err(ChannelError::InvalidStreamBinding(
                    "HTTPS stream requires SNI".into(),
                ))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsBindingSnapshot {
    pub tls_session_id: String,
    pub stream_id: String,
    pub execution_id: String,
    pub ticket_id: String,
    pub binding_hash: String,
    pub stream_audit_anchor: String,
    pub sni: String,
    pub http_host: String,
    pub port: u16,
    pub redirect_depth: u8,
    pub alpn: String,
    pub tls_audit_anchor: String,
    pub leaf_fingerprint_sha256: String,
}

impl TlsBindingSnapshot {
    pub fn from_grant(grant: &TlsSessionGrant) -> Self {
        Self {
            tls_session_id: grant.tls_session_id().into(),
            stream_id: grant.stream_id().into(),
            execution_id: grant.execution_id().into(),
            ticket_id: grant.ticket_id().into(),
            binding_hash: grant.binding_hash().into(),
            stream_audit_anchor: grant.stream_audit_anchor().into(),
            sni: grant.sni().to_ascii_lowercase(),
            http_host: grant.http_host().to_ascii_lowercase(),
            port: grant.port(),
            redirect_depth: grant.redirect_depth(),
            alpn: grant.alpn().into(),
            tls_audit_anchor: grant.tls_audit_anchor().into(),
            leaf_fingerprint_sha256: grant.leaf_fingerprint_sha256().into(),
        }
    }

    pub fn validate(&self) -> Result<(), ChannelError> {
        validate_identifier(&self.tls_session_id)?;
        validate_identifier(&self.stream_id)?;
        validate_identifier(&self.execution_id)?;
        validate_identifier(&self.ticket_id)?;
        validate_sha256(&self.binding_hash, "binding_hash")?;
        validate_sha256(&self.stream_audit_anchor, "stream_audit_anchor")?;
        validate_sha256(&self.tls_audit_anchor, "tls_audit_anchor")?;
        validate_sha256(&self.leaf_fingerprint_sha256, "leaf_fingerprint")?;
        validate_dns_name(&self.sni)?;
        validate_authority(&self.http_host)?;
        if self.port == 0 {
            return Err(ChannelError::InvalidTlsBinding(
                "port must be non-zero".into(),
            ));
        }
        if self.alpn != "http/1.1" {
            return Err(ChannelError::InvalidAlpn);
        }
        Ok(())
    }
}

pub struct HttpChannelGrant {
    channel_id: String,
    kind: ChannelKind,
    stream: StreamBindingSnapshot,
    tls: Option<TlsBindingSnapshot>,
    consumed: bool,
    grant_fingerprint_sha256: String,
}
