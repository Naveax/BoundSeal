use std::collections::BTreeMap;

use nxb_stream::{BoundedByteStream, ByteStreamBackend};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    audit::{hex_sha256, TlsAuditChain, TlsAuditError, TlsAuditEvent},
    identity::{expected_http_authority, normalize_dns_name},
    model::{is_lower_hex_sha256, TlsProtocolVersion, TlsSessionGrant},
};

#[derive(Debug, Error)]
pub enum LibraryVerifiedTlsError {
    #[error("TLS-library verification metadata is invalid: {0}")]
    InvalidObservation(String),
    #[error("TLS-library audit record could not be committed: {0}")]
    Audit(#[from] TlsAuditError),
}

/// Metadata emitted by a TLS library after it has cryptographically verified the
/// certificate chain and server name. This bridge does not perform a second
/// certificate verification; it binds an already-verified library session to
/// the exact NXB bounded stream and commits that binding to the TLS audit chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LibraryVerifiedTlsObservation {
    pub verifier_id: String,
    pub server_name: String,
    pub protocol_version: TlsProtocolVersion,
    pub alpn: String,
    pub handshake_read_bytes: u64,
    pub handshake_write_bytes: u64,
    pub elapsed_milliseconds: u64,
    pub chain_depth: usize,
    pub chain_fingerprint_sha256: String,
    pub leaf_fingerprint_sha256: String,
    pub trust_anchor_sha256: String,
    pub early_data_accepted: bool,
    pub renegotiation_observed: bool,
    pub session_resumed: bool,
}

#[derive(Debug)]
pub struct LibraryVerifiedTlsBinder {
    audit: TlsAuditChain,
    next_verification_id: u64,
    next_session_id: u64,
}

impl Default for LibraryVerifiedTlsBinder {
    fn default() -> Self {
        Self::new()
    }
}

impl LibraryVerifiedTlsBinder {
    pub fn new() -> Self {
        Self {
            audit: TlsAuditChain::new(),
            next_verification_id: 1,
            next_session_id: 1,
        }
    }

    pub fn bind<B: ByteStreamBackend>(
        &mut self,
        stream: &BoundedByteStream<B>,
        observation: &LibraryVerifiedTlsObservation,
    ) -> Result<TlsSessionGrant, LibraryVerifiedTlsError> {
        stream
            .audit()
            .verify()
            .map_err(|error| LibraryVerifiedTlsError::InvalidObservation(error.to_string()))?;
        validate_observation(stream, observation)?;

        let verification_id = format!(
            "tls-library-verification-{:020}",
            self.next_verification_id
        );
        self.next_verification_id = self.next_verification_id.saturating_add(1);
        let tls_session_id = format!("tls-library-session-{:020}", self.next_session_id);
        self.next_session_id = self.next_session_id.saturating_add(1);

        let stream_grant = stream.grant();
        let normalized_sni = normalize_dns_name(
            stream_grant.sni().ok_or_else(|| {
                LibraryVerifiedTlsError::InvalidObservation("missing SNI".into())
            })?,
        )
        .map_err(|reason| LibraryVerifiedTlsError::InvalidObservation(reason.code().into()))?;
        let matched_san_sha256 = hex_sha256(normalized_sni.as_bytes());
        let stream_audit_anchor = stream.audit().tail_hash().to_string();
        let mut details = BTreeMap::new();
        details.insert("verification_source".into(), "tls_library".into());
        details.insert(
            "trust_anchor_kind".into(),
            "configured_root_store_snapshot".into(),
        );
        let event = TlsAuditEvent {
            verification_id,
            tls_session_id: Some(tls_session_id.clone()),
            verifier_id: observation.verifier_id.clone(),
            status: "verified".into(),
            reason: "library_verified_and_stream_bound".into(),
            stream_id: stream_grant.stream_id().into(),
            execution_id: stream_grant.execution_id().into(),
            ticket_id: stream_grant.ticket_id().into(),
            binding_hash: stream_grant.binding_hash().into(),
            stream_audit_anchor: stream_audit_anchor.clone(),
            sni: normalized_sni.clone(),
            http_host: stream_grant.http_host().to_ascii_lowercase(),
            port: stream_grant.port(),
            redirect_depth: stream_grant.redirect_depth(),
            protocol_version: observation.protocol_version.code().into(),
            alpn: observation.alpn.clone(),
            handshake_read_bytes: observation.handshake_read_bytes,
            handshake_write_bytes: observation.handshake_write_bytes,
            elapsed_milliseconds: observation.elapsed_milliseconds,
            chain_depth: observation.chain_depth,
            chain_fingerprint_sha256: observation.chain_fingerprint_sha256.clone(),
            leaf_fingerprint_sha256: Some(observation.leaf_fingerprint_sha256.clone()),
            root_fingerprint_sha256: Some(observation.trust_anchor_sha256.clone()),
            matched_san_sha256: Some(matched_san_sha256.clone()),
            early_data_accepted: observation.early_data_accepted,
            renegotiation_observed: observation.renegotiation_observed,
            session_resumed: observation.session_resumed,
            details,
        };
        let tls_audit_anchor = self.audit.append(event)?.record_hash.clone();
        self.audit.verify()?;

        Ok(TlsSessionGrant {
            tls_session_id,
            stream_id: stream_grant.stream_id().into(),
            execution_id: stream_grant.execution_id().into(),
            ticket_id: stream_grant.ticket_id().into(),
            binding_hash: stream_grant.binding_hash().into(),
            stream_audit_anchor,
            sni: normalized_sni,
            http_host: stream_grant.http_host().into(),
            port: stream_grant.port(),
            redirect_depth: stream_grant.redirect_depth(),
            protocol_version: observation.protocol_version,
            alpn: observation.alpn.clone(),
            leaf_fingerprint_sha256: observation.leaf_fingerprint_sha256.clone(),
            root_fingerprint_sha256: observation.trust_anchor_sha256.clone(),
            matched_san_sha256,
            tls_audit_anchor,
        })
    }

    pub fn audit(&self) -> &TlsAuditChain {
        &self.audit
    }
}

fn validate_observation<B: ByteStreamBackend>(
    stream: &BoundedByteStream<B>,
    observation: &LibraryVerifiedTlsObservation,
) -> Result<(), LibraryVerifiedTlsError> {
    let grant = stream.grant();
    let expected_sni = grant
        .sni()
        .ok_or_else(|| LibraryVerifiedTlsError::InvalidObservation("missing SNI".into()))?;
    let expected_sni = normalize_dns_name(expected_sni)
        .map_err(|reason| LibraryVerifiedTlsError::InvalidObservation(reason.code().into()))?;
    let observed_sni = normalize_dns_name(&observation.server_name)
        .map_err(|reason| LibraryVerifiedTlsError::InvalidObservation(reason.code().into()))?;

    if grant.scheme() != "https" {
        return Err(LibraryVerifiedTlsError::InvalidObservation(
            "library-verified binding requires HTTPS".into(),
        ));
    }
    if expected_sni != observed_sni {
        return Err(LibraryVerifiedTlsError::InvalidObservation(
            "verified server name does not match stream SNI".into(),
        ));
    }
    if grant.http_host().to_ascii_lowercase()
        != expected_http_authority(&expected_sni, grant.port())
    {
        return Err(LibraryVerifiedTlsError::InvalidObservation(
            "HTTP authority does not match verified SNI".into(),
        ));
    }
    if observation.verifier_id.is_empty()
        || observation.verifier_id.len() > 128
        || !observation.verifier_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(LibraryVerifiedTlsError::InvalidObservation(
            "TLS library verifier identifier is invalid".into(),
        ));
    }
    if !matches!(
        observation.protocol_version,
        TlsProtocolVersion::Tls12 | TlsProtocolVersion::Tls13
    ) || observation.alpn != "http/1.1"
    {
        return Err(LibraryVerifiedTlsError::InvalidObservation(
            "TLS version or ALPN is outside the verified HTTP/1.1 boundary".into(),
        ));
    }
    if observation.chain_depth == 0 || observation.chain_depth > 16 {
        return Err(LibraryVerifiedTlsError::InvalidObservation(
            "certificate chain depth is outside the bridge limit".into(),
        ));
    }
    for (value, name) in [
        (&observation.chain_fingerprint_sha256, "certificate chain"),
        (&observation.leaf_fingerprint_sha256, "leaf certificate"),
        (&observation.trust_anchor_sha256, "trust anchor snapshot"),
    ] {
        if !is_lower_hex_sha256(value) {
            return Err(LibraryVerifiedTlsError::InvalidObservation(format!(
                "{name} fingerprint is invalid"
            )));
        }
    }
    if observation.early_data_accepted
        || observation.renegotiation_observed
        || observation.session_resumed
    {
        return Err(LibraryVerifiedTlsError::InvalidObservation(
            "early data, renegotiation and resumed sessions are rejected".into(),
        ));
    }
    Ok(())
}
