use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const MAX_CERTIFICATE_CHAIN_DEPTH: usize = 8;
pub const MAX_CERTIFICATE_BYTES: u64 = 1024 * 1024;
pub const MAX_CERTIFICATE_CHAIN_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_HANDSHAKE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_HANDSHAKE_TIMEOUT_MILLISECONDS: u64 = 30_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsProtocolVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Other,
}

impl TlsProtocolVersion {
    pub fn code(self) -> &'static str {
        match self {
            Self::Tls10 => "tls_1_0",
            Self::Tls11 => "tls_1_1",
            Self::Tls12 => "tls_1_2",
            Self::Tls13 => "tls_1_3",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsLimits {
    pub maximum_chain_depth: usize,
    pub maximum_certificate_bytes: u64,
    pub maximum_chain_bytes: u64,
    pub maximum_handshake_read_bytes: u64,
    pub maximum_handshake_write_bytes: u64,
    pub handshake_timeout_milliseconds: u64,
    pub maximum_dns_sans: usize,
}

impl TlsLimits {
    pub fn conservative_default() -> Self {
        Self {
            maximum_chain_depth: 6,
            maximum_certificate_bytes: 512 * 1024,
            maximum_chain_bytes: 2 * 1024 * 1024,
            maximum_handshake_read_bytes: 512 * 1024,
            maximum_handshake_write_bytes: 256 * 1024,
            handshake_timeout_milliseconds: 10_000,
            maximum_dns_sans: 128,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.maximum_chain_depth == 0 || self.maximum_chain_depth > MAX_CERTIFICATE_CHAIN_DEPTH {
            return Err("certificate chain depth is outside the supported range".into());
        }
        if self.maximum_certificate_bytes == 0
            || self.maximum_certificate_bytes > MAX_CERTIFICATE_BYTES
        {
            return Err("per-certificate byte limit is outside the supported range".into());
        }
        if self.maximum_chain_bytes < self.maximum_certificate_bytes
            || self.maximum_chain_bytes > MAX_CERTIFICATE_CHAIN_BYTES
        {
            return Err("certificate-chain byte limit is outside the supported range".into());
        }
        if self.maximum_handshake_read_bytes == 0
            || self.maximum_handshake_read_bytes > MAX_HANDSHAKE_BYTES
            || self.maximum_handshake_write_bytes == 0
            || self.maximum_handshake_write_bytes > MAX_HANDSHAKE_BYTES
        {
            return Err("handshake byte limits are outside the supported range".into());
        }
        if self.handshake_timeout_milliseconds == 0
            || self.handshake_timeout_milliseconds > MAX_HANDSHAKE_TIMEOUT_MILLISECONDS
        {
            return Err("handshake timeout is outside the supported range".into());
        }
        if self.maximum_dns_sans == 0 || self.maximum_dns_sans > 1024 {
            return Err("DNS SAN count limit is outside the supported range".into());
        }
        Ok(())
    }
}

impl Default for TlsLimits {
    fn default() -> Self {
        Self::conservative_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsPeerVerifierConfig {
    pub verifier_id: String,
    pub limits: TlsLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsTrustStore {
    trusted_root_fingerprints: BTreeSet<String>,
}

impl TlsTrustStore {
    pub fn new(fingerprints: impl IntoIterator<Item = String>) -> Result<Self, &'static str> {
        let trusted_root_fingerprints = fingerprints.into_iter().collect::<BTreeSet<_>>();
        if trusted_root_fingerprints.is_empty() {
            return Err("TLS trust store must contain at least one root fingerprint");
        }
        if trusted_root_fingerprints.len() > 4096
            || trusted_root_fingerprints
                .iter()
                .any(|value| !is_lower_hex_sha256(value))
        {
            return Err("TLS trust store contains an invalid root fingerprint");
        }
        Ok(Self {
            trusted_root_fingerprints,
        })
    }

    pub(crate) fn trusts(&self, fingerprint: &str) -> bool {
        self.trusted_root_fingerprints.contains(fingerprint)
    }

    pub fn len(&self) -> usize {
        self.trusted_root_fingerprints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.trusted_root_fingerprints.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyntheticCertificate {
    pub fingerprint_sha256: String,
    pub subject_spki_sha256: String,
    pub issuer_spki_sha256: String,
    pub encoded_bytes: u64,
    pub dns_sans: Vec<String>,
    pub common_name: Option<String>,
    pub not_before_epoch_seconds: i64,
    pub not_after_epoch_seconds: i64,
    pub is_ca: bool,
    pub path_len_constraint: Option<u8>,
    pub key_usage_digital_signature: bool,
    pub key_usage_cert_sign: bool,
    pub eku_server_auth: bool,
    pub signature_valid: bool,
    pub unsupported_critical_extension: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsHandshakeObservation {
    pub server_name: String,
    pub protocol_version: TlsProtocolVersion,
    pub alpn: Option<String>,
    pub chain: Vec<SyntheticCertificate>,
    pub handshake_read_bytes: u64,
    pub handshake_write_bytes: u64,
    pub elapsed_milliseconds: u64,
    pub early_data_accepted: bool,
    pub renegotiation_observed: bool,
    pub session_resumed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum TlsRejectionReason {
    HttpTransport,
    MissingSni,
    SniMismatch,
    InvalidSni,
    InvalidHttpAuthority,
    UnsupportedProtocolVersion,
    MissingAlpn,
    UnsupportedAlpn,
    EarlyDataRejected,
    RenegotiationRejected,
    SessionResumptionRejected,
    HandshakeTimeout,
    HandshakeReadBudgetExceeded,
    HandshakeWriteBudgetExceeded,
    EmptyCertificateChain,
    CertificateChainTooDeep,
    CertificateTooLarge { certificate_index: usize },
    CertificateChainTooLarge,
    InvalidCertificateMetadata { certificate_index: usize },
    CertificateNotYetValid { certificate_index: usize },
    CertificateExpired { certificate_index: usize },
    UnsupportedCriticalExtension { certificate_index: usize },
    LeafIsCertificateAuthority,
    LeafMissingServerAuthEku,
    LeafMissingDigitalSignatureUsage,
    MissingDnsSubjectAlternativeName,
    TooManyDnsSubjectAlternativeNames,
    InvalidDnsSubjectAlternativeName,
    HostnameMismatch,
    IntermediateNotCertificateAuthority { certificate_index: usize },
    IntermediateMissingCertificateSignUsage { certificate_index: usize },
    IssuerLinkMismatch { certificate_index: usize },
    InvalidCertificateSignature { certificate_index: usize },
    RootNotCertificateAuthority,
    RootMissingCertificateSignUsage,
    RootNotSelfIssued,
    PathLengthConstraintExceeded { certificate_index: usize },
    UntrustedRoot,
}

impl TlsRejectionReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::HttpTransport => "http_transport",
            Self::MissingSni => "missing_sni",
            Self::SniMismatch => "sni_mismatch",
            Self::InvalidSni => "invalid_sni",
            Self::InvalidHttpAuthority => "invalid_http_authority",
            Self::UnsupportedProtocolVersion => "unsupported_protocol_version",
            Self::MissingAlpn => "missing_alpn",
            Self::UnsupportedAlpn => "unsupported_alpn",
            Self::EarlyDataRejected => "early_data_rejected",
            Self::RenegotiationRejected => "renegotiation_rejected",
            Self::SessionResumptionRejected => "session_resumption_rejected",
            Self::HandshakeTimeout => "handshake_timeout",
            Self::HandshakeReadBudgetExceeded => "handshake_read_budget_exceeded",
            Self::HandshakeWriteBudgetExceeded => "handshake_write_budget_exceeded",
            Self::EmptyCertificateChain => "empty_certificate_chain",
            Self::CertificateChainTooDeep => "certificate_chain_too_deep",
            Self::CertificateTooLarge { .. } => "certificate_too_large",
            Self::CertificateChainTooLarge => "certificate_chain_too_large",
            Self::InvalidCertificateMetadata { .. } => "invalid_certificate_metadata",
            Self::CertificateNotYetValid { .. } => "certificate_not_yet_valid",
            Self::CertificateExpired { .. } => "certificate_expired",
            Self::UnsupportedCriticalExtension { .. } => "unsupported_critical_extension",
            Self::LeafIsCertificateAuthority => "leaf_is_certificate_authority",
            Self::LeafMissingServerAuthEku => "leaf_missing_server_auth_eku",
            Self::LeafMissingDigitalSignatureUsage => "leaf_missing_digital_signature_usage",
            Self::MissingDnsSubjectAlternativeName => "missing_dns_subject_alternative_name",
            Self::TooManyDnsSubjectAlternativeNames => "too_many_dns_subject_alternative_names",
            Self::InvalidDnsSubjectAlternativeName => "invalid_dns_subject_alternative_name",
            Self::HostnameMismatch => "hostname_mismatch",
            Self::IntermediateNotCertificateAuthority { .. } => {
                "intermediate_not_certificate_authority"
            }
            Self::IntermediateMissingCertificateSignUsage { .. } => {
                "intermediate_missing_certificate_sign_usage"
            }
            Self::IssuerLinkMismatch { .. } => "issuer_link_mismatch",
            Self::InvalidCertificateSignature { .. } => "invalid_certificate_signature",
            Self::RootNotCertificateAuthority => "root_not_certificate_authority",
            Self::RootMissingCertificateSignUsage => "root_missing_certificate_sign_usage",
            Self::RootNotSelfIssued => "root_not_self_issued",
            Self::PathLengthConstraintExceeded { .. } => "path_length_constraint_exceeded",
            Self::UntrustedRoot => "untrusted_root",
        }
    }

    pub(crate) fn details(&self) -> BTreeMap<String, String> {
        let mut details = BTreeMap::new();
        let index = match self {
            Self::CertificateTooLarge { certificate_index }
            | Self::InvalidCertificateMetadata { certificate_index }
            | Self::CertificateNotYetValid { certificate_index }
            | Self::CertificateExpired { certificate_index }
            | Self::UnsupportedCriticalExtension { certificate_index }
            | Self::IntermediateNotCertificateAuthority { certificate_index }
            | Self::IntermediateMissingCertificateSignUsage { certificate_index }
            | Self::IssuerLinkMismatch { certificate_index }
            | Self::InvalidCertificateSignature { certificate_index }
            | Self::PathLengthConstraintExceeded { certificate_index } => Some(*certificate_index),
            _ => None,
        };
        if let Some(index) = index {
            details.insert("certificate_index".into(), index.to_string());
        }
        details
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TlsVerificationOutcome {
    Verified,
    Rejected { reason: TlsRejectionReason },
}

impl TlsVerificationOutcome {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Rejected { .. } => "rejected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSessionGrant {
    pub(crate) tls_session_id: String,
    pub(crate) stream_id: String,
    pub(crate) execution_id: String,
    pub(crate) ticket_id: String,
    pub(crate) binding_hash: String,
    pub(crate) stream_audit_anchor: String,
    pub(crate) sni: String,
    pub(crate) http_host: String,
    pub(crate) port: u16,
    pub(crate) redirect_depth: u8,
    pub(crate) protocol_version: TlsProtocolVersion,
    pub(crate) alpn: String,
    pub(crate) leaf_fingerprint_sha256: String,
    pub(crate) root_fingerprint_sha256: String,
    pub(crate) matched_san_sha256: String,
    pub(crate) tls_audit_anchor: String,
}

impl TlsSessionGrant {
    pub fn tls_session_id(&self) -> &str {
        &self.tls_session_id
    }

    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub fn ticket_id(&self) -> &str {
        &self.ticket_id
    }

    pub fn sni(&self) -> &str {
        &self.sni
    }

    pub fn alpn(&self) -> &str {
        &self.alpn
    }

    pub fn protocol_version(&self) -> TlsProtocolVersion {
        self.protocol_version
    }

    pub fn tls_audit_anchor(&self) -> &str {
        &self.tls_audit_anchor
    }

    pub fn leaf_fingerprint_sha256(&self) -> &str {
        &self.leaf_fingerprint_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsVerificationDecision {
    pub outcome: TlsVerificationOutcome,
    pub grant: Option<TlsSessionGrant>,
}

impl TlsVerificationDecision {
    pub fn is_verified(&self) -> bool {
        matches!(self.outcome, TlsVerificationOutcome::Verified) && self.grant.is_some()
    }
}

pub(crate) fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
