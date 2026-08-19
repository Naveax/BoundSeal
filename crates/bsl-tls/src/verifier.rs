use std::collections::BTreeMap;

use bsl_stream::{BoundedByteStream, ByteStreamBackend};
use thiserror::Error;

use crate::{
    audit::{hex_sha256, TlsAuditChain, TlsAuditError, TlsAuditEvent},
    identity::{expected_http_authority, match_dns_san, normalize_dns_name},
    model::{
        is_lower_hex_sha256, SyntheticCertificate, TlsHandshakeObservation, TlsPeerVerifierConfig,
        TlsProtocolVersion, TlsRejectionReason, TlsSessionGrant, TlsTrustStore,
        TlsVerificationDecision, TlsVerificationOutcome,
    },
};

#[derive(Debug, Error)]
pub enum TlsVerifierError {
    #[error("TLS verifier configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("TLS audit record could not be committed: {0}")]
    Audit(#[from] TlsAuditError),
}

#[derive(Debug)]
pub struct TlsPeerVerifier {
    config: TlsPeerVerifierConfig,
    trust_store: TlsTrustStore,
    audit: TlsAuditChain,
    next_verification_id: u64,
    next_session_id: u64,
}

struct VerifiedMaterial {
    normalized_sni: String,
    matched_san_sha256: String,
    leaf_fingerprint_sha256: String,
    root_fingerprint_sha256: String,
}

impl TlsPeerVerifier {
    pub fn new(
        config: TlsPeerVerifierConfig,
        trust_store: TlsTrustStore,
    ) -> Result<Self, TlsVerifierError> {
        if config.verifier_id.is_empty()
            || config.verifier_id.len() > 128
            || !config
                .verifier_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(TlsVerifierError::InvalidConfiguration(
                "verifier_id is invalid".into(),
            ));
        }
        config
            .limits
            .validate()
            .map_err(TlsVerifierError::InvalidConfiguration)?;
        if trust_store.is_empty() {
            return Err(TlsVerifierError::InvalidConfiguration(
                "trust store is empty".into(),
            ));
        }
        Ok(Self {
            config,
            trust_store,
            audit: TlsAuditChain::new(),
            next_verification_id: 1,
            next_session_id: 1,
        })
    }

    pub fn verify<B: ByteStreamBackend>(
        &mut self,
        stream: &BoundedByteStream<B>,
        observation: &TlsHandshakeObservation,
        now_epoch_seconds: i64,
    ) -> Result<TlsVerificationDecision, TlsVerifierError> {
        let verification_id = self.allocate_verification_id();
        let evaluation = self.evaluate(stream, observation, now_epoch_seconds);
        let tls_session_id = evaluation.as_ref().ok().map(|_| self.allocate_session_id());
        let (outcome, material, reason, details) = match evaluation {
            Ok(material) => (
                TlsVerificationOutcome::Verified,
                Some(material),
                "verified".to_string(),
                BTreeMap::new(),
            ),
            Err(rejection) => {
                let details = rejection.details();
                let reason = rejection.code().to_string();
                (
                    TlsVerificationOutcome::Rejected { reason: rejection },
                    None,
                    reason,
                    details,
                )
            }
        };

        let grant = stream.grant();
        let stream_audit_anchor = stream.audit().tail_hash().to_string();
        let chain_fingerprint_sha256 = chain_fingerprint_digest(&observation.chain);
        let leaf_fingerprint_sha256 = observation
            .chain
            .first()
            .filter(|certificate| is_lower_hex_sha256(&certificate.fingerprint_sha256))
            .map(|certificate| certificate.fingerprint_sha256.clone());
        let root_fingerprint_sha256 = observation
            .chain
            .last()
            .filter(|certificate| is_lower_hex_sha256(&certificate.fingerprint_sha256))
            .map(|certificate| certificate.fingerprint_sha256.clone());
        let matched_san_sha256 = material
            .as_ref()
            .map(|value| value.matched_san_sha256.clone());
        let event = TlsAuditEvent {
            verification_id,
            tls_session_id: tls_session_id.clone(),
            verifier_id: self.config.verifier_id.clone(),
            status: outcome.code().into(),
            reason,
            stream_id: grant.stream_id().into(),
            execution_id: grant.execution_id().into(),
            ticket_id: grant.ticket_id().into(),
            binding_hash: grant.binding_hash().into(),
            stream_audit_anchor: stream_audit_anchor.clone(),
            sni: grant.sni().unwrap_or("[missing]").to_ascii_lowercase(),
            http_host: grant.http_host().to_ascii_lowercase(),
            port: grant.port(),
            redirect_depth: grant.redirect_depth(),
            protocol_version: observation.protocol_version.code().into(),
            alpn: observation
                .alpn
                .as_deref()
                .unwrap_or("[missing]")
                .chars()
                .take(64)
                .collect(),
            handshake_read_bytes: observation.handshake_read_bytes,
            handshake_write_bytes: observation.handshake_write_bytes,
            elapsed_milliseconds: observation.elapsed_milliseconds,
            chain_depth: observation.chain.len(),
            chain_fingerprint_sha256,
            leaf_fingerprint_sha256,
            root_fingerprint_sha256,
            matched_san_sha256,
            early_data_accepted: observation.early_data_accepted,
            renegotiation_observed: observation.renegotiation_observed,
            session_resumed: observation.session_resumed,
            details,
        };
        let audit_anchor = self.audit.append(event)?.record_hash.clone();

        let grant = match (material, tls_session_id) {
            (Some(material), Some(tls_session_id)) => Some(TlsSessionGrant {
                tls_session_id,
                stream_id: grant.stream_id().into(),
                execution_id: grant.execution_id().into(),
                ticket_id: grant.ticket_id().into(),
                binding_hash: grant.binding_hash().into(),
                stream_audit_anchor,
                sni: material.normalized_sni,
                http_host: grant.http_host().into(),
                port: grant.port(),
                redirect_depth: grant.redirect_depth(),
                protocol_version: observation.protocol_version,
                alpn: "http/1.1".into(),
                leaf_fingerprint_sha256: material.leaf_fingerprint_sha256,
                root_fingerprint_sha256: material.root_fingerprint_sha256,
                matched_san_sha256: material.matched_san_sha256,
                tls_audit_anchor: audit_anchor,
            }),
            _ => None,
        };
        Ok(TlsVerificationDecision { outcome, grant })
    }

    pub fn audit(&self) -> &TlsAuditChain {
        &self.audit
    }

    fn evaluate<B: ByteStreamBackend>(
        &self,
        stream: &BoundedByteStream<B>,
        observation: &TlsHandshakeObservation,
        now_epoch_seconds: i64,
    ) -> Result<VerifiedMaterial, TlsRejectionReason> {
        let grant = stream.grant();
        if grant.scheme() != "https" {
            return Err(TlsRejectionReason::HttpTransport);
        }
        let expected_sni = grant.sni().ok_or(TlsRejectionReason::MissingSni)?;
        let expected_sni = normalize_dns_name(expected_sni)?;
        let observed_sni = normalize_dns_name(&observation.server_name)?;
        if expected_sni != observed_sni {
            return Err(TlsRejectionReason::SniMismatch);
        }
        if grant.http_host().to_ascii_lowercase()
            != expected_http_authority(&expected_sni, grant.port())
        {
            return Err(TlsRejectionReason::InvalidHttpAuthority);
        }
        if !matches!(
            observation.protocol_version,
            TlsProtocolVersion::Tls12 | TlsProtocolVersion::Tls13
        ) {
            return Err(TlsRejectionReason::UnsupportedProtocolVersion);
        }
        let alpn = observation
            .alpn
            .as_deref()
            .ok_or(TlsRejectionReason::MissingAlpn)?;
        if alpn != "http/1.1" {
            return Err(TlsRejectionReason::UnsupportedAlpn);
        }
        if observation.early_data_accepted {
            return Err(TlsRejectionReason::EarlyDataRejected);
        }
        if observation.renegotiation_observed {
            return Err(TlsRejectionReason::RenegotiationRejected);
        }
        if observation.session_resumed {
            return Err(TlsRejectionReason::SessionResumptionRejected);
        }
        if observation.elapsed_milliseconds > self.config.limits.handshake_timeout_milliseconds {
            return Err(TlsRejectionReason::HandshakeTimeout);
        }
        if observation.handshake_read_bytes > self.config.limits.maximum_handshake_read_bytes {
            return Err(TlsRejectionReason::HandshakeReadBudgetExceeded);
        }
        if observation.handshake_write_bytes > self.config.limits.maximum_handshake_write_bytes {
            return Err(TlsRejectionReason::HandshakeWriteBudgetExceeded);
        }
        self.verify_chain(&expected_sni, &observation.chain, now_epoch_seconds)
    }

    fn verify_chain(
        &self,
        expected_sni: &str,
        chain: &[SyntheticCertificate],
        now_epoch_seconds: i64,
    ) -> Result<VerifiedMaterial, TlsRejectionReason> {
        if chain.is_empty() {
            return Err(TlsRejectionReason::EmptyCertificateChain);
        }
        if chain.len() > self.config.limits.maximum_chain_depth {
            return Err(TlsRejectionReason::CertificateChainTooDeep);
        }

        let mut chain_bytes = 0_u64;
        for (index, certificate) in chain.iter().enumerate() {
            validate_certificate_metadata(certificate, index)?;
            if certificate.encoded_bytes > self.config.limits.maximum_certificate_bytes {
                return Err(TlsRejectionReason::CertificateTooLarge {
                    certificate_index: index,
                });
            }
            chain_bytes = chain_bytes.saturating_add(certificate.encoded_bytes);
            if chain_bytes > self.config.limits.maximum_chain_bytes {
                return Err(TlsRejectionReason::CertificateChainTooLarge);
            }
            if now_epoch_seconds < certificate.not_before_epoch_seconds {
                return Err(TlsRejectionReason::CertificateNotYetValid {
                    certificate_index: index,
                });
            }
            if now_epoch_seconds > certificate.not_after_epoch_seconds {
                return Err(TlsRejectionReason::CertificateExpired {
                    certificate_index: index,
                });
            }
            if certificate.unsupported_critical_extension {
                return Err(TlsRejectionReason::UnsupportedCriticalExtension {
                    certificate_index: index,
                });
            }
        }

        let leaf = &chain[0];
        if leaf.is_ca {
            return Err(TlsRejectionReason::LeafIsCertificateAuthority);
        }
        if !leaf.eku_server_auth {
            return Err(TlsRejectionReason::LeafMissingServerAuthEku);
        }
        if !leaf.key_usage_digital_signature {
            return Err(TlsRejectionReason::LeafMissingDigitalSignatureUsage);
        }
        let identity = match_dns_san(
            expected_sni,
            &leaf.dns_sans,
            self.config.limits.maximum_dns_sans,
        )?;

        for index in 0..chain.len().saturating_sub(1) {
            let certificate = &chain[index];
            let issuer = &chain[index + 1];
            if certificate.issuer_spki_sha256 != issuer.subject_spki_sha256 {
                return Err(TlsRejectionReason::IssuerLinkMismatch {
                    certificate_index: index,
                });
            }
            if !certificate.signature_valid {
                return Err(TlsRejectionReason::InvalidCertificateSignature {
                    certificate_index: index,
                });
            }
        }

        for (index, certificate) in chain
            .iter()
            .enumerate()
            .skip(1)
            .take(chain.len().saturating_sub(2))
        {
            if !certificate.is_ca {
                return Err(TlsRejectionReason::IntermediateNotCertificateAuthority {
                    certificate_index: index,
                });
            }
            if !certificate.key_usage_cert_sign {
                return Err(
                    TlsRejectionReason::IntermediateMissingCertificateSignUsage {
                        certificate_index: index,
                    },
                );
            }
            if let Some(limit) = certificate.path_len_constraint {
                let subordinate_ca_count = index.saturating_sub(1);
                if subordinate_ca_count > usize::from(limit) {
                    return Err(TlsRejectionReason::PathLengthConstraintExceeded {
                        certificate_index: index,
                    });
                }
            }
        }

        let root_index = chain.len() - 1;
        let root = &chain[root_index];
        if !root.is_ca {
            return Err(TlsRejectionReason::RootNotCertificateAuthority);
        }
        if !root.key_usage_cert_sign {
            return Err(TlsRejectionReason::RootMissingCertificateSignUsage);
        }
        if root.subject_spki_sha256 != root.issuer_spki_sha256 {
            return Err(TlsRejectionReason::RootNotSelfIssued);
        }
        if !root.signature_valid {
            return Err(TlsRejectionReason::InvalidCertificateSignature {
                certificate_index: root_index,
            });
        }
        if let Some(limit) = root.path_len_constraint {
            let subordinate_ca_count = root_index.saturating_sub(1);
            if subordinate_ca_count > usize::from(limit) {
                return Err(TlsRejectionReason::PathLengthConstraintExceeded {
                    certificate_index: root_index,
                });
            }
        }
        if !self.trust_store.trusts(&root.fingerprint_sha256) {
            return Err(TlsRejectionReason::UntrustedRoot);
        }

        Ok(VerifiedMaterial {
            normalized_sni: identity.normalized_sni,
            matched_san_sha256: identity.matched_san_sha256,
            leaf_fingerprint_sha256: leaf.fingerprint_sha256.clone(),
            root_fingerprint_sha256: root.fingerprint_sha256.clone(),
        })
    }

    fn allocate_verification_id(&mut self) -> String {
        let value = self.next_verification_id;
        self.next_verification_id = self.next_verification_id.saturating_add(1);
        format!("tls-verification-{value:020}")
    }

    fn allocate_session_id(&mut self) -> String {
        let value = self.next_session_id;
        self.next_session_id = self.next_session_id.saturating_add(1);
        format!("tls-session-{value:020}")
    }
}

fn validate_certificate_metadata(
    certificate: &SyntheticCertificate,
    certificate_index: usize,
) -> Result<(), TlsRejectionReason> {
    if !is_lower_hex_sha256(&certificate.fingerprint_sha256)
        || !is_lower_hex_sha256(&certificate.subject_spki_sha256)
        || !is_lower_hex_sha256(&certificate.issuer_spki_sha256)
        || certificate.encoded_bytes == 0
        || certificate.not_before_epoch_seconds > certificate.not_after_epoch_seconds
    {
        return Err(TlsRejectionReason::InvalidCertificateMetadata { certificate_index });
    }
    Ok(())
}

fn chain_fingerprint_digest(chain: &[SyntheticCertificate]) -> String {
    let material = chain
        .iter()
        .map(|certificate| certificate.fingerprint_sha256.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    hex_sha256(material.as_bytes())
}
