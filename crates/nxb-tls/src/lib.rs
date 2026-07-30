mod audit;
mod grant_access;
mod identity;
mod model;
mod verifier;

pub use audit::{TlsAuditChain, TlsAuditError, TlsAuditEvent, TlsAuditRecord};
pub use model::{
    SyntheticCertificate, TlsHandshakeObservation, TlsLimits, TlsPeerVerifierConfig,
    TlsProtocolVersion, TlsRejectionReason, TlsSessionGrant, TlsTrustStore,
    TlsVerificationDecision, TlsVerificationOutcome, MAX_CERTIFICATE_BYTES,
    MAX_CERTIFICATE_CHAIN_BYTES, MAX_CERTIFICATE_CHAIN_DEPTH, MAX_HANDSHAKE_BYTES,
    MAX_HANDSHAKE_TIMEOUT_MILLISECONDS,
};
pub use verifier::{TlsPeerVerifier, TlsVerifierError};

#[cfg(test)]
mod audit_tests;
