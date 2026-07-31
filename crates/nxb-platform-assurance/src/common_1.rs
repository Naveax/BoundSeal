use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_AUDIT_RECORDS: usize = 16_384;
pub const MAX_OPERATOR_APPROVALS: usize = 16;
pub const MAX_ASSURANCE_REQUIREMENTS: usize = 512;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AssuranceError {
    #[error("identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("SHA-256 field is invalid: {0}")]
    InvalidSha256(String),
    #[error("policy or certificate binding is invalid: {0}")]
    InvalidBinding(String),
    #[error("state transition is invalid: {0}")]
    InvalidTransition(String),
    #[error("approval is denied: {0}")]
    ApprovalDenied(String),
    #[error("assurance closure is denied: {0}")]
    ClosureDenied(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("audit sequence mismatch at record {0}")]
    AuditSequenceMismatch(usize),
    #[error("audit previous hash mismatch at record {0}")]
    AuditPreviousHashMismatch(usize),
    #[error("audit record hash mismatch at record {0}")]
    AuditRecordHashMismatch(usize),
    #[error("audit tail mismatch")]
    AuditTailMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssuranceAuditEvent {
    pub action: String,
    pub subject_id: String,
    pub outcome: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssuranceAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: AssuranceAuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Clone)]
pub struct AssuranceAuditChain {
    genesis_hash: String,
    records: Vec<AssuranceAuditRecord>,
    tail_hash: String,
}
