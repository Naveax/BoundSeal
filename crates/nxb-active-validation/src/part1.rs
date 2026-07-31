use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use nxb_planner::{CapabilityUseReceipt, RequestIntentPlan, RiskClass};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_MUTATIONS_PER_PLAN: u32 = 256;
pub const MAX_MUTATION_VALUE_BYTES: usize = 4096;
pub const MAX_OWNED_OBJECTS: usize = 10_000;
pub const MAX_DIFFERENTIAL_SAMPLES: usize = 32;
pub const MAX_SEMANTIC_TOKENS: usize = 4096;
pub const MAX_SAMPLE_BODY_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("validation identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("SHA-256 field is invalid: {0}")]
    InvalidSha256(String),
    #[error("mutation request is invalid: {0}")]
    InvalidMutation(String),
    #[error("mutation is not authorized by the active plan or capability")]
    MutationDenied,
    #[error("owned-object ledger is full")]
    OwnershipLedgerFull,
    #[error("owned object is unknown")]
    UnknownOwnedObject,
    #[error("owned-object state transition is invalid")]
    InvalidOwnedObjectState,
    #[error("differential sample is invalid: {0}")]
    InvalidSample(String),
    #[error("validation oracle input is insufficient or inconsistent: {0}")]
    InvalidOracleInput(String),
    #[error("validation audit serialization failed: {0}")]
    AuditSerialization(String),
    #[error("validation audit sequence mismatch at record {record_index}")]
    AuditSequenceMismatch { record_index: usize },
    #[error("validation audit previous hash mismatch at record {record_index}")]
    AuditPreviousHashMismatch { record_index: usize },
    #[error("validation audit record hash mismatch at record {record_index}")]
    AuditRecordHashMismatch { record_index: usize },
    #[error("validation audit tail hash mismatch")]
    AuditTailMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MutationLocation {
    Query,
    Header,
    Form,
    Json,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    ReplaceWithMarker,
    AppendMarker,
    EmptyValue,
    TypePreservingMarker,
    BoundedBoundary,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValueClass {
    Text,
    Integer,
    Boolean,
    Opaque,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OwnedObjectState {
    Registered,
    CleanupPending,
    Cleaned,
    CleanupFailed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OracleDecision {
    Confirmed,
    Rejected,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PromotionState {
    Candidate,
    Validated,
    Rejected,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationAuditEvent {
    pub action: String,
    pub subject_id: String,
    pub outcome: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: ValidationAuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Clone)]
pub struct ValidationAuditChain {
    genesis_hash: String,
    records: Vec<ValidationAuditRecord>,
    tail_hash: String,
}

impl ValidationAuditChain {
    pub fn new(genesis_hash: impl Into<String>) -> Result<Self, ValidationError> {
        let genesis_hash = genesis_hash.into();
        validate_sha256(&genesis_hash, "audit genesis")?;
        Ok(Self {
            tail_hash: genesis_hash.clone(),
            genesis_hash,
            records: Vec::new(),
        })
    }

    pub fn append(
        &mut self,
        event: ValidationAuditEvent,
    ) -> Result<&ValidationAuditRecord, ValidationError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event))?;
        self.records.push(ValidationAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("validation audit append"))
    }

    pub fn records(&self) -> &[ValidationAuditRecord] {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut [ValidationAuditRecord] {
        &mut self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), ValidationError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(ValidationError::AuditSequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous_hash {
                return Err(ValidationError::AuditPreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected = hash_serializable(&(
                record.sequence,
                &record.previous_hash,
                &record.event,
            ))?;
            if record.record_hash != expected {
                return Err(ValidationError::AuditRecordHashMismatch {
                    record_index: index,
                });
            }
            previous_hash = expected;
        }
        if self.tail_hash != previous_hash {
            return Err(ValidationError::AuditTailMismatch);
        }
        Ok(())
    }
}

fn validate_identifier(value: &str, name: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(ValidationError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_sha256(value: &str, name: &str) -> Result<(), ValidationError> {
    if !is_sha256(value) {
        return Err(ValidationError::InvalidSha256(name.into()));
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, ValidationError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ValidationError::AuditSerialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
