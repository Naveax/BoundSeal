use std::collections::{BTreeMap, BTreeSet};

use nxb_adapter_boundary::AdapterConformanceCertificate;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_REPLAY_INPUTS: usize = 100_000;
pub const MAX_REPLAY_INPUT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_REPLAY_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_FAULT_RULES: usize = 4096;
pub const MAX_FAULT_MAGNITUDE: u64 = 1_000_000;
pub const MAX_VIRTUAL_TICK: u64 = 10_000_000_000;
pub const MAX_REPRODUCIBILITY_RECEIPTS: usize = 32;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReplayError {
    #[error("replay identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("SHA-256 field is invalid: {0}")]
    InvalidSha256(String),
    #[error("replay bundle is invalid: {0}")]
    InvalidBundle(String),
    #[error("virtual clock transition is invalid")]
    InvalidClock,
    #[error("fault plan is invalid: {0}")]
    InvalidFaultPlan(String),
    #[error("replay transition is invalid")]
    InvalidTransition,
    #[error("replay sequence mismatch")]
    SequenceMismatch,
    #[error("replay drift comparison is invalid: {0}")]
    InvalidComparison(String),
    #[error("reproducibility certification is denied: {0}")]
    CertificationDenied(String),
    #[error("replay audit serialization failed: {0}")]
    AuditSerialization(String),
    #[error("replay audit sequence mismatch at record {record_index}")]
    AuditSequenceMismatch { record_index: usize },
    #[error("replay audit previous hash mismatch at record {record_index}")]
    AuditPreviousHashMismatch { record_index: usize },
    #[error("replay audit record hash mismatch at record {record_index}")]
    AuditRecordHashMismatch { record_index: usize },
    #[error("replay audit tail hash mismatch")]
    AuditTailMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FaultKind {
    Delay,
    Fragment,
    Backpressure,
    Timeout,
    Reset,
    Truncate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStepOutcome {
    Observed,
    Backpressured,
    TimedOut,
    Reset,
    Truncated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplayState {
    Created,
    Running,
    Completed,
    Cancelled,
    EmergencyStopped,
    Failed,
}

impl ReplayState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::EmergencyStopped | Self::Failed
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriftClass {
    Exact,
    TimingDrift,
    SemanticDrift,
    FaultPlanDrift,
    InputDrift,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayAuditEvent {
    pub action: String,
    pub subject_id: String,
    pub outcome: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: ReplayAuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Clone)]
pub struct ReplayAuditChain {
    genesis_hash: String,
    records: Vec<ReplayAuditRecord>,
    tail_hash: String,
}

impl ReplayAuditChain {
    pub fn new(genesis_hash: impl Into<String>) -> Result<Self, ReplayError> {
        let genesis_hash = genesis_hash.into();
        validate_sha256(&genesis_hash, "replay audit genesis")?;
        Ok(Self {
            tail_hash: genesis_hash.clone(),
            genesis_hash,
            records: Vec::new(),
        })
    }

    pub fn append(
        &mut self,
        event: ReplayAuditEvent,
    ) -> Result<&ReplayAuditRecord, ReplayError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event))?;
        self.records.push(ReplayAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("replay audit append"))
    }

    pub fn records(&self) -> &[ReplayAuditRecord] {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut [ReplayAuditRecord] {
        &mut self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), ReplayError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(ReplayError::AuditSequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous_hash {
                return Err(ReplayError::AuditPreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected = hash_serializable(&(
                record.sequence,
                &record.previous_hash,
                &record.event,
            ))?;
            if record.record_hash != expected {
                return Err(ReplayError::AuditRecordHashMismatch {
                    record_index: index,
                });
            }
            previous_hash = expected;
        }
        if self.tail_hash != previous_hash {
            return Err(ReplayError::AuditTailMismatch);
        }
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, name: &str) -> Result<(), ReplayError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(ReplayError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, name: &str) -> Result<(), ReplayError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReplayError::InvalidSha256(name.into()));
    }
    Ok(())
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

pub(crate) fn hash_serializable<T: Serialize>(value: &T) -> Result<String, ReplayError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ReplayError::AuditSerialization(error.to_string()))?;
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
