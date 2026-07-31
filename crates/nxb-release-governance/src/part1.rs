use std::collections::{BTreeMap, BTreeSet, VecDeque};

use nxb_adapter_boundary::AdapterConformanceCertificate;
use nxb_replay_lab::ReproducibilityCertificate;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_COMPONENTS: usize = 10_000;
pub const MAX_DEPENDENCIES_PER_COMPONENT: usize = 256;
pub const MAX_COMPATIBILITY_REQUIREMENTS: usize = 4096;
pub const MAX_MIGRATION_STEPS: usize = 1024;
pub const MAX_RELEASE_GATES: usize = 1024;
pub const MAX_ARTIFACT_ENTRIES: usize = 100_000;
pub const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_ROLLOUT_STAGES: usize = 32;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    #[error("release identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("SHA-256 field is invalid: {0}")]
    InvalidSha256(String),
    #[error("component inventory is invalid: {0}")]
    InvalidInventory(String),
    #[error("compatibility contract is invalid: {0}")]
    InvalidCompatibility(String),
    #[error("release gate is invalid: {0}")]
    InvalidGate(String),
    #[error("artifact manifest is invalid: {0}")]
    InvalidArtifact(String),
    #[error("rollout transition is invalid")]
    InvalidRolloutTransition,
    #[error("platform release certification is denied: {0}")]
    CertificationDenied(String),
    #[error("release audit serialization failed: {0}")]
    AuditSerialization(String),
    #[error("release audit sequence mismatch at record {record_index}")]
    AuditSequenceMismatch { record_index: usize },
    #[error("release audit previous hash mismatch at record {record_index}")]
    AuditPreviousHashMismatch { record_index: usize },
    #[error("release audit record hash mismatch at record {record_index}")]
    AuditRecordHashMismatch { record_index: usize },
    #[error("release audit tail hash mismatch")]
    AuditTailMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    Library,
    Binary,
    FixturePack,
    PolicySchema,
    ReportSchema,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityAxis {
    EventSchema,
    PolicySchema,
    FixtureSchema,
    AdapterSchema,
    ReplaySchema,
    ReportSchema,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Compatible,
    TooOld,
    TooNew,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MigrationKind {
    SchemaForward,
    PolicySnapshotRebind,
    FixtureReindex,
    MetadataOnly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseGateClass {
    HardSafety,
    Compatibility,
    Reproducibility,
    ArtifactIntegrity,
    RollbackReadiness,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    Passed,
    Failed,
    Waived,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RolloutState {
    Planned,
    CanaryRunning,
    CanaryValidated,
    RollbackRunning,
    RolledBack,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseAuditEvent {
    pub action: String,
    pub subject_id: String,
    pub outcome: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: ReleaseAuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Clone)]
pub struct ReleaseAuditChain {
    genesis_hash: String,
    records: Vec<ReleaseAuditRecord>,
    tail_hash: String,
}

impl ReleaseAuditChain {
    pub fn new(genesis_hash: impl Into<String>) -> Result<Self, ReleaseError> {
        let genesis_hash = genesis_hash.into();
        validate_sha256(&genesis_hash, "release audit genesis")?;
        Ok(Self {
            tail_hash: genesis_hash.clone(),
            genesis_hash,
            records: Vec::new(),
        })
    }

    pub fn append(
        &mut self,
        event: ReleaseAuditEvent,
    ) -> Result<&ReleaseAuditRecord, ReleaseError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event))?;
        self.records.push(ReleaseAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("release audit append"))
    }

    pub fn records(&self) -> &[ReleaseAuditRecord] {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut [ReleaseAuditRecord] {
        &mut self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), ReleaseError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(ReleaseError::AuditSequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous_hash {
                return Err(ReleaseError::AuditPreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected = hash_serializable(&(
                record.sequence,
                &record.previous_hash,
                &record.event,
            ))?;
            if record.record_hash != expected {
                return Err(ReleaseError::AuditRecordHashMismatch {
                    record_index: index,
                });
            }
            previous_hash = expected;
        }
        if self.tail_hash != previous_hash {
            return Err(ReleaseError::AuditTailMismatch);
        }
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, name: &str) -> Result<(), ReleaseError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(ReleaseError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, name: &str) -> Result<(), ReleaseError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReleaseError::InvalidSha256(name.into()));
    }
    Ok(())
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

pub(crate) fn hash_serializable<T: Serialize>(value: &T) -> Result<String, ReleaseError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ReleaseError::AuditSerialization(error.to_string()))?;
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
