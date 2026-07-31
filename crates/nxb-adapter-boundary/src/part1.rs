use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_ADAPTER_ACTIONS: usize = 16;
pub const MAX_FIXTURE_OBJECTS: usize = 10_000;
pub const MAX_FIXTURE_OBJECT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_SESSION_MESSAGES: u64 = 100_000;
pub const MAX_MESSAGE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_SESSION_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_CPU_MILLISECONDS: u64 = 600_000;
pub const MAX_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BoundaryError {
    #[error("adapter boundary identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("SHA-256 field is invalid: {0}")]
    InvalidSha256(String),
    #[error("adapter manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("adapter admission is denied: {0}")]
    AdmissionDenied(String),
    #[error("adapter grant is inactive or already consumed")]
    GrantInactive,
    #[error("synthetic fixture is invalid: {0}")]
    InvalidFixture(String),
    #[error("synthetic fixture profile is unknown")]
    UnknownFixtureProfile,
    #[error("adapter envelope is invalid: {0}")]
    InvalidEnvelope(String),
    #[error("adapter session transition is invalid")]
    InvalidSessionTransition,
    #[error("adapter session quota is exceeded: {0}")]
    QuotaExceeded(String),
    #[error("adapter conformance certification is denied: {0}")]
    CertificationDenied(String),
    #[error("adapter audit serialization failed: {0}")]
    AuditSerialization(String),
    #[error("adapter audit sequence mismatch at record {record_index}")]
    AuditSequenceMismatch { record_index: usize },
    #[error("adapter audit previous hash mismatch at record {record_index}")]
    AuditPreviousHashMismatch { record_index: usize },
    #[error("adapter audit record hash mismatch at record {record_index}")]
    AuditRecordHashMismatch { record_index: usize },
    #[error("adapter audit tail hash mismatch")]
    AuditTailMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AdapterCapability {
    FixtureRead,
    DeterministicTransform,
    ObservationEmit,
    Finalization,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AdapterAction {
    LoadFixture,
    ExecuteReadOnly,
    EmitObservation,
    Finalize,
}

impl AdapterAction {
    fn required_capability(self) -> AdapterCapability {
        match self {
            Self::LoadFixture => AdapterCapability::FixtureRead,
            Self::ExecuteReadOnly => AdapterCapability::DeterministicTransform,
            Self::EmitObservation => AdapterCapability::ObservationEmit,
            Self::Finalize => AdapterCapability::Finalization,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FixtureObjectKind {
    RequestMetadata,
    ResponseMetadata,
    StructuredDocument,
    EventSequence,
    ExpectedObservation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdapterOutcome {
    Accepted,
    ProducedObservation,
    NoObservation,
    Finalized,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Open,
    Cancelling,
    Completed,
    Cancelled,
    EmergencyStopped,
    Failed,
}

impl SessionState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::EmergencyStopped | Self::Failed
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterAuditEvent {
    pub action: String,
    pub subject_id: String,
    pub outcome: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: AdapterAuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Clone)]
pub struct AdapterAuditChain {
    genesis_hash: String,
    records: Vec<AdapterAuditRecord>,
    tail_hash: String,
}

impl AdapterAuditChain {
    pub fn new(genesis_hash: impl Into<String>) -> Result<Self, BoundaryError> {
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
        event: AdapterAuditEvent,
    ) -> Result<&AdapterAuditRecord, BoundaryError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event))?;
        self.records.push(AdapterAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("adapter audit append"))
    }

    pub fn records(&self) -> &[AdapterAuditRecord] {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut [AdapterAuditRecord] {
        &mut self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), BoundaryError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(BoundaryError::AuditSequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous_hash {
                return Err(BoundaryError::AuditPreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected = hash_serializable(&(
                record.sequence,
                &record.previous_hash,
                &record.event,
            ))?;
            if record.record_hash != expected {
                return Err(BoundaryError::AuditRecordHashMismatch {
                    record_index: index,
                });
            }
            previous_hash = expected;
        }
        if self.tail_hash != previous_hash {
            return Err(BoundaryError::AuditTailMismatch);
        }
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, name: &str) -> Result<(), BoundaryError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(BoundaryError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, name: &str) -> Result<(), BoundaryError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BoundaryError::InvalidSha256(name.into()));
    }
    Ok(())
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

pub(crate) fn hash_serializable<T: Serialize>(value: &T) -> Result<String, BoundaryError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| BoundaryError::AuditSerialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
}

pub(crate) fn reject_secret_like_text(value: &str) -> Result<(), BoundaryError> {
    let lower = value.to_ascii_lowercase();
    for forbidden in [
        "authorization:",
        "proxy-authorization:",
        "cookie:",
        "set-cookie:",
        "bearer ",
        "password=",
        "token=",
        "secret=",
        "http://",
        "https://",
        "file://",
        "ssh://",
    ] {
        if lower.contains(forbidden) {
            return Err(BoundaryError::InvalidFixture(
                "secret-like or external-destination material".into(),
            ));
        }
    }
    Ok(())
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
