use std::collections::{BTreeMap, BTreeSet};

use nxb_active_validation::{PromotionState, ValidatedFinding};
use nxb_passive_analyzers::{Confidence, Finding, Severity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_GRAPH_NODES: usize = 250_000;
pub const MAX_GRAPH_EDGES: usize = 1_000_000;
pub const MAX_EVIDENCE_RECORDS: usize = 250_000;
pub const MAX_EVIDENCE_SUMMARY_BYTES: usize = 8192;
pub const MAX_EVIDENCE_METADATA: usize = 128;
pub const MAX_REPORT_FINDINGS: usize = 10_000;
pub const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_MANIFEST_ENTRIES: usize = 500_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KnowledgeError {
    #[error("knowledge identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("SHA-256 field is invalid: {0}")]
    InvalidSha256(String),
    #[error("knowledge graph limit was exceeded")]
    GraphLimit,
    #[error("knowledge graph node already exists")]
    DuplicateNode,
    #[error("knowledge graph edge already exists")]
    DuplicateEdge,
    #[error("knowledge graph references an unknown node")]
    UnknownNode,
    #[error("evidence record is invalid or not safely redacted: {0}")]
    InvalidEvidence(String),
    #[error("evidence store limit was exceeded")]
    EvidenceLimit,
    #[error("finding lifecycle transition is invalid")]
    InvalidFindingTransition,
    #[error("finding is not reportable")]
    FindingNotReportable,
    #[error("report limit was exceeded")]
    ReportLimit,
    #[error("report serialization failed: {0}")]
    ReportSerialization(String),
    #[error("export manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("knowledge audit serialization failed: {0}")]
    AuditSerialization(String),
    #[error("knowledge audit sequence mismatch at record {record_index}")]
    AuditSequenceMismatch { record_index: usize },
    #[error("knowledge audit previous hash mismatch at record {record_index}")]
    AuditPreviousHashMismatch { record_index: usize },
    #[error("knowledge audit record hash mismatch at record {record_index}")]
    AuditRecordHashMismatch { record_index: usize },
    #[error("knowledge audit tail hash mismatch")]
    AuditTailMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeNodeKind {
    Origin,
    Endpoint,
    Parameter,
    Session,
    Finding,
    Evidence,
    OwnedObject,
    Workflow,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeEdgeKind {
    Observed,
    Discovered,
    ValidatedBy,
    UsesSession,
    Produces,
    DependsOn,
    SameAs,
    ReportedBy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    Observation,
    Differential,
    ValidationAudit,
    Cleanup,
    Reproduction,
    Report,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    Candidate,
    Validating,
    Validated,
    Reportable,
    Suppressed,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeAuditEvent {
    pub action: String,
    pub subject_id: String,
    pub outcome: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: KnowledgeAuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Clone)]
pub struct KnowledgeAuditChain {
    genesis_hash: String,
    records: Vec<KnowledgeAuditRecord>,
    tail_hash: String,
}

impl KnowledgeAuditChain {
    pub fn new(genesis_hash: impl Into<String>) -> Result<Self, KnowledgeError> {
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
        event: KnowledgeAuditEvent,
    ) -> Result<&KnowledgeAuditRecord, KnowledgeError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event))?;
        self.records.push(KnowledgeAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("knowledge audit append"))
    }

    pub fn records(&self) -> &[KnowledgeAuditRecord] {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut [KnowledgeAuditRecord] {
        &mut self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), KnowledgeError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(KnowledgeError::AuditSequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous_hash {
                return Err(KnowledgeError::AuditPreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected = hash_serializable(&(
                record.sequence,
                &record.previous_hash,
                &record.event,
            ))?;
            if record.record_hash != expected {
                return Err(KnowledgeError::AuditRecordHashMismatch {
                    record_index: index,
                });
            }
            previous_hash = expected;
        }
        if self.tail_hash != previous_hash {
            return Err(KnowledgeError::AuditTailMismatch);
        }
        Ok(())
    }
}

fn validate_identifier(value: &str, name: &str) -> Result<(), KnowledgeError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(KnowledgeError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_sha256(value: &str, name: &str) -> Result<(), KnowledgeError> {
    if !is_sha256(value) {
        return Err(KnowledgeError::InvalidSha256(name.into()));
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, KnowledgeError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| KnowledgeError::AuditSerialization(error.to_string()))?;
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
