use std::collections::{BTreeMap, BTreeSet, VecDeque};

use nxb_active_validation::OracleDecision;
use nxb_knowledge_reporting::FindingState;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_CAPABILITY_GRAPH_NODES: usize = 250_000;
pub const MAX_CAPABILITY_GRAPH_EDGES: usize = 1_000_000;
pub const MAX_RISK_CHAIN_DEPTH: usize = 8;
pub const MAX_WORKFLOW_STEPS: usize = 10_000;
pub const MAX_STEP_DEPENDENCIES: usize = 128;
pub const MAX_STEP_ATTEMPTS: u8 = 3;
pub const MAX_ORACLE_VOTES: usize = 32;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkflowError {
    #[error("workflow identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("SHA-256 field is invalid: {0}")]
    InvalidSha256(String),
    #[error("capability graph limit was exceeded")]
    GraphLimit,
    #[error("capability graph node already exists")]
    DuplicateNode,
    #[error("capability graph edge already exists")]
    DuplicateEdge,
    #[error("capability graph references an unknown node")]
    UnknownNode,
    #[error("risk chain is invalid or not safely bounded")]
    InvalidRiskChain,
    #[error("workflow definition is invalid: {0}")]
    InvalidWorkflow(String),
    #[error("workflow state transition is invalid")]
    InvalidWorkflowState,
    #[error("workflow step is not ready")]
    StepNotReady,
    #[error("workflow lease is unknown, expired or already consumed")]
    InvalidLease,
    #[error("oracle quorum input is invalid or inconsistent")]
    InvalidOracleQuorum,
    #[error("run cannot be certified: {0}")]
    CertificationDenied(String),
    #[error("workflow audit serialization failed: {0}")]
    AuditSerialization(String),
    #[error("workflow audit sequence mismatch at record {record_index}")]
    AuditSequenceMismatch { record_index: usize },
    #[error("workflow audit previous hash mismatch at record {record_index}")]
    AuditPreviousHashMismatch { record_index: usize },
    #[error("workflow audit record hash mismatch at record {record_index}")]
    AuditRecordHashMismatch { record_index: usize },
    #[error("workflow audit tail hash mismatch")]
    AuditTailMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityNodeKind {
    Capability,
    Endpoint,
    Session,
    Finding,
    Evidence,
    OwnedObject,
    Workflow,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEdgeKind {
    Requires,
    Enables,
    BoundTo,
    ValidatedBy,
    Produces,
    Compensates,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowAction {
    Observe,
    GenerateInertMutation,
    CompareDifferential,
    EvaluateOracle,
    RegisterOwnedObject,
    CleanupOwnedObject,
    StoreEvidence,
    BuildReport,
    CertifyRun,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowState {
    Created,
    Running,
    Paused,
    Cancelling,
    Completed,
    Failed,
    EmergencyStopped,
}

impl WorkflowState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::EmergencyStopped
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStepState {
    Pending,
    Leased,
    Succeeded,
    Failed,
    Skipped,
    Compensating,
    Compensated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum QuorumDecision {
    Confirmed,
    Rejected,
    Inconclusive,
    Drift,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowAuditEvent {
    pub action: String,
    pub subject_id: String,
    pub outcome: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: WorkflowAuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Clone)]
pub struct WorkflowAuditChain {
    genesis_hash: String,
    records: Vec<WorkflowAuditRecord>,
    tail_hash: String,
}

impl WorkflowAuditChain {
    pub fn new(genesis_hash: impl Into<String>) -> Result<Self, WorkflowError> {
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
        event: WorkflowAuditEvent,
    ) -> Result<&WorkflowAuditRecord, WorkflowError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event))?;
        self.records.push(WorkflowAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("workflow audit append"))
    }

    pub fn records(&self) -> &[WorkflowAuditRecord] {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut [WorkflowAuditRecord] {
        &mut self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), WorkflowError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(WorkflowError::AuditSequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous_hash {
                return Err(WorkflowError::AuditPreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected = hash_serializable(&(
                record.sequence,
                &record.previous_hash,
                &record.event,
            ))?;
            if record.record_hash != expected {
                return Err(WorkflowError::AuditRecordHashMismatch {
                    record_index: index,
                });
            }
            previous_hash = expected;
        }
        if self.tail_hash != previous_hash {
            return Err(WorkflowError::AuditTailMismatch);
        }
        Ok(())
    }
}

fn validate_identifier(value: &str, name: &str) -> Result<(), WorkflowError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(WorkflowError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_sha256(value: &str, name: &str) -> Result<(), WorkflowError> {
    if !is_sha256(value) {
        return Err(WorkflowError::InvalidSha256(name.into()));
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, WorkflowError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| WorkflowError::AuditSerialization(error.to_string()))?;
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
