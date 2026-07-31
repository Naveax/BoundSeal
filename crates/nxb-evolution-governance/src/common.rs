use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_COMPONENTS: usize = 256;
pub const MAX_STEPS: usize = 512;
pub const MAX_CANARY_SAMPLES: usize = 10_000;
pub const MAX_GENERATIONS: usize = 256;
pub const MAX_STEWARDS: usize = 32;
pub const MAX_ROTATION_OVERLAP_TICKS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvolutionError {
    #[error("identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("SHA-256 field is invalid: {0}")]
    InvalidSha256(String),
    #[error("binding is denied: {0}")]
    BindingDenied(String),
    #[error("evolution contract is invalid: {0}")]
    InvalidEvolution(String),
    #[error("generation contract is invalid: {0}")]
    InvalidGeneration(String),
    #[error("stewardship contract is invalid: {0}")]
    InvalidStewardship(String),
    #[error("audit serialization failed: {0}")]
    AuditSerialization(String),
    #[error("audit sequence mismatch at record {0}")]
    AuditSequenceMismatch(usize),
    #[error("audit previous hash mismatch at record {0}")]
    AuditPreviousHashMismatch(usize),
    #[error("audit record hash mismatch at record {0}")]
    AuditRecordHashMismatch(usize),
    #[error("audit tail hash mismatch")]
    AuditTailMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvolutionAuditEvent {
    pub action: String,
    pub subject_id: String,
    pub outcome: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvolutionAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: EvolutionAuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Clone)]
pub struct EvolutionAuditChain {
    genesis_hash: String,
    records: Vec<EvolutionAuditRecord>,
    tail_hash: String,
}

impl EvolutionAuditChain {
    pub fn new(genesis_hash: impl Into<String>) -> Result<Self, EvolutionError> {
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
        event: EvolutionAuditEvent,
    ) -> Result<&EvolutionAuditRecord, EvolutionError> {
        validate_identifier(&event.action, "audit action")?;
        validate_identifier(&event.subject_id, "audit subject")?;
        validate_identifier(&event.outcome, "audit outcome")?;
        for (key, value) in &event.metadata {
            validate_identifier(key, "audit metadata key")?;
            if value.len() > 512 || contains_secret_like_text(value) {
                return Err(EvolutionError::AuditSerialization(
                    "audit metadata is oversized or secret-like".into(),
                ));
            }
        }
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event))?;
        self.records.push(EvolutionAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("audit record appended"))
    }

    pub fn verify(&self) -> Result<(), EvolutionError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(EvolutionError::AuditSequenceMismatch(index));
            }
            if record.previous_hash != previous_hash {
                return Err(EvolutionError::AuditPreviousHashMismatch(index));
            }
            let expected =
                hash_serializable(&(record.sequence, &record.previous_hash, &record.event))?;
            if expected != record.record_hash {
                return Err(EvolutionError::AuditRecordHashMismatch(index));
            }
            previous_hash = expected;
        }
        if previous_hash != self.tail_hash {
            return Err(EvolutionError::AuditTailMismatch);
        }
        Ok(())
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn records(&self) -> &[EvolutionAuditRecord] {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut [EvolutionAuditRecord] {
        &mut self.records
    }
}

pub(crate) fn validate_identifier(value: &str, name: &str) -> Result<(), EvolutionError> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(EvolutionError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, name: &str) -> Result<(), EvolutionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EvolutionError::InvalidSha256(name.into()));
    }
    Ok(())
}

pub(crate) fn validate_hash_map(
    values: &BTreeMap<String, String>,
    name: &str,
    maximum: usize,
) -> Result<(), EvolutionError> {
    if values.is_empty() || values.len() > maximum {
        return Err(EvolutionError::BindingDenied(format!(
            "{name} count is invalid"
        )));
    }
    for (key, value) in values {
        validate_identifier(key, name)?;
        validate_sha256(value, name)?;
    }
    Ok(())
}

pub(crate) fn hash_serializable<T: Serialize>(value: &T) -> Result<String, EvolutionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| EvolutionError::AuditSerialization(error.to_string()))?;
    Ok(lower_hex(&Sha256::digest(bytes)))
}

pub(crate) fn contains_secret_like_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization:",
        "proxy-authorization:",
        "cookie:",
        "set-cookie:",
        "bearer ",
        "password=",
        "token=",
        "secret=",
        "private_key",
        "http://",
        "https://",
        "file://",
        "ssh://",
    ]
    .iter()
    .any(|forbidden| lower.contains(forbidden))
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
