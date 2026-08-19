use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_AUDIT_RECORDS: usize = 16_384;
pub const MAX_COMPONENTS: usize = 256;
pub const MAX_TRANSFER_OBJECTS: usize = 10_000;
pub const MAX_TRANSFER_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_CUTOVER_TICKS: u64 = 7 * 24 * 60 * 60;
pub const MAX_REVIEWERS: usize = 16;
pub const MAX_EVIDENCE_ROOTS: usize = 10_000;
pub const MAX_SAMPLE_COUNT: usize = 1_024;
pub const MAX_FINDINGS: usize = 4_096;
pub const MAX_TRUST_EPOCH_TICKS: u64 = 365 * 24 * 60 * 60;
pub const MAX_PUBLIC_VERIFIERS: usize = 16;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PostClosureError {
    #[error("identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("SHA-256 field is invalid: {0}")]
    InvalidSha256(String),
    #[error("successor contract is invalid: {0}")]
    InvalidSuccession(String),
    #[error("review or renewal contract is invalid: {0}")]
    InvalidRenewal(String),
    #[error("sunset or program closure is invalid: {0}")]
    InvalidProgramClosure(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
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
pub struct PostClosureAuditEvent {
    pub action: String,
    pub subject_id: String,
    pub outcome: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostClosureAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: PostClosureAuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Clone)]
pub struct PostClosureAuditChain {
    genesis_hash: String,
    records: Vec<PostClosureAuditRecord>,
    tail_hash: String,
}

impl PostClosureAuditChain {
    pub fn new(genesis_hash: impl Into<String>) -> Result<Self, PostClosureError> {
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
        event: PostClosureAuditEvent,
    ) -> Result<&PostClosureAuditRecord, PostClosureError> {
        if self.records.len() >= MAX_AUDIT_RECORDS {
            return Err(PostClosureError::Serialization(
                "audit record ceiling".into(),
            ));
        }
        validate_identifier(&event.action, "audit action")?;
        validate_identifier(&event.subject_id, "audit subject")?;
        validate_identifier(&event.outcome, "audit outcome")?;
        for (key, value) in &event.metadata {
            validate_identifier(key, "audit metadata key")?;
            if value.len() > 512 || contains_secret_like_text(value) {
                return Err(PostClosureError::Serialization(
                    "audit metadata is oversized or secret-like".into(),
                ));
            }
        }
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_serializable(&(sequence, &previous_hash, &event))?;
        self.records.push(PostClosureAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self.records.last().expect("audit record appended"))
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(PostClosureError::AuditSequenceMismatch(index));
            }
            if record.previous_hash != previous_hash {
                return Err(PostClosureError::AuditPreviousHashMismatch(index));
            }
            let expected =
                hash_serializable(&(record.sequence, &record.previous_hash, &record.event))?;
            if record.record_hash != expected {
                return Err(PostClosureError::AuditRecordHashMismatch(index));
            }
            previous_hash = expected;
        }
        if previous_hash != self.tail_hash {
            return Err(PostClosureError::AuditTailMismatch);
        }
        Ok(())
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn records(&self) -> &[PostClosureAuditRecord] {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut [PostClosureAuditRecord] {
        &mut self.records
    }
}

pub(crate) fn validate_identifier(value: &str, name: &str) -> Result<(), PostClosureError> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(PostClosureError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, name: &str) -> Result<(), PostClosureError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PostClosureError::InvalidSha256(name.into()));
    }
    Ok(())
}

pub(crate) fn validate_hash_map(
    values: &BTreeMap<String, String>,
    name: &str,
    maximum: usize,
) -> Result<(), PostClosureError> {
    if values.is_empty() || values.len() > maximum {
        return Err(PostClosureError::InvalidSuccession(format!(
            "{name} count is invalid"
        )));
    }
    for (key, value) in values {
        validate_identifier(key, name)?;
        validate_sha256(value, name)?;
    }
    Ok(())
}

pub(crate) fn hash_serializable<T: Serialize>(value: &T) -> Result<String, PostClosureError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| PostClosureError::Serialization(error.to_string()))?;
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
