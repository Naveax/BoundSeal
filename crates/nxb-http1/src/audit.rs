use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::Http1AuditEvent;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http1AuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: Http1AuditEvent,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct Http1AuditChain {
    genesis_hash: String,
    records: Vec<Http1AuditRecord>,
    tail_hash: String,
}

impl Http1AuditChain {
    pub fn new(genesis_hash: impl Into<String>) -> Result<Self, Http1AuditError> {
        let genesis_hash = genesis_hash.into();
        if !is_lower_hex_sha256(&genesis_hash) {
            return Err(Http1AuditError::InvalidGenesisHash);
        }
        Ok(Self {
            tail_hash: genesis_hash.clone(),
            genesis_hash,
            records: Vec::new(),
        })
    }

    pub fn append(&mut self, event: Http1AuditEvent) -> Result<&Http1AuditRecord, Http1AuditError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = record_hash(sequence, &previous_hash, &event)?;
        self.records.push(Http1AuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self
            .records
            .last()
            .expect("an HTTP/1 audit record was appended before lookup"))
    }

    pub fn records(&self) -> &[Http1AuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), Http1AuditError> {
        let mut expected_previous = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(Http1AuditError::SequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != expected_previous {
                return Err(Http1AuditError::PreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected = record_hash(record.sequence, &record.previous_hash, &record.event)?;
            if record.record_hash != expected {
                return Err(Http1AuditError::RecordHashMismatch {
                    record_index: index,
                });
            }
            expected_previous = expected;
        }
        if self.tail_hash != expected_previous {
            return Err(Http1AuditError::TailHashMismatch);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn records_mut(&mut self) -> &mut [Http1AuditRecord] {
        &mut self.records
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Http1AuditError {
    #[error("HTTP/1 audit genesis must be a lowercase SHA-256 value")]
    InvalidGenesisHash,
    #[error("HTTP/1 audit material could not be serialized: {0}")]
    Serialization(String),
    #[error("HTTP/1 audit sequence mismatch at record {record_index}")]
    SequenceMismatch { record_index: usize },
    #[error("HTTP/1 audit previous-hash mismatch at record {record_index}")]
    PreviousHashMismatch { record_index: usize },
    #[error("HTTP/1 audit record-hash mismatch at record {record_index}")]
    RecordHashMismatch { record_index: usize },
    #[error("HTTP/1 audit tail hash does not match the final record")]
    TailHashMismatch,
}

fn record_hash(
    sequence: u64,
    previous_hash: &str,
    event: &Http1AuditEvent,
) -> Result<String, Http1AuditError> {
    #[derive(Serialize)]
    struct Material<'a> {
        sequence: u64,
        previous_hash: &'a str,
        event: &'a Http1AuditEvent,
    }

    let bytes = serde_json::to_vec(&Material {
        sequence,
        previous_hash,
        event,
    })
    .map_err(|error| Http1AuditError::Serialization(error.to_string()))?;
    Ok(lower_hex(&Sha256::digest(bytes)))
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
