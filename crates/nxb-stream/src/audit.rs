use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{StreamAuditEvent, StreamOpenError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: StreamAuditEvent,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct StreamAuditChain {
    genesis_anchor: String,
    records: Vec<StreamAuditRecord>,
    tail_hash: String,
}

impl StreamAuditChain {
    pub fn new(genesis_anchor: impl Into<String>) -> Result<Self, StreamOpenError> {
        let genesis_anchor = genesis_anchor.into();
        if !is_lower_hex_sha256(&genesis_anchor) {
            return Err(StreamOpenError::InvalidExecutorAuditAnchor);
        }
        Ok(Self {
            tail_hash: genesis_anchor.clone(),
            genesis_anchor,
            records: Vec::new(),
        })
    }

    pub fn records(&self) -> &[StreamAuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn genesis_anchor(&self) -> &str {
        &self.genesis_anchor
    }

    pub fn verify(&self) -> Result<(), StreamAuditError> {
        let mut expected_previous = self.genesis_anchor.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(StreamAuditError::SequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != expected_previous {
                return Err(StreamAuditError::PreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected_hash =
                stream_record_hash(record.sequence, &record.previous_hash, &record.event)?;
            if record.record_hash != expected_hash {
                return Err(StreamAuditError::RecordHashMismatch {
                    record_index: index,
                });
            }
            expected_previous = expected_hash;
        }
        if self.tail_hash != expected_previous {
            return Err(StreamAuditError::TailHashMismatch);
        }
        Ok(())
    }

    pub(crate) fn append(
        &mut self,
        event: StreamAuditEvent,
    ) -> Result<&StreamAuditRecord, StreamAuditError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = stream_record_hash(sequence, &previous_hash, &event)?;
        self.records.push(StreamAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self
            .records
            .last()
            .expect("a stream audit record was appended before lookup"))
    }

    #[cfg(test)]
    pub(crate) fn records_mut(&mut self) -> &mut [StreamAuditRecord] {
        &mut self.records
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StreamAuditError {
    #[error("stream audit material could not be serialized: {0}")]
    Serialization(String),
    #[error("stream audit sequence mismatch at record {record_index}")]
    SequenceMismatch { record_index: usize },
    #[error("stream audit previous-hash mismatch at record {record_index}")]
    PreviousHashMismatch { record_index: usize },
    #[error("stream audit record-hash mismatch at record {record_index}")]
    RecordHashMismatch { record_index: usize },
    #[error("stream audit tail hash does not match the final record")]
    TailHashMismatch,
}

fn stream_record_hash(
    sequence: u64,
    previous_hash: &str,
    event: &StreamAuditEvent,
) -> Result<String, StreamAuditError> {
    #[derive(Serialize)]
    struct Material<'a> {
        sequence: u64,
        previous_hash: &'a str,
        event: &'a StreamAuditEvent,
    }

    let bytes = serde_json::to_vec(&Material {
        sequence,
        previous_hash,
        event,
    })
    .map_err(|error| StreamAuditError::Serialization(error.to_string()))?;
    Ok(to_lower_hex(&Sha256::digest(bytes)))
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
