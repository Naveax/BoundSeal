use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditDestination {
    pub ip: String,
    pub class: String,
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub decision_id: String,
    pub outcome: String,
    pub reason_code: String,
    pub reason_details: BTreeMap<String, String>,
    pub method: String,
    pub url: String,
    pub resolved_destinations: Vec<AuditDestination>,
    pub redirect_depth: u8,
    pub elapsed_milliseconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: AuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Clone)]
pub struct AuditChain {
    records: Vec<AuditRecord>,
    tail_hash: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("audit material could not be serialized: {0}")]
    Serialization(String),
    #[error("audit sequence mismatch at record {record_index}")]
    SequenceMismatch { record_index: usize },
    #[error("audit previous-hash mismatch at record {record_index}")]
    PreviousHashMismatch { record_index: usize },
    #[error("audit record-hash mismatch at record {record_index}")]
    RecordHashMismatch { record_index: usize },
    #[error("audit tail hash does not match the final record")]
    TailHashMismatch,
}

#[derive(Serialize)]
struct HashMaterial<'a> {
    sequence: u64,
    previous_hash: &'a str,
    event: &'a AuditEvent,
}

impl Default for AuditChain {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditChain {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            tail_hash: GENESIS_HASH.into(),
        }
    }

    pub fn append(&mut self, event: AuditEvent) -> Result<&AuditRecord, AuditError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = hash_material(sequence, &previous_hash, &event)?;

        self.records.push(AuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;

        Ok(self
            .records
            .last()
            .expect("a record was appended immediately before lookup"))
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), AuditError> {
        let mut expected_previous = GENESIS_HASH.to_string();

        for (index, record) in self.records.iter().enumerate() {
            let expected_sequence = index as u64 + 1;
            if record.sequence != expected_sequence {
                return Err(AuditError::SequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != expected_previous {
                return Err(AuditError::PreviousHashMismatch {
                    record_index: index,
                });
            }

            let expected_hash = hash_material(
                record.sequence,
                &record.previous_hash,
                &record.event,
            )?;
            if record.record_hash != expected_hash {
                return Err(AuditError::RecordHashMismatch {
                    record_index: index,
                });
            }
            expected_previous = expected_hash;
        }

        if self.tail_hash != expected_previous {
            return Err(AuditError::TailHashMismatch);
        }

        Ok(())
    }
}

fn hash_material(
    sequence: u64,
    previous_hash: &str,
    event: &AuditEvent,
) -> Result<String, AuditError> {
    let bytes = serde_json::to_vec(&HashMaterial {
        sequence,
        previous_hash,
        event,
    })
    .map_err(|error| AuditError::Serialization(error.to_string()))?;

    let digest = Sha256::digest(bytes);
    Ok(to_lower_hex(&digest))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn event(decision_id: &str, url: &str) -> AuditEvent {
        AuditEvent {
            decision_id: decision_id.into(),
            outcome: "deny".into(),
            reason_code: "fixture".into(),
            reason_details: BTreeMap::new(),
            method: "GET".into(),
            url: url.into(),
            resolved_destinations: vec![AuditDestination {
                ip: "127.0.0.1".into(),
                class: "loopback".into(),
                allowed: false,
            }],
            redirect_depth: 0,
            elapsed_milliseconds: 0,
        }
    }

    #[test]
    fn builds_and_verifies_hash_chain() {
        let mut chain = AuditChain::new();
        chain.append(event("decision-1", "https://example.test/a")).unwrap();
        chain.append(event("decision-2", "https://example.test/b")).unwrap();

        assert_eq!(chain.len(), 2);
        assert_eq!(chain.records()[0].previous_hash, GENESIS_HASH);
        assert_eq!(
            chain.records()[1].previous_hash,
            chain.records()[0].record_hash
        );
        assert_eq!(chain.tail_hash(), chain.records()[1].record_hash);
        chain.verify().unwrap();
    }

    #[test]
    fn detects_modified_event_data() {
        let mut chain = AuditChain::new();
        chain.append(event("decision-1", "https://example.test/a")).unwrap();
        chain.records[0].event.method = "POST".into();

        assert_eq!(
            chain.verify(),
            Err(AuditError::RecordHashMismatch { record_index: 0 })
        );
    }

    #[test]
    fn detects_modified_link() {
        let mut chain = AuditChain::new();
        chain.append(event("decision-1", "https://example.test/a")).unwrap();
        chain.append(event("decision-2", "https://example.test/b")).unwrap();
        chain.records[1].previous_hash = GENESIS_HASH.into();

        assert_eq!(
            chain.verify(),
            Err(AuditError::PreviousHashMismatch { record_index: 1 })
        );
    }
}
