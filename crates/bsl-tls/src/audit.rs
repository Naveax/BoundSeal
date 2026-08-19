use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const TLS_AUDIT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsAuditEvent {
    pub verification_id: String,
    pub tls_session_id: Option<String>,
    pub verifier_id: String,
    pub status: String,
    pub reason: String,
    pub stream_id: String,
    pub execution_id: String,
    pub ticket_id: String,
    pub binding_hash: String,
    pub stream_audit_anchor: String,
    pub sni: String,
    pub http_host: String,
    pub port: u16,
    pub redirect_depth: u8,
    pub protocol_version: String,
    pub alpn: String,
    pub handshake_read_bytes: u64,
    pub handshake_write_bytes: u64,
    pub elapsed_milliseconds: u64,
    pub chain_depth: usize,
    pub chain_fingerprint_sha256: String,
    pub leaf_fingerprint_sha256: Option<String>,
    pub root_fingerprint_sha256: Option<String>,
    pub matched_san_sha256: Option<String>,
    pub early_data_accepted: bool,
    pub renegotiation_observed: bool,
    pub session_resumed: bool,
    pub details: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: TlsAuditEvent,
    pub record_hash: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TlsAuditError {
    #[error("TLS audit material could not be serialized: {0}")]
    Serialization(String),
    #[error("TLS audit sequence mismatch at record {record_index}")]
    SequenceMismatch { record_index: usize },
    #[error("TLS audit previous-hash mismatch at record {record_index}")]
    PreviousHashMismatch { record_index: usize },
    #[error("TLS audit record-hash mismatch at record {record_index}")]
    RecordHashMismatch { record_index: usize },
    #[error("TLS audit tail hash does not match the final record")]
    TailHashMismatch,
}

#[derive(Debug)]
pub struct TlsAuditChain {
    records: Vec<TlsAuditRecord>,
    tail_hash: String,
}

impl Default for TlsAuditChain {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsAuditChain {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            tail_hash: TLS_AUDIT_GENESIS_HASH.into(),
        }
    }

    pub fn append(&mut self, event: TlsAuditEvent) -> Result<&TlsAuditRecord, TlsAuditError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let record_hash = tls_record_hash(sequence, &previous_hash, &event)?;
        self.records.push(TlsAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(self
            .records
            .last()
            .expect("a TLS audit record was appended before lookup"))
    }

    pub fn records(&self) -> &[TlsAuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn verify(&self) -> Result<(), TlsAuditError> {
        let mut expected_previous = TLS_AUDIT_GENESIS_HASH.to_string();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(TlsAuditError::SequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != expected_previous {
                return Err(TlsAuditError::PreviousHashMismatch {
                    record_index: index,
                });
            }
            let expected_hash =
                tls_record_hash(record.sequence, &record.previous_hash, &record.event)?;
            if record.record_hash != expected_hash {
                return Err(TlsAuditError::RecordHashMismatch {
                    record_index: index,
                });
            }
            expected_previous = expected_hash;
        }
        if self.tail_hash != expected_previous {
            return Err(TlsAuditError::TailHashMismatch);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn records_mut(&mut self) -> &mut [TlsAuditRecord] {
        &mut self.records
    }
}

fn tls_record_hash(
    sequence: u64,
    previous_hash: &str,
    event: &TlsAuditEvent,
) -> Result<String, TlsAuditError> {
    #[derive(Serialize)]
    struct HashMaterial<'a> {
        sequence: u64,
        previous_hash: &'a str,
        event: &'a TlsAuditEvent,
    }

    let bytes = serde_json::to_vec(&HashMaterial {
        sequence,
        previous_hash,
        event,
    })
    .map_err(|error| TlsAuditError::Serialization(error.to_string()))?;
    Ok(hex_sha256(&bytes))
}

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
