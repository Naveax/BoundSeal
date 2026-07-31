use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const STORE_FORMAT_VERSION: u32 = 1;
pub const MAX_SEGMENT_FINDINGS: usize = 16_384;
pub const MAX_SEGMENT_PLAINTEXT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_METADATA_ENTRIES: usize = 128;
pub const MAX_METADATA_VALUE_BYTES: usize = 4096;

pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    fn clear(&mut self) {
        self.0.fill(0);
        self.0.clear();
    }

    fn duplicate(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl std::fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SensitiveBytes")
            .field("bytes", &self.0.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Error)]
pub enum FindingStoreError {
    #[error("finding-store configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("finding cannot be stored: {0}")]
    InvalidFinding(String),
    #[error("segment sealer is invalid: {0}")]
    InvalidSealer(String),
    #[error("segment sealing failed: {0}")]
    Seal(String),
    #[error("finding-store I/O failed: {0}")]
    Io(String),
    #[error("finding-store serialization failed: {0}")]
    Serialization(String),
    #[error("disk budget would be exceeded")]
    DiskBudget,
    #[error("single finding exceeds the configured segment size")]
    FindingTooLarge,
    #[error("manifest chain is invalid at record {record_index}")]
    ManifestChain { record_index: usize },
    #[error("manifest record hash is invalid at record {record_index}")]
    ManifestRecordHash { record_index: usize },
    #[error("segment file is missing: {0}")]
    MissingSegment(String),
    #[error("segment file hash mismatch: {0}")]
    SegmentFileHash(String),
    #[error("segment payload hash mismatch: {0}")]
    SegmentPayloadHash(String),
    #[error("uncommitted or orphan segment exists: {0}")]
    OrphanSegment(String),
}

#[derive(Debug, Clone)]
pub struct FindingStoreConfig {
    pub root: PathBuf,
    pub segment_max_findings: usize,
    pub segment_max_plaintext_bytes: usize,
    pub disk_budget_bytes: u64,
}

impl FindingStoreConfig {
    pub fn validate(&self) -> Result<(), FindingStoreError> {
        if self.root.as_os_str().is_empty() {
            return Err(FindingStoreError::InvalidConfig("root path is empty".into()));
        }
        if self.segment_max_findings == 0 || self.segment_max_findings > MAX_SEGMENT_FINDINGS {
            return Err(FindingStoreError::InvalidConfig(
                "segment finding bound is outside policy".into(),
            ));
        }
        if self.segment_max_plaintext_bytes < 1024
            || self.segment_max_plaintext_bytes > MAX_SEGMENT_PLAINTEXT_BYTES
        {
            return Err(FindingStoreError::InvalidConfig(
                "segment byte bound is outside policy".into(),
            ));
        }
        if self.disk_budget_bytes < self.segment_max_plaintext_bytes as u64 {
            return Err(FindingStoreError::InvalidConfig(
                "disk budget cannot hold one maximum segment".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentSealContext {
    pub store_id: String,
    pub sequence: u64,
    pub previous_manifest_hash: String,
    pub plaintext_sha256: String,
    pub finding_count: u64,
    pub plaintext_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedPayload {
    pub algorithm: String,
    pub key_id_sha256: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub authentication_tag: Vec<u8>,
}

impl std::fmt::Debug for SealedPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealedPayload")
            .field("algorithm", &self.algorithm)
            .field("key_id_sha256", &self.key_id_sha256)
            .field("nonce_bytes", &self.nonce.len())
            .field("ciphertext_bytes", &self.ciphertext.len())
            .field("authentication_tag_bytes", &self.authentication_tag.len())
            .finish()
    }
}

pub trait SegmentSealer {
    fn algorithm_id(&self) -> &str;
    fn key_id_sha256(&self) -> &str;
    fn maximum_overhead_bytes(&self) -> u64;

    fn seal(
        &mut self,
        context: &SegmentSealContext,
        plaintext: SensitiveBytes,
    ) -> Result<SealedPayload, FindingStoreError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SegmentFile {
    version: u32,
    sequence: u64,
    algorithm: String,
    key_id_sha256: String,
    nonce_hex: String,
    ciphertext_hex: String,
    authentication_tag_hex: String,
    plaintext_sha256: String,
    finding_count: u64,
    plaintext_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentManifestRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub file_name: String,
    pub file_sha256: String,
    pub ciphertext_sha256: String,
    pub plaintext_sha256: String,
    pub algorithm: String,
    pub key_id_sha256: String,
    pub finding_count: u64,
    pub plaintext_bytes: u64,
    pub sealed_bytes: u64,
    pub record_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingStoreCheckpoint {
    pub store_id: String,
    pub committed_segments: u64,
    pub committed_findings: u64,
    pub committed_plaintext_bytes: u64,
    pub committed_sealed_bytes: u64,
    pub disk_bytes: u64,
    pub manifest_tail_sha256: String,
}
