use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const FINDING_ID_HEX_BYTES: usize = 64;
pub const FIXED_RECORD_BYTES: u64 = 65;
pub const MAX_HOT_SET_ENTRIES: usize = 1_000_000;
pub const MAX_RUN_ENTRIES: usize = 1_000_000;
pub const MAX_RUNS: usize = 4096;

#[derive(Debug, Error)]
pub enum ExactDedupError {
    #[error("exact-dedup configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("finding identifier is not canonical SHA-256")]
    InvalidFindingId,
    #[error("exact-dedup I/O failed: {0}")]
    Io(String),
    #[error("exact-dedup serialization failed: {0}")]
    Serialization(String),
    #[error("dedup disk budget would be exceeded")]
    DiskBudget,
    #[error("dedup run limit would be exceeded")]
    RunLimit,
    #[error("dedup manifest chain is invalid at record {record_index}")]
    ManifestChain { record_index: usize },
    #[error("dedup manifest record hash is invalid at record {record_index}")]
    ManifestRecordHash { record_index: usize },
    #[error("dedup run file is missing: {0}")]
    MissingRun(String),
    #[error("dedup run file hash mismatch: {0}")]
    RunHash(String),
    #[error("dedup run file structure is invalid: {0}")]
    RunStructure(String),
    #[error("uncommitted or orphan dedup run exists: {0}")]
    OrphanRun(String),
}

#[derive(Debug, Clone)]
pub struct ExactDedupConfig {
    pub root: PathBuf,
    pub hot_set_max_entries: usize,
    pub run_max_entries: usize,
    pub disk_budget_bytes: u64,
}

impl ExactDedupConfig {
    pub fn validate(&self) -> Result<(), ExactDedupError> {
        if self.root.as_os_str().is_empty() {
            return Err(ExactDedupError::InvalidConfig("root path is empty".into()));
        }
        if self.hot_set_max_entries == 0
            || self.hot_set_max_entries > MAX_HOT_SET_ENTRIES
            || self.run_max_entries == 0
            || self.run_max_entries > MAX_RUN_ENTRIES
        {
            return Err(ExactDedupError::InvalidConfig(
                "hot-set or run bound is outside policy".into(),
            ));
        }
        let minimum_run_bytes = (self.run_max_entries as u64)
            .min(self.hot_set_max_entries as u64)
            .saturating_mul(FIXED_RECORD_BYTES);
        if self.disk_budget_bytes < minimum_run_bytes.saturating_add(4096) {
            return Err(ExactDedupError::InvalidConfig(
                "disk budget cannot hold one configured run".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DedupRunRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub file_name: String,
    pub file_sha256: String,
    pub first_finding_id: String,
    pub last_finding_id: String,
    pub entry_count: u64,
    pub file_bytes: u64,
    pub record_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactDedupOutcome {
    Unique,
    Duplicate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExactDedupCheckpoint {
    pub index_id: String,
    pub committed_runs: u64,
    pub committed_unique_ids: u64,
    pub pending_unique_ids: u64,
    pub duplicate_observations: u64,
    pub disk_bytes: u64,
    pub manifest_tail_sha256: String,
}

#[derive(Debug)]
pub struct DiskBackedExactDedupIndex {
    config: ExactDedupConfig,
    index_id: String,
    hot_set: BTreeSet<String>,
    runs: Vec<DedupRunRecord>,
    manifest_tail: String,
    committed_unique_ids: u64,
    duplicate_observations: u64,
    disk_bytes: u64,
}
