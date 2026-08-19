use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_COMPONENTS: usize = 256;
pub const MAX_INVARIANTS: usize = 256;
pub const MAX_MAINTENANCE_DURATION_TICKS: u64 = 7 * 24 * 60 * 60;
pub const MAX_MAINTENANCE_OPERATIONS: u64 = 10_000;
pub const MAX_ARCHIVE_OBJECTS: usize = 10_000;
pub const MAX_ARCHIVE_OBJECT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_ARCHIVE_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_RETENTION_DAYS: u32 = 3_650;
pub const MAX_RECOVERY_TICKS: u64 = 30 * 24 * 60 * 60;
pub const MAX_VERIFIERS: usize = 16;
pub const MAX_EVIDENCE_SAMPLES: u32 = 10_000;

include!("common_part1.rs");
include!("common_part2.rs");
