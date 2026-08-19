use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::adaptive_scheduler::AuthorizedWorkItem;
use super::coverage_saturation::{PairKey, RunStopReason};

pub const MAX_SHARD_COUNT: u32 = 4096;
pub const MAX_SHARDED_PAIRS: usize = 100_000_000;
pub const MAX_SHARD_IN_FLIGHT: usize = 1_000_000;
pub const MAX_SHARD_LEASE_SECONDS: i64 = 86_400;
pub const MAX_RESOURCE_UNITS: u64 = 1_000_000_000_000_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ShardingError {
    #[error("sharding configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("sharding input is invalid: {0}")]
    InvalidInput(String),
    #[error("endpoint-rule pair already has an owner")]
    PairDuplicate,
    #[error("origin was observed with a conflicting session or credential partition")]
    OriginPartitionConflict,
    #[error("global queue budget was exhausted")]
    GlobalQueueBudget,
    #[error("shard queue budget was exhausted")]
    ShardQueueBudget,
    #[error("global resource reservation was exhausted")]
    GlobalResourceBudget,
    #[error("shard resource reservation was exhausted")]
    ShardResourceBudget,
    #[error("shard identifier is unknown")]
    ShardUnknown,
    #[error("shard in-flight budget was exhausted")]
    ShardInFlightBudget,
    #[error("authorization has expired")]
    AuthorizationExpired,
    #[error("coordinator is stopped: {0:?}")]
    RunStopped(RunStopReason),
    #[error("no work remains in the requested shard")]
    NoWork,
    #[error("lease is unknown")]
    LeaseUnknown,
    #[error("lease has expired")]
    LeaseExpired,
    #[error("execution usage exceeded the work reservation")]
    UsageExceedsReservation,
    #[error("finding identifier is invalid")]
    InvalidFindingId,
    #[error("sharding serialization failed: {0}")]
    Serialization(String),
    #[error("sharding receipt digest mismatch")]
    ReceiptDigest,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardResources {
    pub requests: u64,
    pub mutations: u64,
    pub accounted_memory_bytes: u64,
    pub evidence_bytes: u64,
    pub disk_bytes: u64,
    pub elapsed_milliseconds: u64,
}

impl ShardResources {
    pub fn validate(self) -> Result<Self, ShardingError> {
        if self.requests > MAX_RESOURCE_UNITS
            || self.mutations > MAX_RESOURCE_UNITS
            || self.accounted_memory_bytes > MAX_RESOURCE_UNITS
            || self.evidence_bytes > MAX_RESOURCE_UNITS
            || self.disk_bytes > MAX_RESOURCE_UNITS
            || self.elapsed_milliseconds > MAX_RESOURCE_UNITS
        {
            return Err(ShardingError::InvalidInput(
                "resource value exceeds architecture guard".into(),
            ));
        }
        Ok(self)
    }

    fn checked_add(self, other: Self) -> Self {
        Self {
            requests: self.requests.saturating_add(other.requests),
            mutations: self.mutations.saturating_add(other.mutations),
            accounted_memory_bytes: self
                .accounted_memory_bytes
                .saturating_add(other.accounted_memory_bytes),
            evidence_bytes: self.evidence_bytes.saturating_add(other.evidence_bytes),
            disk_bytes: self.disk_bytes.saturating_add(other.disk_bytes),
            elapsed_milliseconds: self
                .elapsed_milliseconds
                .saturating_add(other.elapsed_milliseconds),
        }
    }

    fn checked_sub(self, other: Self) -> Self {
        Self {
            requests: self.requests.saturating_sub(other.requests),
            mutations: self.mutations.saturating_sub(other.mutations),
            accounted_memory_bytes: self
                .accounted_memory_bytes
                .saturating_sub(other.accounted_memory_bytes),
            evidence_bytes: self.evidence_bytes.saturating_sub(other.evidence_bytes),
            disk_bytes: self.disk_bytes.saturating_sub(other.disk_bytes),
            elapsed_milliseconds: self
                .elapsed_milliseconds
                .saturating_sub(other.elapsed_milliseconds),
        }
    }

    fn exceeds(self, budget: Self) -> bool {
        self.requests > budget.requests
            || self.mutations > budget.mutations
            || self.accounted_memory_bytes > budget.accounted_memory_bytes
            || self.evidence_bytes > budget.evidence_bytes
            || self.disk_bytes > budget.disk_bytes
            || self.elapsed_milliseconds > budget.elapsed_milliseconds
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardLimits {
    pub shard_count: u32,
    pub maximum_global_pairs: usize,
    pub maximum_pairs_per_shard: usize,
    pub maximum_in_flight_per_shard: usize,
    pub lease_seconds: i64,
    pub global_resource_budget: ShardResources,
    pub per_shard_resource_budget: ShardResources,
}

impl ShardLimits {
    pub fn validate(self) -> Result<Self, ShardingError> {
        self.global_resource_budget.validate()?;
        self.per_shard_resource_budget.validate()?;
        if self.shard_count == 0
            || self.shard_count > MAX_SHARD_COUNT
            || self.maximum_global_pairs == 0
            || self.maximum_global_pairs > MAX_SHARDED_PAIRS
            || self.maximum_pairs_per_shard == 0
            || self.maximum_pairs_per_shard > self.maximum_global_pairs
            || self.maximum_in_flight_per_shard == 0
            || self.maximum_in_flight_per_shard > MAX_SHARD_IN_FLIGHT
            || self.lease_seconds <= 0
            || self.lease_seconds > MAX_SHARD_LEASE_SECONDS
            || self.per_shard_resource_budget.exceeds(self.global_resource_budget)
        {
            return Err(ShardingError::InvalidConfig(
                "one or more sharding limits are outside policy".into(),
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardedWorkItem {
    pub origin_sha256: String,
    pub session_partition_sha256: String,
    pub credential_partition_sha256: String,
    pub work: AuthorizedWorkItem,
    pub resource_reservation: ShardResources,
}

impl ShardedWorkItem {
    pub fn validate(&self) -> Result<(), ShardingError> {
        for value in [
            &self.origin_sha256,
            &self.session_partition_sha256,
            &self.credential_partition_sha256,
        ] {
            validate_shard_sha256(value)?;
        }
        self.work.validate().map_err(|error| {
            ShardingError::InvalidInput(format!("authorized work item: {error}"))
        })?;
        self.resource_reservation.validate()?;
        if self.resource_reservation.requests < self.work.estimated_requests
            || self.resource_reservation.mutations < self.work.estimated_mutations
            || self.resource_reservation.requests == 0
        {
            return Err(ShardingError::InvalidInput(
                "resource reservation does not cover authorized work".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardAssignment {
    pub shard_id: u32,
    pub origin_sha256: String,
    pub pair: PairKey,
    pub assignment_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardLease {
    pub lease_id: String,
    pub shard_id: u32,
    pub origin_sha256: String,
    pub pair: PairKey,
    pub plan_sha256: String,
    pub capability_sha256: String,
    pub authorization_sha256: String,
    pub session_partition_sha256: String,
    pub credential_partition_sha256: String,
    pub reservation: ShardResources,
    pub issued_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardExecutionResult {
    pub usage: ShardResources,
    pub finding_ids: BTreeSet<String>,
}

impl ShardExecutionResult {
    pub fn validate(&self) -> Result<(), ShardingError> {
        self.usage.validate()?;
        for finding_id in &self.finding_ids {
            validate_shard_sha256(finding_id).map_err(|_| ShardingError::InvalidFindingId)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct OriginBinding {
    shard_id: u32,
    session_partition_sha256: String,
    credential_partition_sha256: String,
}

#[derive(Debug, Clone)]
struct ShardLeaseState {
    item: ShardedWorkItem,
    expires_at_epoch_seconds: i64,
}

#[derive(Debug, Default)]
struct ShardState {
    queued: BTreeMap<PairKey, ShardedWorkItem>,
    in_flight: BTreeMap<String, ShardLeaseState>,
    completed_pairs: BTreeSet<PairKey>,
    failed_pairs: BTreeSet<PairKey>,
    expired_pairs: BTreeSet<PairKey>,
    reserved_resources: ShardResources,
    used_resources: ShardResources,
    accepted_unique_findings: u64,
    duplicate_findings: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardSummary {
    pub shard_id: u32,
    pub queued_pairs: u64,
    pub in_flight_pairs: u64,
    pub completed_pairs: u64,
    pub failed_pairs: u64,
    pub expired_pairs: u64,
    pub reserved_resources: ShardResources,
    pub used_resources: ShardResources,
    pub accepted_unique_findings: u64,
    pub duplicate_findings: u64,
    pub state_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardingReceipt {
    pub shard_count: u32,
    pub origin_bindings: u64,
    pub owned_pairs: u64,
    pub queued_pairs: u64,
    pub in_flight_pairs: u64,
    pub completed_pairs: u64,
    pub failed_pairs: u64,
    pub expired_pairs: u64,
    pub global_reserved_resources: ShardResources,
    pub global_used_resources: ShardResources,
    pub global_unique_findings: u64,
    pub global_duplicate_findings: u64,
    pub stop_reason: Option<RunStopReason>,
    pub shard_summaries: Vec<ShardSummary>,
    pub ownership_sha256: String,
    pub origin_bindings_sha256: String,
    pub global_findings_sha256: String,
    pub receipt_sha256: String,
}

impl ShardingReceipt {
    pub fn verify(&self) -> Result<(), ShardingError> {
        let mut material = self.clone();
        material.receipt_sha256.clear();
        if shard_hash_serializable(&material)? != self.receipt_sha256 {
            return Err(ShardingError::ReceiptDigest);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DeterministicShardCoordinator {
    limits: ShardLimits,
    run_partition_sha256: String,
    shards: BTreeMap<u32, ShardState>,
    origin_bindings: BTreeMap<String, OriginBinding>,
    pair_owners: BTreeMap<PairKey, u32>,
    global_finding_ids: BTreeSet<String>,
    global_duplicate_findings: u64,
    global_reserved_resources: ShardResources,
    global_used_resources: ShardResources,
    next_lease_sequence: u64,
    stop_reason: Option<RunStopReason>,
}

fn validate_shard_sha256(value: &str) -> Result<(), ShardingError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ShardingError::InvalidInput("SHA-256 field".into()));
    }
    Ok(())
}

fn shard_hash_serializable<T: Serialize>(value: &T) -> Result<String, ShardingError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ShardingError::Serialization(error.to_string()))?;
    Ok(shard_hash_bytes(&bytes))
}

fn shard_hash_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn shard_index_from_digest(digest: &str, shard_count: u32) -> Result<u32, ShardingError> {
    validate_shard_sha256(digest)?;
    let prefix = u64::from_str_radix(&digest[..16], 16)
        .map_err(|_| ShardingError::InvalidInput("shard digest prefix".into()))?;
    Ok((prefix % u64::from(shard_count)) as u32)
}
