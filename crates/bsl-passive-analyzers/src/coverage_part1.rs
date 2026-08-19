use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_COVERAGE_ENDPOINTS: usize = 10_000_000;
pub const MAX_COVERAGE_RULES: usize = 100_000;
pub const MAX_COVERAGE_PAIRS: usize = 100_000_000;
pub const MAX_SATURATION_WINDOWS: usize = 4096;
pub const MAX_WINDOW_CHECKS: u64 = 10_000_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoverageError {
    #[error("coverage configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("coverage input is invalid: {0}")]
    InvalidInput(String),
    #[error("coverage endpoint budget was exhausted")]
    EndpointBudget,
    #[error("coverage rule budget was exhausted")]
    RuleBudget,
    #[error("coverage pair budget was exhausted")]
    PairBudget,
    #[error("endpoint was not admitted")]
    EndpointNotAdmitted,
    #[error("rule was not enabled")]
    RuleNotEnabled,
    #[error("endpoint-rule pair already has an outcome")]
    PairAlreadyRecorded,
    #[error("run is already stopped")]
    RunStopped,
    #[error("resource boundary reached: {0:?}")]
    ResourceBoundary(RunStopReason),
    #[error("coverage cannot be completed while pairs or queues remain")]
    IncompleteCoverage,
    #[error("coverage serialization failed: {0}")]
    Serialization(String),
    #[error("coverage receipt digest mismatch")]
    ReceiptDigest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageLimits {
    pub maximum_endpoints: usize,
    pub maximum_rules: usize,
    pub maximum_recorded_pairs: usize,
    pub maximum_windows: usize,
}

impl CoverageLimits {
    pub fn validate(self) -> Result<Self, CoverageError> {
        if self.maximum_endpoints == 0
            || self.maximum_endpoints > MAX_COVERAGE_ENDPOINTS
            || self.maximum_rules == 0
            || self.maximum_rules > MAX_COVERAGE_RULES
            || self.maximum_recorded_pairs == 0
            || self.maximum_recorded_pairs > MAX_COVERAGE_PAIRS
            || self.maximum_windows == 0
            || self.maximum_windows > MAX_SATURATION_WINDOWS
        {
            return Err(CoverageError::InvalidConfig(
                "one or more coverage limits are outside policy".into(),
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceUse {
    pub accounted_memory_bytes: u64,
    pub evidence_bytes: u64,
    pub disk_bytes: u64,
    pub requests: u64,
    pub elapsed_milliseconds: u64,
}

impl ResourceUse {
    fn checked_add(self, delta: Self) -> Self {
        Self {
            accounted_memory_bytes: self
                .accounted_memory_bytes
                .saturating_add(delta.accounted_memory_bytes),
            evidence_bytes: self.evidence_bytes.saturating_add(delta.evidence_bytes),
            disk_bytes: self.disk_bytes.saturating_add(delta.disk_bytes),
            requests: self.requests.saturating_add(delta.requests),
            elapsed_milliseconds: self
                .elapsed_milliseconds
                .saturating_add(delta.elapsed_milliseconds),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageResourceBudget {
    pub memory_budget_bytes: u64,
    pub evidence_budget_bytes: u64,
    pub disk_budget_bytes: u64,
    pub request_budget: u64,
    pub time_budget_milliseconds: u64,
}

impl CoverageResourceBudget {
    pub fn validate(self) -> Result<Self, CoverageError> {
        if self.memory_budget_bytes == 0
            || self.evidence_budget_bytes == 0
            || self.disk_budget_bytes == 0
            || self.request_budget == 0
            || self.time_budget_milliseconds == 0
        {
            return Err(CoverageError::InvalidConfig(
                "all resource budgets must be non-zero".into(),
            ));
        }
        Ok(self)
    }

    fn first_exceeded(self, usage: ResourceUse) -> Option<RunStopReason> {
        if usage.accounted_memory_bytes > self.memory_budget_bytes {
            Some(RunStopReason::MemoryBudget)
        } else if usage.evidence_bytes > self.evidence_budget_bytes {
            Some(RunStopReason::EvidenceBudget)
        } else if usage.disk_bytes > self.disk_budget_bytes {
            Some(RunStopReason::DiskBudget)
        } else if usage.requests > self.request_budget {
            Some(RunStopReason::RequestBudget)
        } else if usage.elapsed_milliseconds > self.time_budget_milliseconds {
            Some(RunStopReason::TimeBudget)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PairSkipReason {
    NotApplicable,
    CapabilityDenied,
    MethodDenied,
    RateLimited,
    DependencyUnavailable,
    ResourceBudget,
    Cancelled,
    EmergencyStop,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidationDispositionCount {
    Validated,
    Rejected,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionMetrics {
    pub unique_findings: u64,
    pub duplicate_findings: u64,
    pub validated_findings: u64,
    pub rejected_findings: u64,
    pub inconclusive_findings: u64,
    pub resource_delta: ResourceUse,
}

impl ExecutionMetrics {
    pub fn validate(self) -> Result<Self, CoverageError> {
        let classified = self
            .validated_findings
            .saturating_add(self.rejected_findings)
            .saturating_add(self.inconclusive_findings);
        if classified > self.unique_findings || self.resource_delta.requests == 0 {
            return Err(CoverageError::InvalidInput(
                "execution metrics are inconsistent".into(),
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PairOutcome {
    Executed { metrics: ExecutionMetrics },
    Skipped { reason: PairSkipReason },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PairKey {
    pub endpoint_sha256: String,
    pub rule_id: String,
}

impl PairKey {
    pub fn new(endpoint_sha256: &str, rule_id: &str) -> Result<Self, CoverageError> {
        validate_coverage_sha256(endpoint_sha256, "endpoint_sha256")?;
        validate_coverage_rule_id(rule_id)?;
        Ok(Self {
            endpoint_sha256: endpoint_sha256.into(),
            rule_id: rule_id.into(),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStopReason {
    Completed,
    Saturated,
    MemoryBudget,
    EvidenceBudget,
    DiskBudget,
    RequestBudget,
    TimeBudget,
    Cancelled,
    EmergencyStop,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueTelemetry {
    pub high_priority_unexplored_pairs: u64,
    pub validation_queue: u64,
    pub cleanup_queue: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SaturationPolicy {
    pub checks_per_window: u64,
    pub minimum_completed_checks: u64,
    pub required_consecutive_low_yield_windows: usize,
    pub yield_threshold_numerator: u64,
    pub yield_threshold_denominator: u64,
}

impl SaturationPolicy {
    pub fn validate(self, maximum_windows: usize) -> Result<Self, CoverageError> {
        if self.checks_per_window == 0
            || self.checks_per_window > MAX_WINDOW_CHECKS
            || self.minimum_completed_checks < self.checks_per_window
            || self.required_consecutive_low_yield_windows == 0
            || self.required_consecutive_low_yield_windows > maximum_windows
            || self.yield_threshold_denominator == 0
            || self.yield_threshold_numerator > self.yield_threshold_denominator
        {
            return Err(CoverageError::InvalidConfig(
                "saturation policy is outside deterministic bounds".into(),
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SaturationWindow {
    pub completed_checks: u64,
    pub new_unique_findings: u64,
    pub below_yield_threshold: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageReceipt {
    pub admitted_endpoints: u64,
    pub considered_endpoints: u64,
    pub analyzed_endpoints: u64,
    pub untested_endpoints: u64,
    pub enabled_rules: u64,
    pub theoretical_pairs: u64,
    pub recorded_pairs: u64,
    pub untested_pairs: u64,
    pub executed_pairs: u64,
    pub skipped_pairs: u64,
    pub skipped_by_reason: BTreeMap<PairSkipReason, u64>,
    pub unique_findings: u64,
    pub duplicate_findings: u64,
    pub validated_findings: u64,
    pub rejected_findings: u64,
    pub inconclusive_findings: u64,
    pub resource_use: ResourceUse,
    pub queue_telemetry: QueueTelemetry,
    pub saturation_windows: Vec<SaturationWindow>,
    pub stop_reason: Option<RunStopReason>,
    pub endpoint_set_sha256: String,
    pub rule_set_sha256: String,
    pub pair_outcomes_sha256: String,
    pub receipt_sha256: String,
}

impl CoverageReceipt {
    pub fn verify(&self) -> Result<(), CoverageError> {
        let mut material = self.clone();
        material.receipt_sha256.clear();
        let expected = coverage_hash_serializable(&material)?;
        if expected != self.receipt_sha256 {
            return Err(CoverageError::ReceiptDigest);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct CoverageTracker {
    limits: CoverageLimits,
    budget: CoverageResourceBudget,
    saturation_policy: SaturationPolicy,
    admitted_endpoints: BTreeSet<String>,
    considered_endpoints: BTreeSet<String>,
    analyzed_endpoints: BTreeSet<String>,
    enabled_rules: BTreeSet<String>,
    pair_outcomes: BTreeMap<PairKey, PairOutcome>,
    skipped_by_reason: BTreeMap<PairSkipReason, u64>,
    unique_findings: u64,
    duplicate_findings: u64,
    validated_findings: u64,
    rejected_findings: u64,
    inconclusive_findings: u64,
    resource_use: ResourceUse,
    queue_telemetry: QueueTelemetry,
    saturation_windows: Vec<SaturationWindow>,
    current_window_checks: u64,
    current_window_unique_findings: u64,
    stop_reason: Option<RunStopReason>,
}

fn validate_coverage_sha256(value: &str, name: &str) -> Result<(), CoverageError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CoverageError::InvalidInput(name.into()));
    }
    Ok(())
}

fn validate_coverage_rule_id(value: &str) -> Result<(), CoverageError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(CoverageError::InvalidInput("rule_id".into()));
    }
    Ok(())
}

fn coverage_hash_serializable<T: Serialize>(value: &T) -> Result<String, CoverageError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CoverageError::Serialization(error.to_string()))?;
    Ok(coverage_hash_bytes(&bytes))
}

fn coverage_hash_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
