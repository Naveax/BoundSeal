use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::coverage_saturation::{PairKey, RunStopReason};

pub const SCHEDULER_SCORE_SCALE: u128 = 1_000_000_000;
pub const MAX_SCHEDULER_RULES: usize = 100_000;
pub const MAX_SCHEDULER_PAIRS: usize = 10_000_000;
pub const MAX_SCHEDULER_IN_FLIGHT: usize = 1_000_000;
pub const MAX_RULE_WEIGHT: u32 = 10_000;
pub const MAX_ITEM_COST: u64 = 1_000_000_000_000;
pub const MAX_LEASE_SECONDS: i64 = 86_400;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    #[error("scheduler configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("scheduler input is invalid: {0}")]
    InvalidInput(String),
    #[error("scheduler rule is not registered")]
    RuleUnknown,
    #[error("scheduler pair was already observed")]
    PairDuplicate,
    #[error("scheduler queue budget was exhausted")]
    QueueBudget,
    #[error("scheduler request reservation budget was exhausted")]
    RequestReservationBudget,
    #[error("scheduler mutation reservation budget was exhausted")]
    MutationReservationBudget,
    #[error("scheduler in-flight budget was exhausted")]
    InFlightBudget,
    #[error("work authorization has expired")]
    AuthorizationExpired,
    #[error("scheduler is stopped: {0:?}")]
    RunStopped(RunStopReason),
    #[error("no schedulable work remains")]
    NoWork,
    #[error("lease is unknown")]
    LeaseUnknown,
    #[error("lease has expired")]
    LeaseExpired,
    #[error("scheduler metrics are inconsistent")]
    MetricMismatch,
    #[error("scheduler serialization failed: {0}")]
    Serialization(String),
    #[error("scheduler receipt digest mismatch")]
    ReceiptDigest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchedulerLimits {
    pub maximum_rules: usize,
    pub maximum_known_pairs: usize,
    pub maximum_queued_pairs: usize,
    pub maximum_in_flight: usize,
    pub maximum_outstanding_request_reservations: u64,
    pub maximum_outstanding_mutation_reservations: u64,
    pub lease_seconds: i64,
}

impl SchedulerLimits {
    pub fn validate(self) -> Result<Self, SchedulerError> {
        if self.maximum_rules == 0
            || self.maximum_rules > MAX_SCHEDULER_RULES
            || self.maximum_known_pairs == 0
            || self.maximum_known_pairs > MAX_SCHEDULER_PAIRS
            || self.maximum_queued_pairs == 0
            || self.maximum_queued_pairs > self.maximum_known_pairs
            || self.maximum_in_flight == 0
            || self.maximum_in_flight > MAX_SCHEDULER_IN_FLIGHT
            || self.maximum_outstanding_request_reservations == 0
            || self.maximum_outstanding_mutation_reservations == 0
            || self.lease_seconds <= 0
            || self.lease_seconds > MAX_LEASE_SECONDS
        {
            return Err(SchedulerError::InvalidConfig(
                "one or more scheduler limits are outside policy".into(),
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleProfile {
    pub rule_id: String,
    pub severity_weight: u32,
    pub confidence_weight: u32,
    pub base_priority_weight: u32,
    pub minimum_cost_units: u64,
}

impl RuleProfile {
    pub fn validate(&self) -> Result<(), SchedulerError> {
        validate_scheduler_rule_id(&self.rule_id)?;
        if self.severity_weight == 0
            || self.severity_weight > MAX_RULE_WEIGHT
            || self.confidence_weight == 0
            || self.confidence_weight > MAX_RULE_WEIGHT
            || self.base_priority_weight == 0
            || self.base_priority_weight > MAX_RULE_WEIGHT
            || self.minimum_cost_units == 0
            || self.minimum_cost_units > MAX_ITEM_COST
        {
            return Err(SchedulerError::InvalidInput("rule profile bounds".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleMetrics {
    pub completed_checks: u64,
    pub unique_findings: u64,
    pub duplicate_findings: u64,
    pub validated_findings: u64,
    pub rejected_findings: u64,
    pub inconclusive_findings: u64,
    pub requests: u64,
    pub evidence_bytes: u64,
    pub elapsed_milliseconds: u64,
    pub cost_units: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleObservation {
    pub unique_findings: u64,
    pub duplicate_findings: u64,
    pub validated_findings: u64,
    pub rejected_findings: u64,
    pub inconclusive_findings: u64,
    pub requests: u64,
    pub evidence_bytes: u64,
    pub elapsed_milliseconds: u64,
    pub cost_units: u64,
}

impl RuleObservation {
    pub fn validate(self) -> Result<Self, SchedulerError> {
        let classified = self
            .validated_findings
            .saturating_add(self.rejected_findings)
            .saturating_add(self.inconclusive_findings);
        if classified > self.unique_findings
            || self.requests == 0
            || self.cost_units == 0
            || self.cost_units > MAX_ITEM_COST
        {
            return Err(SchedulerError::MetricMismatch);
        }
        Ok(self)
    }
}

impl RuleMetrics {
    fn apply(&mut self, observation: RuleObservation) {
        self.completed_checks = self.completed_checks.saturating_add(1);
        self.unique_findings = self
            .unique_findings
            .saturating_add(observation.unique_findings);
        self.duplicate_findings = self
            .duplicate_findings
            .saturating_add(observation.duplicate_findings);
        self.validated_findings = self
            .validated_findings
            .saturating_add(observation.validated_findings);
        self.rejected_findings = self
            .rejected_findings
            .saturating_add(observation.rejected_findings);
        self.inconclusive_findings = self
            .inconclusive_findings
            .saturating_add(observation.inconclusive_findings);
        self.requests = self.requests.saturating_add(observation.requests);
        self.evidence_bytes = self
            .evidence_bytes
            .saturating_add(observation.evidence_bytes);
        self.elapsed_milliseconds = self
            .elapsed_milliseconds
            .saturating_add(observation.elapsed_milliseconds);
        self.cost_units = self.cost_units.saturating_add(observation.cost_units);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizedWorkItem {
    pub pair: PairKey,
    pub plan_sha256: String,
    pub capability_sha256: String,
    pub authorization_sha256: String,
    pub authorization_expires_at_epoch_seconds: i64,
    pub estimated_requests: u64,
    pub estimated_mutations: u64,
    pub estimated_cost_units: u64,
    pub item_priority_weight: u32,
}

impl AuthorizedWorkItem {
    pub fn validate(&self) -> Result<(), SchedulerError> {
        for (value, name) in [
            (&self.plan_sha256, "plan_sha256"),
            (&self.capability_sha256, "capability_sha256"),
            (&self.authorization_sha256, "authorization_sha256"),
        ] {
            validate_scheduler_sha256(value, name)?;
        }
        if self.authorization_expires_at_epoch_seconds <= 0
            || self.estimated_requests == 0
            || self.estimated_requests > MAX_ITEM_COST
            || self.estimated_mutations > MAX_ITEM_COST
            || self.estimated_cost_units == 0
            || self.estimated_cost_units > MAX_ITEM_COST
            || self.item_priority_weight == 0
            || self.item_priority_weight > MAX_RULE_WEIGHT
        {
            return Err(SchedulerError::InvalidInput("work item bounds".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleScore {
    pub fixed_point_score: u64,
    pub useful_reward_units: u64,
    pub penalty_units: u64,
    pub accounted_cost_units: u64,
    pub exploration_numerator: u64,
    pub exploration_denominator: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RankedWorkItem {
    pub pair: PairKey,
    pub score: RuleScore,
    pub authorization_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduleLease {
    pub lease_id: String,
    pub pair: PairKey,
    pub plan_sha256: String,
    pub capability_sha256: String,
    pub authorization_sha256: String,
    pub score: RuleScore,
    pub issued_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum WorkFailureReason {
    CapabilityDenied,
    ResourceDenied,
    DependencyUnavailable,
    Cancelled,
    EmergencyStop,
}

#[derive(Debug, Clone)]
struct LeaseState {
    item: AuthorizedWorkItem,
    score: RuleScore,
    expires_at_epoch_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchedulerReceipt {
    pub registered_rules: u64,
    pub known_pairs: u64,
    pub queued_pairs: u64,
    pub in_flight_pairs: u64,
    pub completed_pairs: u64,
    pub failed_pairs: u64,
    pub expired_authorizations: u64,
    pub outstanding_request_reservations: u64,
    pub outstanding_mutation_reservations: u64,
    pub stop_reason: Option<RunStopReason>,
    pub profiles_sha256: String,
    pub metrics_sha256: String,
    pub queue_sha256: String,
    pub in_flight_sha256: String,
    pub terminal_pairs_sha256: String,
    pub receipt_sha256: String,
}

impl SchedulerReceipt {
    pub fn verify(&self) -> Result<(), SchedulerError> {
        let mut material = self.clone();
        material.receipt_sha256.clear();
        if scheduler_hash_serializable(&material)? != self.receipt_sha256 {
            return Err(SchedulerError::ReceiptDigest);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct AdaptiveRuleScheduler {
    limits: SchedulerLimits,
    profiles: BTreeMap<String, RuleProfile>,
    metrics: BTreeMap<String, RuleMetrics>,
    queued: BTreeMap<PairKey, AuthorizedWorkItem>,
    in_flight: BTreeMap<String, LeaseState>,
    known_pairs: BTreeSet<PairKey>,
    completed_pairs: BTreeSet<PairKey>,
    failed_pairs: BTreeMap<PairKey, WorkFailureReason>,
    expired_pairs: BTreeSet<PairKey>,
    outstanding_request_reservations: u64,
    outstanding_mutation_reservations: u64,
    next_lease_sequence: u64,
    stop_reason: Option<RunStopReason>,
}

fn validate_scheduler_sha256(value: &str, name: &str) -> Result<(), SchedulerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SchedulerError::InvalidInput(name.into()));
    }
    Ok(())
}

fn validate_scheduler_rule_id(value: &str) -> Result<(), SchedulerError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(SchedulerError::InvalidInput("rule_id".into()));
    }
    Ok(())
}

fn scheduler_hash_serializable<T: Serialize>(value: &T) -> Result<String, SchedulerError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| SchedulerError::Serialization(error.to_string()))?;
    Ok(scheduler_hash_bytes(&bytes))
}

fn scheduler_hash_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
