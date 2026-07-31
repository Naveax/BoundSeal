use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_CORRELATION_CLUSTERS: usize = 1_000_000;
pub const MAX_MEMBERS_PER_CLUSTER: usize = 1_000_000;
pub const MAX_ENDPOINTS_PER_CLUSTER: usize = 1_000_000;
pub const MAX_TOTAL_CORRELATION_MEMBERS: usize = 10_000_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CorrelationError {
    #[error("correlation limits are invalid: {0}")]
    InvalidLimits(String),
    #[error("correlation input is invalid: {0}")]
    InvalidInput(String),
    #[error("correlation cluster budget was exhausted")]
    ClusterBudget,
    #[error("correlation member budget was exhausted")]
    MemberBudget,
    #[error("correlation endpoint budget was exhausted")]
    EndpointBudget,
    #[error("finding identity was observed with conflicting root-cause material")]
    FindingIdentityConflict,
    #[error("correlation serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationLimits {
    pub maximum_clusters: usize,
    pub maximum_members_per_cluster: usize,
    pub maximum_endpoints_per_cluster: usize,
    pub maximum_total_members: usize,
}

impl CorrelationLimits {
    pub fn validate(self) -> Result<Self, CorrelationError> {
        if self.maximum_clusters == 0
            || self.maximum_clusters > MAX_CORRELATION_CLUSTERS
            || self.maximum_members_per_cluster == 0
            || self.maximum_members_per_cluster > MAX_MEMBERS_PER_CLUSTER
            || self.maximum_endpoints_per_cluster == 0
            || self.maximum_endpoints_per_cluster > MAX_ENDPOINTS_PER_CLUSTER
            || self.maximum_total_members == 0
            || self.maximum_total_members > MAX_TOTAL_CORRELATION_MEMBERS
            || self.maximum_members_per_cluster > self.maximum_total_members
        {
            return Err(CorrelationError::InvalidLimits(
                "one or more limits are outside policy".into(),
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationEvidence {
    pub policy_snapshot_sha256: String,
    pub normalization_version: String,
    pub component_sha256: String,
    pub normalized_evidence_sha256: String,
    pub response_shape_sha256: String,
}

impl CorrelationEvidence {
    pub fn validate(&self) -> Result<(), CorrelationError> {
        for (value, name) in [
            (&self.policy_snapshot_sha256, "policy snapshot"),
            (&self.component_sha256, "component"),
            (&self.normalized_evidence_sha256, "normalized evidence"),
            (&self.response_shape_sha256, "response shape"),
        ] {
            if !correlation_is_sha256(value) {
                return Err(CorrelationError::InvalidInput(name.into()));
            }
        }
        if self.normalization_version.is_empty()
            || self.normalization_version.len() > 128
            || !self.normalization_version.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(CorrelationError::InvalidInput(
                "normalization version".into(),
            ));
        }
        Ok(())
    }

    pub fn root_cause_id(&self, rule_id: &str) -> Result<String, CorrelationError> {
        self.validate()?;
        validate_rule_id(rule_id)?;
        correlation_hash_serializable(&(
            rule_id,
            &self.policy_snapshot_sha256,
            &self.normalization_version,
            &self.component_sha256,
            &self.normalized_evidence_sha256,
            &self.response_shape_sha256,
        ))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationDisposition {
    NewRootCause,
    AdditionalAffectedEndpoint,
    AdditionalFindingSameEndpoint,
    ExactDuplicate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootCauseCluster {
    pub root_cause_id: String,
    pub rule_id: String,
    pub title: String,
    pub policy_snapshot_sha256: String,
    pub normalization_version: String,
    pub component_sha256: String,
    pub normalized_evidence_sha256: String,
    pub response_shape_sha256: String,
    pub highest_severity: Severity,
    pub minimum_confidence: Confidence,
    pub finding_ids: BTreeSet<String>,
    pub affected_endpoint_sha256: BTreeSet<String>,
    pub evidence_sha256: BTreeSet<String>,
}

impl RootCauseCluster {
    pub fn finding_count(&self) -> u64 {
        self.finding_ids.len() as u64
    }

    pub fn affected_endpoint_count(&self) -> u64 {
        self.affected_endpoint_sha256.len() as u64
    }

    pub fn cluster_digest(&self) -> Result<String, CorrelationError> {
        correlation_hash_serializable(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationReceipt {
    pub root_cause_clusters: u64,
    pub total_finding_memberships: u64,
    pub total_endpoint_memberships: u64,
    pub total_evidence_memberships: u64,
    pub exact_duplicate_observations: u64,
    pub correlation_tail_sha256: String,
}

#[derive(Debug, Clone)]
struct FindingBinding {
    root_cause_id: String,
    finding_digest: String,
}

#[derive(Debug)]
pub struct RootCauseCorrelator {
    limits: CorrelationLimits,
    clusters: BTreeMap<String, RootCauseCluster>,
    finding_bindings: BTreeMap<String, FindingBinding>,
    total_members: usize,
    exact_duplicate_observations: u64,
}
