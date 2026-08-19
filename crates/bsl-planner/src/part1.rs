use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub const MAX_PLAN_ENDPOINTS: usize = 100_000;
pub const MAX_QUEUE_ITEMS: usize = 100_000;
pub const MAX_GLOBAL_CONCURRENCY: u16 = 64;
pub const MAX_HOST_CONCURRENCY: u16 = 16;
pub const MAX_RETRY_COUNT: u8 = 5;
pub const MAX_CAPABILITY_REQUESTS: u64 = 100_000;
pub const MAX_CAPABILITY_MUTATIONS: u64 = 10_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PlannerError {
    #[error("planner identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("request plan is invalid: {0}")]
    InvalidPlan(String),
    #[error("scheduler limits are invalid: {0}")]
    InvalidSchedulerLimits(String),
    #[error("work queue is full")]
    QueueFull,
    #[error("work item is duplicated")]
    DuplicateWorkItem,
    #[error("work item is unknown")]
    UnknownWorkItem,
    #[error("work item is not in the expected state")]
    InvalidWorkState,
    #[error("run transition is invalid from {from:?} to {to:?}")]
    InvalidRunTransition { from: RunState, to: RunState },
    #[error("probe capability is invalid: {0}")]
    InvalidCapability(String),
    #[error("probe capability is expired or revoked")]
    CapabilityInactive,
    #[error("probe capability does not authorize this operation: {0}")]
    CapabilityDenied(String),
    #[error("planner audit material could not be serialized: {0}")]
    AuditSerialization(String),
    #[error("planner audit sequence mismatch at record {record_index}")]
    AuditSequenceMismatch { record_index: usize },
    #[error("planner audit previous hash mismatch at record {record_index}")]
    AuditPreviousHashMismatch { record_index: usize },
    #[error("planner audit record hash mismatch at record {record_index}")]
    AuditRecordHashMismatch { record_index: usize },
    #[error("planner audit tail hash mismatch")]
    AuditTailMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Passive,
    SafeActive,
    SensitiveActive,
    Forbidden,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum WorkPriority {
    Critical,
    High,
    Normal,
    Low,
}

impl WorkPriority {
    fn rank(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Normal => 2,
            Self::Low => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestIntentPlan {
    pub endpoint_id: String,
    pub canonical_url: String,
    pub canonical_url_sha256: String,
    pub origin: String,
    pub method: String,
    pub parameter_names: BTreeSet<String>,
    pub body_kind: String,
    pub session_required: bool,
    pub risk_class: RiskClass,
    pub provenance_sha256: String,
    pub policy_snapshot_sha256: String,
    pub estimated_request_bytes: u64,
    pub estimated_response_bytes: u64,
    pub redirect_budget: u8,
    pub retry_budget: u8,
    pub active_execution_allowed: bool,
}

impl RequestIntentPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint_id: impl Into<String>,
        url: Url,
        method: impl Into<String>,
        parameter_names: BTreeSet<String>,
        body_kind: impl Into<String>,
        session_required: bool,
        risk_class: RiskClass,
        provenance_sha256: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        estimated_request_bytes: u64,
        estimated_response_bytes: u64,
        redirect_budget: u8,
        retry_budget: u8,
        active_execution_allowed: bool,
    ) -> Result<Self, PlannerError> {
        let endpoint_id = endpoint_id.into();
        validate_identifier(&endpoint_id, "endpoint_id")?;
        let method = method.into().to_ascii_uppercase();
        validate_method(&method)?;
        let body_kind = body_kind.into();
        validate_identifier(&body_kind, "body_kind")?;
        let provenance_sha256 = provenance_sha256.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&provenance_sha256, "provenance")?;
        validate_sha256(&policy_snapshot_sha256, "policy snapshot")?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(PlannerError::InvalidPlan(
                "URL must be credential-free absolute HTTP(S) without a fragment".into(),
            ));
        }
        if parameter_names.len() > 1024
            || parameter_names.iter().any(|name| {
                name.is_empty()
                    || name.len() > 256
                    || name.bytes().any(|byte| byte.is_ascii_control())
            })
        {
            return Err(PlannerError::InvalidPlan(
                "parameter-name set is invalid".into(),
            ));
        }
        if estimated_request_bytes > 64 * 1024 * 1024
            || estimated_response_bytes > 128 * 1024 * 1024
            || redirect_budget > 16
            || retry_budget > MAX_RETRY_COUNT
        {
            return Err(PlannerError::InvalidPlan(
                "cost or retry budgets exceed hard limits".into(),
            ));
        }
        if risk_class == RiskClass::Forbidden && active_execution_allowed {
            return Err(PlannerError::InvalidPlan(
                "forbidden work cannot be active".into(),
            ));
        }
        let origin = normalized_origin(&url)?;
        Ok(Self {
            endpoint_id,
            canonical_url_sha256: hash_bytes(url.as_str().as_bytes()),
            canonical_url: url.to_string(),
            origin,
            method,
            parameter_names,
            body_kind,
            session_required,
            risk_class,
            provenance_sha256,
            policy_snapshot_sha256,
            estimated_request_bytes,
            estimated_response_bytes,
            redirect_budget,
            retry_budget,
            active_execution_allowed,
        })
    }

    pub fn fingerprint(&self) -> String {
        hash_serializable(&(
            &self.canonical_url_sha256,
            &self.method,
            &self.parameter_names,
            &self.body_kind,
            self.session_required,
            self.risk_class,
            &self.policy_snapshot_sha256,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkItem {
    pub work_id: String,
    pub plan: RequestIntentPlan,
    pub priority: WorkPriority,
    pub enqueued_at_milliseconds: u64,
    pub deadline_milliseconds: u64,
    pub attempt: u8,
    pub session_id: Option<String>,
    pub account_id: Option<String>,
    pub tenant_id: Option<String>,
}

