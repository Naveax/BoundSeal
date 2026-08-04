#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use nxb_knowledge_reporting::ExportManifest;
use nxb_operator_runtime::RuntimeRecovery;
use nxb_operator_state::OperatorRunStatus;
use nxb_resumable_runner::{RunnerCheckpoint, RunnerManifest, RunnerStatus, RunnerStopReason};
use nxb_unified_operator::UnifiedOperatorPlan;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const RUN_CLOSURE_VERSION: u32 = 1;
pub const MAX_UNTESTED_SCOPE_ENTRIES: usize = 16_384;
pub const MAX_CLOSURE_ARTIFACTS: usize = 256;
pub const MAX_CLOSURE_METADATA: usize = 128;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClosureDisposition {
    Complete,
    Partial,
    Aborted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClosureReason {
    QueueExhausted,
    RequestBudgetExhausted,
    EmergencyStop,
    RuntimeContinuationDenied,
    RuntimeCompleted,
    RuntimeAborted,
}

impl ClosureReason {
    fn from_runner(reason: RunnerStopReason) -> Self {
        match reason {
            RunnerStopReason::QueueExhausted => Self::QueueExhausted,
            RunnerStopReason::RequestBudgetExhausted => Self::RequestBudgetExhausted,
            RunnerStopReason::EmergencyStop => Self::EmergencyStop,
            RunnerStopReason::RuntimeContinuationDenied => Self::RuntimeContinuationDenied,
            RunnerStopReason::RuntimeCompleted => Self::RuntimeCompleted,
            RunnerStopReason::RuntimeAborted => Self::RuntimeAborted,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunCoverageSummary {
    pub maximum_requests: u64,
    pub completed_requests: u64,
    pub visited_targets: u64,
    pub pending_targets: u64,
    pub rejected_candidates: u64,
    pub recovery_gap_count: u64,
    pub maximum_depth_observed: u16,
    pub total_response_bytes: u64,
    pub evidence_bytes: u64,
    pub request_budget_basis_points: u16,
}

impl RunCoverageSummary {
    fn validate(&self) -> Result<(), RunClosureError> {
        if self.maximum_requests == 0
            || self.completed_requests > self.maximum_requests
            || self.request_budget_basis_points > 10_000
        {
            return Err(RunClosureError::InvalidCoverage);
        }
        let expected = self
            .completed_requests
            .saturating_mul(10_000)
            .checked_div(self.maximum_requests)
            .unwrap_or(0) as u16;
        if expected != self.request_budget_basis_points {
            return Err(RunClosureError::InvalidCoverage);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunClosureArtifacts {
    pub evidence_export_root_sha256: String,
    pub report_json_sha256: String,
    pub report_markdown_sha256: String,
    pub knowledge_audit_tail_sha256: String,
    pub session_audit_tail_sha256: String,
    pub vault_audit_tail_sha256: String,
    pub provider_teardown_receipt_sha256: String,
    pub runtime_checkpoint_sha256: String,
    pub runner_checkpoint_sha256: String,
    pub additional_artifacts: BTreeMap<String, String>,
}

impl RunClosureArtifacts {
    fn validate(&self) -> Result<(), RunClosureError> {
        for value in [
            &self.evidence_export_root_sha256,
            &self.report_json_sha256,
            &self.report_markdown_sha256,
            &self.knowledge_audit_tail_sha256,
            &self.session_audit_tail_sha256,
            &self.vault_audit_tail_sha256,
            &self.provider_teardown_receipt_sha256,
            &self.runtime_checkpoint_sha256,
            &self.runner_checkpoint_sha256,
        ] {
            validate_sha256(value)?;
        }
        if self.additional_artifacts.len() > MAX_CLOSURE_ARTIFACTS {
            return Err(RunClosureError::ArtifactLimit);
        }
        for (name, digest) in &self.additional_artifacts {
            validate_identifier(name)?;
            validate_sha256(digest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TerminalRunSnapshot {
    pub runner_manifest_sha256: String,
    pub runner_checkpoint_sha256: String,
    pub runner_status: RunnerStatus,
    pub runner_stop_reason: ClosureReason,
    pub completed_requests: u64,
    pub visited_targets: u64,
    pub pending_targets: u64,
    pub rejected_candidates: u64,
    pub recovery_gap_count: u64,
    pub runtime_checkpoint_sha256: String,
    pub runtime_status: OperatorRunStatus,
    pub maximum_depth_observed: u16,
    pub total_response_bytes: u64,
    pub evidence_bytes: u64,
}

impl TerminalRunSnapshot {
    pub fn from_components(
        runner_manifest: &RunnerManifest,
        runner_checkpoint: &RunnerCheckpoint,
        runtime: &RuntimeRecovery,
    ) -> Result<Self, RunClosureError> {
        let reason = runner_checkpoint
            .stop_reason
            .ok_or(RunClosureError::MissingStopReason)?;
        Ok(Self {
            runner_manifest_sha256: runner_manifest.manifest_sha256.clone(),
            runner_checkpoint_sha256: runner_checkpoint.checkpoint_sha256.clone(),
            runner_status: runner_checkpoint.status,
            runner_stop_reason: ClosureReason::from_runner(reason),
            completed_requests: runner_checkpoint.completed_requests,
            visited_targets: runner_checkpoint.visited_target_sha256.len() as u64,
            pending_targets: runner_checkpoint.pending_queue.len() as u64,
            rejected_candidates: runner_checkpoint.rejected_candidates,
            recovery_gap_count: runner_checkpoint.recovery_gap_count,
            runtime_checkpoint_sha256: runtime.state.latest.checkpoint_sha256.clone(),
            runtime_status: runtime.state.latest.status,
            maximum_depth_observed: runtime.state.latest.counters.maximum_depth_observed,
            total_response_bytes: runtime.state.latest.counters.total_response_bytes,
            evidence_bytes: runtime.state.latest.counters.evidence_bytes,
        })
    }

    fn validate(
        &self,
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
    ) -> Result<(), RunClosureError> {
        for value in [
            &self.runner_manifest_sha256,
            &self.runner_checkpoint_sha256,
            &self.runtime_checkpoint_sha256,
        ] {
            validate_sha256(value)?;
        }
        if self.runner_manifest_sha256 != runner_manifest.manifest_sha256
            || self.completed_requests > plan.binding.maximum_requests
            || self.maximum_depth_observed > plan.binding.maximum_depth
            || self.total_response_bytes > plan.binding.maximum_total_response_bytes
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        if !self.runner_status.is_terminal() || !self.runtime_status.is_terminal() {
            return Err(RunClosureError::NonTerminalState);
        }
        match (self.runner_status, self.runtime_status) {
            (RunnerStatus::Completed, OperatorRunStatus::Completed)
            | (RunnerStatus::Aborted, OperatorRunStatus::Aborted) => {}
            _ => return Err(RunClosureError::TerminalStateMismatch),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunClosureInput {
    pub snapshot: TerminalRunSnapshot,
    pub artifacts: RunClosureArtifacts,
    pub untested_scope_sha256: BTreeSet<String>,
    pub metadata: BTreeMap<String, String>,
    pub generated_at_epoch_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunClosureManifest {
    pub version: u32,
    pub closure_id: String,
    pub operator_id: String,
    pub plan_sha256: String,
    pub binding_sha256: String,
    pub policy_snapshot_sha256: String,
    pub disposition: ClosureDisposition,
    pub reason: ClosureReason,
    pub coverage: RunCoverageSummary,
    pub artifacts: RunClosureArtifacts,
    pub untested_scope_sha256: BTreeSet<String>,
    pub metadata: BTreeMap<String, String>,
    pub generated_at_epoch_seconds: i64,
    pub manifest_sha256: String,
}

impl RunClosureManifest {
    pub fn build(
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
        export_manifest: &ExportManifest,
        input: RunClosureInput,
    ) -> Result<Self, RunClosureError> {
        plan.validate()?;
        runner_manifest.validate_binding(plan)?;
        export_manifest.verify()?;
        input.snapshot.validate(plan, runner_manifest)?;
        input.artifacts.validate()?;
        if input.artifacts.evidence_export_root_sha256 != export_manifest.root_sha256
            || input.artifacts.runner_checkpoint_sha256 != input.snapshot.runner_checkpoint_sha256
            || input.artifacts.runtime_checkpoint_sha256 != input.snapshot.runtime_checkpoint_sha256
            || export_manifest.policy_snapshot_sha256 != plan.binding.policy_sha256
            || input.generated_at_epoch_seconds < runner_manifest.created_at_epoch_seconds
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        validate_untrusted_metadata(&input.metadata)?;
        if input.untested_scope_sha256.len() > MAX_UNTESTED_SCOPE_ENTRIES {
            return Err(RunClosureError::UntestedScopeLimit);
        }
        for digest in &input.untested_scope_sha256 {
            validate_sha256(digest)?;
        }
        let disposition = match input.snapshot.runner_status {
            RunnerStatus::Aborted => ClosureDisposition::Aborted,
            RunnerStatus::Completed
                if input.snapshot.pending_targets == 0
                    && input.untested_scope_sha256.is_empty() =>
            {
                ClosureDisposition::Complete
            }
            RunnerStatus::Completed => ClosureDisposition::Partial,
            _ => return Err(RunClosureError::NonTerminalState),
        };
        if disposition != ClosureDisposition::Complete && input.untested_scope_sha256.is_empty() {
            return Err(RunClosureError::MissingUntestedScope);
        }
        let coverage = RunCoverageSummary {
            maximum_requests: plan.binding.maximum_requests,
            completed_requests: input.snapshot.completed_requests,
            visited_targets: input.snapshot.visited_targets,
            pending_targets: input.snapshot.pending_targets,
            rejected_candidates: input.snapshot.rejected_candidates,
            recovery_gap_count: input.snapshot.recovery_gap_count,
            maximum_depth_observed: input.snapshot.maximum_depth_observed,
            total_response_bytes: input.snapshot.total_response_bytes,
            evidence_bytes: input.snapshot.evidence_bytes,
            request_budget_basis_points: input
                .snapshot
                .completed_requests
                .saturating_mul(10_000)
                .checked_div(plan.binding.maximum_requests)
                .unwrap_or(0) as u16,
        };
        coverage.validate()?;
        let mut manifest = Self {
            version: RUN_CLOSURE_VERSION,
            closure_id: String::new(),
            operator_id: plan.operator_id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            binding_sha256: plan.binding_sha256.clone(),
            policy_snapshot_sha256: plan.binding.policy_sha256.clone(),
            disposition,
            reason: input.snapshot.runner_stop_reason,
            coverage,
            artifacts: input.artifacts,
            untested_scope_sha256: input.untested_scope_sha256,
            metadata: input.metadata,
            generated_at_epoch_seconds: input.generated_at_epoch_seconds,
            manifest_sha256: String::new(),
        };
        let body_sha256 = manifest.calculate_sha256()?;
        manifest.closure_id = format!("closure-{}", &body_sha256[..24]);
        manifest.manifest_sha256 = manifest.calculate_sha256()?;
        manifest.verify(plan)?;
        Ok(manifest)
    }

    pub fn verify(&self, plan: &UnifiedOperatorPlan) -> Result<(), RunClosureError> {
        if self.version != RUN_CLOSURE_VERSION
            || self.operator_id != plan.operator_id
            || self.plan_sha256 != plan.plan_sha256
            || self.binding_sha256 != plan.binding_sha256
            || self.policy_snapshot_sha256 != plan.binding.policy_sha256
            || self.generated_at_epoch_seconds <= 0
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        validate_identifier(&self.closure_id)?;
        validate_sha256(&self.manifest_sha256)?;
        self.coverage.validate()?;
        self.artifacts.validate()?;
        validate_untrusted_metadata(&self.metadata)?;
        for digest in &self.untested_scope_sha256 {
            validate_sha256(digest)?;
        }
        if self.manifest_sha256 != self.calculate_sha256()? {
            return Err(RunClosureError::ManifestDigestMismatch);
        }
        match self.disposition {
            ClosureDisposition::Complete
                if self.coverage.pending_targets == 0 && self.untested_scope_sha256.is_empty() => {}
            ClosureDisposition::Partial | ClosureDisposition::Aborted
                if !self.untested_scope_sha256.is_empty() => {}
            _ => return Err(RunClosureError::DispositionMismatch),
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, RunClosureError> {
        self.verify_shape_only()?;
        serde_json::to_vec(self).map_err(|error| RunClosureError::Serialization(error.to_string()))
    }

    fn verify_shape_only(&self) -> Result<(), RunClosureError> {
        validate_identifier(&self.closure_id)?;
        validate_sha256(&self.manifest_sha256)?;
        self.coverage.validate()?;
        self.artifacts.validate()?;
        validate_untrusted_metadata(&self.metadata)?;
        Ok(())
    }

    fn calculate_sha256(&self) -> Result<String, RunClosureError> {
        let mut material = self.clone();
        material.manifest_sha256.clear();
        hash_serializable(&material)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunClosureCertificate {
    pub manifest: RunClosureManifest,
    pub signature_hex: String,
}

impl RunClosureCertificate {
    pub fn verify(
        &self,
        plan: &UnifiedOperatorPlan,
        public_key: &[u8],
    ) -> Result<(), RunClosureError> {
        self.manifest.verify(plan)?;
        if public_key.len() != 32
            || lower_hex(&Sha256::digest(public_key)) != plan.activation_key_id_sha256
        {
            return Err(RunClosureError::PublicKeyMismatch);
        }
        let signature = decode_hex(&self.signature_hex)?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&self.manifest.signing_bytes()?, &signature)
            .map_err(|_| RunClosureError::InvalidSignature)
    }
}

fn validate_untrusted_metadata(values: &BTreeMap<String, String>) -> Result<(), RunClosureError> {
    if values.len() > MAX_CLOSURE_METADATA {
        return Err(RunClosureError::MetadataLimit);
    }
    for (key, value) in values {
        validate_identifier(key)?;
        if value.is_empty()
            || value.len() > 512
            || value.bytes().any(|byte| byte == 0)
            || contains_secret_like_text(value)
        {
            return Err(RunClosureError::UnsafeMetadata);
        }
    }
    Ok(())
}

fn contains_secret_like_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization:",
        "proxy-authorization:",
        "cookie:",
        "set-cookie:",
        "bearer ",
        "password=",
        "token=",
        "secret=",
        "private_key",
        "http://",
        "https://",
        "file://",
        "ssh://",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn validate_identifier(value: &str) -> Result<(), RunClosureError> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(RunClosureError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), RunClosureError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RunClosureError::InvalidSha256);
    }
    Ok(())
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, RunClosureError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| RunClosureError::Serialization(error.to_string()))?;
    Ok(lower_hex(&Sha256::digest(bytes)))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, RunClosureError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(RunClosureError::InvalidSignature);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = decode_nibble(chunk[0])?;
            let low = decode_nibble(chunk[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(value: u8) -> Result<u8, RunClosureError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(RunClosureError::InvalidSignature),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Error)]
pub enum RunClosureError {
    #[error("closure component binding mismatch")]
    ComponentMismatch,
    #[error("closure requires terminal runner and runtime states")]
    NonTerminalState,
    #[error("runner and runtime terminal states do not match")]
    TerminalStateMismatch,
    #[error("runner stop reason is missing")]
    MissingStopReason,
    #[error("closure coverage summary is invalid")]
    InvalidCoverage,
    #[error("closure disposition does not match coverage")]
    DispositionMismatch,
    #[error("partial or aborted closure must identify untested scope")]
    MissingUntestedScope,
    #[error("untested scope limit exceeded")]
    UntestedScopeLimit,
    #[error("closure artifact limit exceeded")]
    ArtifactLimit,
    #[error("closure metadata limit exceeded")]
    MetadataLimit,
    #[error("closure metadata contains unsafe content")]
    UnsafeMetadata,
    #[error("closure identifier is invalid")]
    InvalidIdentifier,
    #[error("closure SHA-256 field is invalid")]
    InvalidSha256,
    #[error("closure manifest digest mismatch")]
    ManifestDigestMismatch,
    #[error("closure public key does not match the signed plan")]
    PublicKeyMismatch,
    #[error("closure signature is invalid")]
    InvalidSignature,
    #[error("closure serialization failed: {0}")]
    Serialization(String),
    #[error(transparent)]
    Unified(#[from] nxb_unified_operator::UnifiedOperatorError),
    #[error(transparent)]
    Runner(#[from] nxb_resumable_runner::RunnerError),
    #[error(transparent)]
    Knowledge(#[from] nxb_knowledge_reporting::KnowledgeError),
}
