#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use nxb_knowledge_reporting::ExportManifest;
use nxb_live_run_host::{LiveRunLaunchBundle, LiveRunTeardownOutcome};
use nxb_operator_runtime::RuntimeRecovery;
use nxb_operator_state::{OperatorRunStatus, OPERATOR_CHECKPOINT_VERSION};
use nxb_resumable_runner::{
    RunnerCheckpoint, RunnerManifest, RunnerStatus, RunnerStopReason, RESUMABLE_RUNNER_VERSION,
};
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
    fn from_snapshot(plan: &UnifiedOperatorPlan, snapshot: &TerminalRunSnapshot) -> Self {
        Self {
            maximum_requests: plan.binding.maximum_requests,
            completed_requests: snapshot.completed_requests,
            visited_targets: snapshot.visited_targets,
            pending_targets: snapshot.pending_targets,
            rejected_candidates: snapshot.rejected_candidates,
            recovery_gap_count: snapshot.recovery_gap_count,
            maximum_depth_observed: snapshot.maximum_depth_observed,
            total_response_bytes: snapshot.total_response_bytes,
            evidence_bytes: snapshot.evidence_bytes,
            request_budget_basis_points: snapshot
                .completed_requests
                .saturating_mul(10_000)
                .checked_div(plan.binding.maximum_requests)
                .unwrap_or(0) as u16,
        }
    }

    fn validate(&self) -> Result<(), RunClosureError> {
        if self.maximum_requests == 0
            || self.completed_requests > self.maximum_requests
            || self.completed_requests > self.visited_targets
            || self.pending_targets > self.visited_targets
            || self.recovery_gap_count > self.completed_requests
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
    pub external_teardown_evidence_sha256: String,
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
            &self.external_teardown_evidence_sha256,
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
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum ExternalTeardownEvidence {
    Completed { receipt_sha256: String },
    Failed { failure_sha256: String },
}

impl ExternalTeardownEvidence {
    fn validate(&self) -> Result<(), RunClosureError> {
        validate_sha256(self.digest())
    }

    fn digest(&self) -> &str {
        match self {
            Self::Completed { receipt_sha256 } => receipt_sha256,
            Self::Failed { failure_sha256 } => failure_sha256,
        }
    }

    fn succeeded(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TerminalRunSnapshot {
    pub live_run_bundle_sha256: String,
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
    pub external_teardown: ExternalTeardownEvidence,
}

impl TerminalRunSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn from_components(
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
        runner_checkpoint: &RunnerCheckpoint,
        runtime: &RuntimeRecovery,
        launch_bundle: &LiveRunLaunchBundle,
        teardown: &LiveRunTeardownOutcome,
    ) -> Result<Self, RunClosureError> {
        plan.validate()?;
        runner_manifest.validate_binding(plan)?;
        launch_bundle.validate()?;
        if launch_bundle.bundle_sha256 != launch_bundle.calculate_sha256()?
            || launch_bundle.unified_plan_sha256 != plan.plan_sha256
            || launch_bundle.unified_binding_sha256 != plan.binding_sha256
            || launch_bundle.runner_manifest_sha256 != runner_manifest.manifest_sha256
            || launch_bundle.policy_snapshot_sha256 != plan.binding.policy_sha256
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        if runner_checkpoint.version != RESUMABLE_RUNNER_VERSION
            || runner_checkpoint.manifest_sha256 != runner_manifest.manifest_sha256
            || runner_checkpoint.completed_requests != runtime.committed_requests
            || runner_checkpoint.completed_requests
                != runtime.state.latest.counters.requests_completed
            || runtime.unresolved_request.is_some()
            || runtime.continuation_allowed
            || runtime.state.continuation_allowed
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        let mut runner_material = runner_checkpoint.clone();
        runner_material.checkpoint_sha256.clear();
        if runner_checkpoint.checkpoint_sha256 != hash_serializable(&runner_material)? {
            return Err(RunClosureError::ComponentDigestMismatch);
        }
        let runtime_checkpoint = &runtime.state.latest;
        if runtime_checkpoint.version != OPERATOR_CHECKPOINT_VERSION
            || runtime_checkpoint.identity.operator_id != plan.operator_id
            || runtime_checkpoint.identity.plan_sha256 != plan.plan_sha256
            || runtime_checkpoint.identity.binding_sha256 != plan.binding_sha256
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        let mut runtime_material = runtime_checkpoint.clone();
        runtime_material.checkpoint_sha256.clear();
        if runtime_checkpoint.checkpoint_sha256 != hash_serializable(&runtime_material)? {
            return Err(RunClosureError::ComponentDigestMismatch);
        }
        let reason = runner_checkpoint
            .stop_reason
            .ok_or(RunClosureError::MissingStopReason)?;
        let external_teardown = match teardown {
            LiveRunTeardownOutcome::Completed {
                external_teardown_receipt_sha256,
                runtime_checkpoint_sha256,
                runner_checkpoint_sha256,
            } => {
                validate_sha256(external_teardown_receipt_sha256)?;
                if runtime_checkpoint_sha256 != &runtime_checkpoint.checkpoint_sha256
                    || runner_checkpoint_sha256 != &runner_checkpoint.checkpoint_sha256
                    || runner_checkpoint.status != RunnerStatus::Completed
                    || runtime_checkpoint.status != OperatorRunStatus::Completed
                    || reason != RunnerStopReason::RuntimeCompleted
                {
                    return Err(RunClosureError::TeardownOutcomeMismatch);
                }
                ExternalTeardownEvidence::Completed {
                    receipt_sha256: external_teardown_receipt_sha256.clone(),
                }
            }
            LiveRunTeardownOutcome::Aborted {
                reason: failure,
                runtime_checkpoint_sha256,
                runner_checkpoint_sha256,
            } => {
                if failure.is_empty()
                    || failure.len() > 2_048
                    || runtime_checkpoint_sha256 != &runtime_checkpoint.checkpoint_sha256
                    || runner_checkpoint_sha256 != &runner_checkpoint.checkpoint_sha256
                    || runner_checkpoint.status != RunnerStatus::Aborted
                    || runtime_checkpoint.status != OperatorRunStatus::Aborted
                    || reason != RunnerStopReason::RuntimeAborted
                {
                    return Err(RunClosureError::TeardownOutcomeMismatch);
                }
                ExternalTeardownEvidence::Failed {
                    failure_sha256: lower_hex(&Sha256::digest(failure.as_bytes())),
                }
            }
        };
        let snapshot = Self {
            live_run_bundle_sha256: launch_bundle.bundle_sha256.clone(),
            runner_manifest_sha256: runner_manifest.manifest_sha256.clone(),
            runner_checkpoint_sha256: runner_checkpoint.checkpoint_sha256.clone(),
            runner_status: runner_checkpoint.status,
            runner_stop_reason: ClosureReason::from_runner(reason),
            completed_requests: runner_checkpoint.completed_requests,
            visited_targets: runner_checkpoint.visited_target_sha256.len() as u64,
            pending_targets: runner_checkpoint.pending_queue.len() as u64,
            rejected_candidates: runner_checkpoint.rejected_candidates,
            recovery_gap_count: runner_checkpoint.recovery_gap_count,
            runtime_checkpoint_sha256: runtime_checkpoint.checkpoint_sha256.clone(),
            runtime_status: runtime_checkpoint.status,
            maximum_depth_observed: runtime_checkpoint.counters.maximum_depth_observed,
            total_response_bytes: runtime_checkpoint.counters.total_response_bytes,
            evidence_bytes: runtime_checkpoint.counters.evidence_bytes,
            external_teardown,
        };
        snapshot.validate_binding(plan, runner_manifest, launch_bundle)?;
        Ok(snapshot)
    }

    fn validate_shape(&self, plan: &UnifiedOperatorPlan) -> Result<(), RunClosureError> {
        for value in [
            &self.live_run_bundle_sha256,
            &self.runner_manifest_sha256,
            &self.runner_checkpoint_sha256,
            &self.runtime_checkpoint_sha256,
        ] {
            validate_sha256(value)?;
        }
        self.external_teardown.validate()?;
        if self.completed_requests > plan.binding.maximum_requests
            || self.completed_requests > self.visited_targets
            || self.pending_targets > self.visited_targets
            || self.recovery_gap_count > self.completed_requests
            || self.maximum_depth_observed > plan.binding.maximum_depth
            || self.total_response_bytes > plan.binding.maximum_total_response_bytes
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        match (
            self.runner_status,
            self.runtime_status,
            self.runner_stop_reason,
            self.external_teardown.succeeded(),
        ) {
            (
                RunnerStatus::Completed,
                OperatorRunStatus::Completed,
                ClosureReason::RuntimeCompleted,
                true,
            )
            | (
                RunnerStatus::Aborted,
                OperatorRunStatus::Aborted,
                ClosureReason::RuntimeAborted,
                false,
            ) => {}
            _ => return Err(RunClosureError::TerminalStateMismatch),
        }
        Ok(())
    }

    fn validate_binding(
        &self,
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
        launch_bundle: &LiveRunLaunchBundle,
    ) -> Result<(), RunClosureError> {
        self.validate_shape(plan)?;
        if self.runner_manifest_sha256 != runner_manifest.manifest_sha256
            || self.live_run_bundle_sha256 != launch_bundle.bundle_sha256
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunClosureInput {
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
    pub terminal: TerminalRunSnapshot,
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
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
        runner_checkpoint: &RunnerCheckpoint,
        runtime: &RuntimeRecovery,
        launch_bundle: &LiveRunLaunchBundle,
        teardown: &LiveRunTeardownOutcome,
        export_manifest: &ExportManifest,
        input: RunClosureInput,
    ) -> Result<Self, RunClosureError> {
        plan.validate()?;
        runner_manifest.validate_binding(plan)?;
        export_manifest.verify()?;
        let terminal = TerminalRunSnapshot::from_components(
            plan,
            runner_manifest,
            runner_checkpoint,
            runtime,
            launch_bundle,
            teardown,
        )?;
        input.artifacts.validate()?;
        if input.artifacts.evidence_export_root_sha256 != export_manifest.root_sha256
            || input.artifacts.runner_checkpoint_sha256 != terminal.runner_checkpoint_sha256
            || input.artifacts.runtime_checkpoint_sha256 != terminal.runtime_checkpoint_sha256
            || input.artifacts.external_teardown_evidence_sha256
                != terminal.external_teardown.digest()
            || export_manifest.policy_snapshot_sha256 != plan.binding.policy_sha256
            || input.generated_at_epoch_seconds < runner_manifest.created_at_epoch_seconds
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        validate_untrusted_metadata(&input.metadata)?;
        Self::validate_untested_scope(&input.untested_scope_sha256)?;
        let disposition = Self::expected_disposition(&terminal, &input.untested_scope_sha256)?;
        let coverage = RunCoverageSummary::from_snapshot(plan, &terminal);
        coverage.validate()?;
        let mut manifest = Self {
            version: RUN_CLOSURE_VERSION,
            closure_id: String::new(),
            operator_id: plan.operator_id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            binding_sha256: plan.binding_sha256.clone(),
            policy_snapshot_sha256: plan.binding.policy_sha256.clone(),
            terminal: terminal.clone(),
            disposition,
            reason: terminal.runner_stop_reason,
            coverage,
            artifacts: input.artifacts,
            untested_scope_sha256: input.untested_scope_sha256,
            metadata: input.metadata,
            generated_at_epoch_seconds: input.generated_at_epoch_seconds,
            manifest_sha256: String::new(),
        };
        manifest.closure_id = manifest.calculate_closure_id()?;
        manifest.manifest_sha256 = manifest.calculate_sha256()?;
        manifest.verify(plan)?;
        Ok(manifest)
    }

    pub fn verify(&self, plan: &UnifiedOperatorPlan) -> Result<(), RunClosureError> {
        plan.validate()?;
        if self.version != RUN_CLOSURE_VERSION
            || self.operator_id != plan.operator_id
            || self.plan_sha256 != plan.plan_sha256
            || self.binding_sha256 != plan.binding_sha256
            || self.policy_snapshot_sha256 != plan.binding.policy_sha256
            || self.generated_at_epoch_seconds <= 0
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        self.terminal.validate_shape(plan)?;
        validate_identifier(&self.closure_id)?;
        validate_sha256(&self.manifest_sha256)?;
        self.coverage.validate()?;
        self.artifacts.validate()?;
        validate_untrusted_metadata(&self.metadata)?;
        Self::validate_untested_scope(&self.untested_scope_sha256)?;
        if self.artifacts.runner_checkpoint_sha256 != self.terminal.runner_checkpoint_sha256
            || self.artifacts.runtime_checkpoint_sha256 != self.terminal.runtime_checkpoint_sha256
            || self.artifacts.external_teardown_evidence_sha256
                != self.terminal.external_teardown.digest()
            || self.reason != self.terminal.runner_stop_reason
            || self.coverage != RunCoverageSummary::from_snapshot(plan, &self.terminal)
        {
            return Err(RunClosureError::ComponentMismatch);
        }
        let expected_disposition =
            Self::expected_disposition(&self.terminal, &self.untested_scope_sha256)?;
        if self.disposition != expected_disposition {
            return Err(RunClosureError::DispositionMismatch);
        }
        if self.closure_id != self.calculate_closure_id()? {
            return Err(RunClosureError::ClosureIdMismatch);
        }
        if self.manifest_sha256 != self.calculate_sha256()? {
            return Err(RunClosureError::ManifestDigestMismatch);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_components(
        &self,
        plan: &UnifiedOperatorPlan,
        runner_manifest: &RunnerManifest,
        runner_checkpoint: &RunnerCheckpoint,
        runtime: &RuntimeRecovery,
        launch_bundle: &LiveRunLaunchBundle,
        teardown: &LiveRunTeardownOutcome,
        export_manifest: &ExportManifest,
    ) -> Result<(), RunClosureError> {
        self.verify(plan)?;
        runner_manifest.validate_binding(plan)?;
        export_manifest.verify()?;
        let terminal = TerminalRunSnapshot::from_components(
            plan,
            runner_manifest,
            runner_checkpoint,
            runtime,
            launch_bundle,
            teardown,
        )?;
        if terminal != self.terminal
            || export_manifest.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || export_manifest.root_sha256 != self.artifacts.evidence_export_root_sha256
        {
            return Err(RunClosureError::ComponentMismatch);
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
        for value in [
            &self.terminal.live_run_bundle_sha256,
            &self.terminal.runner_manifest_sha256,
            &self.terminal.runner_checkpoint_sha256,
            &self.terminal.runtime_checkpoint_sha256,
        ] {
            validate_sha256(value)?;
        }
        self.coverage.validate()?;
        self.artifacts.validate()?;
        validate_untrusted_metadata(&self.metadata)?;
        Self::validate_untested_scope(&self.untested_scope_sha256)?;
        if self.closure_id != self.calculate_closure_id()? {
            return Err(RunClosureError::ClosureIdMismatch);
        }
        if self.manifest_sha256 != self.calculate_sha256()? {
            return Err(RunClosureError::ManifestDigestMismatch);
        }
        Ok(())
    }

    fn expected_disposition(
        terminal: &TerminalRunSnapshot,
        untested_scope_sha256: &BTreeSet<String>,
    ) -> Result<ClosureDisposition, RunClosureError> {
        match terminal.runner_status {
            RunnerStatus::Completed
                if terminal.pending_targets == 0 && untested_scope_sha256.is_empty() =>
            {
                Ok(ClosureDisposition::Complete)
            }
            RunnerStatus::Completed if !untested_scope_sha256.is_empty() => {
                Ok(ClosureDisposition::Partial)
            }
            RunnerStatus::Aborted if !untested_scope_sha256.is_empty() => {
                Ok(ClosureDisposition::Aborted)
            }
            RunnerStatus::Completed | RunnerStatus::Aborted => {
                Err(RunClosureError::MissingUntestedScope)
            }
            _ => Err(RunClosureError::NonTerminalState),
        }
    }

    fn validate_untested_scope(values: &BTreeSet<String>) -> Result<(), RunClosureError> {
        if values.len() > MAX_UNTESTED_SCOPE_ENTRIES {
            return Err(RunClosureError::UntestedScopeLimit);
        }
        for digest in values {
            validate_sha256(digest)?;
        }
        Ok(())
    }

    fn calculate_closure_id(&self) -> Result<String, RunClosureError> {
        let mut material = self.clone();
        material.closure_id.clear();
        material.manifest_sha256.clear();
        let digest = hash_serializable(&material)?;
        Ok(format!("closure-{}", &digest[..24]))
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
    #[error("closure identifier does not match canonical manifest content")]
    ClosureIdMismatch,
    #[error("terminal component checkpoint digest mismatch")]
    ComponentDigestMismatch,
    #[error("NXB-145 teardown outcome does not match terminal components")]
    TeardownOutcomeMismatch,
    #[error("closure public key does not match the signed plan")]
    PublicKeyMismatch,
    #[error("closure signature is invalid")]
    InvalidSignature,
    #[error("closure serialization failed: {0}")]
    Serialization(String),
    #[error(transparent)]
    Unified(#[from] nxb_unified_operator::UnifiedOperatorError),
    #[error(transparent)]
    LiveHost(#[from] nxb_live_run_host::LiveRunHostError),
    #[error(transparent)]
    Runner(#[from] nxb_resumable_runner::RunnerError),
    #[error(transparent)]
    Knowledge(#[from] nxb_knowledge_reporting::KnowledgeError),
}
