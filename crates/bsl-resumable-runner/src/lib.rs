#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions, TryLockError},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use bsl_executor::ExecutionControl;
use bsl_live_adapter::{
    LiveAuthenticatedResult, LivePassivePipeline, LivePassiveRequest, LiveSessionInjection,
    PassiveMethod,
};
use bsl_operator::{discover_response, OperatorConfig};
use bsl_operator_runtime::{
    CheckpointBoundRuntime, RuntimeClock, RuntimeCommittedRequest, RuntimeError,
    RuntimeExecutionReceipt, RuntimeMethod, RuntimeRecovery, RuntimeRequestSpec,
};
use bsl_operator_state::{OperatorRunStatus, RecoveredOperatorState};
use bsl_policy::CompiledPolicy;
use bsl_session::SessionBroker;
use bsl_session_injection::BoundSessionInjection;
use bsl_stream::StreamControl;
use bsl_transport::ConnectionAttempt;
use bsl_unified_operator::UnifiedOperatorPlan;
use bsl_vault::InMemorySecretVault;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub const RESUMABLE_RUNNER_VERSION: u32 = 1;
pub const MAX_RUNNER_QUEUE_ENTRIES: usize = 512;
pub const MAX_RUNNER_CHECKPOINT_BYTES: u64 = 4 * 1024 * 1024;
pub const RUNNER_TERMINAL_RESERVATION_BYTES: u64 = 64 * 1024;
const RUNNER_MANIFEST_FILE: &str = "runner-manifest.json";
const RUNNER_LOCK_FILE: &str = ".bsl-resumable-runner.lock";
const EMERGENCY_STOP_FILE: &str = "EMERGENCY_STOP";
const CHECKPOINT_PREFIX: &str = "runner-checkpoint-";
const CHECKPOINT_SUFFIX: &str = ".json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerCandidate {
    pub method: RuntimeMethod,
    pub target: String,
    pub depth: u16,
    pub parent_target_sha256: String,
}

impl RunnerCandidate {
    pub fn seed(method: RuntimeMethod, target: impl Into<String>, depth: u16) -> Self {
        Self {
            method,
            target: target.into(),
            depth,
            parent_target_sha256: zero_sha256(),
        }
    }

    pub fn child(
        method: RuntimeMethod,
        target: impl Into<String>,
        depth: u16,
        parent_target_sha256: impl Into<String>,
    ) -> Self {
        Self {
            method,
            target: target.into(),
            depth,
            parent_target_sha256: parent_target_sha256.into(),
        }
    }

    pub fn target_sha256(&self) -> String {
        hash_bytes(self.target.as_bytes())
    }

    pub fn validate(&self, plan: &UnifiedOperatorPlan) -> Result<(), RunnerError> {
        RuntimeRequestSpec {
            method: self.method,
            target: self.target.clone(),
            depth: self.depth,
        }
        .validate(plan)?;
        validate_sha256(&self.parent_target_sha256)?;
        Ok(())
    }

    fn validate_plan_scope(&self, manifest: &RunnerManifest) -> Result<(), RunnerError> {
        if self.depth > manifest.maximum_depth
            || !self.target.starts_with('/')
            || self.target.contains('?')
            || self.target.contains('#')
            || self.target.contains('%')
            || self.target.contains('\\')
        {
            return Err(RunnerError::InvalidCheckpointQueue);
        }
        Ok(())
    }

    fn sort_key(&self) -> (u16, &str, &str) {
        (self.depth, self.target.as_str(), self.method.code())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerManifest {
    pub version: u32,
    pub plan_sha256: String,
    pub binding_sha256: String,
    pub discovery_plan_sha256: String,
    pub authority: String,
    pub seed: RunnerCandidate,
    pub maximum_requests: u64,
    pub maximum_depth: u16,
    pub maximum_response_body_bytes: u64,
    pub maximum_queue_entries: u64,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub manifest_sha256: String,
}

impl RunnerManifest {
    pub fn build(
        plan: &UnifiedOperatorPlan,
        seed: RunnerCandidate,
        maximum_queue_entries: u64,
        now_epoch_seconds: i64,
    ) -> Result<Self, RunnerError> {
        plan.verify(now_epoch_seconds)?;
        let mut manifest = Self {
            version: RESUMABLE_RUNNER_VERSION,
            plan_sha256: plan.plan_sha256.clone(),
            binding_sha256: plan.binding_sha256.clone(),
            discovery_plan_sha256: plan.binding.discovery_plan_sha256.clone(),
            authority: plan.binding.authority.clone(),
            seed,
            maximum_requests: plan.binding.maximum_requests,
            maximum_depth: plan.binding.maximum_depth,
            maximum_response_body_bytes: plan.binding.maximum_response_body_bytes,
            maximum_queue_entries,
            created_at_epoch_seconds: now_epoch_seconds,
            expires_at_epoch_seconds: plan.expires_at_epoch_seconds,
            manifest_sha256: String::new(),
        };
        manifest.validate(plan, now_epoch_seconds)?;
        manifest.manifest_sha256 = manifest.calculate_sha256()?;
        Ok(manifest)
    }

    pub fn validate(
        &self,
        plan: &UnifiedOperatorPlan,
        now_epoch_seconds: i64,
    ) -> Result<(), RunnerError> {
        self.validate_binding(plan)?;
        if now_epoch_seconds < self.created_at_epoch_seconds
            || now_epoch_seconds > self.expires_at_epoch_seconds
        {
            return Err(RunnerError::InvalidManifestWindow);
        }
        plan.verify(now_epoch_seconds)?;
        Ok(())
    }

    pub fn validate_binding(&self, plan: &UnifiedOperatorPlan) -> Result<(), RunnerError> {
        if self.version != RESUMABLE_RUNNER_VERSION
            || self.created_at_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.created_at_epoch_seconds
            || self.expires_at_epoch_seconds > plan.expires_at_epoch_seconds
        {
            return Err(RunnerError::InvalidManifestWindow);
        }
        plan.validate()?;
        for value in [
            &self.plan_sha256,
            &self.binding_sha256,
            &self.discovery_plan_sha256,
        ] {
            validate_sha256(value)?;
        }
        if !self.manifest_sha256.is_empty() {
            validate_sha256(&self.manifest_sha256)?;
        }
        if self.plan_sha256 != plan.plan_sha256
            || self.binding_sha256 != plan.binding_sha256
            || self.discovery_plan_sha256 != plan.binding.discovery_plan_sha256
            || self.authority != plan.binding.authority
            || self.maximum_requests != plan.binding.maximum_requests
            || self.maximum_depth != plan.binding.maximum_depth
            || self.maximum_response_body_bytes != plan.binding.maximum_response_body_bytes
        {
            return Err(RunnerError::ManifestBindingMismatch);
        }
        if self.maximum_queue_entries == 0
            || self.maximum_queue_entries as usize > MAX_RUNNER_QUEUE_ENTRIES
            || self.maximum_queue_entries < self.maximum_requests
        {
            return Err(RunnerError::InvalidQueueBudget);
        }
        self.seed.validate_plan_scope(self)?;
        self.seed.validate(plan)?;
        if self.seed.depth != 0 || self.seed.parent_target_sha256 != zero_sha256() {
            return Err(RunnerError::InvalidSeed);
        }
        if !self.manifest_sha256.is_empty() && self.manifest_sha256 != self.calculate_sha256()? {
            return Err(RunnerError::ManifestDigestMismatch);
        }
        Ok(())
    }

    pub fn calculate_sha256(&self) -> Result<String, RunnerError> {
        let mut material = self.clone();
        material.manifest_sha256.clear();
        hash_serializable(&material)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunnerStatus {
    Running,
    TeardownPending,
    Completed,
    Aborted,
}

impl RunnerStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunnerStopReason {
    QueueExhausted,
    RequestBudgetExhausted,
    EmergencyStop,
    RuntimeContinuationDenied,
    RuntimeCompleted,
    RuntimeAborted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerCheckpoint {
    pub version: u32,
    pub sequence: u64,
    pub previous_checkpoint_sha256: String,
    pub manifest_sha256: String,
    pub completed_requests: u64,
    pub pending_queue: Vec<RunnerCandidate>,
    pub visited_target_sha256: BTreeSet<String>,
    pub rejected_candidates: u64,
    pub recovery_gap_count: u64,
    pub last_runtime_request: Option<RuntimeCommittedRequest>,
    pub status: RunnerStatus,
    pub stop_reason: Option<RunnerStopReason>,
    pub created_at_epoch_seconds: i64,
    pub checkpoint_sha256: String,
}

impl RunnerCheckpoint {
    fn initial(manifest: &RunnerManifest, now_epoch_seconds: i64) -> Result<Self, RunnerError> {
        let mut checkpoint = Self {
            version: RESUMABLE_RUNNER_VERSION,
            sequence: 0,
            previous_checkpoint_sha256: zero_sha256(),
            manifest_sha256: manifest.manifest_sha256.clone(),
            completed_requests: 0,
            pending_queue: vec![manifest.seed.clone()],
            visited_target_sha256: BTreeSet::from([manifest.seed.target_sha256()]),
            rejected_candidates: 0,
            recovery_gap_count: 0,
            last_runtime_request: None,
            status: RunnerStatus::Running,
            stop_reason: None,
            created_at_epoch_seconds: now_epoch_seconds,
            checkpoint_sha256: String::new(),
        };
        checkpoint.checkpoint_sha256 = checkpoint.calculate_sha256()?;
        Ok(checkpoint)
    }

    fn calculate_sha256(&self) -> Result<String, RunnerError> {
        let mut material = self.clone();
        material.checkpoint_sha256.clear();
        hash_serializable(&material)
    }

    fn verify(
        &self,
        previous: Option<&RunnerCheckpoint>,
        manifest: &RunnerManifest,
        plan: &UnifiedOperatorPlan,
    ) -> Result<(), RunnerError> {
        if self.version != RESUMABLE_RUNNER_VERSION
            || self.manifest_sha256 != manifest.manifest_sha256
            || self.completed_requests > manifest.maximum_requests
            || self.pending_queue.len() > manifest.maximum_queue_entries as usize
            || self.created_at_epoch_seconds <= 0
        {
            return Err(RunnerError::InvalidCheckpoint);
        }
        validate_sha256(&self.previous_checkpoint_sha256)?;
        validate_sha256(&self.checkpoint_sha256)?;
        if self.checkpoint_sha256 != self.calculate_sha256()? {
            return Err(RunnerError::CheckpointDigestMismatch);
        }
        match previous {
            None => {
                if self.sequence != 0
                    || self.previous_checkpoint_sha256 != zero_sha256()
                    || self.completed_requests != 0
                    || self.pending_queue != vec![manifest.seed.clone()]
                    || self.visited_target_sha256 != BTreeSet::from([manifest.seed.target_sha256()])
                    || self.rejected_candidates != 0
                    || self.recovery_gap_count != 0
                    || self.last_runtime_request.is_some()
                    || self.status != RunnerStatus::Running
                    || self.stop_reason.is_some()
                {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
            }
            Some(previous) => {
                if self.sequence != previous.sequence + 1
                    || self.previous_checkpoint_sha256 != previous.checkpoint_sha256
                    || self.completed_requests < previous.completed_requests
                    || self.rejected_candidates < previous.rejected_candidates
                    || self.recovery_gap_count < previous.recovery_gap_count
                    || self.created_at_epoch_seconds < previous.created_at_epoch_seconds
                    || previous.status.is_terminal()
                    || !previous
                        .visited_target_sha256
                        .is_subset(&self.visited_target_sha256)
                {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
                let completed_delta = self.completed_requests - previous.completed_requests;
                if completed_delta > 1 || self.recovery_gap_count - previous.recovery_gap_count > 1
                {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
                match completed_delta {
                    0 => {
                        if !matches!(
                            (previous.status, self.status),
                            (RunnerStatus::Running, RunnerStatus::TeardownPending)
                                | (RunnerStatus::TeardownPending, RunnerStatus::Completed)
                                | (RunnerStatus::TeardownPending, RunnerStatus::Aborted)
                        ) || self.pending_queue != previous.pending_queue
                            || self.visited_target_sha256 != previous.visited_target_sha256
                            || self.rejected_candidates != previous.rejected_candidates
                            || self.recovery_gap_count != previous.recovery_gap_count
                            || self.last_runtime_request != previous.last_runtime_request
                        {
                            return Err(RunnerError::CheckpointChainMismatch);
                        }
                    }
                    1 => {
                        if previous.status != RunnerStatus::Running
                            || !matches!(
                                self.status,
                                RunnerStatus::Running | RunnerStatus::TeardownPending
                            )
                        {
                            return Err(RunnerError::CheckpointChainMismatch);
                        }
                        let committed = self
                            .last_runtime_request
                            .as_ref()
                            .ok_or(RunnerError::CheckpointChainMismatch)?;
                        let expected = previous
                            .pending_queue
                            .first()
                            .ok_or(RunnerError::CheckpointChainMismatch)?;
                        verify_committed_candidate(
                            committed,
                            expected,
                            previous.completed_requests,
                        )?;
                    }
                    _ => return Err(RunnerError::CheckpointChainMismatch),
                }
            }
        }
        for target_sha256 in &self.visited_target_sha256 {
            validate_sha256(target_sha256)?;
        }
        match (self.completed_requests, self.last_runtime_request.as_ref()) {
            (0, None) => {}
            (0, Some(_)) | (_, None) => return Err(RunnerError::CheckpointChainMismatch),
            (completed, Some(committed)) => {
                if committed.request_index.checked_add(1) != Some(completed) {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
                for value in [
                    &committed.request_target_sha256,
                    &committed.execution_receipt_sha256,
                    &committed.checkpoint_sha256,
                ] {
                    validate_sha256(value)?;
                }
                if committed.depth > manifest.maximum_depth
                    || !self
                        .visited_target_sha256
                        .contains(&committed.request_target_sha256)
                {
                    return Err(RunnerError::CheckpointChainMismatch);
                }
            }
        }
        let mut queue_hashes = BTreeSet::new();
        for candidate in &self.pending_queue {
            candidate.validate(plan)?;
            candidate.validate_plan_scope(manifest)?;
            let target_sha256 = candidate.target_sha256();
            if !self.visited_target_sha256.contains(&target_sha256)
                || !queue_hashes.insert(target_sha256)
            {
                return Err(RunnerError::InvalidCheckpointQueue);
            }
        }
        if self.visited_target_sha256.len() > manifest.maximum_queue_entries as usize {
            return Err(RunnerError::InvalidCheckpointQueue);
        }
        if self.status.is_terminal() && self.stop_reason.is_none() {
            return Err(RunnerError::InvalidCheckpoint);
        }
        if self.status == RunnerStatus::Running && self.stop_reason.is_some() {
            return Err(RunnerError::InvalidCheckpoint);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RunnerRecovery {
    pub checkpoint: RunnerCheckpoint,
    pub runtime: RuntimeRecovery,
    pub continuation_allowed: bool,
    pub reconciled_runtime_commit: bool,
}

#[derive(Debug, Clone)]
pub struct RunnerExecutionResult {
    pub receipt: RuntimeExecutionReceipt,
    pub discovered_candidates: Vec<RunnerCandidate>,
}

pub fn discover_authenticated_response(
    manifest: &RunnerManifest,
    policy: &CompiledPolicy,
    config: &OperatorConfig,
    executed: &RunnerCandidate,
    result: &LiveAuthenticatedResult,
) -> Result<Vec<RunnerCandidate>, RunnerError> {
    config.validate()?;
    if !config.passive_only
        || config.follow_redirects
        || config.allow_session_mutation
        || config.maximum_depth > manifest.maximum_depth
        || config.maximum_requests > manifest.maximum_requests
        || config.maximum_endpoints > manifest.maximum_queue_entries
        || config.maximum_body_bytes > manifest.maximum_response_body_bytes
    {
        return Err(RunnerError::DiscoveryConfigurationExceedsPlan);
    }
    if executed.method == RuntimeMethod::Head {
        return Ok(Vec::new());
    }
    let exchange = result
        .live
        .exchange
        .as_ref()
        .ok_or(RunnerError::MissingExecutionObservation)?;
    if exchange.response.body.is_empty() {
        return Ok(Vec::new());
    }
    let base = Url::parse(&format!(
        "https://{}{}",
        manifest.authority, executed.target
    ))
    .map_err(|error| RunnerError::InvalidDiscoveryBase(error.to_string()))?;
    let content_type = exchange
        .response
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| header.value.as_slice());
    let batch = discover_response(
        config,
        policy,
        &base,
        executed.depth,
        content_type,
        &exchange.response.body,
    )?;
    let parent_target_sha256 = executed.target_sha256();
    let mut candidates = Vec::new();
    for candidate in batch.candidates {
        let url = Url::parse(&candidate.canonical_url)
            .map_err(|error| RunnerError::InvalidDiscoveryBase(error.to_string()))?;
        if url.scheme() != "https"
            || url.host_str() != Some(manifest.authority.as_str())
            || url.port_or_known_default() != Some(443)
            || url.query().is_some()
            || url.fragment().is_some()
        {
            continue;
        }
        let method = match candidate.method.as_str() {
            "GET" => RuntimeMethod::Get,
            "HEAD" => RuntimeMethod::Head,
            _ => continue,
        };
        let discovered = RunnerCandidate::child(
            method,
            url.path().to_string(),
            candidate.depth,
            parent_target_sha256.clone(),
        );
        if discovered.validate_plan_scope(manifest).is_ok() {
            candidates.push(discovered);
        }
    }
    candidates.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    candidates.dedup_by(|left, right| {
        left.method == right.method && left.target_sha256() == right.target_sha256()
    });
    Ok(candidates)
}

#[derive(Debug, Clone)]
pub struct RunnerStepReceipt {
    pub executed: RunnerCandidate,
    pub runtime_receipt_sha256: String,
    pub runner_checkpoint_sha256: String,
    pub completed_requests: u64,
    pub pending_requests: u64,
    pub accepted_candidates: u64,
    pub rejected_candidates: u64,
    pub status: RunnerStatus,
    pub stop_reason: Option<RunnerStopReason>,
}

struct RunnerLock {
    file: Option<File>,
}

impl Drop for RunnerLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.unlock();
            drop(file);
        }
    }
}

pub struct ResumableBoundedRunner {
    directory: PathBuf,
    plan: UnifiedOperatorPlan,
    manifest: RunnerManifest,
    latest: RunnerCheckpoint,
    runner_bytes: u64,
    _lock: RunnerLock,
}

impl std::fmt::Debug for ResumableBoundedRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResumableBoundedRunner")
            .field("directory", &self.directory)
            .field("plan_sha256", &self.plan.plan_sha256)
            .field("manifest_sha256", &self.manifest.manifest_sha256)
            .field("checkpoint_sequence", &self.latest.sequence)
            .field("completed_requests", &self.latest.completed_requests)
            .field("pending_requests", &self.latest.pending_queue.len())
            .field("runner_bytes", &self.runner_bytes)
            .field("status", &self.latest.status)
            .finish()
    }
}

pub fn inspect_runner(
    directory: &Path,
    plan: &UnifiedOperatorPlan,
    expected_manifest: &RunnerManifest,
) -> Result<RunnerCheckpoint, RunnerError> {
    expected_manifest.validate_binding(plan)?;
    let manifest: RunnerManifest = read_canonical(&directory.join(RUNNER_MANIFEST_FILE))?;
    manifest.validate_binding(plan)?;
    if &manifest != expected_manifest {
        return Err(RunnerError::ManifestBindingMismatch);
    }
    scan_checkpoints(directory, &manifest, plan)
}

pub fn request_emergency_stop_at(directory: &Path) -> Result<(), RunnerError> {
    fs::create_dir_all(directory).map_err(io_error)?;
    let path = directory.join(EMERGENCY_STOP_FILE);
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => return Err(io_error(error)),
    };
    file.write_all(b"stop\n")
        .and_then(|()| file.sync_all())
        .map_err(io_error)
}

impl ResumableBoundedRunner {
    pub fn initialize(
        directory: impl Into<PathBuf>,
        plan: UnifiedOperatorPlan,
        manifest: RunnerManifest,
        runtime: RuntimeRecovery,
        clock: RuntimeClock,
    ) -> Result<(Self, RunnerRecovery), RunnerError> {
        let clock = clock.validate()?;
        manifest.validate(&plan, clock.epoch_seconds)?;
        if runtime.committed_requests != 0
            || runtime.unresolved_request.is_some()
            || !runtime.continuation_allowed
        {
            return Err(RunnerError::RuntimeStateMismatch);
        }
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(io_error)?;
        for entry in fs::read_dir(&directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if entry.file_name() != RUNNER_LOCK_FILE {
                return Err(RunnerError::DirectoryNotEmpty);
            }
        }
        let lock = acquire_lock(&directory, clock)?;
        publish_canonical(&directory.join(RUNNER_MANIFEST_FILE), &manifest)?;
        let checkpoint = RunnerCheckpoint::initial(&manifest, clock.epoch_seconds)?;
        checkpoint.verify(None, &manifest, &plan)?;
        publish_checkpoint(&directory, &checkpoint)?;
        let runner_bytes = directory_file_bytes(&directory)?;
        ensure_workspace_budget(
            &plan,
            &runtime,
            runner_bytes
                .checked_add(
                    MAX_RUNNER_CHECKPOINT_BYTES
                        .saturating_mul(2)
                        .saturating_add(RUNNER_TERMINAL_RESERVATION_BYTES),
                )
                .ok_or(RunnerError::WorkspaceBudgetExceeded)?,
        )?;
        let recovery = RunnerRecovery {
            checkpoint: checkpoint.clone(),
            runtime,
            continuation_allowed: true,
            reconciled_runtime_commit: false,
        };
        Ok((
            Self {
                directory,
                plan,
                manifest,
                latest: checkpoint,
                runner_bytes,
                _lock: lock,
            },
            recovery,
        ))
    }

    pub fn open(
        directory: impl Into<PathBuf>,
        plan: UnifiedOperatorPlan,
        expected_manifest: RunnerManifest,
        runtime: RuntimeRecovery,
        clock: RuntimeClock,
    ) -> Result<(Self, RunnerRecovery), RunnerError> {
        let clock = clock.validate()?;
        expected_manifest.validate_binding(&plan)?;
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(io_error)?;
        let lock = acquire_lock(&directory, clock)?;
        let manifest: RunnerManifest = read_canonical(&directory.join(RUNNER_MANIFEST_FILE))?;
        manifest.validate_binding(&plan)?;
        if manifest != expected_manifest {
            return Err(RunnerError::ManifestBindingMismatch);
        }
        let mut latest = scan_checkpoints(&directory, &manifest, &plan)?;
        let mut reconciled = false;
        if runtime.committed_requests == latest.completed_requests + 1 {
            let committed = runtime
                .last_committed_request
                .clone()
                .ok_or(RunnerError::RuntimeStateMismatch)?;
            let expected = latest
                .pending_queue
                .first()
                .cloned()
                .ok_or(RunnerError::RuntimeStateMismatch)?;
            verify_committed_candidate(&committed, &expected, latest.completed_requests)?;
            latest = reconcile_runtime_commit(
                &directory,
                &manifest,
                &plan,
                latest,
                committed,
                clock.epoch_seconds,
            )?;
            reconciled = true;
        } else if runtime.committed_requests != latest.completed_requests {
            return Err(RunnerError::RuntimeStateMismatch);
        }
        let runner_bytes = directory_file_bytes(&directory)?;
        ensure_workspace_budget(
            &plan,
            &runtime,
            runner_bytes
                .checked_add(MAX_RUNNER_CHECKPOINT_BYTES)
                .ok_or(RunnerError::WorkspaceBudgetExceeded)?,
        )?;
        let continuation_allowed = runtime.continuation_allowed
            && runtime.unresolved_request.is_none()
            && plan.verify(clock.epoch_seconds).is_ok()
            && latest.status == RunnerStatus::Running;
        let recovery = RunnerRecovery {
            checkpoint: latest.clone(),
            runtime,
            continuation_allowed,
            reconciled_runtime_commit: reconciled,
        };
        Ok((
            Self {
                directory,
                plan,
                manifest,
                latest,
                runner_bytes,
                _lock: lock,
            },
            recovery,
        ))
    }

    pub fn recovery(&self, runtime: RuntimeRecovery) -> Result<RunnerRecovery, RunnerError> {
        if runtime.committed_requests != self.latest.completed_requests {
            return Err(RunnerError::RuntimeStateMismatch);
        }
        Ok(RunnerRecovery {
            continuation_allowed: runtime.continuation_allowed
                && runtime.unresolved_request.is_none()
                && self.latest.status == RunnerStatus::Running,
            checkpoint: self.latest.clone(),
            runtime,
            reconciled_runtime_commit: false,
        })
    }

    pub fn execute_next_with<F>(
        &mut self,
        runtime: &mut CheckpointBoundRuntime,
        clock: RuntimeClock,
        executor: F,
    ) -> Result<Option<RunnerStepReceipt>, RunnerError>
    where
        F: FnOnce(&RuntimeRequestSpec) -> Result<RunnerExecutionResult, RunnerError>,
    {
        let clock = clock.validate()?;
        if self.latest.status != RunnerStatus::Running {
            return Err(RunnerError::ContinuationDenied);
        }
        if self.directory.join(EMERGENCY_STOP_FILE).exists() {
            self.enter_teardown(RunnerStopReason::EmergencyStop, clock.epoch_seconds)?;
            return Ok(None);
        }
        if self.latest.completed_requests >= self.manifest.maximum_requests {
            self.enter_teardown(
                RunnerStopReason::RequestBudgetExhausted,
                clock.epoch_seconds,
            )?;
            return Ok(None);
        }
        let executed = match self.latest.pending_queue.first().cloned() {
            Some(candidate) => candidate,
            None => {
                self.enter_teardown(RunnerStopReason::QueueExhausted, clock.epoch_seconds)?;
                return Ok(None);
            }
        };
        executed.validate(&self.plan)?;
        let spec = RuntimeRequestSpec {
            method: executed.method,
            target: executed.target.clone(),
            depth: executed.depth,
        };
        let external_reserved_bytes = self
            .runner_bytes
            .checked_add(
                MAX_RUNNER_CHECKPOINT_BYTES
                    .saturating_mul(2)
                    .saturating_add(RUNNER_TERMINAL_RESERVATION_BYTES),
            )
            .ok_or(RunnerError::WorkspaceBudgetExceeded)?;
        let mut observed_candidates = None;
        let (receipt, state) = runtime.execute_with_reserved_workspace(
            spec,
            clock,
            external_reserved_bytes,
            |request| {
                let result = executor(request)
                    .map_err(|error| RuntimeError::ExecutionIndeterminate(error.to_string()))?;
                observed_candidates = Some(result.discovered_candidates);
                Ok(result.receipt)
            },
        )?;
        let discovered = observed_candidates.ok_or(RunnerError::MissingExecutionObservation)?;
        self.commit_runtime_step(executed, receipt, state, discovered, clock.epoch_seconds)
            .map(Some)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_next_live_authenticated<F>(
        &mut self,
        runtime: &mut CheckpointBoundRuntime,
        pipeline: &mut LivePassivePipeline,
        attempt: ConnectionAttempt,
        elapsed_since_authorization: Duration,
        execution_control: ExecutionControl,
        stream_control: StreamControl,
        bound: &BoundSessionInjection,
        broker: &mut SessionBroker,
        vault: &mut InMemorySecretVault,
        clock: RuntimeClock,
        observer: F,
    ) -> Result<Option<RunnerStepReceipt>, RunnerError>
    where
        F: FnOnce(
            &RunnerCandidate,
            &LiveAuthenticatedResult,
        ) -> Result<Vec<RunnerCandidate>, RunnerError>,
    {
        if self.latest.status != RunnerStatus::Running
            || self.latest.pending_queue.is_empty()
            || self.latest.completed_requests >= self.manifest.maximum_requests
            || self.directory.join(EMERGENCY_STOP_FILE).exists()
        {
            return self
                .execute_next_with(runtime, clock, |_| Err(RunnerError::ContinuationDenied));
        }
        let candidate = self
            .latest
            .pending_queue
            .first()
            .cloned()
            .ok_or(RunnerError::QueueExhausted)?;
        let request =
            LivePassiveRequest::new(candidate.method.passive(), candidate.target.clone())?;
        let mut observer = Some(observer);
        self.execute_next_with(runtime, clock, |spec| {
            let result = pipeline.execute_authenticated(
                attempt,
                elapsed_since_authorization,
                request,
                execution_control,
                stream_control,
                LiveSessionInjection {
                    bound,
                    broker,
                    vault,
                    now_epoch_seconds: clock.epoch_seconds,
                },
            )?;
            let discovered = observer
                .take()
                .ok_or(RunnerError::MissingExecutionObservation)?(
                &candidate, &result
            )?;
            let receipt = RuntimeExecutionReceipt::from_live(spec, &result, clock.epoch_seconds)?;
            Ok(RunnerExecutionResult {
                receipt,
                discovered_candidates: discovered,
            })
        })
    }

    pub fn request_emergency_stop(&self) -> Result<(), RunnerError> {
        request_emergency_stop_at(&self.directory)
    }

    pub fn begin_teardown(
        &mut self,
        reason: RunnerStopReason,
        clock: RuntimeClock,
    ) -> Result<RunnerCheckpoint, RunnerError> {
        let clock = clock.validate()?;
        self.enter_teardown(reason, clock.epoch_seconds)
    }

    pub fn record_runtime_terminal(
        &mut self,
        runtime: &RuntimeRecovery,
        clock: RuntimeClock,
    ) -> Result<RunnerCheckpoint, RunnerError> {
        let clock = clock.validate()?;
        let (status, reason) = match runtime.state.latest.status {
            OperatorRunStatus::Completed => {
                (RunnerStatus::Completed, RunnerStopReason::RuntimeCompleted)
            }
            OperatorRunStatus::Aborted => (RunnerStatus::Aborted, RunnerStopReason::RuntimeAborted),
            _ => return Err(RunnerError::RuntimeNotTerminal),
        };
        if self.latest.status != RunnerStatus::TeardownPending {
            return Err(RunnerError::TeardownNotStarted);
        }
        if runtime.state.latest.counters.requests_completed != self.latest.completed_requests {
            return Err(RunnerError::RuntimeStateMismatch);
        }
        ensure_workspace_budget(
            &self.plan,
            runtime,
            self.runner_bytes
                .checked_add(MAX_RUNNER_CHECKPOINT_BYTES)
                .ok_or(RunnerError::WorkspaceBudgetExceeded)?,
        )?;
        let checkpoint = self.next_checkpoint(
            self.latest.pending_queue.clone(),
            self.latest.visited_target_sha256.clone(),
            self.latest.completed_requests,
            self.latest.rejected_candidates,
            self.latest.recovery_gap_count,
            self.latest.last_runtime_request.clone(),
            status,
            Some(reason),
            clock.epoch_seconds,
        )?;
        self.publish_and_set(checkpoint)
    }

    pub fn manifest(&self) -> &RunnerManifest {
        &self.manifest
    }

    pub fn latest_checkpoint(&self) -> &RunnerCheckpoint {
        &self.latest
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn commit_runtime_step(
        &mut self,
        executed: RunnerCandidate,
        receipt: RuntimeExecutionReceipt,
        state: RecoveredOperatorState,
        discovered: Vec<RunnerCandidate>,
        now_epoch_seconds: i64,
    ) -> Result<RunnerStepReceipt, RunnerError> {
        receipt.verify()?;
        let expected_completed = self
            .latest
            .completed_requests
            .checked_add(1)
            .ok_or(RunnerError::RequestBudgetExceeded)?;
        if state.latest.counters.requests_completed != expected_completed
            || receipt.request_method != executed.method.code()
            || receipt.request_target_sha256 != executed.target_sha256()
        {
            return Err(RunnerError::RuntimeStateMismatch);
        }
        let mut queue = self.latest.pending_queue.clone();
        if queue.first() != Some(&executed) {
            return Err(RunnerError::CheckpointQueueMismatch);
        }
        queue.remove(0);
        let mut visited = self.latest.visited_target_sha256.clone();
        let mut accepted = Vec::new();
        let mut rejected = 0_u64;
        for candidate in discovered {
            if candidate.depth != executed.depth.saturating_add(1)
                || candidate.parent_target_sha256 != executed.target_sha256()
                || candidate.validate(&self.plan).is_err()
                || candidate.validate_plan_scope(&self.manifest).is_err()
            {
                rejected = rejected.saturating_add(1);
                continue;
            }
            let target_sha256 = candidate.target_sha256();
            if visited.insert(target_sha256) {
                accepted.push(candidate);
            }
        }
        accepted.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        let available = self
            .manifest
            .maximum_queue_entries
            .saturating_sub(queue.len() as u64) as usize;
        if accepted.len() > available {
            rejected = rejected.saturating_add((accepted.len() - available) as u64);
            accepted.truncate(available);
        }
        queue.extend(accepted.iter().cloned());
        let rejected_total = self.latest.rejected_candidates.saturating_add(rejected);
        let runtime_request = RuntimeCommittedRequest {
            request_index: expected_completed - 1,
            method: executed.method,
            request_target_sha256: executed.target_sha256(),
            depth: executed.depth,
            execution_receipt_sha256: receipt.receipt_sha256.clone(),
            checkpoint_sequence: state.latest.sequence,
            checkpoint_sha256: state.latest.checkpoint_sha256.clone(),
        };
        let (status, stop_reason) = if expected_completed >= self.manifest.maximum_requests {
            (
                RunnerStatus::TeardownPending,
                Some(RunnerStopReason::RequestBudgetExhausted),
            )
        } else if queue.is_empty() {
            (
                RunnerStatus::TeardownPending,
                Some(RunnerStopReason::QueueExhausted),
            )
        } else {
            (RunnerStatus::Running, None)
        };
        let checkpoint = self.next_checkpoint(
            queue,
            visited,
            expected_completed,
            rejected_total,
            self.latest.recovery_gap_count,
            Some(runtime_request),
            status,
            stop_reason,
            now_epoch_seconds,
        )?;
        let checkpoint = self.publish_and_set(checkpoint)?;
        Ok(RunnerStepReceipt {
            executed,
            runtime_receipt_sha256: receipt.receipt_sha256,
            runner_checkpoint_sha256: checkpoint.checkpoint_sha256,
            completed_requests: checkpoint.completed_requests,
            pending_requests: checkpoint.pending_queue.len() as u64,
            accepted_candidates: accepted.len() as u64,
            rejected_candidates: rejected,
            status: checkpoint.status,
            stop_reason: checkpoint.stop_reason,
        })
    }

    fn enter_teardown(
        &mut self,
        reason: RunnerStopReason,
        now_epoch_seconds: i64,
    ) -> Result<RunnerCheckpoint, RunnerError> {
        if self.latest.status == RunnerStatus::TeardownPending {
            return Ok(self.latest.clone());
        }
        if self.latest.status.is_terminal() {
            return Err(RunnerError::ContinuationDenied);
        }
        let checkpoint = self.next_checkpoint(
            self.latest.pending_queue.clone(),
            self.latest.visited_target_sha256.clone(),
            self.latest.completed_requests,
            self.latest.rejected_candidates,
            self.latest.recovery_gap_count,
            self.latest.last_runtime_request.clone(),
            RunnerStatus::TeardownPending,
            Some(reason),
            now_epoch_seconds,
        )?;
        self.publish_and_set(checkpoint)
    }

    #[allow(clippy::too_many_arguments)]
    fn next_checkpoint(
        &self,
        pending_queue: Vec<RunnerCandidate>,
        visited_target_sha256: BTreeSet<String>,
        completed_requests: u64,
        rejected_candidates: u64,
        recovery_gap_count: u64,
        last_runtime_request: Option<RuntimeCommittedRequest>,
        status: RunnerStatus,
        stop_reason: Option<RunnerStopReason>,
        now_epoch_seconds: i64,
    ) -> Result<RunnerCheckpoint, RunnerError> {
        let mut checkpoint = RunnerCheckpoint {
            version: RESUMABLE_RUNNER_VERSION,
            sequence: self.latest.sequence + 1,
            previous_checkpoint_sha256: self.latest.checkpoint_sha256.clone(),
            manifest_sha256: self.manifest.manifest_sha256.clone(),
            completed_requests,
            pending_queue,
            visited_target_sha256,
            rejected_candidates,
            recovery_gap_count,
            last_runtime_request,
            status,
            stop_reason,
            created_at_epoch_seconds: now_epoch_seconds,
            checkpoint_sha256: String::new(),
        };
        checkpoint.checkpoint_sha256 = checkpoint.calculate_sha256()?;
        checkpoint.verify(Some(&self.latest), &self.manifest, &self.plan)?;
        Ok(checkpoint)
    }

    fn publish_and_set(
        &mut self,
        checkpoint: RunnerCheckpoint,
    ) -> Result<RunnerCheckpoint, RunnerError> {
        let bytes = canonical_bytes(&checkpoint)?;
        if bytes.len() as u64 > MAX_RUNNER_CHECKPOINT_BYTES {
            return Err(RunnerError::CheckpointTooLarge);
        }
        if self
            .runner_bytes
            .checked_add(bytes.len() as u64)
            .ok_or(RunnerError::WorkspaceBudgetExceeded)?
            > self.plan.maximum_workspace_bytes
        {
            return Err(RunnerError::WorkspaceBudgetExceeded);
        }
        publish_bytes(
            &self
                .directory
                .join(checkpoint_file_name(checkpoint.sequence)),
            &bytes,
        )?;
        self.runner_bytes = directory_file_bytes(&self.directory)?;
        self.latest = checkpoint.clone();
        Ok(checkpoint)
    }
}

fn reconcile_runtime_commit(
    directory: &Path,
    manifest: &RunnerManifest,
    plan: &UnifiedOperatorPlan,
    previous: RunnerCheckpoint,
    committed: RuntimeCommittedRequest,
    now_epoch_seconds: i64,
) -> Result<RunnerCheckpoint, RunnerError> {
    if previous.pending_queue.is_empty() {
        return Err(RunnerError::RuntimeStateMismatch);
    }
    let mut queue = previous.pending_queue.clone();
    queue.remove(0);
    let (status, stop_reason) = if committed.request_index + 1 >= manifest.maximum_requests {
        (
            RunnerStatus::TeardownPending,
            Some(RunnerStopReason::RequestBudgetExhausted),
        )
    } else if queue.is_empty() {
        (
            RunnerStatus::TeardownPending,
            Some(RunnerStopReason::QueueExhausted),
        )
    } else {
        (RunnerStatus::Running, None)
    };
    let mut checkpoint = RunnerCheckpoint {
        version: RESUMABLE_RUNNER_VERSION,
        sequence: previous.sequence + 1,
        previous_checkpoint_sha256: previous.checkpoint_sha256.clone(),
        manifest_sha256: manifest.manifest_sha256.clone(),
        completed_requests: previous.completed_requests + 1,
        pending_queue: queue,
        visited_target_sha256: previous.visited_target_sha256.clone(),
        rejected_candidates: previous.rejected_candidates,
        recovery_gap_count: previous.recovery_gap_count + 1,
        last_runtime_request: Some(committed),
        status,
        stop_reason,
        created_at_epoch_seconds: now_epoch_seconds,
        checkpoint_sha256: String::new(),
    };
    checkpoint.checkpoint_sha256 = checkpoint.calculate_sha256()?;
    checkpoint.verify(Some(&previous), manifest, plan)?;
    publish_checkpoint(directory, &checkpoint)?;
    Ok(checkpoint)
}

fn verify_committed_candidate(
    committed: &RuntimeCommittedRequest,
    candidate: &RunnerCandidate,
    expected_index: u64,
) -> Result<(), RunnerError> {
    if committed.request_index != expected_index
        || committed.method != candidate.method
        || committed.request_target_sha256 != candidate.target_sha256()
        || committed.depth != candidate.depth
    {
        return Err(RunnerError::RuntimeStateMismatch);
    }
    validate_sha256(&committed.execution_receipt_sha256)?;
    validate_sha256(&committed.checkpoint_sha256)?;
    Ok(())
}

fn scan_checkpoints(
    directory: &Path,
    manifest: &RunnerManifest,
    plan: &UnifiedOperatorPlan,
) -> Result<RunnerCheckpoint, RunnerError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if !entry.file_type().map_err(io_error)?.is_file() {
            return Err(RunnerError::UnexpectedEntry);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RunnerError::UnexpectedEntry)?;
        if matches!(
            name.as_str(),
            RUNNER_MANIFEST_FILE | RUNNER_LOCK_FILE | EMERGENCY_STOP_FILE
        ) {
            continue;
        }
        if name.starts_with('.') && name.ends_with(".tmp") {
            return Err(RunnerError::InterruptedPublication);
        }
        let sequence = parse_checkpoint_name(&name)?;
        paths.push((sequence, entry.path()));
    }
    paths.sort_by_key(|(sequence, _)| *sequence);
    if paths.is_empty() {
        return Err(RunnerError::MissingCheckpoint);
    }
    let mut previous = None;
    for (expected, (sequence, path)) in paths.into_iter().enumerate() {
        if sequence != expected as u64 {
            return Err(RunnerError::CheckpointSequenceGap);
        }
        let checkpoint: RunnerCheckpoint = read_canonical(&path)?;
        checkpoint.verify(previous.as_ref(), manifest, plan)?;
        previous = Some(checkpoint);
    }
    previous.ok_or(RunnerError::MissingCheckpoint)
}

fn publish_checkpoint(directory: &Path, checkpoint: &RunnerCheckpoint) -> Result<(), RunnerError> {
    let bytes = canonical_bytes(checkpoint)?;
    if bytes.len() as u64 > MAX_RUNNER_CHECKPOINT_BYTES {
        return Err(RunnerError::CheckpointTooLarge);
    }
    publish_bytes(
        &directory.join(checkpoint_file_name(checkpoint.sequence)),
        &bytes,
    )
}

fn publish_canonical<T: Serialize>(path: &Path, value: &T) -> Result<(), RunnerError> {
    publish_bytes(path, &canonical_bytes(value)?)
}

fn publish_bytes(path: &Path, bytes: &[u8]) -> Result<(), RunnerError> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(RunnerError::UnexpectedEntry)?;
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let publication = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(io_error)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(io_error)?;
        fs::hard_link(&temporary, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                RunnerError::RecordAlreadyExists
            } else {
                io_error(error)
            }
        })?;
        Ok::<(), RunnerError>(())
    })();
    let _ = fs::remove_file(&temporary);
    publication
}

fn acquire_lock(directory: &Path, clock: RuntimeClock) -> Result<RunnerLock, RunnerError> {
    let path = directory.join(RUNNER_LOCK_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(io_error)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(RunnerError::RunnerLocked),
        Err(TryLockError::Error(error)) => return Err(io_error(error)),
    }
    file.set_len(0).map_err(io_error)?;
    let bytes = format!(
        "pid={}\nepoch_seconds={}\n",
        std::process::id(),
        clock.epoch_seconds
    );
    file.write_all(bytes.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(io_error)?;
    Ok(RunnerLock { file: Some(file) })
}

fn checkpoint_file_name(sequence: u64) -> String {
    format!("{CHECKPOINT_PREFIX}{sequence:020}{CHECKPOINT_SUFFIX}")
}

fn parse_checkpoint_name(name: &str) -> Result<u64, RunnerError> {
    let value = name
        .strip_prefix(CHECKPOINT_PREFIX)
        .and_then(|value| value.strip_suffix(CHECKPOINT_SUFFIX))
        .ok_or(RunnerError::UnexpectedEntry)?;
    if value.len() != 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RunnerError::UnexpectedEntry);
    }
    value.parse().map_err(|_| RunnerError::UnexpectedEntry)
}

fn read_canonical<T>(path: &Path) -> Result<T, RunnerError>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = fs::read(path).map_err(io_error)?;
    let value = serde_json::from_slice(&bytes)
        .map_err(|error| RunnerError::Serialization(error.to_string()))?;
    if bytes != canonical_bytes(&value)? {
        return Err(RunnerError::NonCanonicalRecord);
    }
    Ok(value)
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, RunnerError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| RunnerError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, RunnerError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| RunnerError::Serialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn directory_file_bytes(directory: &Path) -> Result<u64, RunnerError> {
    let mut total = 0_u64;
    for entry in fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if !entry.file_type().map_err(io_error)?.is_file() {
            return Err(RunnerError::UnexpectedEntry);
        }
        total = total
            .checked_add(entry.metadata().map_err(io_error)?.len())
            .ok_or(RunnerError::WorkspaceBudgetExceeded)?;
    }
    Ok(total)
}

fn ensure_workspace_budget(
    plan: &UnifiedOperatorPlan,
    runtime: &RuntimeRecovery,
    runner_reserved_bytes: u64,
) -> Result<(), RunnerError> {
    let total = runtime
        .state
        .state_file_bytes
        .checked_add(runtime.journal_bytes)
        .and_then(|value| value.checked_add(runner_reserved_bytes))
        .ok_or(RunnerError::WorkspaceBudgetExceeded)?;
    if total > plan.maximum_workspace_bytes {
        return Err(RunnerError::WorkspaceBudgetExceeded);
    }
    Ok(())
}

fn zero_sha256() -> String {
    "0".repeat(64)
}

fn validate_sha256(value: &str) -> Result<(), RunnerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RunnerError::InvalidSha256);
    }
    Ok(())
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

fn io_error(error: std::io::Error) -> RunnerError {
    RunnerError::Io(error.to_string())
}

trait RuntimeMethodExt {
    fn passive(self) -> PassiveMethod;
}

impl RuntimeMethodExt for RuntimeMethod {
    fn passive(self) -> PassiveMethod {
        match self {
            RuntimeMethod::Get => PassiveMethod::Get,
            RuntimeMethod::Head => PassiveMethod::Head,
        }
    }
}

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("runner manifest validity window is invalid")]
    InvalidManifestWindow,
    #[error("runner manifest does not match the unified operator plan")]
    ManifestBindingMismatch,
    #[error("runner manifest digest mismatch")]
    ManifestDigestMismatch,
    #[error("runner queue budget is invalid")]
    InvalidQueueBudget,
    #[error("runner seed is invalid")]
    InvalidSeed,
    #[error("runner directory must be empty during initialization")]
    DirectoryNotEmpty,
    #[error("runner is locked by another process")]
    RunnerLocked,
    #[error("runner checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("runner checkpoint digest mismatch")]
    CheckpointDigestMismatch,
    #[error("runner checkpoint chain mismatch")]
    CheckpointChainMismatch,
    #[error("runner checkpoint queue is invalid")]
    InvalidCheckpointQueue,
    #[error("runner checkpoint queue does not match the executed request")]
    CheckpointQueueMismatch,
    #[error("runner checkpoint sequence contains a gap")]
    CheckpointSequenceGap,
    #[error("runner checkpoint exceeds its byte bound")]
    CheckpointTooLarge,
    #[error("combined runtime and runner workspace budget exceeded")]
    WorkspaceBudgetExceeded,
    #[error("runner checkpoint is missing")]
    MissingCheckpoint,
    #[error("runner state and runtime state do not match")]
    RuntimeStateMismatch,
    #[error("runner continuation is denied")]
    ContinuationDenied,
    #[error("runner request budget exceeded")]
    RequestBudgetExceeded,
    #[error("runner queue is exhausted")]
    QueueExhausted,
    #[error("runner execution observer did not return an observation")]
    MissingExecutionObservation,
    #[error("passive discovery configuration exceeds the signed runner plan")]
    DiscoveryConfigurationExceedsPlan,
    #[error("passive discovery base URL is invalid: {0}")]
    InvalidDiscoveryBase(String),
    #[error("runner teardown has not started")]
    TeardownNotStarted,
    #[error("runtime is not in a terminal state")]
    RuntimeNotTerminal,
    #[error("runner directory contains an unexpected entry")]
    UnexpectedEntry,
    #[error("runner publication was interrupted")]
    InterruptedPublication,
    #[error("runner record already exists")]
    RecordAlreadyExists,
    #[error("runner record is not canonical")]
    NonCanonicalRecord,
    #[error("invalid SHA-256 value")]
    InvalidSha256,
    #[error("runner serialization failed: {0}")]
    Serialization(String),
    #[error("runner I/O failed: {0}")]
    Io(String),
    #[error(transparent)]
    Operator(#[from] bsl_operator::OperatorError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error(transparent)]
    Unified(#[from] bsl_unified_operator::UnifiedOperatorError),
    #[error(transparent)]
    Live(#[from] bsl_live_adapter::LiveAuthenticatedError),
    #[error(transparent)]
    LiveAdapter(#[from] bsl_live_adapter::LiveAdapterError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsl_operator_runtime::RuntimeExecutionReceipt;
    use bsl_unified_operator::{
        consume_activation_once, UnifiedComponentBinding, UnifiedOperatorActivationCertificate,
        UnifiedOperatorActivationPayload, UnifiedOperatorPlanParameters,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::{
        collections::BTreeSet,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn sha(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[21_u8; 32]).expect("deterministic key")
    }

    fn plan() -> UnifiedOperatorPlan {
        let key_pair = key_pair();
        UnifiedOperatorPlan::build(UnifiedOperatorPlanParameters {
            operator_id: "runner-test".into(),
            binding: UnifiedComponentBinding {
                discovery_plan_sha256: sha('a'),
                policy_sha256: sha('b'),
                target_origin_sha256: sha('c'),
                discovery_session_id: "discovery-runner".into(),
                authority: "example.com".into(),
                run_id: "run-runner".into(),
                worker_id: "worker-runner".into(),
                account_id: "account-runner".into(),
                tenant_id: "tenant-runner".into(),
                role_id: "role-runner".into(),
                session_injection_manifest_sha256: sha('d'),
                external_vault_plan_sha256: sha('e'),
                external_vault_bootstrap_receipt_sha256: sha('f'),
                external_session_id_sha256: sha('1'),
                provider_id: "provider-runner".into(),
                provider_instance_sha256: sha('2'),
                provider_capability_sha256: sha('3'),
                secret_binding_root_sha256: sha('4'),
                secret_count: 1,
                allowed_path_prefixes: BTreeSet::from(["/app".into()]),
                maximum_requests: 4,
                maximum_depth: 2,
                maximum_response_body_bytes: 1024,
                maximum_total_response_bytes: 4096,
                minimum_request_interval_milliseconds: 200,
                maximum_concurrency: 1,
                component_expires_at_epoch_seconds: 2_000,
            },
            checkpoint_interval_requests: 1,
            maximum_workspace_bytes: 32 * 1024 * 1024,
            created_at_epoch_seconds: 1_000,
            expires_at_epoch_seconds: 1_900,
            activation_public_key: key_pair.public_key().as_ref().to_vec(),
        })
        .expect("plan")
    }

    fn unique_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("bsl-runner-{label}-{}-{nanos}", std::process::id()))
    }

    fn setup(
        label: &str,
    ) -> (
        PathBuf,
        UnifiedOperatorPlan,
        bsl_unified_operator::ConsumedUnifiedOperatorActivation,
    ) {
        let root = unique_root(label);
        let plan = plan();
        let payload = UnifiedOperatorActivationPayload::template(
            format!("activation-{label}"),
            &plan,
            1_050,
            1_800,
        )
        .expect("payload");
        let signature = key_pair().sign(&payload.signing_bytes().expect("bytes"));
        let certificate = UnifiedOperatorActivationCertificate {
            payload,
            signature_hex: lower_hex(signature.as_ref()),
        };
        let consumed = consume_activation_once(
            &root.join("activation"),
            &plan,
            &certificate,
            key_pair().public_key().as_ref(),
            1_100,
        )
        .expect("consume");
        (root, plan, consumed)
    }

    fn clock(seconds: i64) -> RuntimeClock {
        RuntimeClock {
            epoch_seconds: seconds,
            epoch_milliseconds: seconds as u64 * 1_000,
        }
    }

    fn fake_receipt(spec: &RuntimeRequestSpec, clock: RuntimeClock) -> RuntimeExecutionReceipt {
        let mut receipt = RuntimeExecutionReceipt {
            version: bsl_operator_runtime::OPERATOR_RUNTIME_VERSION,
            request_method: spec.method.code().into(),
            request_target_sha256: hash_bytes(spec.target.as_bytes()),
            response_status: 200,
            response_body_bytes: 128,
            live_receipt_sha256: sha('5'),
            injection_authorization_sha256: sha('6'),
            session_audit_tail: sha('7'),
            vault_audit_tail: sha('8'),
            completed_at_epoch_seconds: clock.epoch_seconds,
            receipt_sha256: String::new(),
        };
        let mut material = receipt.clone();
        material.receipt_sha256.clear();
        receipt.receipt_sha256 = hash_serializable(&material).expect("digest");
        receipt
    }

    #[test]
    fn manifest_rejects_noncanonical_seed_path() {
        let plan = plan();
        let error = RunnerManifest::build(
            &plan,
            RunnerCandidate::seed(RuntimeMethod::Get, "/app/%2fadmin", 0),
            8,
            1_100,
        )
        .expect_err("encoded seed path must fail closed");
        assert!(matches!(error, RunnerError::InvalidCheckpointQueue));
    }

    #[test]
    fn checkpoint_chain_rejects_skipped_runtime_commit() {
        let plan = plan();
        let manifest = RunnerManifest::build(
            &plan,
            RunnerCandidate::seed(RuntimeMethod::Get, "/app", 0),
            8,
            1_100,
        )
        .expect("manifest");
        let previous = RunnerCheckpoint::initial(&manifest, 1_100).expect("checkpoint");
        let mut tampered = previous.clone();
        tampered.sequence = 1;
        tampered.previous_checkpoint_sha256 = previous.checkpoint_sha256.clone();
        tampered.completed_requests = 2;
        tampered.created_at_epoch_seconds = 1_101;
        tampered.checkpoint_sha256 = tampered.calculate_sha256().expect("digest");
        assert!(matches!(
            tampered.verify(Some(&previous), &manifest, &plan),
            Err(RunnerError::CheckpointChainMismatch)
        ));
    }

    #[test]
    fn queue_executes_deterministically_and_resumes() {
        let (root, plan, consumed) = setup("resume");
        let (mut runtime, runtime_recovery) = CheckpointBoundRuntime::initialize(
            root.join("runtime-state"),
            root.join("runtime-journal"),
            plan.clone(),
            &consumed,
            clock(1_101),
        )
        .expect("runtime");
        let manifest = RunnerManifest::build(
            &plan,
            RunnerCandidate::seed(RuntimeMethod::Get, "/app", 0),
            16,
            1_101,
        )
        .expect("manifest");
        let (mut runner, _) = ResumableBoundedRunner::initialize(
            root.join("runner"),
            plan.clone(),
            manifest.clone(),
            runtime_recovery,
            clock(1_101),
        )
        .expect("runner");
        let first = runner
            .execute_next_with(&mut runtime, clock(1_101), |spec| {
                Ok(RunnerExecutionResult {
                    receipt: fake_receipt(spec, clock(1_101)),
                    discovered_candidates: vec![RunnerCandidate::child(
                        RuntimeMethod::Get,
                        "/app/next",
                        1,
                        hash_bytes(b"/app"),
                    )],
                })
            })
            .expect("first")
            .expect("receipt");
        assert_eq!(first.accepted_candidates, 1);
        drop(runner);
        drop(runtime);

        let (mut runtime, runtime_recovery) = CheckpointBoundRuntime::open(
            root.join("runtime-state"),
            root.join("runtime-journal"),
            plan.clone(),
            consumed.activation_certificate_sha256(),
            consumed.marker_path(),
            clock(1_102),
        )
        .expect("reopen runtime");
        let (mut runner, recovery) = ResumableBoundedRunner::open(
            root.join("runner"),
            plan,
            manifest,
            runtime_recovery,
            clock(1_102),
        )
        .expect("reopen runner");
        assert!(recovery.continuation_allowed);
        let second = runner
            .execute_next_with(&mut runtime, clock(1_102), |spec| {
                Ok(RunnerExecutionResult {
                    receipt: fake_receipt(spec, clock(1_102)),
                    discovered_candidates: Vec::new(),
                })
            })
            .expect("second")
            .expect("receipt");
        assert_eq!(second.status, RunnerStatus::TeardownPending);
        assert_eq!(second.stop_reason, Some(RunnerStopReason::QueueExhausted));
        let runtime_state = runtime
            .begin_teardown("runner queue exhausted", clock(1_103))
            .expect("begin teardown");
        assert_eq!(
            runtime_state.latest.status,
            OperatorRunStatus::TeardownPending
        );
        let _runtime_state = runtime
            .complete_teardown(&sha('9'), clock(1_104))
            .expect("complete teardown");
        let runtime_recovery = runtime.recover(clock(1_104)).expect("terminal recovery");
        let final_checkpoint = runner
            .record_runtime_terminal(&runtime_recovery, clock(1_104))
            .expect("record terminal");
        assert_eq!(final_checkpoint.status, RunnerStatus::Completed);
        drop(runner);
        drop(runtime);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn runtime_commit_is_reconciled_without_retry() {
        let (root, plan, consumed) = setup("reconcile");
        let (mut runtime, runtime_recovery) = CheckpointBoundRuntime::initialize(
            root.join("runtime-state"),
            root.join("runtime-journal"),
            plan.clone(),
            &consumed,
            clock(1_101),
        )
        .expect("runtime");
        let manifest = RunnerManifest::build(
            &plan,
            RunnerCandidate::seed(RuntimeMethod::Get, "/app", 0),
            16,
            1_101,
        )
        .expect("manifest");
        let (runner, _) = ResumableBoundedRunner::initialize(
            root.join("runner"),
            plan.clone(),
            manifest.clone(),
            runtime_recovery,
            clock(1_101),
        )
        .expect("runner");
        runtime
            .execute_with(
                RuntimeRequestSpec {
                    method: RuntimeMethod::Get,
                    target: "/app".into(),
                    depth: 0,
                },
                clock(1_101),
                |spec| Ok(fake_receipt(spec, clock(1_101))),
            )
            .expect("runtime commit");
        drop(runner);
        drop(runtime);

        let (runtime, runtime_recovery) = CheckpointBoundRuntime::open(
            root.join("runtime-state"),
            root.join("runtime-journal"),
            plan.clone(),
            consumed.activation_certificate_sha256(),
            consumed.marker_path(),
            clock(1_102),
        )
        .expect("runtime reopen");
        let (runner, recovery) = ResumableBoundedRunner::open(
            root.join("runner"),
            plan,
            manifest,
            runtime_recovery,
            clock(1_102),
        )
        .expect("runner reconcile");
        assert!(recovery.reconciled_runtime_commit);
        assert_eq!(recovery.checkpoint.completed_requests, 1);
        assert_eq!(recovery.checkpoint.recovery_gap_count, 1);
        assert_eq!(recovery.checkpoint.status, RunnerStatus::TeardownPending);
        drop(runner);
        drop(runtime);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn emergency_stop_is_durable_and_prevents_execution() {
        let (root, plan, consumed) = setup("stop");
        let (runtime, runtime_recovery) = CheckpointBoundRuntime::initialize(
            root.join("runtime-state"),
            root.join("runtime-journal"),
            plan.clone(),
            &consumed,
            clock(1_101),
        )
        .expect("runtime");
        let manifest = RunnerManifest::build(
            &plan,
            RunnerCandidate::seed(RuntimeMethod::Get, "/app", 0),
            16,
            1_101,
        )
        .expect("manifest");
        let (mut runner, _) = ResumableBoundedRunner::initialize(
            root.join("runner"),
            plan,
            manifest,
            runtime_recovery,
            clock(1_101),
        )
        .expect("runner");
        runner.request_emergency_stop().expect("stop marker");
        let mut runtime = runtime;
        let mut called = false;
        let result = runner
            .execute_next_with(&mut runtime, clock(1_102), |_| {
                called = true;
                unreachable!()
            })
            .expect("stop");
        assert!(result.is_none());
        assert!(!called);
        assert_eq!(
            runner.latest_checkpoint().status,
            RunnerStatus::TeardownPending
        );
        drop(runner);
        drop(runtime);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
