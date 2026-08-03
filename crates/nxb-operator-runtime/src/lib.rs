#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions, TryLockError},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use nxb_executor::ExecutionControl;
use nxb_live_adapter::{
    LiveAuthenticatedResult, LivePassivePipeline, LivePassiveRequest, LiveSessionInjection,
    PassiveMethod,
};
use nxb_operator_state::{
    CheckpointUpdate, OperatorCheckpoint, OperatorCounters, OperatorRunStatus, OperatorStateStore,
    RecoveredOperatorState,
};
use nxb_session::SessionBroker;
use nxb_session_injection::BoundSessionInjection;
use nxb_stream::StreamControl;
use nxb_transport::{ConnectionAttempt, TransportScheme};
use nxb_unified_operator::{ConsumedUnifiedOperatorActivation, UnifiedOperatorPlan};
use nxb_vault::InMemorySecretVault;
use nxb_vault_provider::{
    deprovision_external_session, ExternalVaultTeardownReceipt, ProvisionedExternalSession,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const OPERATOR_RUNTIME_VERSION: u32 = 1;
pub const MAX_RUNTIME_OUTCOME_BYTES: u64 = 16 * 1024;
pub const RUNTIME_COMMIT_RESERVATION_BYTES: u64 = 4 * 1024;
const RUNTIME_LOCK_FILE: &str = ".nxb-operator-runtime.lock";
const PREPARED_SUFFIX: &str = "-prepared.json";
const OUTCOME_SUFFIX: &str = "-outcome.json";
const COMMIT_SUFFIX: &str = "-commit.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMethod {
    Get,
    Head,
}

impl RuntimeMethod {
    pub fn code(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
        }
    }

    fn passive(self) -> PassiveMethod {
        match self {
            Self::Get => PassiveMethod::Get,
            Self::Head => PassiveMethod::Head,
        }
    }
}

impl From<PassiveMethod> for RuntimeMethod {
    fn from(value: PassiveMethod) -> Self {
        match value {
            PassiveMethod::Get => Self::Get,
            PassiveMethod::Head => Self::Head,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClock {
    pub epoch_seconds: i64,
    pub epoch_milliseconds: u64,
}

impl RuntimeClock {
    pub fn validate(self) -> Result<Self, RuntimeError> {
        if self.epoch_seconds <= 0 || self.epoch_milliseconds / 1_000 != self.epoch_seconds as u64 {
            return Err(RuntimeError::InvalidClock);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRequestSpec {
    pub method: RuntimeMethod,
    pub target: String,
    pub depth: u16,
}

impl RuntimeRequestSpec {
    pub fn validate(&self, plan: &UnifiedOperatorPlan) -> Result<(), RuntimeError> {
        LivePassiveRequest::new(self.method.passive(), self.target.clone())?;
        if self.depth > plan.binding.maximum_depth {
            return Err(RuntimeError::DepthDenied);
        }
        if !plan
            .binding
            .allowed_path_prefixes
            .iter()
            .any(|prefix| path_matches_prefix(&self.target, prefix))
        {
            return Err(RuntimeError::PathDenied);
        }
        Ok(())
    }

    fn target_sha256(&self) -> String {
        hash_bytes(self.target.as_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeExecutionReceipt {
    pub version: u32,
    pub request_method: String,
    pub request_target_sha256: String,
    pub response_status: u16,
    pub response_body_bytes: u64,
    pub live_receipt_sha256: String,
    pub injection_authorization_sha256: String,
    pub session_audit_tail: String,
    pub vault_audit_tail: String,
    pub completed_at_epoch_seconds: i64,
    pub receipt_sha256: String,
}

impl RuntimeExecutionReceipt {
    fn from_live(
        spec: &RuntimeRequestSpec,
        result: &LiveAuthenticatedResult,
        completed_at_epoch_seconds: i64,
    ) -> Result<Self, RuntimeError> {
        let live = result
            .live
            .receipt
            .as_ref()
            .ok_or(RuntimeError::LiveExecutionIncomplete)?;
        live.verify()?;
        result.injection_authorization.verify()?;
        let expected_target = spec.target_sha256();
        if live.request_method != spec.method.code()
            || live.request_target_sha256 != expected_target
            || result.injection_authorization.request_method != spec.method.code()
            || result.injection_authorization.request_target_sha256 != expected_target
        {
            return Err(RuntimeError::ExecutionBindingMismatch);
        }
        let mut receipt = Self {
            version: OPERATOR_RUNTIME_VERSION,
            request_method: spec.method.code().into(),
            request_target_sha256: expected_target,
            response_status: live.response_status,
            response_body_bytes: live.response_body_bytes,
            live_receipt_sha256: live.receipt_sha256.clone(),
            injection_authorization_sha256: result
                .injection_authorization
                .authorization_sha256
                .clone(),
            session_audit_tail: result.session_audit_tail.clone(),
            vault_audit_tail: result.vault_audit_tail.clone(),
            completed_at_epoch_seconds,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt.calculate_sha256()?;
        receipt.verify()?;
        Ok(receipt)
    }

    pub fn verify(&self) -> Result<(), RuntimeError> {
        if self.version != OPERATOR_RUNTIME_VERSION
            || !matches!(self.request_method.as_str(), "GET" | "HEAD")
            || !(100..=599).contains(&self.response_status)
            || self.completed_at_epoch_seconds <= 0
        {
            return Err(RuntimeError::InvalidExecutionReceipt);
        }
        for value in [
            &self.request_target_sha256,
            &self.live_receipt_sha256,
            &self.injection_authorization_sha256,
            &self.session_audit_tail,
            &self.vault_audit_tail,
            &self.receipt_sha256,
        ] {
            validate_sha256(value)?;
        }
        if self.receipt_sha256 != self.calculate_sha256()? {
            return Err(RuntimeError::ExecutionReceiptDigestMismatch);
        }
        Ok(())
    }

    fn calculate_sha256(&self) -> Result<String, RuntimeError> {
        let mut material = self.clone();
        material.receipt_sha256.clear();
        hash_serializable(&material)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PreparedRequestRecord {
    version: u32,
    request_index: u64,
    previous_checkpoint_sha256: String,
    method: RuntimeMethod,
    request_target_sha256: String,
    depth: u16,
    prepared_at_epoch_seconds: i64,
    prepared_at_epoch_milliseconds: u64,
    record_sha256: String,
}

impl PreparedRequestRecord {
    fn build(
        request_index: u64,
        previous: &OperatorCheckpoint,
        spec: &RuntimeRequestSpec,
        clock: RuntimeClock,
    ) -> Result<Self, RuntimeError> {
        let mut record = Self {
            version: OPERATOR_RUNTIME_VERSION,
            request_index,
            previous_checkpoint_sha256: previous.checkpoint_sha256.clone(),
            method: spec.method,
            request_target_sha256: spec.target_sha256(),
            depth: spec.depth,
            prepared_at_epoch_seconds: clock.epoch_seconds,
            prepared_at_epoch_milliseconds: clock.epoch_milliseconds,
            record_sha256: String::new(),
        };
        record.record_sha256 = record.calculate_sha256()?;
        record.verify()?;
        Ok(record)
    }

    fn verify(&self) -> Result<(), RuntimeError> {
        if self.version != OPERATOR_RUNTIME_VERSION
            || self.prepared_at_epoch_seconds <= 0
            || self.prepared_at_epoch_milliseconds / 1_000 != self.prepared_at_epoch_seconds as u64
        {
            return Err(RuntimeError::InvalidJournalRecord);
        }
        validate_sha256(&self.previous_checkpoint_sha256)?;
        validate_sha256(&self.request_target_sha256)?;
        validate_sha256(&self.record_sha256)?;
        if self.record_sha256 != self.calculate_sha256()? {
            return Err(RuntimeError::JournalDigestMismatch);
        }
        Ok(())
    }

    fn calculate_sha256(&self) -> Result<String, RuntimeError> {
        let mut material = self.clone();
        material.record_sha256.clear();
        hash_serializable(&material)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RequestOutcomeRecord {
    version: u32,
    request_index: u64,
    prepared_record_sha256: String,
    execution: RuntimeExecutionReceipt,
    resulting_counters: OperatorCounters,
    completed_at_epoch_milliseconds: u64,
    record_sha256: String,
}

impl RequestOutcomeRecord {
    fn verify(&self) -> Result<(), RuntimeError> {
        if self.version != OPERATOR_RUNTIME_VERSION
            || self.completed_at_epoch_milliseconds / 1_000
                != self.execution.completed_at_epoch_seconds as u64
        {
            return Err(RuntimeError::InvalidJournalRecord);
        }
        validate_sha256(&self.prepared_record_sha256)?;
        validate_sha256(&self.record_sha256)?;
        self.execution.verify()?;
        if self.record_sha256 != self.calculate_sha256()? {
            return Err(RuntimeError::JournalDigestMismatch);
        }
        Ok(())
    }

    fn calculate_sha256(&self) -> Result<String, RuntimeError> {
        let mut material = self.clone();
        material.record_sha256.clear();
        hash_serializable(&material)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RequestCommitRecord {
    version: u32,
    request_index: u64,
    outcome_record_sha256: String,
    checkpoint_sequence: u64,
    checkpoint_sha256: String,
    counters: OperatorCounters,
    committed_at_epoch_seconds: i64,
    committed_at_epoch_milliseconds: u64,
    record_sha256: String,
}

impl RequestCommitRecord {
    fn build(
        outcome: &RequestOutcomeRecord,
        checkpoint: &OperatorCheckpoint,
    ) -> Result<Self, RuntimeError> {
        let mut record = Self {
            version: OPERATOR_RUNTIME_VERSION,
            request_index: outcome.request_index,
            outcome_record_sha256: outcome.record_sha256.clone(),
            checkpoint_sequence: checkpoint.sequence,
            checkpoint_sha256: checkpoint.checkpoint_sha256.clone(),
            counters: checkpoint.counters,
            committed_at_epoch_seconds: outcome.execution.completed_at_epoch_seconds,
            committed_at_epoch_milliseconds: outcome.completed_at_epoch_milliseconds,
            record_sha256: String::new(),
        };
        record.record_sha256 = record.calculate_sha256()?;
        record.verify()?;
        Ok(record)
    }

    fn verify(&self) -> Result<(), RuntimeError> {
        if self.version != OPERATOR_RUNTIME_VERSION
            || self.checkpoint_sequence != self.request_index + 1
            || self.counters.requests_completed != self.request_index + 1
            || self.committed_at_epoch_seconds <= 0
            || self.committed_at_epoch_milliseconds / 1_000
                != self.committed_at_epoch_seconds as u64
        {
            return Err(RuntimeError::InvalidJournalRecord);
        }
        validate_sha256(&self.outcome_record_sha256)?;
        validate_sha256(&self.checkpoint_sha256)?;
        validate_sha256(&self.record_sha256)?;
        if self.record_sha256 != self.calculate_sha256()? {
            return Err(RuntimeError::JournalDigestMismatch);
        }
        Ok(())
    }

    fn calculate_sha256(&self) -> Result<String, RuntimeError> {
        let mut material = self.clone();
        material.record_sha256.clear();
        hash_serializable(&material)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedRequestPhase {
    Prepared,
    OutcomePersisted,
}

#[derive(Debug, Clone)]
pub struct RuntimeRecovery {
    pub state: RecoveredOperatorState,
    pub journal_bytes: u64,
    pub committed_requests: u64,
    pub unresolved_request: Option<(u64, UnresolvedRequestPhase)>,
    pub continuation_allowed: bool,
}

#[derive(Default)]
struct RecordPaths {
    prepared: Option<PathBuf>,
    outcome: Option<PathBuf>,
    commit: Option<PathBuf>,
}

struct JournalScan {
    journal_bytes: u64,
    committed_requests: u64,
    next_request_index: u64,
    last_committed_epoch_milliseconds: Option<u64>,
    unresolved_request: Option<(u64, UnresolvedRequestPhase)>,
    reconcile: Option<RequestOutcomeRecord>,
}

struct RuntimeLock {
    file: Option<File>,
}

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.unlock();
            drop(file);
        }
    }
}

pub struct CheckpointBoundRuntime {
    plan: UnifiedOperatorPlan,
    state_store: OperatorStateStore,
    journal_directory: PathBuf,
    _lock: RuntimeLock,
    next_request_index: u64,
    journal_bytes: u64,
    last_committed_epoch_milliseconds: Option<u64>,
    blocked: bool,
}

impl std::fmt::Debug for CheckpointBoundRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CheckpointBoundRuntime")
            .field("plan_sha256", &self.plan.plan_sha256)
            .field("state_directory", &self.state_store.directory())
            .field("journal_directory", &self.journal_directory)
            .field("next_request_index", &self.next_request_index)
            .field("journal_bytes", &self.journal_bytes)
            .field("blocked", &self.blocked)
            .finish()
    }
}

impl CheckpointBoundRuntime {
    pub fn initialize(
        state_directory: impl Into<PathBuf>,
        journal_directory: impl Into<PathBuf>,
        plan: UnifiedOperatorPlan,
        consumed_activation: &ConsumedUnifiedOperatorActivation,
        clock: RuntimeClock,
    ) -> Result<(Self, RuntimeRecovery), RuntimeError> {
        let clock = clock.validate()?;
        let journal_directory = journal_directory.into();
        fs::create_dir_all(&journal_directory).map_err(io_error)?;
        for entry in fs::read_dir(&journal_directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if entry.file_name() != RUNTIME_LOCK_FILE {
                return Err(RuntimeError::JournalDirectoryNotEmpty);
            }
        }
        let lock = acquire_lock(&journal_directory, clock)?;
        let (state_store, state) = OperatorStateStore::initialize(
            state_directory,
            plan.clone(),
            consumed_activation,
            clock.epoch_seconds,
        )?;
        let runtime = Self {
            plan,
            state_store,
            journal_directory,
            _lock: lock,
            next_request_index: 0,
            journal_bytes: 0,
            last_committed_epoch_milliseconds: None,
            blocked: false,
        };
        let recovery = RuntimeRecovery {
            continuation_allowed: state.continuation_allowed,
            state,
            journal_bytes: 0,
            committed_requests: 0,
            unresolved_request: None,
        };
        Ok((runtime, recovery))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open(
        state_directory: impl Into<PathBuf>,
        journal_directory: impl Into<PathBuf>,
        plan: UnifiedOperatorPlan,
        activation_certificate_sha256: impl Into<String>,
        activation_marker_path: impl Into<PathBuf>,
        clock: RuntimeClock,
    ) -> Result<(Self, RuntimeRecovery), RuntimeError> {
        let clock = clock.validate()?;
        let journal_directory = journal_directory.into();
        fs::create_dir_all(&journal_directory).map_err(io_error)?;
        let lock = acquire_lock(&journal_directory, clock)?;
        let (state_store, state) = OperatorStateStore::open(
            state_directory,
            plan.clone(),
            activation_certificate_sha256,
            activation_marker_path,
            clock.epoch_seconds,
        )?;
        let scan = scan_journal(&journal_directory, state_store.directory(), &state)?;
        let scan = if let Some(outcome) = scan.reconcile.clone() {
            let checkpoint = read_checkpoint(
                state_store.directory(),
                outcome.request_index.saturating_add(1),
            )?;
            let commit = RequestCommitRecord::build(&outcome, &checkpoint)?;
            let bytes = record_bytes(&commit)?;
            if bytes.len() as u64 > RUNTIME_COMMIT_RESERVATION_BYTES {
                return Err(RuntimeError::CommitReservationExceeded);
            }
            publish_record(
                &journal_directory.join(commit_file_name(outcome.request_index)),
                &bytes,
            )?;
            scan_journal(&journal_directory, state_store.directory(), &state)?
        } else {
            scan
        };
        let exact_workspace = state
            .state_file_bytes
            .checked_add(scan.journal_bytes)
            .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;
        if exact_workspace > plan.maximum_workspace_bytes {
            return Err(RuntimeError::WorkspaceBudgetExceeded);
        }
        let continuation_allowed = state.continuation_allowed && scan.unresolved_request.is_none();
        let recovery = RuntimeRecovery {
            state: state.clone(),
            journal_bytes: scan.journal_bytes,
            committed_requests: scan.committed_requests,
            unresolved_request: scan.unresolved_request,
            continuation_allowed,
        };
        let runtime = Self {
            plan,
            state_store,
            journal_directory,
            _lock: lock,
            next_request_index: scan.next_request_index,
            journal_bytes: scan.journal_bytes,
            last_committed_epoch_milliseconds: scan.last_committed_epoch_milliseconds,
            blocked: !continuation_allowed && !state.latest.status.is_terminal(),
        };
        Ok((runtime, recovery))
    }

    pub fn recover(&self, clock: RuntimeClock) -> Result<RuntimeRecovery, RuntimeError> {
        let clock = clock.validate()?;
        let state = self.state_store.recover(clock.epoch_seconds)?;
        let scan = scan_journal(
            &self.journal_directory,
            self.state_store.directory(),
            &state,
        )?;
        let exact_workspace = state
            .state_file_bytes
            .checked_add(scan.journal_bytes)
            .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;
        if exact_workspace > self.plan.maximum_workspace_bytes {
            return Err(RuntimeError::WorkspaceBudgetExceeded);
        }
        Ok(RuntimeRecovery {
            continuation_allowed: state.continuation_allowed && scan.unresolved_request.is_none(),
            state,
            journal_bytes: scan.journal_bytes,
            committed_requests: scan.committed_requests,
            unresolved_request: scan.unresolved_request,
        })
    }

    pub fn execute_with<F>(
        &mut self,
        spec: RuntimeRequestSpec,
        clock: RuntimeClock,
        executor: F,
    ) -> Result<(RuntimeExecutionReceipt, RecoveredOperatorState), RuntimeError>
    where
        F: FnOnce(&RuntimeRequestSpec) -> Result<RuntimeExecutionReceipt, RuntimeError>,
    {
        let clock = clock.validate()?;
        if self.blocked {
            return Err(RuntimeError::RuntimeBlocked);
        }
        spec.validate(&self.plan)?;
        let recovered = self.state_store.recover(clock.epoch_seconds)?;
        if !recovered.continuation_allowed
            || !matches!(
                recovered.latest.status,
                OperatorRunStatus::Ready | OperatorRunStatus::Running
            )
        {
            return Err(RuntimeError::ContinuationDenied);
        }
        if recovered.latest.counters.requests_completed != self.next_request_index {
            return Err(RuntimeError::StateJournalMismatch);
        }
        if let Some(previous) = self.last_committed_epoch_milliseconds {
            let elapsed = clock
                .epoch_milliseconds
                .checked_sub(previous)
                .ok_or(RuntimeError::ClockRegression)?;
            if elapsed < self.plan.binding.minimum_request_interval_milliseconds {
                return Err(RuntimeError::RequestIntervalDenied);
            }
        }

        let prepared =
            PreparedRequestRecord::build(self.next_request_index, &recovered.latest, &spec, clock)?;
        let prepared_bytes = record_bytes(&prepared)?;
        let prospective = recovered
            .state_file_bytes
            .checked_add(self.journal_bytes)
            .and_then(|value| value.checked_add(prepared_bytes.len() as u64))
            .and_then(|value| value.checked_add(MAX_RUNTIME_OUTCOME_BYTES))
            .and_then(|value| value.checked_add(RUNTIME_COMMIT_RESERVATION_BYTES))
            .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;
        if prospective > self.plan.maximum_workspace_bytes {
            return Err(RuntimeError::WorkspaceBudgetExceeded);
        }
        publish_record(
            &self
                .journal_directory
                .join(prepared_file_name(self.next_request_index)),
            &prepared_bytes,
        )?;
        self.journal_bytes = self
            .journal_bytes
            .checked_add(prepared_bytes.len() as u64)
            .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;

        let execution = match executor(&spec) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.blocked = true;
                return Err(RuntimeError::ExecutionIndeterminate(error.to_string()));
            }
        };
        if let Err(error) = execution.verify() {
            self.blocked = true;
            return Err(error);
        }
        if execution.request_method != spec.method.code()
            || execution.request_target_sha256 != spec.target_sha256()
        {
            self.blocked = true;
            return Err(RuntimeError::ExecutionBindingMismatch);
        }
        if execution.response_body_bytes > self.plan.binding.maximum_response_body_bytes {
            self.blocked = true;
            return Err(RuntimeError::ResponseBodyBudgetExceeded);
        }

        let request_count = recovered
            .latest
            .counters
            .requests_completed
            .checked_add(1)
            .ok_or(RuntimeError::RequestBudgetExceeded)?;
        let total_response_bytes = recovered
            .latest
            .counters
            .total_response_bytes
            .checked_add(execution.response_body_bytes)
            .ok_or(RuntimeError::ResponseBudgetExceeded)?;
        if request_count > self.plan.binding.maximum_requests
            || total_response_bytes > self.plan.binding.maximum_total_response_bytes
        {
            self.blocked = true;
            return Err(RuntimeError::ResponseBudgetExceeded);
        }

        let mut outcome = RequestOutcomeRecord {
            version: OPERATOR_RUNTIME_VERSION,
            request_index: self.next_request_index,
            prepared_record_sha256: prepared.record_sha256.clone(),
            execution: execution.clone(),
            resulting_counters: OperatorCounters::default(),
            completed_at_epoch_milliseconds: clock.epoch_milliseconds,
            record_sha256: String::new(),
        };
        let mut outcome_bytes = Vec::new();
        let mut evidence_bytes = 0_u64;
        for _ in 0..8 {
            outcome.resulting_counters = OperatorCounters {
                requests_completed: request_count,
                total_response_bytes,
                last_response_body_bytes: execution.response_body_bytes,
                maximum_depth_observed: recovered
                    .latest
                    .counters
                    .maximum_depth_observed
                    .max(spec.depth),
                evidence_bytes,
            };
            outcome.record_sha256 = outcome.calculate_sha256()?;
            outcome_bytes = record_bytes(&outcome)?;
            if outcome_bytes.len() as u64 > MAX_RUNTIME_OUTCOME_BYTES {
                self.blocked = true;
                return Err(RuntimeError::OutcomeTooLarge);
            }
            let calculated = recovered
                .latest
                .counters
                .evidence_bytes
                .checked_add(prepared_bytes.len() as u64)
                .and_then(|value| value.checked_add(outcome_bytes.len() as u64))
                .and_then(|value| value.checked_add(RUNTIME_COMMIT_RESERVATION_BYTES))
                .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;
            if calculated == evidence_bytes {
                break;
            }
            evidence_bytes = calculated;
        }
        if outcome.resulting_counters.evidence_bytes != evidence_bytes {
            outcome.resulting_counters.evidence_bytes = evidence_bytes;
            outcome.record_sha256 = outcome.calculate_sha256()?;
            outcome_bytes = record_bytes(&outcome)?;
        }
        outcome.verify()?;
        publish_record(
            &self
                .journal_directory
                .join(outcome_file_name(self.next_request_index)),
            &outcome_bytes,
        )?;
        self.journal_bytes = self
            .journal_bytes
            .checked_add(outcome_bytes.len() as u64)
            .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;

        let state = match self.state_store.append(
            CheckpointUpdate {
                status: OperatorRunStatus::Running,
                counters: outcome.resulting_counters,
                stop_reason: None,
            },
            clock.epoch_seconds,
        ) {
            Ok(state) => state,
            Err(error) => {
                self.blocked = true;
                return Err(RuntimeError::CheckpointAfterExecution(error.to_string()));
            }
        };
        let commit = RequestCommitRecord::build(&outcome, &state.latest)?;
        let commit_bytes = record_bytes(&commit)?;
        if commit_bytes.len() as u64 > RUNTIME_COMMIT_RESERVATION_BYTES {
            self.blocked = true;
            return Err(RuntimeError::CommitReservationExceeded);
        }
        if let Err(error) = publish_record(
            &self
                .journal_directory
                .join(commit_file_name(self.next_request_index)),
            &commit_bytes,
        ) {
            self.blocked = true;
            return Err(RuntimeError::CommitAfterCheckpoint(error.to_string()));
        }
        self.journal_bytes = self
            .journal_bytes
            .checked_add(commit_bytes.len() as u64)
            .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;
        self.next_request_index = self
            .next_request_index
            .checked_add(1)
            .ok_or(RuntimeError::RequestBudgetExceeded)?;
        self.last_committed_epoch_milliseconds = Some(clock.epoch_milliseconds);
        Ok((execution, state))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_live_authenticated(
        &mut self,
        pipeline: &mut LivePassivePipeline,
        attempt: ConnectionAttempt,
        elapsed_since_authorization: Duration,
        request: LivePassiveRequest,
        execution_control: ExecutionControl,
        stream_control: StreamControl,
        bound: &BoundSessionInjection,
        broker: &mut SessionBroker,
        vault: &mut InMemorySecretVault,
        depth: u16,
        clock: RuntimeClock,
    ) -> Result<(RuntimeExecutionReceipt, RecoveredOperatorState), RuntimeError> {
        validate_live_attempt(&self.plan, &attempt, depth)?;
        let spec = RuntimeRequestSpec {
            method: request.method.into(),
            target: request.target.clone(),
            depth,
        };
        self.execute_with(spec, clock, |spec| {
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
            RuntimeExecutionReceipt::from_live(spec, &result, clock.epoch_seconds)
        })
    }

    pub fn begin_teardown(
        &mut self,
        reason: impl Into<String>,
        clock: RuntimeClock,
    ) -> Result<RecoveredOperatorState, RuntimeError> {
        let clock = clock.validate()?;
        let recovered = self.state_store.recover(clock.epoch_seconds)?;
        if recovered.latest.status == OperatorRunStatus::TeardownPending {
            return Ok(recovered);
        }
        if recovered.latest.status.is_terminal() {
            return Err(RuntimeError::ContinuationDenied);
        }
        let state = self.state_store.append(
            CheckpointUpdate {
                status: OperatorRunStatus::TeardownPending,
                counters: recovered.latest.counters,
                stop_reason: Some(reason.into()),
            },
            clock.epoch_seconds,
        )?;
        self.blocked = true;
        Ok(state)
    }

    pub fn complete_teardown(
        &mut self,
        teardown_receipt_sha256: &str,
        clock: RuntimeClock,
    ) -> Result<RecoveredOperatorState, RuntimeError> {
        let clock = clock.validate()?;
        validate_sha256(teardown_receipt_sha256)?;
        let recovered = self.state_store.recover(clock.epoch_seconds)?;
        if recovered.latest.status != OperatorRunStatus::TeardownPending {
            return Err(RuntimeError::TeardownNotStarted);
        }
        let state = self.state_store.append(
            CheckpointUpdate {
                status: OperatorRunStatus::Completed,
                counters: recovered.latest.counters,
                stop_reason: Some(format!("teardown:{teardown_receipt_sha256}")),
            },
            clock.epoch_seconds,
        )?;
        self.blocked = true;
        Ok(state)
    }

    pub fn abort(
        &mut self,
        reason: impl Into<String>,
        clock: RuntimeClock,
    ) -> Result<RecoveredOperatorState, RuntimeError> {
        let clock = clock.validate()?;
        let recovered = self.state_store.recover(clock.epoch_seconds)?;
        if recovered.latest.status.is_terminal() {
            return Err(RuntimeError::ContinuationDenied);
        }
        let state = self.state_store.append(
            CheckpointUpdate {
                status: OperatorRunStatus::Aborted,
                counters: recovered.latest.counters,
                stop_reason: Some(reason.into()),
            },
            clock.epoch_seconds,
        )?;
        self.blocked = true;
        Ok(state)
    }

    pub fn deprovision_external_session(
        &mut self,
        provisioned: ProvisionedExternalSession,
        broker: &mut SessionBroker,
        vault: &mut InMemorySecretVault,
        clock: RuntimeClock,
    ) -> Result<(ExternalVaultTeardownReceipt, RecoveredOperatorState), RuntimeError> {
        let clock = clock.validate()?;
        self.begin_teardown("external session teardown started", clock)?;
        match deprovision_external_session(provisioned, broker, vault, clock.epoch_seconds) {
            Ok(receipt) => {
                receipt.verify()?;
                let state = self.complete_teardown(&receipt.receipt_sha256, clock)?;
                Ok((receipt, state))
            }
            Err(error) => {
                let _ = vault.emergency_purge();
                let _ = self.abort("external session teardown failed", clock);
                Err(RuntimeError::ExternalTeardown(error.to_string()))
            }
        }
    }

    pub fn state_directory(&self) -> &Path {
        self.state_store.directory()
    }

    pub fn journal_directory(&self) -> &Path {
        &self.journal_directory
    }
}

fn scan_journal(
    journal_directory: &Path,
    state_directory: &Path,
    state: &RecoveredOperatorState,
) -> Result<JournalScan, RuntimeError> {
    let mut records: BTreeMap<u64, RecordPaths> = BTreeMap::new();
    let mut journal_bytes = 0_u64;
    for entry in fs::read_dir(journal_directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let file_type = entry.file_type().map_err(io_error)?;
        if !file_type.is_file() {
            return Err(RuntimeError::UnexpectedJournalEntry);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RuntimeError::UnexpectedJournalEntry)?;
        if name == RUNTIME_LOCK_FILE {
            continue;
        }
        if name.starts_with('.') && name.ends_with(".tmp") {
            return Err(RuntimeError::IncompleteJournalPublication);
        }
        let (index, kind) = parse_record_file_name(&name)?;
        let path = entry.path();
        journal_bytes = journal_bytes
            .checked_add(fs::metadata(&path).map_err(io_error)?.len())
            .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;
        let paths = records.entry(index).or_default();
        let slot = match kind {
            RecordKind::Prepared => &mut paths.prepared,
            RecordKind::Outcome => &mut paths.outcome,
            RecordKind::Commit => &mut paths.commit,
        };
        if slot.replace(path).is_some() {
            return Err(RuntimeError::DuplicateJournalRecord);
        }
    }

    let mut committed_requests = 0_u64;
    let mut last_committed = None;
    let mut unresolved = None;
    let mut reconcile = None;
    let mut incomplete_seen = false;
    for (expected, (index, paths)) in records.into_iter().enumerate() {
        if incomplete_seen {
            return Err(RuntimeError::StateJournalMismatch);
        }
        let expected = expected as u64;
        if index != expected {
            return Err(RuntimeError::JournalSequenceGap);
        }
        let prepared_path = paths
            .prepared
            .as_ref()
            .ok_or(RuntimeError::MissingPreparedRecord)?;
        let prepared: PreparedRequestRecord = read_canonical(prepared_path)?;
        prepared.verify()?;
        if prepared.request_index != index {
            return Err(RuntimeError::StateJournalMismatch);
        }
        let outcome = match paths.outcome.as_ref() {
            Some(path) => {
                let outcome: RequestOutcomeRecord = read_canonical(path)?;
                outcome.verify()?;
                if outcome.request_index != index
                    || outcome.prepared_record_sha256 != prepared.record_sha256
                {
                    return Err(RuntimeError::StateJournalMismatch);
                }
                Some(outcome)
            }
            None => None,
        };
        let commit = match paths.commit.as_ref() {
            Some(path) => {
                let commit: RequestCommitRecord = read_canonical(path)?;
                commit.verify()?;
                Some(commit)
            }
            None => None,
        };
        match (outcome, commit) {
            (None, None) => {
                unresolved = Some((index, UnresolvedRequestPhase::Prepared));
            }
            (None, Some(_)) => return Err(RuntimeError::CommitWithoutOutcome),
            (Some(outcome), None) => {
                if let Ok(checkpoint) = read_checkpoint(state_directory, index + 1) {
                    if checkpoint.counters == outcome.resulting_counters {
                        reconcile = Some(outcome);
                    } else {
                        unresolved = Some((index, UnresolvedRequestPhase::OutcomePersisted));
                    }
                } else {
                    unresolved = Some((index, UnresolvedRequestPhase::OutcomePersisted));
                }
            }
            (Some(outcome), Some(commit)) => {
                if commit.request_index != index
                    || commit.outcome_record_sha256 != outcome.record_sha256
                    || commit.counters != outcome.resulting_counters
                {
                    return Err(RuntimeError::StateJournalMismatch);
                }
                let checkpoint = read_checkpoint(state_directory, commit.checkpoint_sequence)?;
                if checkpoint.checkpoint_sha256 != commit.checkpoint_sha256
                    || checkpoint.counters != commit.counters
                {
                    return Err(RuntimeError::StateJournalMismatch);
                }
                committed_requests += 1;
                last_committed = Some(commit.committed_at_epoch_milliseconds);
            }
        }
        incomplete_seen = unresolved.is_some() || reconcile.is_some();
    }
    if reconcile.is_none() && state.latest.counters.requests_completed != committed_requests {
        return Err(RuntimeError::StateJournalMismatch);
    }
    if reconcile.is_some()
        && state.latest.counters.requests_completed != committed_requests.saturating_add(1)
    {
        return Err(RuntimeError::StateJournalMismatch);
    }
    let next_request_index = committed_requests;
    Ok(JournalScan {
        journal_bytes,
        committed_requests,
        next_request_index,
        last_committed_epoch_milliseconds: last_committed,
        unresolved_request: unresolved,
        reconcile,
    })
}

#[derive(Debug, Clone, Copy)]
enum RecordKind {
    Prepared,
    Outcome,
    Commit,
}

fn parse_record_file_name(name: &str) -> Result<(u64, RecordKind), RuntimeError> {
    let rest = name
        .strip_prefix("request-")
        .ok_or(RuntimeError::UnexpectedJournalEntry)?;
    for (suffix, kind) in [
        (PREPARED_SUFFIX, RecordKind::Prepared),
        (OUTCOME_SUFFIX, RecordKind::Outcome),
        (COMMIT_SUFFIX, RecordKind::Commit),
    ] {
        if let Some(index) = rest.strip_suffix(suffix) {
            if index.len() == 20 && index.bytes().all(|byte| byte.is_ascii_digit()) {
                return Ok((
                    index
                        .parse()
                        .map_err(|_| RuntimeError::UnexpectedJournalEntry)?,
                    kind,
                ));
            }
        }
    }
    Err(RuntimeError::UnexpectedJournalEntry)
}

fn read_checkpoint(
    state_directory: &Path,
    sequence: u64,
) -> Result<OperatorCheckpoint, RuntimeError> {
    read_canonical(&state_directory.join(format!("checkpoint-{sequence:020}.json")))
}

fn acquire_lock(
    journal_directory: &Path,
    clock: RuntimeClock,
) -> Result<RuntimeLock, RuntimeError> {
    let path = journal_directory.join(RUNTIME_LOCK_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(io_error)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(RuntimeError::RuntimeLocked),
        Err(TryLockError::Error(error)) => return Err(io_error(error)),
    }
    if let Err(error) = file.set_len(0) {
        let _ = file.unlock();
        return Err(io_error(error));
    }
    let bytes = format!(
        "pid={}\nepoch_seconds={}\n",
        std::process::id(),
        clock.epoch_seconds
    );
    if let Err(error) = file
        .write_all(bytes.as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _ = file.unlock();
        return Err(io_error(error));
    }
    Ok(RuntimeLock { file: Some(file) })
}

fn publish_record(path: &Path, bytes: &[u8]) -> Result<(), RuntimeError> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(RuntimeError::UnexpectedJournalEntry)?;
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
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
                RuntimeError::JournalRecordAlreadyExists
            } else {
                io_error(error)
            }
        })?;
        Ok::<(), RuntimeError>(())
    })();
    if let Err(error) = publication {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    fs::remove_file(&temporary).map_err(io_error)
}

fn read_canonical<T>(path: &Path) -> Result<T, RuntimeError>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = fs::read(path).map_err(io_error)?;
    let value = serde_json::from_slice(&bytes)
        .map_err(|error| RuntimeError::Serialization(error.to_string()))?;
    if bytes != record_bytes(&value)? {
        return Err(RuntimeError::NonCanonicalJournalRecord);
    }
    Ok(value)
}

fn record_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| RuntimeError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_live_attempt(
    plan: &UnifiedOperatorPlan,
    attempt: &ConnectionAttempt,
    depth: u16,
) -> Result<(), RuntimeError> {
    if attempt.scheme != TransportScheme::Https
        || attempt.port != 443
        || attempt.http_host != plan.binding.authority
        || attempt.sni.as_deref() != Some(plan.binding.authority.as_str())
        || u16::from(attempt.redirect_depth) != depth
    {
        return Err(RuntimeError::LiveAttemptBindingMismatch);
    }
    Ok(())
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|remaining| remaining.starts_with('/'))
}

fn prepared_file_name(index: u64) -> String {
    format!("request-{index:020}{PREPARED_SUFFIX}")
}

fn outcome_file_name(index: u64) -> String {
    format!("request-{index:020}{OUTCOME_SUFFIX}")
}

fn commit_file_name(index: u64) -> String {
    format!("request-{index:020}{COMMIT_SUFFIX}")
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, RuntimeError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| RuntimeError::Serialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn validate_sha256(value: &str) -> Result<(), RuntimeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RuntimeError::InvalidSha256);
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

fn io_error(error: std::io::Error) -> RuntimeError {
    RuntimeError::Io(error.to_string())
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime clock is invalid")]
    InvalidClock,
    #[error("runtime clock regressed")]
    ClockRegression,
    #[error("runtime journal directory must be empty during initialization")]
    JournalDirectoryNotEmpty,
    #[error("runtime journal is locked by another process or a crashed owner")]
    RuntimeLocked,
    #[error("runtime continuation is blocked")]
    RuntimeBlocked,
    #[error("operator state does not allow continuation")]
    ContinuationDenied,
    #[error("request path is outside the signed path scope")]
    PathDenied,
    #[error("request depth exceeds the signed depth budget")]
    DepthDenied,
    #[error("minimum request interval has not elapsed")]
    RequestIntervalDenied,
    #[error("request budget exceeded")]
    RequestBudgetExceeded,
    #[error("response body budget exceeded")]
    ResponseBodyBudgetExceeded,
    #[error("total response budget exceeded")]
    ResponseBudgetExceeded,
    #[error("runtime workspace budget exceeded")]
    WorkspaceBudgetExceeded,
    #[error("authenticated live execution did not produce a completed receipt")]
    LiveExecutionIncomplete,
    #[error("authenticated execution result does not match the prepared request")]
    ExecutionBindingMismatch,
    #[error("live connection attempt does not match the signed operator binding")]
    LiveAttemptBindingMismatch,
    #[error("execution outcome is indeterminate and requires teardown or abort: {0}")]
    ExecutionIndeterminate(String),
    #[error("runtime execution receipt is invalid")]
    InvalidExecutionReceipt,
    #[error("runtime execution receipt digest mismatch")]
    ExecutionReceiptDigestMismatch,
    #[error("runtime outcome record exceeds its bound")]
    OutcomeTooLarge,
    #[error("runtime commit record exceeds its reserved workspace")]
    CommitReservationExceeded,
    #[error("checkpoint publication failed after live execution: {0}")]
    CheckpointAfterExecution(String),
    #[error("commit publication failed after checkpoint: {0}")]
    CommitAfterCheckpoint(String),
    #[error("runtime journal contains an unexpected entry")]
    UnexpectedJournalEntry,
    #[error("runtime journal publication was interrupted")]
    IncompleteJournalPublication,
    #[error("runtime journal record already exists")]
    JournalRecordAlreadyExists,
    #[error("runtime journal sequence contains a gap")]
    JournalSequenceGap,
    #[error("runtime journal contains a duplicate record")]
    DuplicateJournalRecord,
    #[error("runtime journal is missing a prepared record")]
    MissingPreparedRecord,
    #[error("runtime journal contains a commit without an outcome")]
    CommitWithoutOutcome,
    #[error("runtime journal record is invalid")]
    InvalidJournalRecord,
    #[error("runtime journal record digest mismatch")]
    JournalDigestMismatch,
    #[error("runtime journal record is not canonical")]
    NonCanonicalJournalRecord,
    #[error("runtime journal and checkpoint state do not match")]
    StateJournalMismatch,
    #[error("teardown has not entered teardown-pending state")]
    TeardownNotStarted,
    #[error("external session teardown failed: {0}")]
    ExternalTeardown(String),
    #[error("invalid SHA-256 value")]
    InvalidSha256,
    #[error("runtime serialization failed: {0}")]
    Serialization(String),
    #[error("runtime I/O failed: {0}")]
    Io(String),
    #[error(transparent)]
    State(#[from] nxb_operator_state::OperatorStateError),
    #[error(transparent)]
    Live(#[from] nxb_live_adapter::LiveAuthenticatedError),
    #[error(transparent)]
    LiveAdapter(#[from] nxb_live_adapter::LiveAdapterError),
    #[error(transparent)]
    Injection(#[from] nxb_session_injection::SessionInjectionError),
    #[error(transparent)]
    VaultProvider(#[from] nxb_vault_provider::VaultProviderError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use nxb_unified_operator::{
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
        Ed25519KeyPair::from_seed_unchecked(&[13_u8; 32]).expect("deterministic key")
    }

    fn plan() -> UnifiedOperatorPlan {
        let key_pair = key_pair();
        UnifiedOperatorPlan::build(UnifiedOperatorPlanParameters {
            operator_id: "operator-runtime-test".into(),
            binding: UnifiedComponentBinding {
                discovery_plan_sha256: sha('a'),
                policy_sha256: sha('b'),
                target_origin_sha256: sha('c'),
                discovery_session_id: "discovery-runtime".into(),
                authority: "example.com".into(),
                run_id: "run-runtime".into(),
                worker_id: "worker-runtime".into(),
                account_id: "account-runtime".into(),
                tenant_id: "tenant-runtime".into(),
                role_id: "role-runtime".into(),
                session_injection_manifest_sha256: sha('d'),
                external_vault_plan_sha256: sha('e'),
                external_vault_bootstrap_receipt_sha256: sha('f'),
                external_session_id_sha256: sha('1'),
                provider_id: "provider-runtime".into(),
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
            maximum_workspace_bytes: 1024 * 1024,
            created_at_epoch_seconds: 1_000,
            expires_at_epoch_seconds: 1_900,
            activation_public_key: key_pair.public_key().as_ref().to_vec(),
        })
        .expect("valid plan")
    }

    fn unique_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nxb-runtime-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn setup(
        label: &str,
    ) -> (
        PathBuf,
        UnifiedOperatorPlan,
        ConsumedUnifiedOperatorActivation,
    ) {
        let root = unique_root(label);
        let plan = plan();
        let payload =
            UnifiedOperatorActivationPayload::template("runtime-activation", &plan, 1_050, 1_800)
                .expect("payload");
        let signature = key_pair().sign(&payload.signing_bytes().expect("signing bytes"));
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
        .expect("consume activation");
        (root, plan, consumed)
    }

    fn fake_receipt(spec: &RuntimeRequestSpec, clock: RuntimeClock) -> RuntimeExecutionReceipt {
        let mut receipt = RuntimeExecutionReceipt {
            version: OPERATOR_RUNTIME_VERSION,
            request_method: spec.method.code().into(),
            request_target_sha256: spec.target_sha256(),
            response_status: 200,
            response_body_bytes: 128,
            live_receipt_sha256: sha('5'),
            injection_authorization_sha256: sha('6'),
            session_audit_tail: sha('7'),
            vault_audit_tail: sha('8'),
            completed_at_epoch_seconds: clock.epoch_seconds,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt.calculate_sha256().expect("digest");
        receipt
    }

    #[test]
    fn successful_request_is_journaled_and_checkpointed_exactly_once() {
        let (root, runtime_plan, consumed) = setup("success");
        let clock = RuntimeClock {
            epoch_seconds: 1_101,
            epoch_milliseconds: 1_101_000,
        };
        let (mut runtime, initial) = CheckpointBoundRuntime::initialize(
            root.join("state"),
            root.join("journal"),
            runtime_plan,
            &consumed,
            clock,
        )
        .expect("initialize");
        assert!(initial.continuation_allowed);
        let spec = RuntimeRequestSpec {
            method: RuntimeMethod::Get,
            target: "/app/profile".into(),
            depth: 1,
        };
        let (_, state) = runtime
            .execute_with(spec, clock, |request| Ok(fake_receipt(request, clock)))
            .expect("execute");
        assert_eq!(state.latest.counters.requests_completed, 1);
        assert_eq!(state.latest.counters.total_response_bytes, 128);
        assert!(runtime
            .journal_directory()
            .join(commit_file_name(0))
            .is_file());
        drop(runtime);
        let (_, reopened) = CheckpointBoundRuntime::open(
            root.join("state"),
            root.join("journal"),
            plan(),
            consumed.activation_certificate_sha256(),
            consumed.marker_path(),
            RuntimeClock {
                epoch_seconds: 1_102,
                epoch_milliseconds: 1_102_000,
            },
        )
        .expect("reopen");
        assert_eq!(reopened.committed_requests, 1);
        assert!(reopened.continuation_allowed);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn executor_failure_leaves_indeterminate_record_and_blocks_resume() {
        let (root, plan, consumed) = setup("indeterminate");
        let clock = RuntimeClock {
            epoch_seconds: 1_101,
            epoch_milliseconds: 1_101_000,
        };
        let (mut runtime, _) = CheckpointBoundRuntime::initialize(
            root.join("state"),
            root.join("journal"),
            plan.clone(),
            &consumed,
            clock,
        )
        .expect("initialize");
        let error = runtime
            .execute_with(
                RuntimeRequestSpec {
                    method: RuntimeMethod::Get,
                    target: "/app/profile".into(),
                    depth: 1,
                },
                clock,
                |_| Err(RuntimeError::LiveExecutionIncomplete),
            )
            .expect_err("execution must be indeterminate");
        assert!(matches!(error, RuntimeError::ExecutionIndeterminate(_)));
        drop(runtime);
        let (mut reopened, recovery) = CheckpointBoundRuntime::open(
            root.join("state"),
            root.join("journal"),
            plan,
            consumed.activation_certificate_sha256(),
            consumed.marker_path(),
            RuntimeClock {
                epoch_seconds: 1_102,
                epoch_milliseconds: 1_102_000,
            },
        )
        .expect("reopen blocked runtime");
        assert_eq!(
            recovery.unresolved_request,
            Some((0, UnresolvedRequestPhase::Prepared))
        );
        assert!(!recovery.continuation_allowed);
        let aborted = reopened
            .abort(
                "indeterminate request",
                RuntimeClock {
                    epoch_seconds: 1_102,
                    epoch_milliseconds: 1_102_000,
                },
            )
            .expect("abort");
        assert_eq!(aborted.latest.status, OperatorRunStatus::Aborted);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn request_interval_and_path_scope_fail_before_execution() {
        let (root, plan, consumed) = setup("gates");
        let first = RuntimeClock {
            epoch_seconds: 1_101,
            epoch_milliseconds: 1_101_000,
        };
        let (mut runtime, _) = CheckpointBoundRuntime::initialize(
            root.join("state"),
            root.join("journal"),
            plan,
            &consumed,
            first,
        )
        .expect("initialize");
        runtime
            .execute_with(
                RuntimeRequestSpec {
                    method: RuntimeMethod::Head,
                    target: "/app".into(),
                    depth: 0,
                },
                first,
                |request| Ok(fake_receipt(request, first)),
            )
            .expect("first request");
        let mut called = false;
        let interval_error = runtime
            .execute_with(
                RuntimeRequestSpec {
                    method: RuntimeMethod::Get,
                    target: "/app/next".into(),
                    depth: 1,
                },
                RuntimeClock {
                    epoch_seconds: 1_101,
                    epoch_milliseconds: 1_101_100,
                },
                |request| {
                    called = true;
                    Ok(fake_receipt(
                        request,
                        RuntimeClock {
                            epoch_seconds: 1_101,
                            epoch_milliseconds: 1_101_100,
                        },
                    ))
                },
            )
            .expect_err("interval gate");
        assert!(matches!(
            interval_error,
            RuntimeError::RequestIntervalDenied
        ));
        assert!(!called);
        let path_error = runtime
            .execute_with(
                RuntimeRequestSpec {
                    method: RuntimeMethod::Get,
                    target: "/admin".into(),
                    depth: 0,
                },
                RuntimeClock {
                    epoch_seconds: 1_102,
                    epoch_milliseconds: 1_102_000,
                },
                |_| panic!("path denial must happen before execution"),
            )
            .expect_err("path gate");
        assert!(matches!(path_error, RuntimeError::PathDenied));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn os_lock_rejects_concurrent_owner_and_recovers_stale_path() {
        let (root, runtime_plan, consumed) = setup("os-lock");
        let clock = RuntimeClock {
            epoch_seconds: 1_101,
            epoch_milliseconds: 1_101_000,
        };
        let state_directory = root.join("state");
        let journal_directory = root.join("journal");
        let (runtime, _) = CheckpointBoundRuntime::initialize(
            &state_directory,
            &journal_directory,
            runtime_plan.clone(),
            &consumed,
            clock,
        )
        .expect("initialize");
        assert!(matches!(
            CheckpointBoundRuntime::open(
                &state_directory,
                &journal_directory,
                runtime_plan.clone(),
                consumed.activation_certificate_sha256(),
                consumed.marker_path(),
                clock,
            ),
            Err(RuntimeError::RuntimeLocked)
        ));
        drop(runtime);
        fs::write(journal_directory.join(RUNTIME_LOCK_FILE), b"stale owner\n")
            .expect("write stale lock path");
        let (reopened, recovery) = CheckpointBoundRuntime::open(
            state_directory,
            journal_directory,
            runtime_plan,
            consumed.activation_certificate_sha256(),
            consumed.marker_path(),
            RuntimeClock {
                epoch_seconds: 1_102,
                epoch_milliseconds: 1_102_000,
            },
        )
        .expect("OS lock must recover a stale path");
        assert!(recovery.continuation_allowed);
        drop(reopened);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn completion_requires_teardown_pending_state() {
        let (root, plan, consumed) = setup("teardown");
        let clock = RuntimeClock {
            epoch_seconds: 1_101,
            epoch_milliseconds: 1_101_000,
        };
        let (mut runtime, _) = CheckpointBoundRuntime::initialize(
            root.join("state"),
            root.join("journal"),
            plan,
            &consumed,
            clock,
        )
        .expect("initialize");
        assert!(matches!(
            runtime.complete_teardown(&sha('9'), clock),
            Err(RuntimeError::TeardownNotStarted)
        ));
        runtime
            .begin_teardown("cleanup", clock)
            .expect("begin teardown");
        let completed = runtime
            .complete_teardown(&sha('9'), clock)
            .expect("complete teardown");
        assert_eq!(completed.latest.status, OperatorRunStatus::Completed);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
