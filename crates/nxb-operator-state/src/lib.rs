#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use nxb_unified_operator::{ConsumedUnifiedOperatorActivation, UnifiedOperatorPlan};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const OPERATOR_CHECKPOINT_VERSION: u32 = 1;
pub const MAX_CHECKPOINT_REASON_BYTES: usize = 512;
const CHECKPOINT_PREFIX: &str = "checkpoint-";
const CHECKPOINT_SUFFIX: &str = ".json";
const CHECKPOINT_DIGITS: usize = 20;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRunStatus {
    Ready,
    Running,
    TeardownPending,
    Completed,
    Aborted,
}

impl OperatorRunStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }

    fn requires_reason(self) -> bool {
        matches!(
            self,
            Self::TeardownPending | Self::Completed | Self::Aborted
        )
    }

    fn permits_continuation(self) -> bool {
        matches!(self, Self::Ready | Self::Running)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorStateIdentity {
    pub operator_id: String,
    pub plan_sha256: String,
    pub binding_sha256: String,
    pub activation_certificate_sha256: String,
    pub activation_expires_at_epoch_seconds: i64,
}

impl OperatorStateIdentity {
    fn validate(&self, plan: &UnifiedOperatorPlan) -> Result<(), OperatorStateError> {
        if self.operator_id != plan.operator_id
            || self.plan_sha256 != plan.plan_sha256
            || self.binding_sha256 != plan.binding_sha256
        {
            return Err(OperatorStateError::IdentityMismatch);
        }
        validate_sha256(
            &self.activation_certificate_sha256,
            "activation_certificate_sha256",
        )?;
        if self.activation_expires_at_epoch_seconds <= plan.created_at_epoch_seconds
            || self.activation_expires_at_epoch_seconds > plan.expires_at_epoch_seconds
        {
            return Err(OperatorStateError::InvalidActivationExpiry);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorCounters {
    pub requests_completed: u64,
    pub total_response_bytes: u64,
    pub last_response_body_bytes: u64,
    pub maximum_depth_observed: u16,
    pub evidence_bytes: u64,
}

impl OperatorCounters {
    fn validate_against_plan(&self, plan: &UnifiedOperatorPlan) -> Result<(), OperatorStateError> {
        if self.requests_completed > plan.binding.maximum_requests {
            return Err(OperatorStateError::RequestBudgetExceeded);
        }
        if self.total_response_bytes > plan.binding.maximum_total_response_bytes {
            return Err(OperatorStateError::ResponseBudgetExceeded);
        }
        if self.last_response_body_bytes > plan.binding.maximum_response_body_bytes {
            return Err(OperatorStateError::ResponseBodyBudgetExceeded);
        }
        if self.maximum_depth_observed > plan.binding.maximum_depth {
            return Err(OperatorStateError::DepthBudgetExceeded);
        }
        Ok(())
    }

    fn validate_monotonic(&self, previous: &Self) -> Result<(), OperatorStateError> {
        if self.requests_completed < previous.requests_completed
            || self.total_response_bytes < previous.total_response_bytes
            || self.maximum_depth_observed < previous.maximum_depth_observed
            || self.evidence_bytes < previous.evidence_bytes
        {
            return Err(OperatorStateError::CounterRegression);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorCheckpoint {
    pub version: u32,
    pub sequence: u64,
    pub identity: OperatorStateIdentity,
    pub status: OperatorRunStatus,
    pub counters: OperatorCounters,
    pub created_at_epoch_seconds: i64,
    pub stop_reason: Option<String>,
    pub previous_checkpoint_sha256: Option<String>,
    pub checkpoint_sha256: String,
}

impl OperatorCheckpoint {
    fn initial(
        plan: &UnifiedOperatorPlan,
        consumed: &ConsumedUnifiedOperatorActivation,
        now_epoch_seconds: i64,
    ) -> Self {
        Self {
            version: OPERATOR_CHECKPOINT_VERSION,
            sequence: 0,
            identity: OperatorStateIdentity {
                operator_id: plan.operator_id.clone(),
                plan_sha256: plan.plan_sha256.clone(),
                binding_sha256: plan.binding_sha256.clone(),
                activation_certificate_sha256: consumed.activation_certificate_sha256().to_owned(),
                activation_expires_at_epoch_seconds: consumed.expires_at_epoch_seconds(),
            },
            status: OperatorRunStatus::Ready,
            counters: OperatorCounters::default(),
            created_at_epoch_seconds: now_epoch_seconds,
            stop_reason: None,
            previous_checkpoint_sha256: None,
            checkpoint_sha256: String::new(),
        }
    }

    fn validate_static(&self, plan: &UnifiedOperatorPlan) -> Result<(), OperatorStateError> {
        if self.version != OPERATOR_CHECKPOINT_VERSION {
            return Err(OperatorStateError::UnsupportedCheckpointVersion);
        }
        self.identity.validate(plan)?;
        self.counters.validate_against_plan(plan)?;
        if self.created_at_epoch_seconds <= 0 {
            return Err(OperatorStateError::InvalidCheckpointTime);
        }
        match (&self.stop_reason, self.status.requires_reason()) {
            (Some(reason), true) => validate_reason(reason)?,
            (None, false) => {}
            _ => return Err(OperatorStateError::InvalidStopReason),
        }
        if self.sequence == 0 {
            if self.status != OperatorRunStatus::Ready
                || self.counters != OperatorCounters::default()
                || self.previous_checkpoint_sha256.is_some()
            {
                return Err(OperatorStateError::InvalidInitialCheckpoint);
            }
        } else {
            let previous = self
                .previous_checkpoint_sha256
                .as_deref()
                .ok_or(OperatorStateError::MissingPreviousCheckpointHash)?;
            validate_sha256(previous, "previous_checkpoint_sha256")?;
        }
        validate_sha256(&self.checkpoint_sha256, "checkpoint_sha256")?;
        if self.checkpoint_sha256 != self.calculate_sha256()? {
            return Err(OperatorStateError::CheckpointDigestMismatch);
        }
        Ok(())
    }

    fn calculate_sha256(&self) -> Result<String, OperatorStateError> {
        let mut material = self.clone();
        material.checkpoint_sha256.clear();
        hash_serializable(&material)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointUpdate {
    pub status: OperatorRunStatus,
    pub counters: OperatorCounters,
    pub stop_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RecoveredOperatorState {
    pub latest: OperatorCheckpoint,
    pub checkpoint_count: u64,
    pub state_file_bytes: u64,
    pub continuation_allowed: bool,
}

pub struct OperatorStateStore {
    directory: PathBuf,
    plan: UnifiedOperatorPlan,
    activation_certificate_sha256: String,
    activation_marker_path: PathBuf,
}

impl fmt::Debug for OperatorStateStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorStateStore")
            .field("directory", &self.directory)
            .field("plan_sha256", &self.plan.plan_sha256)
            .field("binding_sha256", &self.plan.binding_sha256)
            .field(
                "activation_certificate_sha256",
                &self.activation_certificate_sha256,
            )
            .field("activation_marker_path", &self.activation_marker_path)
            .finish()
    }
}

impl OperatorStateStore {
    pub fn initialize(
        directory: impl Into<PathBuf>,
        plan: UnifiedOperatorPlan,
        consumed: &ConsumedUnifiedOperatorActivation,
        now_epoch_seconds: i64,
    ) -> Result<(Self, RecoveredOperatorState), OperatorStateError> {
        plan.verify(now_epoch_seconds)?;
        if consumed.plan_sha256() != plan.plan_sha256
            || consumed.binding_sha256() != plan.binding_sha256
            || consumed.expires_at_epoch_seconds() < now_epoch_seconds
            || !consumed.marker_path().is_file()
        {
            return Err(OperatorStateError::ConsumedActivationMismatch);
        }
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(io_error)?;
        if fs::read_dir(&directory).map_err(io_error)?.next().is_some() {
            return Err(OperatorStateError::StateDirectoryNotEmpty);
        }
        let store = Self {
            directory,
            plan,
            activation_certificate_sha256: consumed.activation_certificate_sha256().to_owned(),
            activation_marker_path: consumed.marker_path().to_path_buf(),
        };
        let mut initial = OperatorCheckpoint::initial(&store.plan, consumed, now_epoch_seconds);
        initial.checkpoint_sha256 = initial.calculate_sha256()?;
        let bytes = checkpoint_bytes(&initial)?;
        if bytes.len() as u64 > store.plan.maximum_workspace_bytes {
            return Err(OperatorStateError::WorkspaceBudgetExceeded);
        }
        store.publish_checkpoint(&initial, &bytes)?;
        let recovered = store.recover(now_epoch_seconds)?;
        Ok((store, recovered))
    }

    pub fn open(
        directory: impl Into<PathBuf>,
        plan: UnifiedOperatorPlan,
        activation_certificate_sha256: impl Into<String>,
        activation_marker_path: impl Into<PathBuf>,
        now_epoch_seconds: i64,
    ) -> Result<(Self, RecoveredOperatorState), OperatorStateError> {
        verify_plan_digest(&plan)?;
        let activation_certificate_sha256 = activation_certificate_sha256.into();
        validate_sha256(
            &activation_certificate_sha256,
            "activation_certificate_sha256",
        )?;
        let activation_marker_path = activation_marker_path.into();
        if !activation_marker_path.is_file() {
            return Err(OperatorStateError::ActivationMarkerMissing);
        }
        let store = Self {
            directory: directory.into(),
            plan,
            activation_certificate_sha256,
            activation_marker_path,
        };
        let recovered = store.recover(now_epoch_seconds)?;
        Ok((store, recovered))
    }

    pub fn recover(
        &self,
        now_epoch_seconds: i64,
    ) -> Result<RecoveredOperatorState, OperatorStateError> {
        verify_plan_digest(&self.plan)?;
        if !self.activation_marker_path.is_file() {
            return Err(OperatorStateError::ActivationMarkerMissing);
        }
        let entries = checkpoint_entries(&self.directory)?;
        if entries.is_empty() {
            return Err(OperatorStateError::CheckpointChainEmpty);
        }
        let mut previous: Option<OperatorCheckpoint> = None;
        let mut state_file_bytes = 0_u64;
        for (expected_sequence, (sequence, path)) in entries.into_iter().enumerate() {
            let expected_sequence = expected_sequence as u64;
            if sequence != expected_sequence {
                return Err(OperatorStateError::CheckpointSequenceGap);
            }
            let bytes = fs::read(&path).map_err(io_error)?;
            state_file_bytes = state_file_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(OperatorStateError::WorkspaceBudgetExceeded)?;
            let checkpoint: OperatorCheckpoint = serde_json::from_slice(&bytes)
                .map_err(|error| OperatorStateError::Serialization(error.to_string()))?;
            if bytes != checkpoint_bytes(&checkpoint)? {
                return Err(OperatorStateError::NonCanonicalCheckpoint);
            }
            if checkpoint.sequence != sequence {
                return Err(OperatorStateError::CheckpointSequenceMismatch);
            }
            checkpoint.validate_static(&self.plan)?;
            if checkpoint.identity.activation_certificate_sha256
                != self.activation_certificate_sha256
            {
                return Err(OperatorStateError::IdentityMismatch);
            }
            if let Some(previous_checkpoint) = &previous {
                validate_transition(previous_checkpoint, &checkpoint, &self.plan)?;
            }
            let accounted = checkpoint
                .counters
                .evidence_bytes
                .checked_add(state_file_bytes)
                .ok_or(OperatorStateError::WorkspaceBudgetExceeded)?;
            if accounted > self.plan.maximum_workspace_bytes {
                return Err(OperatorStateError::WorkspaceBudgetExceeded);
            }
            previous = Some(checkpoint);
        }
        let latest = previous.ok_or(OperatorStateError::CheckpointChainEmpty)?;
        let continuation_allowed = latest.status.permits_continuation()
            && now_epoch_seconds >= self.plan.created_at_epoch_seconds
            && now_epoch_seconds <= self.plan.expires_at_epoch_seconds
            && now_epoch_seconds <= latest.identity.activation_expires_at_epoch_seconds;
        Ok(RecoveredOperatorState {
            checkpoint_count: latest.sequence + 1,
            latest,
            state_file_bytes,
            continuation_allowed,
        })
    }

    pub fn append(
        &self,
        update: CheckpointUpdate,
        now_epoch_seconds: i64,
    ) -> Result<RecoveredOperatorState, OperatorStateError> {
        let recovered = self.recover(now_epoch_seconds)?;
        let previous = &recovered.latest;
        if previous.status.is_terminal() {
            return Err(OperatorStateError::TerminalState);
        }
        if update.status.permits_continuation()
            || update.counters.requests_completed > previous.counters.requests_completed
            || update.counters.total_response_bytes > previous.counters.total_response_bytes
            || update.counters.maximum_depth_observed > previous.counters.maximum_depth_observed
        {
            self.plan.verify(now_epoch_seconds)?;
            if now_epoch_seconds > previous.identity.activation_expires_at_epoch_seconds {
                return Err(OperatorStateError::ActivationExpired);
            }
        }
        let mut checkpoint = OperatorCheckpoint {
            version: OPERATOR_CHECKPOINT_VERSION,
            sequence: previous.sequence + 1,
            identity: previous.identity.clone(),
            status: update.status,
            counters: update.counters,
            created_at_epoch_seconds: now_epoch_seconds,
            stop_reason: update.stop_reason,
            previous_checkpoint_sha256: Some(previous.checkpoint_sha256.clone()),
            checkpoint_sha256: String::new(),
        };
        validate_transition(previous, &checkpoint, &self.plan)?;
        checkpoint.checkpoint_sha256 = checkpoint.calculate_sha256()?;
        let bytes = checkpoint_bytes(&checkpoint)?;
        let accounted = checkpoint
            .counters
            .evidence_bytes
            .checked_add(recovered.state_file_bytes)
            .and_then(|value| value.checked_add(bytes.len() as u64))
            .ok_or(OperatorStateError::WorkspaceBudgetExceeded)?;
        if accounted > self.plan.maximum_workspace_bytes {
            return Err(OperatorStateError::WorkspaceBudgetExceeded);
        }
        self.publish_checkpoint(&checkpoint, &bytes)?;
        self.recover(now_epoch_seconds)
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn publish_checkpoint(
        &self,
        checkpoint: &OperatorCheckpoint,
        bytes: &[u8],
    ) -> Result<(), OperatorStateError> {
        let final_path = self
            .directory
            .join(checkpoint_file_name(checkpoint.sequence));
        let temporary_path = self.directory.join(format!(
            ".{}.{}.tmp",
            checkpoint_file_name(checkpoint.sequence),
            std::process::id()
        ));
        let publication = (|| -> Result<(), OperatorStateError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary_path)
                .map_err(io_error)?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(io_error)?;
            fs::hard_link(&temporary_path, &final_path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    OperatorStateError::CheckpointAlreadyExists
                } else {
                    io_error(error)
                }
            })?;
            Ok(())
        })();
        if let Err(error) = publication {
            let _ = fs::remove_file(&temporary_path);
            return Err(error);
        }
        fs::remove_file(&temporary_path).map_err(io_error)
    }
}

fn validate_transition(
    previous: &OperatorCheckpoint,
    next: &OperatorCheckpoint,
    plan: &UnifiedOperatorPlan,
) -> Result<(), OperatorStateError> {
    if next.sequence != previous.sequence + 1
        || next.previous_checkpoint_sha256.as_deref() != Some(previous.checkpoint_sha256.as_str())
    {
        return Err(OperatorStateError::CheckpointChainMismatch);
    }
    if next.identity != previous.identity {
        return Err(OperatorStateError::IdentityMismatch);
    }
    if next.created_at_epoch_seconds < previous.created_at_epoch_seconds {
        return Err(OperatorStateError::CheckpointTimeRegression);
    }
    next.counters.validate_against_plan(plan)?;
    next.counters.validate_monotonic(&previous.counters)?;
    let request_delta = next
        .counters
        .requests_completed
        .saturating_sub(previous.counters.requests_completed);
    if request_delta > plan.checkpoint_interval_requests {
        return Err(OperatorStateError::CheckpointIntervalExceeded);
    }
    let transition_allowed = matches!(
        (previous.status, next.status),
        (OperatorRunStatus::Ready, OperatorRunStatus::Running)
            | (OperatorRunStatus::Ready, OperatorRunStatus::TeardownPending)
            | (OperatorRunStatus::Ready, OperatorRunStatus::Aborted)
            | (OperatorRunStatus::Running, OperatorRunStatus::Running)
            | (
                OperatorRunStatus::Running,
                OperatorRunStatus::TeardownPending
            )
            | (OperatorRunStatus::Running, OperatorRunStatus::Aborted)
            | (
                OperatorRunStatus::TeardownPending,
                OperatorRunStatus::Completed
            )
            | (
                OperatorRunStatus::TeardownPending,
                OperatorRunStatus::Aborted
            )
    );
    if !transition_allowed {
        return Err(OperatorStateError::InvalidStatusTransition);
    }
    if !next.status.permits_continuation() && next.counters != previous.counters {
        return Err(OperatorStateError::CleanupCountersChanged);
    }
    match (&next.stop_reason, next.status.requires_reason()) {
        (Some(reason), true) => validate_reason(reason)?,
        (None, false) => {}
        _ => return Err(OperatorStateError::InvalidStopReason),
    }
    Ok(())
}

fn checkpoint_entries(directory: &Path) -> Result<BTreeMap<u64, PathBuf>, OperatorStateError> {
    let mut entries = BTreeMap::new();
    for entry in fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let file_type = entry.file_type().map_err(io_error)?;
        if !file_type.is_file() {
            return Err(OperatorStateError::UnexpectedStateEntry);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| OperatorStateError::UnexpectedStateEntry)?;
        if name.starts_with('.') && name.ends_with(".tmp") {
            return Err(OperatorStateError::IncompleteCheckpointPublication);
        }
        let sequence = parse_checkpoint_file_name(&name)?;
        if entries.insert(sequence, entry.path()).is_some() {
            return Err(OperatorStateError::DuplicateCheckpointSequence);
        }
    }
    Ok(entries)
}

fn checkpoint_file_name(sequence: u64) -> String {
    format!("{CHECKPOINT_PREFIX}{sequence:020}{CHECKPOINT_SUFFIX}")
}

fn parse_checkpoint_file_name(name: &str) -> Result<u64, OperatorStateError> {
    let digits = name
        .strip_prefix(CHECKPOINT_PREFIX)
        .and_then(|value| value.strip_suffix(CHECKPOINT_SUFFIX))
        .ok_or(OperatorStateError::UnexpectedStateEntry)?;
    if digits.len() != CHECKPOINT_DIGITS || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OperatorStateError::UnexpectedStateEntry);
    }
    digits
        .parse()
        .map_err(|_| OperatorStateError::UnexpectedStateEntry)
}

fn checkpoint_bytes(checkpoint: &OperatorCheckpoint) -> Result<Vec<u8>, OperatorStateError> {
    let mut bytes = serde_json::to_vec_pretty(checkpoint)
        .map_err(|error| OperatorStateError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn verify_plan_digest(plan: &UnifiedOperatorPlan) -> Result<(), OperatorStateError> {
    plan.validate()?;
    if plan.plan_sha256 != plan.calculate_sha256()? {
        return Err(OperatorStateError::PlanDigestMismatch);
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<(), OperatorStateError> {
    if reason.is_empty()
        || reason.len() > MAX_CHECKPOINT_REASON_BYTES
        || reason.chars().any(char::is_control)
    {
        return Err(OperatorStateError::InvalidStopReason);
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), OperatorStateError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OperatorStateError::InvalidSha256(field.to_owned()));
    }
    Ok(())
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, OperatorStateError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| OperatorStateError::Serialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
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

fn io_error(error: std::io::Error) -> OperatorStateError {
    OperatorStateError::Io(error.to_string())
}

#[derive(Debug, Error)]
pub enum OperatorStateError {
    #[error("unsupported operator checkpoint version")]
    UnsupportedCheckpointVersion,
    #[error("unified operator plan digest mismatch")]
    PlanDigestMismatch,
    #[error("operator-state identity does not match the unified plan or activation")]
    IdentityMismatch,
    #[error("consumed activation does not match the unified plan")]
    ConsumedActivationMismatch,
    #[error("activation expiration is invalid")]
    InvalidActivationExpiry,
    #[error("activation expired before continuation")]
    ActivationExpired,
    #[error("consumed activation marker is missing")]
    ActivationMarkerMissing,
    #[error("state directory must be empty during initialization")]
    StateDirectoryNotEmpty,
    #[error("checkpoint chain is empty")]
    CheckpointChainEmpty,
    #[error("checkpoint sequence contains a gap")]
    CheckpointSequenceGap,
    #[error("checkpoint sequence does not match its file name")]
    CheckpointSequenceMismatch,
    #[error("checkpoint sequence is duplicated")]
    DuplicateCheckpointSequence,
    #[error("checkpoint chain binding is invalid")]
    CheckpointChainMismatch,
    #[error("checkpoint is missing its previous-checkpoint hash")]
    MissingPreviousCheckpointHash,
    #[error("checkpoint SHA-256 does not match its contents")]
    CheckpointDigestMismatch,
    #[error("checkpoint bytes are not in canonical serialized form")]
    NonCanonicalCheckpoint,
    #[error("checkpoint already exists")]
    CheckpointAlreadyExists,
    #[error("checkpoint publication was interrupted")]
    IncompleteCheckpointPublication,
    #[error("unexpected entry exists in the dedicated state directory")]
    UnexpectedStateEntry,
    #[error("initial checkpoint is invalid")]
    InvalidInitialCheckpoint,
    #[error("checkpoint timestamp is invalid")]
    InvalidCheckpointTime,
    #[error("checkpoint timestamp regressed")]
    CheckpointTimeRegression,
    #[error("request budget exceeded")]
    RequestBudgetExceeded,
    #[error("response byte budget exceeded")]
    ResponseBudgetExceeded,
    #[error("single-response body budget exceeded")]
    ResponseBodyBudgetExceeded,
    #[error("discovery depth budget exceeded")]
    DepthBudgetExceeded,
    #[error("workspace byte budget exceeded")]
    WorkspaceBudgetExceeded,
    #[error("checkpoint request interval exceeded")]
    CheckpointIntervalExceeded,
    #[error("checkpoint counters regressed")]
    CounterRegression,
    #[error("cleanup or terminal checkpoint changed execution counters")]
    CleanupCountersChanged,
    #[error("checkpoint status transition is invalid")]
    InvalidStatusTransition,
    #[error("terminal state cannot be advanced")]
    TerminalState,
    #[error("checkpoint stop reason is invalid")]
    InvalidStopReason,
    #[error("invalid SHA-256 field: {0}")]
    InvalidSha256(String),
    #[error("state serialization failed: {0}")]
    Serialization(String),
    #[error("state I/O failed: {0}")]
    Io(String),
    #[error(transparent)]
    Unified(#[from] nxb_unified_operator::UnifiedOperatorError),
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
        Ed25519KeyPair::from_seed_unchecked(&[11_u8; 32]).expect("deterministic key")
    }

    fn plan(maximum_workspace_bytes: u64) -> UnifiedOperatorPlan {
        let key_pair = key_pair();
        UnifiedOperatorPlan::build(UnifiedOperatorPlanParameters {
            operator_id: "operator-state-test".into(),
            binding: UnifiedComponentBinding {
                discovery_plan_sha256: sha('a'),
                policy_sha256: sha('b'),
                target_origin_sha256: sha('c'),
                discovery_session_id: "discovery-1".into(),
                authority: "example.com".into(),
                run_id: "run-1".into(),
                worker_id: "worker-1".into(),
                account_id: "account-1".into(),
                tenant_id: "tenant-1".into(),
                role_id: "role-1".into(),
                session_injection_manifest_sha256: sha('d'),
                external_vault_plan_sha256: sha('e'),
                external_vault_bootstrap_receipt_sha256: sha('f'),
                external_session_id_sha256: sha('1'),
                provider_id: "provider-1".into(),
                provider_instance_sha256: sha('2'),
                provider_capability_sha256: sha('3'),
                secret_binding_root_sha256: sha('4'),
                secret_count: 2,
                allowed_path_prefixes: BTreeSet::from(["/app".into()]),
                maximum_requests: 8,
                maximum_depth: 2,
                maximum_response_body_bytes: 1024,
                maximum_total_response_bytes: 4096,
                minimum_request_interval_milliseconds: 1000,
                maximum_concurrency: 1,
                component_expires_at_epoch_seconds: 2_000,
            },
            checkpoint_interval_requests: 2,
            maximum_workspace_bytes,
            created_at_epoch_seconds: 1_000,
            expires_at_epoch_seconds: 1_900,
            activation_public_key: key_pair.public_key().as_ref().to_vec(),
        })
        .expect("valid plan")
    }

    fn certificate(plan: &UnifiedOperatorPlan) -> UnifiedOperatorActivationCertificate {
        let key_pair = key_pair();
        let payload = UnifiedOperatorActivationPayload::template(
            "operator-state-activation",
            plan,
            1_050,
            1_800,
        )
        .expect("payload");
        let signature = key_pair.sign(&payload.signing_bytes().expect("signing bytes"));
        UnifiedOperatorActivationCertificate {
            payload,
            signature_hex: lower_hex(signature.as_ref()),
        }
    }

    fn unique_directory(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nxb-operator-state-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn initialized_store(
        label: &str,
        maximum_workspace_bytes: u64,
    ) -> (PathBuf, OperatorStateStore) {
        let root = unique_directory(label);
        let activation_directory = root.join("activation");
        let state_directory = root.join("state");
        let plan = plan(maximum_workspace_bytes);
        let certificate = certificate(&plan);
        let consumed = consume_activation_once(
            &activation_directory,
            &plan,
            &certificate,
            key_pair().public_key().as_ref(),
            1_100,
        )
        .expect("consume activation");
        let (store, recovered) =
            OperatorStateStore::initialize(&state_directory, plan, &consumed, 1_100)
                .expect("initialize store");
        assert_eq!(recovered.latest.status, OperatorRunStatus::Ready);
        (root, store)
    }

    #[test]
    fn checkpoint_chain_round_trips_and_resumes() {
        let (root, store) = initialized_store("round-trip", 1024 * 1024);
        let recovered = store
            .append(
                CheckpointUpdate {
                    status: OperatorRunStatus::Running,
                    counters: OperatorCounters {
                        requests_completed: 2,
                        total_response_bytes: 512,
                        last_response_body_bytes: 256,
                        maximum_depth_observed: 1,
                        evidence_bytes: 128,
                    },
                    stop_reason: None,
                },
                1_200,
            )
            .expect("append running checkpoint");
        assert_eq!(recovered.latest.sequence, 1);
        assert!(recovered.continuation_allowed);
        let (_, opened) = OperatorStateStore::open(
            store.directory(),
            store.plan.clone(),
            store.activation_certificate_sha256.clone(),
            store.activation_marker_path.clone(),
            1_300,
        )
        .expect("open state");
        assert_eq!(opened.latest, recovered.latest);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn request_and_workspace_budgets_fail_closed() {
        let (root, store) = initialized_store("budget", 1024 * 1024);
        let request_error = store
            .append(
                CheckpointUpdate {
                    status: OperatorRunStatus::Running,
                    counters: OperatorCounters {
                        requests_completed: 3,
                        ..OperatorCounters::default()
                    },
                    stop_reason: None,
                },
                1_200,
            )
            .expect_err("checkpoint interval must fail");
        assert!(matches!(
            request_error,
            OperatorStateError::CheckpointIntervalExceeded
        ));
        let workspace_error = store
            .append(
                CheckpointUpdate {
                    status: OperatorRunStatus::Running,
                    counters: OperatorCounters {
                        evidence_bytes: 1024 * 1024,
                        ..OperatorCounters::default()
                    },
                    stop_reason: None,
                },
                1_200,
            )
            .expect_err("workspace accounting must fail");
        assert!(matches!(
            workspace_error,
            OperatorStateError::WorkspaceBudgetExceeded
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn terminal_state_cannot_be_advanced() {
        let (root, store) = initialized_store("terminal", 1024 * 1024);
        store
            .append(
                CheckpointUpdate {
                    status: OperatorRunStatus::Aborted,
                    counters: OperatorCounters::default(),
                    stop_reason: Some("operator requested stop".into()),
                },
                2_100,
            )
            .expect("cleanup is allowed after expiry");
        assert!(matches!(
            store
                .append(
                    CheckpointUpdate {
                        status: OperatorRunStatus::Running,
                        counters: OperatorCounters::default(),
                        stop_reason: None,
                    },
                    2_101,
                )
                .expect_err("terminal state must not advance"),
            OperatorStateError::TerminalState
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn tampered_checkpoint_is_rejected() {
        let (root, store) = initialized_store("tamper", 1024 * 1024);
        let path = store.directory().join(checkpoint_file_name(0));
        let mut bytes = fs::read(&path).expect("read checkpoint");
        let position = bytes
            .iter()
            .position(|byte| *byte == b'0')
            .expect("checkpoint contains zero");
        bytes[position] = b'1';
        fs::write(&path, bytes).expect("tamper checkpoint");
        assert!(store.recover(1_200).is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }
    #[test]
    fn missing_activation_marker_blocks_recovery() {
        let (root, store) = initialized_store("marker", 1024 * 1024);
        fs::remove_file(&store.activation_marker_path).expect("remove marker");
        assert!(matches!(
            store.recover(1_200).expect_err("missing marker must fail"),
            OperatorStateError::ActivationMarkerMissing
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }
    #[test]
    fn noncanonical_checkpoint_bytes_are_rejected() {
        let (root, store) = initialized_store("noncanonical", 1024 * 1024);
        let path = store.directory().join(checkpoint_file_name(0));
        let mut bytes = fs::read(&path).expect("read checkpoint");
        bytes.push(b'\n');
        fs::write(&path, bytes).expect("rewrite checkpoint");
        assert!(matches!(
            store
                .recover(1_200)
                .expect_err("noncanonical bytes must fail"),
            OperatorStateError::NonCanonicalCheckpoint
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn completion_requires_teardown_checkpoint() {
        let (root, store) = initialized_store("teardown-order", 1024 * 1024);
        store
            .append(
                CheckpointUpdate {
                    status: OperatorRunStatus::Running,
                    counters: OperatorCounters::default(),
                    stop_reason: None,
                },
                1_150,
            )
            .expect("enter running state");
        assert!(matches!(
            store
                .append(
                    CheckpointUpdate {
                        status: OperatorRunStatus::Completed,
                        counters: OperatorCounters::default(),
                        stop_reason: Some("completed".into()),
                    },
                    1_160,
                )
                .expect_err("direct completion must fail"),
            OperatorStateError::InvalidStatusTransition
        ));
        store
            .append(
                CheckpointUpdate {
                    status: OperatorRunStatus::TeardownPending,
                    counters: OperatorCounters::default(),
                    stop_reason: Some("teardown started".into()),
                },
                1_170,
            )
            .expect("enter teardown");
        store
            .append(
                CheckpointUpdate {
                    status: OperatorRunStatus::Completed,
                    counters: OperatorCounters::default(),
                    stop_reason: Some("teardown completed".into()),
                },
                1_180,
            )
            .expect("complete after teardown");
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn interrupted_publication_is_rejected() {
        let (root, store) = initialized_store("temporary", 1024 * 1024);
        fs::write(store.directory().join(".checkpoint-000.tmp"), b"partial")
            .expect("write temp file");
        assert!(matches!(
            store
                .recover(1_200)
                .expect_err("temporary file must fail closed"),
            OperatorStateError::IncompleteCheckpointPublication
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
