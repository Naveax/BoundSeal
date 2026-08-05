#![forbid(unsafe_code)]

use std::{fmt, time::Duration};

use nxb_evidence_key_provider::{
    EvidenceKeyProvider, EvidenceKeyProviderIdentity, ProviderFailure as EvidenceProviderFailure,
    ProviderKeyMaterial, ProviderKeyRequest as EvidenceKeyRequest,
    ProviderSessionDisposition as EvidenceSessionDisposition,
    ProviderSessionOutcome as EvidenceSessionOutcome,
    ProviderSessionRequest as EvidenceSessionRequest, EVIDENCE_SEALING_KEY_BYTES,
};
use nxb_vault::SecretKind;
use nxb_vault_provider::{
    ExternalVaultProvider, ProviderFailure as VaultProviderFailure, ProviderIdentity,
    ProviderSecretRequest, ProviderSessionOutcome as VaultSessionOutcome,
    ProviderSessionRequest as VaultSessionRequest,
};
use nxb_vault_provider_process::{
    sha256_hex, ProcessProviderSession, ProcessVaultProvider, ProcessVaultProviderConfig,
    ProcessVaultProviderError, MAX_PROCESS_OPERATION_SECONDS, PROCESS_PROVIDER_PROTOCOL_VERSION,
};
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroize;

pub const PROCESS_EVIDENCE_KEY_ADAPTER_VERSION: u32 = 1;
pub const PROCESS_EVIDENCE_KEY_BACKEND_KIND: &str = "pinned-process";
pub const MAX_PROCESS_EVIDENCE_KEY_HANDLE_BYTES: usize = 512;

const SYNTHETIC_AUTHORITY: &str = "evidence-key-provider.invalid";
const SYNTHETIC_ORIGIN: &[u8] = b"https://evidence-key-provider.invalid:443";
const ADAPTER_WORKER_ID: &str = "evidence-key-process";
const ADAPTER_TENANT_ID: &str = "evidence-key-store";
const ADAPTER_ROLE_ID: &str = "sealing-key";
const FALLBACK_FAILURE_CODE: &str = "process_adapter_failure";

#[derive(Clone)]
pub struct ProcessEvidenceKeyProviderConfig {
    pub process: ProcessVaultProviderConfig,
    pub store_id: String,
    pub key_id: String,
    pub provider_handle: String,
    pub required_version_sha256: Option<String>,
    pub session_expires_at_epoch_seconds: i64,
}

impl ProcessEvidenceKeyProviderConfig {
    pub fn evidence_identity(
        &self,
    ) -> Result<EvidenceKeyProviderIdentity, ProcessEvidenceKeyProviderError> {
        validate_config(self)?;
        let provider_handle_sha256 = sha256_hex(self.provider_handle.as_bytes());
        let operation_timeout_milliseconds = timeout_milliseconds(self.process.operation_timeout)?;
        let descriptor = CapabilityDescriptor {
            adapter_version: PROCESS_EVIDENCE_KEY_ADAPTER_VERSION,
            process_protocol_version: PROCESS_PROVIDER_PROTOCOL_VERSION,
            process_identity: &self.process.expected_identity,
            executable_sha256: &self.process.executable_sha256,
            store_id: &self.store_id,
            key_id: &self.key_id,
            provider_handle_sha256: &provider_handle_sha256,
            required_version_sha256: &self.required_version_sha256,
            session_expires_at_epoch_seconds: self.session_expires_at_epoch_seconds,
            operation_timeout_milliseconds,
        };
        let bytes = serde_json::to_vec(&descriptor)
            .map_err(|_| ProcessEvidenceKeyProviderError::Serialization)?;
        Ok(EvidenceKeyProviderIdentity {
            provider_id: self.process.expected_identity.provider_id.clone(),
            backend_kind: PROCESS_EVIDENCE_KEY_BACKEND_KIND.into(),
            capability_sha256: sha256_hex(&bytes),
        })
    }
}

impl fmt::Debug for ProcessEvidenceKeyProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessEvidenceKeyProviderConfig")
            .field("process", &self.process)
            .field("store_id", &self.store_id)
            .field("key_id", &self.key_id)
            .field("provider_handle", &"<redacted>")
            .field("required_version_sha256", &self.required_version_sha256)
            .field(
                "session_expires_at_epoch_seconds",
                &self.session_expires_at_epoch_seconds,
            )
            .finish()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProcessEvidenceKeyProviderError {
    #[error("process evidence-key provider configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("process evidence-key provider capability serialization failed")]
    Serialization,
    #[error(transparent)]
    Process(#[from] ProcessVaultProviderError),
}

#[derive(Serialize)]
struct CapabilityDescriptor<'a> {
    adapter_version: u32,
    process_protocol_version: u32,
    process_identity: &'a ProviderIdentity,
    executable_sha256: &'a str,
    store_id: &'a str,
    key_id: &'a str,
    provider_handle_sha256: &'a str,
    required_version_sha256: &'a Option<String>,
    session_expires_at_epoch_seconds: i64,
    operation_timeout_milliseconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveBinding {
    plan_id: String,
    plan_sha256: String,
    store_id: String,
    policy_snapshot_sha256: String,
}

pub struct ProcessEvidenceKeyProvider {
    identity: EvidenceKeyProviderIdentity,
    inner: ProcessVaultProvider,
    configured_store_id: String,
    configured_key_id: String,
    provider_handle: String,
    required_version_sha256: Option<String>,
    session_expires_at_epoch_seconds: i64,
    session: Option<ProcessProviderSession>,
    binding: Option<ActiveBinding>,
    fetched: bool,
    finished: bool,
}

impl ProcessEvidenceKeyProvider {
    pub fn connect(
        config: ProcessEvidenceKeyProviderConfig,
    ) -> Result<Self, ProcessEvidenceKeyProviderError> {
        let identity = config.evidence_identity()?;
        let ProcessEvidenceKeyProviderConfig {
            process,
            store_id,
            key_id,
            provider_handle,
            required_version_sha256,
            session_expires_at_epoch_seconds,
        } = config;
        let inner = ProcessVaultProvider::connect(process)?;
        Ok(Self {
            identity,
            inner,
            configured_store_id: store_id,
            configured_key_id: key_id,
            provider_handle,
            required_version_sha256,
            session_expires_at_epoch_seconds,
            session: None,
            binding: None,
            fetched: false,
            finished: false,
        })
    }

    fn mapped_session_request(&self, request: &EvidenceSessionRequest) -> VaultSessionRequest {
        VaultSessionRequest {
            bootstrap_id_sha256: sha256_hex(request.plan_id.as_bytes()),
            plan_sha256: request.plan_sha256.clone(),
            discovery_plan_sha256: request.policy_snapshot_sha256.clone(),
            target_origin_sha256: sha256_hex(SYNTHETIC_ORIGIN),
            authority: SYNTHETIC_AUTHORITY.into(),
            scheme: "https".into(),
            run_id: request.plan_id.clone(),
            worker_id: ADAPTER_WORKER_ID.into(),
            account_id: request.store_id.clone(),
            tenant_id: ADAPTER_TENANT_ID.into(),
            role_id: ADAPTER_ROLE_ID.into(),
            requested_secret_count: 1,
            session_expires_at_epoch_seconds: self.session_expires_at_epoch_seconds,
        }
    }

    fn request_matches_binding(
        &self,
        request: &EvidenceKeyRequest,
        binding: &ActiveBinding,
    ) -> bool {
        request.plan_id == binding.plan_id
            && request.plan_sha256 == binding.plan_sha256
            && request.store_id == binding.store_id
            && request.policy_snapshot_sha256 == binding.policy_snapshot_sha256
            && request.store_id == self.configured_store_id
            && request.key_id == self.configured_key_id
    }
}

impl fmt::Debug for ProcessEvidenceKeyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessEvidenceKeyProvider")
            .field("identity", &self.identity)
            .field("inner", &self.inner)
            .field("configured_store_id", &self.configured_store_id)
            .field("configured_key_id", &self.configured_key_id)
            .field("provider_handle", &"<redacted>")
            .field("required_version_sha256", &self.required_version_sha256)
            .field(
                "session_expires_at_epoch_seconds",
                &self.session_expires_at_epoch_seconds,
            )
            .field("binding", &self.binding)
            .field("fetched", &self.fetched)
            .field("finished", &self.finished)
            .finish()
    }
}

impl Drop for ProcessEvidenceKeyProvider {
    fn drop(&mut self) {
        self.provider_handle.zeroize();
        if let Some(required_version_sha256) = &mut self.required_version_sha256 {
            required_version_sha256.zeroize();
        }
    }
}

impl EvidenceKeyProvider for ProcessEvidenceKeyProvider {
    fn identity(&self) -> EvidenceKeyProviderIdentity {
        self.identity.clone()
    }

    fn begin(
        &mut self,
        request: &EvidenceSessionRequest,
    ) -> Result<(), EvidenceProviderFailure> {
        if self.finished || self.session.is_some() || self.binding.is_some() {
            return Err(local_failure("process_adapter_invalid_state"));
        }
        if request.store_id != self.configured_store_id {
            return Err(local_failure("process_store_mismatch"));
        }
        let session = self
            .inner
            .begin(&self.mapped_session_request(request))
            .map_err(map_vault_failure)?;
        self.binding = Some(ActiveBinding {
            plan_id: request.plan_id.clone(),
            plan_sha256: request.plan_sha256.clone(),
            store_id: request.store_id.clone(),
            policy_snapshot_sha256: request.policy_snapshot_sha256.clone(),
        });
        self.session = Some(session);
        Ok(())
    }

    fn fetch_key(
        &mut self,
        request: &EvidenceKeyRequest,
    ) -> Result<ProviderKeyMaterial, EvidenceProviderFailure> {
        if self.finished || self.fetched {
            return Err(local_failure("process_adapter_invalid_state"));
        }
        let request_matches = {
            let binding = self
                .binding
                .as_ref()
                .ok_or_else(|| local_failure("process_adapter_invalid_state"))?;
            self.request_matches_binding(request, binding)
        };
        if !request_matches {
            return Err(local_failure("process_request_mismatch"));
        }
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| local_failure("process_adapter_invalid_state"))?;
        let material = self
            .inner
            .fetch(
                session,
                &ProviderSecretRequest {
                    logical_id: request.key_id.clone(),
                    provider_handle: self.provider_handle.clone(),
                    kind: SecretKind::ApiKey,
                    maximum_value_bytes: EVIDENCE_SEALING_KEY_BYTES as u64,
                    required_version_sha256: self.required_version_sha256.clone(),
                },
            )
            .map_err(map_vault_failure)?;
        let (version_id, mut value, expires_at_epoch_seconds) = material.into_parts();
        if self
            .required_version_sha256
            .as_ref()
            .is_some_and(|expected| sha256_hex(version_id.as_bytes()) != *expected)
        {
            value.zeroize();
            return Err(local_failure("process_version_mismatch"));
        }
        let material = ProviderKeyMaterial::new(
            request.key_id.clone(),
            version_id,
            expires_at_epoch_seconds,
            value,
        )
        .map_err(|_| local_failure("process_key_material_invalid"))?;
        self.fetched = true;
        Ok(material)
    }

    fn finish(
        &mut self,
        outcome: &EvidenceSessionOutcome,
    ) -> Result<(), EvidenceProviderFailure> {
        if self.finished {
            return Err(local_failure("process_adapter_invalid_state"));
        }
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| local_failure("process_adapter_invalid_state"))?;
        let outcome_valid = outcome.plan_sha256 == binding.plan_sha256
            && match outcome.disposition {
                EvidenceSessionDisposition::Completed => {
                    self.fetched
                        && outcome.receipt_sha256.is_some()
                        && outcome.failure_code.is_none()
                }
                EvidenceSessionDisposition::Aborted => {
                    outcome.receipt_sha256.is_none() && outcome.failure_code.is_some()
                }
            };
        let vault_outcome = if outcome_valid
            && outcome.disposition == EvidenceSessionDisposition::Completed
        {
            VaultSessionOutcome::Committed
        } else {
            VaultSessionOutcome::Aborted
        };
        let session = self
            .session
            .take()
            .ok_or_else(|| local_failure("process_adapter_invalid_state"))?;
        self.binding.take();
        self.finished = true;
        self.inner
            .finish(session, vault_outcome)
            .map_err(map_vault_failure)?;
        if !outcome_valid {
            return Err(local_failure("process_outcome_mismatch"));
        }
        Ok(())
    }
}

fn validate_config(
    config: &ProcessEvidenceKeyProviderConfig,
) -> Result<(), ProcessEvidenceKeyProviderError> {
    if !valid_identifier(&config.store_id) {
        return Err(ProcessEvidenceKeyProviderError::InvalidConfiguration(
            "store_id",
        ));
    }
    if !valid_identifier(&config.key_id) {
        return Err(ProcessEvidenceKeyProviderError::InvalidConfiguration(
            "key_id",
        ));
    }
    if !valid_provider_handle(&config.provider_handle) {
        return Err(ProcessEvidenceKeyProviderError::InvalidConfiguration(
            "provider_handle",
        ));
    }
    if config
        .required_version_sha256
        .as_ref()
        .is_some_and(|value| !valid_sha256(value))
    {
        return Err(ProcessEvidenceKeyProviderError::InvalidConfiguration(
            "required_version_sha256",
        ));
    }
    if config.session_expires_at_epoch_seconds <= 0 {
        return Err(ProcessEvidenceKeyProviderError::InvalidConfiguration(
            "session_expires_at_epoch_seconds",
        ));
    }
    if !valid_sha256(&config.process.executable_sha256) {
        return Err(ProcessEvidenceKeyProviderError::InvalidConfiguration(
            "executable_sha256",
        ));
    }
    config.process.expected_identity.validate().map_err(|_| {
        ProcessEvidenceKeyProviderError::InvalidConfiguration("expected_identity")
    })?;
    if config.process.expected_identity.provider_instance_sha256
        != config.process.executable_sha256
    {
        return Err(ProcessEvidenceKeyProviderError::InvalidConfiguration(
            "provider_instance_sha256",
        ));
    }
    if config.process.operation_timeout.is_zero()
        || config.process.operation_timeout > Duration::from_secs(MAX_PROCESS_OPERATION_SECONDS)
    {
        return Err(ProcessEvidenceKeyProviderError::InvalidConfiguration(
            "operation_timeout",
        ));
    }
    timeout_milliseconds(config.process.operation_timeout)?;
    Ok(())
}

fn timeout_milliseconds(
    timeout: Duration,
) -> Result<u64, ProcessEvidenceKeyProviderError> {
    u64::try_from(timeout.as_millis()).map_err(|_| {
        ProcessEvidenceKeyProviderError::InvalidConfiguration("operation_timeout")
    })
}

fn map_vault_failure(failure: VaultProviderFailure) -> EvidenceProviderFailure {
    local_failure(failure.code())
}

fn local_failure(code: &str) -> EvidenceProviderFailure {
    EvidenceProviderFailure::new(code.to_string()).unwrap_or_else(|_| {
        EvidenceProviderFailure::new(FALLBACK_FAILURE_CODE)
            .expect("internal fallback provider failure code is valid")
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_provider_handle(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROCESS_EVIDENCE_KEY_HANDLE_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
