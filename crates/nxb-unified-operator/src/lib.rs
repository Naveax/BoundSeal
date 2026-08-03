use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const UNIFIED_OPERATOR_PLAN_VERSION: u32 = 1;
pub const UNIFIED_OPERATOR_ACTIVATION_VERSION: u32 = 1;
pub const MAX_UNIFIED_OPERATOR_LIFETIME_SECONDS: i64 = 4 * 60 * 60;
pub const MAX_UNIFIED_OPERATOR_ACTIVATION_SECONDS: i64 = 60 * 60;
pub const MIN_UNIFIED_OPERATOR_WORKSPACE_BYTES: u64 = 1024 * 1024;
pub const MAX_UNIFIED_OPERATOR_WORKSPACE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_UNIFIED_OPERATOR_REQUESTS: u64 = 128;
pub const MAX_UNIFIED_OPERATOR_DEPTH: u16 = 4;
pub const MAX_UNIFIED_OPERATOR_RESPONSE_BODY_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_UNIFIED_OPERATOR_TOTAL_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
pub const MIN_UNIFIED_OPERATOR_REQUEST_INTERVAL_MILLISECONDS: u64 = 200;
pub const MAX_UNIFIED_OPERATOR_PATH_PREFIXES: usize = 32;
pub const MAX_UNIFIED_OPERATOR_SECRET_COUNT: u64 = 64;

const DENIED_PATH_TOKENS: &[&str] = &[
    "delete",
    "destroy",
    "disable",
    "drop",
    "logoff",
    "logout",
    "remove",
    "reset",
    "revoke",
    "shutdown",
    "signout",
    "terminate",
    "unsubscribe",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnifiedComponentBinding {
    pub discovery_plan_sha256: String,
    pub policy_sha256: String,
    pub target_origin_sha256: String,
    pub discovery_session_id: String,
    pub authority: String,
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub session_injection_manifest_sha256: String,
    pub external_vault_plan_sha256: String,
    pub external_vault_bootstrap_receipt_sha256: String,
    pub external_session_id_sha256: String,
    pub provider_id: String,
    pub provider_instance_sha256: String,
    pub provider_capability_sha256: String,
    pub secret_binding_root_sha256: String,
    pub secret_count: u64,
    pub allowed_path_prefixes: BTreeSet<String>,
    pub maximum_requests: u64,
    pub maximum_depth: u16,
    pub maximum_response_body_bytes: u64,
    pub maximum_total_response_bytes: u64,
    pub minimum_request_interval_milliseconds: u64,
    pub maximum_concurrency: u16,
    pub component_expires_at_epoch_seconds: i64,
}

impl UnifiedComponentBinding {
    pub fn validate(&self) -> Result<(), UnifiedOperatorError> {
        for (value, field) in [
            (&self.discovery_plan_sha256, "discovery_plan_sha256"),
            (&self.policy_sha256, "policy_sha256"),
            (&self.target_origin_sha256, "target_origin_sha256"),
            (
                &self.session_injection_manifest_sha256,
                "session_injection_manifest_sha256",
            ),
            (&self.external_vault_plan_sha256, "external_vault_plan_sha256"),
            (
                &self.external_vault_bootstrap_receipt_sha256,
                "external_vault_bootstrap_receipt_sha256",
            ),
            (&self.external_session_id_sha256, "external_session_id_sha256"),
            (&self.provider_instance_sha256, "provider_instance_sha256"),
            (&self.provider_capability_sha256, "provider_capability_sha256"),
            (&self.secret_binding_root_sha256, "secret_binding_root_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        for (value, field) in [
            (&self.discovery_session_id, "discovery_session_id"),
            (&self.run_id, "run_id"),
            (&self.worker_id, "worker_id"),
            (&self.account_id, "account_id"),
            (&self.tenant_id, "tenant_id"),
            (&self.role_id, "role_id"),
            (&self.provider_id, "provider_id"),
        ] {
            validate_identifier(value, field)?;
        }
        validate_authority(&self.authority)?;
        if self.secret_count == 0 || self.secret_count > MAX_UNIFIED_OPERATOR_SECRET_COUNT {
            return Err(UnifiedOperatorError::InvalidSecretCount);
        }
        if self.allowed_path_prefixes.is_empty()
            || self.allowed_path_prefixes.len() > MAX_UNIFIED_OPERATOR_PATH_PREFIXES
        {
            return Err(UnifiedOperatorError::InvalidPathScope);
        }
        for path in &self.allowed_path_prefixes {
            validate_passive_path(path)?;
        }
        if self.maximum_requests == 0 || self.maximum_requests > MAX_UNIFIED_OPERATOR_REQUESTS {
            return Err(UnifiedOperatorError::InvalidRequestBudget);
        }
        if self.maximum_depth > MAX_UNIFIED_OPERATOR_DEPTH {
            return Err(UnifiedOperatorError::InvalidDepthBudget);
        }
        if self.maximum_response_body_bytes == 0
            || self.maximum_response_body_bytes > MAX_UNIFIED_OPERATOR_RESPONSE_BODY_BYTES
        {
            return Err(UnifiedOperatorError::InvalidResponseBodyBudget);
        }
        if self.maximum_total_response_bytes < self.maximum_response_body_bytes
            || self.maximum_total_response_bytes > MAX_UNIFIED_OPERATOR_TOTAL_RESPONSE_BYTES
        {
            return Err(UnifiedOperatorError::InvalidTotalResponseBudget);
        }
        if self.minimum_request_interval_milliseconds
            < MIN_UNIFIED_OPERATOR_REQUEST_INTERVAL_MILLISECONDS
        {
            return Err(UnifiedOperatorError::InvalidRequestInterval);
        }
        if self.maximum_concurrency != 1 {
            return Err(UnifiedOperatorError::InvalidConcurrency);
        }
        if self.component_expires_at_epoch_seconds <= 0 {
            return Err(UnifiedOperatorError::InvalidComponentExpiry);
        }
        Ok(())
    }

    pub fn calculate_sha256(&self) -> Result<String, UnifiedOperatorError> {
        self.validate()?;
        hash_serializable(self)
    }
}

#[derive(Debug, Clone)]
pub struct UnifiedOperatorPlanParameters {
    pub operator_id: String,
    pub binding: UnifiedComponentBinding,
    pub checkpoint_interval_requests: u64,
    pub maximum_workspace_bytes: u64,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub activation_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnifiedOperatorPlan {
    pub version: u32,
    pub operator_id: String,
    pub binding: UnifiedComponentBinding,
    pub binding_sha256: String,
    pub checkpoint_interval_requests: u64,
    pub maximum_workspace_bytes: u64,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub activation_key_id_sha256: String,
    pub plan_sha256: String,
}

impl UnifiedOperatorPlan {
    pub fn build(parameters: UnifiedOperatorPlanParameters) -> Result<Self, UnifiedOperatorError> {
        if parameters.activation_public_key.len() != 32 {
            return Err(UnifiedOperatorError::InvalidActivationPublicKey);
        }
        parameters.binding.validate()?;
        let binding_sha256 = parameters.binding.calculate_sha256()?;
        let mut plan = Self {
            version: UNIFIED_OPERATOR_PLAN_VERSION,
            operator_id: parameters.operator_id,
            binding: parameters.binding,
            binding_sha256,
            checkpoint_interval_requests: parameters.checkpoint_interval_requests,
            maximum_workspace_bytes: parameters.maximum_workspace_bytes,
            created_at_epoch_seconds: parameters.created_at_epoch_seconds,
            expires_at_epoch_seconds: parameters.expires_at_epoch_seconds,
            activation_key_id_sha256: hash_bytes(&parameters.activation_public_key),
            plan_sha256: String::new(),
        };
        plan.validate()?;
        plan.plan_sha256 = plan.calculate_sha256()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), UnifiedOperatorError> {
        if self.version != UNIFIED_OPERATOR_PLAN_VERSION {
            return Err(UnifiedOperatorError::UnsupportedPlanVersion);
        }
        validate_identifier(&self.operator_id, "operator_id")?;
        self.binding.validate()?;
        validate_sha256(&self.binding_sha256, "binding_sha256")?;
        validate_sha256(
            &self.activation_key_id_sha256,
            "activation_key_id_sha256",
        )?;
        if !self.plan_sha256.is_empty() {
            validate_sha256(&self.plan_sha256, "plan_sha256")?;
        }
        if self.binding_sha256 != self.binding.calculate_sha256()? {
            return Err(UnifiedOperatorError::BindingDigestMismatch);
        }
        if self.created_at_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.created_at_epoch_seconds
            || self
                .expires_at_epoch_seconds
                .saturating_sub(self.created_at_epoch_seconds)
                > MAX_UNIFIED_OPERATOR_LIFETIME_SECONDS
            || self.expires_at_epoch_seconds > self.binding.component_expires_at_epoch_seconds
        {
            return Err(UnifiedOperatorError::InvalidPlanWindow);
        }
        if self.checkpoint_interval_requests == 0
            || self.checkpoint_interval_requests > self.binding.maximum_requests
        {
            return Err(UnifiedOperatorError::InvalidCheckpointInterval);
        }
        if !(MIN_UNIFIED_OPERATOR_WORKSPACE_BYTES..=MAX_UNIFIED_OPERATOR_WORKSPACE_BYTES)
            .contains(&self.maximum_workspace_bytes)
        {
            return Err(UnifiedOperatorError::InvalidWorkspaceBudget);
        }
        Ok(())
    }

    pub fn calculate_sha256(&self) -> Result<String, UnifiedOperatorError> {
        let mut material = self.clone();
        material.plan_sha256.clear();
        hash_serializable(&material)
    }

    pub fn verify(&self, now_epoch_seconds: i64) -> Result<(), UnifiedOperatorError> {
        self.validate()?;
        if self.plan_sha256 != self.calculate_sha256()? {
            return Err(UnifiedOperatorError::PlanDigestMismatch);
        }
        if now_epoch_seconds < self.created_at_epoch_seconds
            || now_epoch_seconds > self.expires_at_epoch_seconds
        {
            return Err(UnifiedOperatorError::PlanExpired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnifiedOperatorActivationPayload {
    pub version: u32,
    pub activation_id: String,
    pub plan_sha256: String,
    pub binding_sha256: String,
    pub discovery_plan_sha256: String,
    pub session_injection_manifest_sha256: String,
    pub external_vault_plan_sha256: String,
    pub external_vault_bootstrap_receipt_sha256: String,
    pub maximum_requests: u64,
    pub maximum_total_response_bytes: u64,
    pub not_before_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub signer_key_id_sha256: String,
}

impl UnifiedOperatorActivationPayload {
    pub fn template(
        activation_id: impl Into<String>,
        plan: &UnifiedOperatorPlan,
        not_before_epoch_seconds: i64,
        expires_at_epoch_seconds: i64,
    ) -> Result<Self, UnifiedOperatorError> {
        plan.validate()?;
        let payload = Self {
            version: UNIFIED_OPERATOR_ACTIVATION_VERSION,
            activation_id: activation_id.into(),
            plan_sha256: plan.plan_sha256.clone(),
            binding_sha256: plan.binding_sha256.clone(),
            discovery_plan_sha256: plan.binding.discovery_plan_sha256.clone(),
            session_injection_manifest_sha256: plan
                .binding
                .session_injection_manifest_sha256
                .clone(),
            external_vault_plan_sha256: plan.binding.external_vault_plan_sha256.clone(),
            external_vault_bootstrap_receipt_sha256: plan
                .binding
                .external_vault_bootstrap_receipt_sha256
                .clone(),
            maximum_requests: plan.binding.maximum_requests,
            maximum_total_response_bytes: plan.binding.maximum_total_response_bytes,
            not_before_epoch_seconds,
            expires_at_epoch_seconds,
            signer_key_id_sha256: plan.activation_key_id_sha256.clone(),
        };
        payload.validate(plan)?;
        Ok(payload)
    }

    pub fn validate(&self, plan: &UnifiedOperatorPlan) -> Result<(), UnifiedOperatorError> {
        if self.version != UNIFIED_OPERATOR_ACTIVATION_VERSION {
            return Err(UnifiedOperatorError::UnsupportedActivationVersion);
        }
        validate_identifier(&self.activation_id, "activation_id")?;
        for (value, field) in [
            (&self.plan_sha256, "plan_sha256"),
            (&self.binding_sha256, "binding_sha256"),
            (&self.discovery_plan_sha256, "discovery_plan_sha256"),
            (
                &self.session_injection_manifest_sha256,
                "session_injection_manifest_sha256",
            ),
            (&self.external_vault_plan_sha256, "external_vault_plan_sha256"),
            (
                &self.external_vault_bootstrap_receipt_sha256,
                "external_vault_bootstrap_receipt_sha256",
            ),
            (&self.signer_key_id_sha256, "signer_key_id_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        if self.not_before_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.not_before_epoch_seconds
            || self
                .expires_at_epoch_seconds
                .saturating_sub(self.not_before_epoch_seconds)
                > MAX_UNIFIED_OPERATOR_ACTIVATION_SECONDS
            || self.expires_at_epoch_seconds > plan.expires_at_epoch_seconds
        {
            return Err(UnifiedOperatorError::InvalidActivationWindow);
        }
        if self.plan_sha256 != plan.plan_sha256
            || self.binding_sha256 != plan.binding_sha256
            || self.discovery_plan_sha256 != plan.binding.discovery_plan_sha256
            || self.session_injection_manifest_sha256
                != plan.binding.session_injection_manifest_sha256
            || self.external_vault_plan_sha256 != plan.binding.external_vault_plan_sha256
            || self.external_vault_bootstrap_receipt_sha256
                != plan.binding.external_vault_bootstrap_receipt_sha256
            || self.maximum_requests != plan.binding.maximum_requests
            || self.maximum_total_response_bytes != plan.binding.maximum_total_response_bytes
            || self.signer_key_id_sha256 != plan.activation_key_id_sha256
        {
            return Err(UnifiedOperatorError::ActivationBindingMismatch);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, UnifiedOperatorError> {
        serde_json::to_vec(self)
            .map_err(|error| UnifiedOperatorError::Serialization(error.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnifiedOperatorActivationCertificate {
    pub payload: UnifiedOperatorActivationPayload,
    pub signature_hex: String,
}

impl UnifiedOperatorActivationCertificate {
    pub fn verify(
        &self,
        plan: &UnifiedOperatorPlan,
        public_key: &[u8],
        now_epoch_seconds: i64,
    ) -> Result<(), UnifiedOperatorError> {
        plan.verify(now_epoch_seconds)?;
        if public_key.len() != 32
            || hash_bytes(public_key) != self.payload.signer_key_id_sha256
            || self.payload.signer_key_id_sha256 != plan.activation_key_id_sha256
        {
            return Err(UnifiedOperatorError::ActivationKeyMismatch);
        }
        self.payload.validate(plan)?;
        if now_epoch_seconds < self.payload.not_before_epoch_seconds
            || now_epoch_seconds > self.payload.expires_at_epoch_seconds
        {
            return Err(UnifiedOperatorError::ActivationExpired);
        }
        let signature = decode_lower_hex(&self.signature_hex, "signature_hex")?;
        if signature.len() != 64 {
            return Err(UnifiedOperatorError::InvalidSignature);
        }
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&self.payload.signing_bytes()?, &signature)
            .map_err(|_| UnifiedOperatorError::InvalidSignature)
    }

    pub fn certificate_sha256(&self) -> Result<String, UnifiedOperatorError> {
        hash_serializable(self)
    }
}

pub struct ConsumedUnifiedOperatorActivation {
    plan_sha256: String,
    binding_sha256: String,
    activation_certificate_sha256: String,
    expires_at_epoch_seconds: i64,
    marker_path: PathBuf,
}

impl ConsumedUnifiedOperatorActivation {
    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    pub fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }

    pub fn activation_certificate_sha256(&self) -> &str {
        &self.activation_certificate_sha256
    }

    pub fn expires_at_epoch_seconds(&self) -> i64 {
        self.expires_at_epoch_seconds
    }

    pub fn marker_path(&self) -> &Path {
        &self.marker_path
    }
}

impl fmt::Debug for ConsumedUnifiedOperatorActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumedUnifiedOperatorActivation")
            .field("plan_sha256", &self.plan_sha256)
            .field("binding_sha256", &self.binding_sha256)
            .field(
                "activation_certificate_sha256",
                &self.activation_certificate_sha256,
            )
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("marker_path", &self.marker_path)
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct UnifiedOperatorUseMarker {
    version: u32,
    operator_id_sha256: String,
    activation_id_sha256: String,
    plan_sha256: String,
    binding_sha256: String,
    activation_certificate_sha256: String,
    consumed_at_epoch_seconds: i64,
    state: String,
}

pub fn consume_activation_once(
    state_directory: &Path,
    plan: &UnifiedOperatorPlan,
    certificate: &UnifiedOperatorActivationCertificate,
    public_key: &[u8],
    now_epoch_seconds: i64,
) -> Result<ConsumedUnifiedOperatorActivation, UnifiedOperatorError> {
    certificate.verify(plan, public_key, now_epoch_seconds)?;
    fs::create_dir_all(state_directory)
        .map_err(|error| UnifiedOperatorError::Io(error.to_string()))?;
    let activation_certificate_sha256 = certificate.certificate_sha256()?;
    let marker_name = format!(
        "unified-operator-{}.json",
        hash_bytes(certificate.payload.activation_id.as_bytes())
    );
    let marker_path = state_directory.join(marker_name);
    let marker = UnifiedOperatorUseMarker {
        version: 1,
        operator_id_sha256: hash_bytes(plan.operator_id.as_bytes()),
        activation_id_sha256: hash_bytes(certificate.payload.activation_id.as_bytes()),
        plan_sha256: plan.plan_sha256.clone(),
        binding_sha256: plan.binding_sha256.clone(),
        activation_certificate_sha256: activation_certificate_sha256.clone(),
        consumed_at_epoch_seconds: now_epoch_seconds,
        state: "consumed".into(),
    };
    let bytes = serde_json::to_vec_pretty(&marker)
        .map_err(|error| UnifiedOperatorError::Serialization(error.to_string()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                UnifiedOperatorError::ActivationReplay
            } else {
                UnifiedOperatorError::Io(error.to_string())
            }
        })?;
    if let Err(error) = file
        .write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
    {
        let _ = fs::remove_file(&marker_path);
        return Err(UnifiedOperatorError::Io(error.to_string()));
    }
    Ok(ConsumedUnifiedOperatorActivation {
        plan_sha256: plan.plan_sha256.clone(),
        binding_sha256: plan.binding_sha256.clone(),
        activation_certificate_sha256,
        expires_at_epoch_seconds: certificate.payload.expires_at_epoch_seconds,
        marker_path,
    })
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UnifiedOperatorError {
    #[error("unsupported unified operator plan version")]
    UnsupportedPlanVersion,
    #[error("unsupported unified operator activation version")]
    UnsupportedActivationVersion,
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("invalid SHA-256 field: {0}")]
    InvalidSha256(String),
    #[error("invalid authority")]
    InvalidAuthority,
    #[error("invalid secret count")]
    InvalidSecretCount,
    #[error("invalid path scope")]
    InvalidPathScope,
    #[error("invalid request budget")]
    InvalidRequestBudget,
    #[error("invalid depth budget")]
    InvalidDepthBudget,
    #[error("invalid per-response body budget")]
    InvalidResponseBodyBudget,
    #[error("invalid total-response byte budget")]
    InvalidTotalResponseBudget,
    #[error("invalid minimum request interval")]
    InvalidRequestInterval,
    #[error("unified operator v1 requires sequential execution")]
    InvalidConcurrency,
    #[error("invalid component expiration")]
    InvalidComponentExpiry,
    #[error("invalid activation public key")]
    InvalidActivationPublicKey,
    #[error("component binding digest mismatch")]
    BindingDigestMismatch,
    #[error("invalid unified operator validity window")]
    InvalidPlanWindow,
    #[error("invalid checkpoint interval")]
    InvalidCheckpointInterval,
    #[error("invalid workspace budget")]
    InvalidWorkspaceBudget,
    #[error("unified operator plan digest mismatch")]
    PlanDigestMismatch,
    #[error("unified operator plan is outside its validity window")]
    PlanExpired,
    #[error("invalid unified operator activation window")]
    InvalidActivationWindow,
    #[error("unified operator activation does not match the plan")]
    ActivationBindingMismatch,
    #[error("unified operator activation key mismatch")]
    ActivationKeyMismatch,
    #[error("unified operator activation is outside its validity window")]
    ActivationExpired,
    #[error("invalid Ed25519 signature")]
    InvalidSignature,
    #[error("unified operator activation was already consumed")]
    ActivationReplay,
    #[error("invalid lower-hex field: {0}")]
    InvalidHex(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("I/O failed: {0}")]
    Io(String),
}

fn validate_identifier(value: &str, field: &str) -> Result<(), UnifiedOperatorError> {
    if !(1..=128).contains(&value.len())
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
    {
        return Err(UnifiedOperatorError::InvalidIdentifier(field.into()));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), UnifiedOperatorError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(UnifiedOperatorError::InvalidSha256(field.into()));
    }
    Ok(())
}

fn validate_authority(value: &str) -> Result<(), UnifiedOperatorError> {
    if value.is_empty()
        || value.len() > 253
        || value != value.trim()
        || value != value.to_ascii_lowercase()
        || value.contains('/')
        || value.contains('\\')
        || value.contains('@')
        || value.chars().any(char::is_whitespace)
    {
        return Err(UnifiedOperatorError::InvalidAuthority);
    }
    Ok(())
}

fn validate_passive_path(path: &str) -> Result<(), UnifiedOperatorError> {
    if !path.starts_with('/')
        || path.len() > 2048
        || path.contains('?')
        || path.contains('#')
        || path.contains('%')
        || path.contains('\\')
        || path.contains("//")
        || path.contains(';')
        || path.chars().any(char::is_control)
    {
        return Err(UnifiedOperatorError::InvalidPathScope);
    }
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        if segment == "."
            || segment == ".."
            || segment
                .split(['-', '_', '.'])
                .any(|token| DENIED_PATH_TOKENS.contains(&token.to_ascii_lowercase().as_str()))
        {
            return Err(UnifiedOperatorError::InvalidPathScope);
        }
    }
    Ok(())
}

fn decode_lower_hex(value: &str, field: &str) -> Result<Vec<u8>, UnifiedOperatorError> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(UnifiedOperatorError::InvalidHex(field.into()));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or_else(|| UnifiedOperatorError::InvalidHex(field.into()))?;
            let low = hex_nibble(pair[1]).ok_or_else(|| UnifiedOperatorError::InvalidHex(field.into()))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    lower_hex(digest.as_slice())
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, UnifiedOperatorError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| UnifiedOperatorError::Serialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
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

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sha(value: char) -> String {
        value.to_string().repeat(64)
    }

    fn binding() -> UnifiedComponentBinding {
        UnifiedComponentBinding {
            discovery_plan_sha256: sha('a'),
            policy_sha256: sha('b'),
            target_origin_sha256: sha('c'),
            discovery_session_id: "discovery-session-1".into(),
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
            allowed_path_prefixes: BTreeSet::from(["/app".into(), "/api/read".into()]),
            maximum_requests: 16,
            maximum_depth: 2,
            maximum_response_body_bytes: 1024 * 1024,
            maximum_total_response_bytes: 8 * 1024 * 1024,
            minimum_request_interval_milliseconds: 1000,
            maximum_concurrency: 1,
            component_expires_at_epoch_seconds: 2_000,
        }
    }

    fn key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7_u8; 32]).expect("valid deterministic key")
    }

    fn plan() -> UnifiedOperatorPlan {
        let key_pair = key_pair();
        UnifiedOperatorPlan::build(UnifiedOperatorPlanParameters {
            operator_id: "operator-1".into(),
            binding: binding(),
            checkpoint_interval_requests: 4,
            maximum_workspace_bytes: 64 * 1024 * 1024,
            created_at_epoch_seconds: 1_000,
            expires_at_epoch_seconds: 1_900,
            activation_public_key: key_pair.public_key().as_ref().to_vec(),
        })
        .expect("valid plan")
    }

    fn certificate(plan: &UnifiedOperatorPlan) -> UnifiedOperatorActivationCertificate {
        let key_pair = key_pair();
        let payload = UnifiedOperatorActivationPayload::template(
            "activation-1",
            plan,
            1_100,
            1_800,
        )
        .expect("valid payload");
        let signature = key_pair.sign(&payload.signing_bytes().expect("signing bytes"));
        UnifiedOperatorActivationCertificate {
            payload,
            signature_hex: lower_hex(signature.as_ref()),
        }
    }

    #[test]
    fn signed_plan_and_activation_verify() {
        let plan = plan();
        let certificate = certificate(&plan);
        certificate
            .verify(&plan, key_pair().public_key().as_ref(), 1_200)
            .expect("certificate should verify");
    }

    #[test]
    fn component_expiry_caps_unified_plan() {
        let key_pair = key_pair();
        let error = UnifiedOperatorPlan::build(UnifiedOperatorPlanParameters {
            operator_id: "operator-1".into(),
            binding: binding(),
            checkpoint_interval_requests: 4,
            maximum_workspace_bytes: 64 * 1024 * 1024,
            created_at_epoch_seconds: 1_000,
            expires_at_epoch_seconds: 2_001,
            activation_public_key: key_pair.public_key().as_ref().to_vec(),
        })
        .expect_err("component expiry must cap the plan");
        assert_eq!(error, UnifiedOperatorError::InvalidPlanWindow);
    }

    #[test]
    fn destructive_path_scope_is_rejected() {
        let mut binding = binding();
        binding.allowed_path_prefixes.insert("/account/logout".into());
        assert_eq!(
            binding.validate().expect_err("logout path must fail"),
            UnifiedOperatorError::InvalidPathScope
        );
    }

    #[test]
    fn activation_tampering_is_rejected() {
        let plan = plan();
        let mut certificate = certificate(&plan);
        certificate.payload.maximum_requests = 15;
        assert_eq!(
            certificate
                .verify(&plan, key_pair().public_key().as_ref(), 1_200)
                .expect_err("tampering must fail"),
            UnifiedOperatorError::ActivationBindingMismatch
        );
    }

    #[test]
    fn activation_is_consumed_once() {
        let plan = plan();
        let certificate = certificate(&plan);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "nxb-unified-operator-{}-{unique}",
            std::process::id()
        ));
        let consumed = consume_activation_once(
            &directory,
            &plan,
            &certificate,
            key_pair().public_key().as_ref(),
            1_200,
        )
        .expect("first consumption succeeds");
        assert!(consumed.marker_path().exists());
        assert_eq!(
            consume_activation_once(
                &directory,
                &plan,
                &certificate,
                key_pair().public_key().as_ref(),
                1_200,
            )
            .expect_err("replay must fail"),
            UnifiedOperatorError::ActivationReplay
        );
        fs::remove_dir_all(directory).expect("cleanup");
    }
}
