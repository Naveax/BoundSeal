#![forbid(unsafe_code)]

use std::fmt;

use nxb_evidence_sealer::{EvidenceSealingKey, ProductionEvidenceSealer};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const EVIDENCE_KEY_PLAN_VERSION: u32 = 1;
pub const EVIDENCE_KEY_ACTIVATION_VERSION: u32 = 1;
pub const EVIDENCE_KEY_RECEIPT_VERSION: u32 = 1;
pub const MAX_PLAN_LIFETIME_SECONDS: i64 = 15 * 60;
pub const EVIDENCE_SEALING_KEY_BYTES: usize = 32;

const ACTIVATION_DOMAIN: &str = "nxb-evidence-key-activation-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyProviderIdentity {
    pub provider_id: String,
    pub backend_kind: String,
    pub capability_sha256: String,
}

impl EvidenceKeyProviderIdentity {
    fn validate(&self) -> Result<(), EvidenceKeyProviderError> {
        validate_identifier(&self.provider_id, "provider_id")?;
        validate_identifier(&self.backend_kind, "backend_kind")?;
        validate_sha256(&self.capability_sha256, "capability_sha256")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyPlanInput {
    pub provider_identity: EvidenceKeyProviderIdentity,
    pub key_id: String,
    pub store_id: String,
    pub policy_snapshot_sha256: String,
    pub activation_public_key_hex: String,
    pub issued_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyPlan {
    pub version: u32,
    pub plan_id: String,
    pub provider_identity: EvidenceKeyProviderIdentity,
    pub key_id: String,
    pub store_id: String,
    pub policy_snapshot_sha256: String,
    pub activation_public_key_hex: String,
    pub issued_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub maximum_key_fetches: u32,
    pub plan_sha256: String,
}

#[derive(Serialize)]
struct PlanIdentityMaterial<'a> {
    version: u32,
    provider_identity: &'a EvidenceKeyProviderIdentity,
    key_id: &'a str,
    store_id: &'a str,
    policy_snapshot_sha256: &'a str,
    activation_public_key_hex: &'a str,
    issued_at_epoch_seconds: i64,
    expires_at_epoch_seconds: i64,
    maximum_key_fetches: u32,
}

#[derive(Serialize)]
struct PlanHashMaterial<'a> {
    version: u32,
    plan_id: &'a str,
    provider_identity: &'a EvidenceKeyProviderIdentity,
    key_id: &'a str,
    store_id: &'a str,
    policy_snapshot_sha256: &'a str,
    activation_public_key_hex: &'a str,
    issued_at_epoch_seconds: i64,
    expires_at_epoch_seconds: i64,
    maximum_key_fetches: u32,
}

impl EvidenceKeyPlan {
    pub fn create(input: EvidenceKeyPlanInput) -> Result<Self, EvidenceKeyProviderError> {
        input.provider_identity.validate()?;
        validate_identifier(&input.key_id, "key_id")?;
        validate_identifier(&input.store_id, "store_id")?;
        validate_sha256(&input.policy_snapshot_sha256, "policy_snapshot_sha256")?;
        validate_ed25519_public_key(&input.activation_public_key_hex)?;
        validate_time_window(
            input.issued_at_epoch_seconds,
            input.expires_at_epoch_seconds,
        )?;

        let identity_sha256 = hash_serializable(&PlanIdentityMaterial {
            version: EVIDENCE_KEY_PLAN_VERSION,
            provider_identity: &input.provider_identity,
            key_id: &input.key_id,
            store_id: &input.store_id,
            policy_snapshot_sha256: &input.policy_snapshot_sha256,
            activation_public_key_hex: &input.activation_public_key_hex,
            issued_at_epoch_seconds: input.issued_at_epoch_seconds,
            expires_at_epoch_seconds: input.expires_at_epoch_seconds,
            maximum_key_fetches: 1,
        })?;
        let plan_id = format!("evidence-key-plan-{}", &identity_sha256[..24]);
        let plan_sha256 = hash_serializable(&PlanHashMaterial {
            version: EVIDENCE_KEY_PLAN_VERSION,
            plan_id: &plan_id,
            provider_identity: &input.provider_identity,
            key_id: &input.key_id,
            store_id: &input.store_id,
            policy_snapshot_sha256: &input.policy_snapshot_sha256,
            activation_public_key_hex: &input.activation_public_key_hex,
            issued_at_epoch_seconds: input.issued_at_epoch_seconds,
            expires_at_epoch_seconds: input.expires_at_epoch_seconds,
            maximum_key_fetches: 1,
        })?;
        Ok(Self {
            version: EVIDENCE_KEY_PLAN_VERSION,
            plan_id,
            provider_identity: input.provider_identity,
            key_id: input.key_id,
            store_id: input.store_id,
            policy_snapshot_sha256: input.policy_snapshot_sha256,
            activation_public_key_hex: input.activation_public_key_hex,
            issued_at_epoch_seconds: input.issued_at_epoch_seconds,
            expires_at_epoch_seconds: input.expires_at_epoch_seconds,
            maximum_key_fetches: 1,
            plan_sha256,
        })
    }

    pub fn validate(&self, now_epoch_seconds: i64) -> Result<(), EvidenceKeyProviderError> {
        if self.version != EVIDENCE_KEY_PLAN_VERSION || self.maximum_key_fetches != 1 {
            return Err(EvidenceKeyProviderError::InvalidPlan);
        }
        self.provider_identity.validate()?;
        validate_identifier(&self.key_id, "key_id")?;
        validate_identifier(&self.store_id, "store_id")?;
        validate_sha256(&self.policy_snapshot_sha256, "policy_snapshot_sha256")?;
        validate_ed25519_public_key(&self.activation_public_key_hex)?;
        validate_time_window(self.issued_at_epoch_seconds, self.expires_at_epoch_seconds)?;
        if now_epoch_seconds < self.issued_at_epoch_seconds
            || now_epoch_seconds > self.expires_at_epoch_seconds
        {
            return Err(EvidenceKeyProviderError::PlanNotActive);
        }
        let expected = Self::create(EvidenceKeyPlanInput {
            provider_identity: self.provider_identity.clone(),
            key_id: self.key_id.clone(),
            store_id: self.store_id.clone(),
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            activation_public_key_hex: self.activation_public_key_hex.clone(),
            issued_at_epoch_seconds: self.issued_at_epoch_seconds,
            expires_at_epoch_seconds: self.expires_at_epoch_seconds,
        })?;
        if expected.plan_id != self.plan_id || expected.plan_sha256 != self.plan_sha256 {
            return Err(EvidenceKeyProviderError::PlanDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyActivation {
    pub version: u32,
    pub activation_id: String,
    pub plan_sha256: String,
    pub signature_hex: String,
}

#[derive(Serialize)]
struct ActivationMessage<'a> {
    domain: &'static str,
    plan_sha256: &'a str,
}

impl EvidenceKeyActivation {
    pub fn from_signature(
        plan_sha256: impl Into<String>,
        signature: &[u8],
    ) -> Result<Self, EvidenceKeyProviderError> {
        let plan_sha256 = plan_sha256.into();
        validate_sha256(&plan_sha256, "plan_sha256")?;
        if signature.len() != 64 {
            return Err(EvidenceKeyProviderError::InvalidActivation);
        }
        let signature_sha256 = hash_bytes(signature);
        Ok(Self {
            version: EVIDENCE_KEY_ACTIVATION_VERSION,
            activation_id: format!("evidence-key-activation-{}", &signature_sha256[..24]),
            plan_sha256,
            signature_hex: lower_hex(signature),
        })
    }

    pub fn signing_message(plan_sha256: &str) -> Result<Vec<u8>, EvidenceKeyProviderError> {
        validate_sha256(plan_sha256, "plan_sha256")?;
        canonical_json(&ActivationMessage {
            domain: ACTIVATION_DOMAIN,
            plan_sha256,
        })
    }

    fn verify(&self, plan: &EvidenceKeyPlan) -> Result<(), EvidenceKeyProviderError> {
        if self.version != EVIDENCE_KEY_ACTIVATION_VERSION || self.plan_sha256 != plan.plan_sha256 {
            return Err(EvidenceKeyProviderError::InvalidActivation);
        }
        let signature = decode_hex(&self.signature_hex, "signature")?;
        if signature.len() != 64
            || self.activation_id
                != format!("evidence-key-activation-{}", &hash_bytes(&signature)[..24])
        {
            return Err(EvidenceKeyProviderError::InvalidActivation);
        }
        let public_key = decode_hex(&plan.activation_public_key_hex, "activation_public_key")?;
        let message = Self::signing_message(&plan.plan_sha256)?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&message, &signature)
            .map_err(|_| EvidenceKeyProviderError::ActivationSignatureInvalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSessionRequest {
    pub plan_id: String,
    pub plan_sha256: String,
    pub store_id: String,
    pub policy_snapshot_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderKeyRequest {
    pub plan_id: String,
    pub plan_sha256: String,
    pub key_id: String,
    pub store_id: String,
    pub policy_snapshot_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSessionDisposition {
    Completed,
    Aborted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSessionOutcome {
    pub disposition: ProviderSessionDisposition,
    pub plan_sha256: String,
    pub receipt_sha256: Option<String>,
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderFailure {
    pub code: String,
}

impl ProviderFailure {
    pub fn new(code: impl Into<String>) -> Result<Self, EvidenceKeyProviderError> {
        let code = code.into();
        validate_identifier(&code, "provider_failure_code")?;
        Ok(Self { code })
    }
}

pub struct ProviderKeyMaterial {
    pub key_id: String,
    pub version_id: String,
    pub expires_at_epoch_seconds: i64,
    bytes: Zeroizing<Vec<u8>>,
}

impl ProviderKeyMaterial {
    pub fn new(
        key_id: impl Into<String>,
        version_id: impl Into<String>,
        expires_at_epoch_seconds: i64,
        mut bytes: Vec<u8>,
    ) -> Result<Self, EvidenceKeyProviderError> {
        let key_id = key_id.into();
        let version_id = version_id.into();
        validate_identifier(&key_id, "key_id")?;
        validate_identifier(&version_id, "version_id")?;
        if bytes.len() != EVIDENCE_SEALING_KEY_BYTES {
            bytes.fill(0);
            return Err(EvidenceKeyProviderError::InvalidKeyMaterial);
        }
        Ok(Self {
            key_id,
            version_id,
            expires_at_epoch_seconds,
            bytes: Zeroizing::new(bytes),
        })
    }

    fn copy_key(&self) -> Result<[u8; EVIDENCE_SEALING_KEY_BYTES], EvidenceKeyProviderError> {
        self.bytes
            .as_slice()
            .try_into()
            .map_err(|_| EvidenceKeyProviderError::InvalidKeyMaterial)
    }
}

impl fmt::Debug for ProviderKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderKeyMaterial")
            .field("key_id", &self.key_id)
            .field("version_id", &self.version_id)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

pub trait EvidenceKeyProvider {
    fn identity(&self) -> EvidenceKeyProviderIdentity;

    fn begin(&mut self, request: &ProviderSessionRequest) -> Result<(), ProviderFailure>;

    fn fetch_key(
        &mut self,
        request: &ProviderKeyRequest,
    ) -> Result<ProviderKeyMaterial, ProviderFailure>;

    fn finish(&mut self, outcome: &ProviderSessionOutcome) -> Result<(), ProviderFailure>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyAcquisitionReceipt {
    pub version: u32,
    pub receipt_id: String,
    pub plan_id: String,
    pub plan_sha256: String,
    pub activation_id: String,
    pub provider_identity_sha256: String,
    pub key_id: String,
    pub key_version_id: String,
    pub store_id: String,
    pub policy_snapshot_sha256: String,
    pub acquired_at_epoch_seconds: i64,
    pub key_expires_at_epoch_seconds: i64,
    pub receipt_sha256: String,
}

#[derive(Serialize)]
struct ReceiptHashMaterial<'a> {
    version: u32,
    receipt_id: &'a str,
    plan_id: &'a str,
    plan_sha256: &'a str,
    activation_id: &'a str,
    provider_identity_sha256: &'a str,
    key_id: &'a str,
    key_version_id: &'a str,
    store_id: &'a str,
    policy_snapshot_sha256: &'a str,
    acquired_at_epoch_seconds: i64,
    key_expires_at_epoch_seconds: i64,
}

impl EvidenceKeyAcquisitionReceipt {
    fn create(
        plan: &EvidenceKeyPlan,
        activation: &EvidenceKeyActivation,
        key_version_id: String,
        acquired_at_epoch_seconds: i64,
        key_expires_at_epoch_seconds: i64,
    ) -> Result<Self, EvidenceKeyProviderError> {
        let provider_identity_sha256 = hash_serializable(&plan.provider_identity)?;
        let identity_sha256 = hash_serializable(&(
            &plan.plan_sha256,
            &activation.activation_id,
            &provider_identity_sha256,
            &plan.key_id,
            &key_version_id,
            acquired_at_epoch_seconds,
        ))?;
        let receipt_id = format!("evidence-key-receipt-{}", &identity_sha256[..24]);
        let receipt_sha256 = hash_serializable(&ReceiptHashMaterial {
            version: EVIDENCE_KEY_RECEIPT_VERSION,
            receipt_id: &receipt_id,
            plan_id: &plan.plan_id,
            plan_sha256: &plan.plan_sha256,
            activation_id: &activation.activation_id,
            provider_identity_sha256: &provider_identity_sha256,
            key_id: &plan.key_id,
            key_version_id: &key_version_id,
            store_id: &plan.store_id,
            policy_snapshot_sha256: &plan.policy_snapshot_sha256,
            acquired_at_epoch_seconds,
            key_expires_at_epoch_seconds,
        })?;
        Ok(Self {
            version: EVIDENCE_KEY_RECEIPT_VERSION,
            receipt_id,
            plan_id: plan.plan_id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            activation_id: activation.activation_id.clone(),
            provider_identity_sha256,
            key_id: plan.key_id.clone(),
            key_version_id,
            store_id: plan.store_id.clone(),
            policy_snapshot_sha256: plan.policy_snapshot_sha256.clone(),
            acquired_at_epoch_seconds,
            key_expires_at_epoch_seconds,
            receipt_sha256,
        })
    }
}

pub fn acquire_evidence_sealer<P: EvidenceKeyProvider>(
    plan: EvidenceKeyPlan,
    activation: EvidenceKeyActivation,
    provider: &mut P,
    now_epoch_seconds: i64,
) -> Result<(ProductionEvidenceSealer, EvidenceKeyAcquisitionReceipt), EvidenceKeyProviderError> {
    plan.validate(now_epoch_seconds)?;
    activation.verify(&plan)?;
    if provider.identity() != plan.provider_identity {
        return Err(EvidenceKeyProviderError::ProviderIdentityMismatch);
    }

    let session_request = ProviderSessionRequest {
        plan_id: plan.plan_id.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        store_id: plan.store_id.clone(),
        policy_snapshot_sha256: plan.policy_snapshot_sha256.clone(),
    };
    provider
        .begin(&session_request)
        .map_err(provider_begin_error)?;

    let acquisition = (|| {
        let key_request = ProviderKeyRequest {
            plan_id: plan.plan_id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            key_id: plan.key_id.clone(),
            store_id: plan.store_id.clone(),
            policy_snapshot_sha256: plan.policy_snapshot_sha256.clone(),
        };
        let material = provider
            .fetch_key(&key_request)
            .map_err(provider_fetch_error)?;
        if material.key_id != plan.key_id
            || material.expires_at_epoch_seconds < plan.expires_at_epoch_seconds
        {
            return Err(EvidenceKeyProviderError::InvalidKeyMaterial);
        }
        let key_bytes = material.copy_key()?;
        let receipt = EvidenceKeyAcquisitionReceipt::create(
            &plan,
            &activation,
            material.version_id.clone(),
            now_epoch_seconds,
            material.expires_at_epoch_seconds,
        )?;
        let sealer =
            ProductionEvidenceSealer::new(plan.key_id.clone(), EvidenceSealingKey::new(key_bytes))
                .map_err(|error| EvidenceKeyProviderError::Sealer(error.to_string()))?;
        Ok((sealer, receipt))
    })();

    let outcome = match &acquisition {
        Ok((_, receipt)) => ProviderSessionOutcome {
            disposition: ProviderSessionDisposition::Completed,
            plan_sha256: plan.plan_sha256.clone(),
            receipt_sha256: Some(receipt.receipt_sha256.clone()),
            failure_code: None,
        },
        Err(error) => ProviderSessionOutcome {
            disposition: ProviderSessionDisposition::Aborted,
            plan_sha256: plan.plan_sha256.clone(),
            receipt_sha256: None,
            failure_code: Some(error.failure_code().into()),
        },
    };
    if let Err(failure) = provider.finish(&outcome) {
        return Err(EvidenceKeyProviderError::ProviderTeardownFailure(
            failure.code,
        ));
    }
    acquisition
}

fn provider_begin_error(failure: ProviderFailure) -> EvidenceKeyProviderError {
    EvidenceKeyProviderError::ProviderBeginFailure(failure.code)
}

fn provider_fetch_error(failure: ProviderFailure) -> EvidenceKeyProviderError {
    EvidenceKeyProviderError::ProviderFetchFailure(failure.code)
}

fn validate_time_window(issued_at: i64, expires_at: i64) -> Result<(), EvidenceKeyProviderError> {
    let lifetime = expires_at
        .checked_sub(issued_at)
        .ok_or(EvidenceKeyProviderError::InvalidPlan)?;
    if issued_at < 0 || lifetime <= 0 || lifetime > MAX_PLAN_LIFETIME_SECONDS {
        return Err(EvidenceKeyProviderError::InvalidPlan);
    }
    Ok(())
}

fn validate_ed25519_public_key(value: &str) -> Result<(), EvidenceKeyProviderError> {
    let bytes = decode_hex(value, "activation_public_key")?;
    if bytes.len() != 32 {
        return Err(EvidenceKeyProviderError::InvalidPlan);
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &str) -> Result<(), EvidenceKeyProviderError> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(EvidenceKeyProviderError::InvalidIdentifier(field.into()));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), EvidenceKeyProviderError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EvidenceKeyProviderError::InvalidSha256(field.into()));
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, EvidenceKeyProviderError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| EvidenceKeyProviderError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, EvidenceKeyProviderError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| EvidenceKeyProviderError::Serialization(error.to_string()))?;
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

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, EvidenceKeyProviderError> {
    if !value.len().is_multiple_of(2) {
        return Err(EvidenceKeyProviderError::InvalidHex(field.into()));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for index in (0..bytes.len()).step_by(2) {
        let high = hex_nibble(bytes[index])
            .ok_or_else(|| EvidenceKeyProviderError::InvalidHex(field.into()))?;
        let low = hex_nibble(bytes[index + 1])
            .ok_or_else(|| EvidenceKeyProviderError::InvalidHex(field.into()))?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvidenceKeyProviderError {
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("invalid SHA-256 field: {0}")]
    InvalidSha256(String),
    #[error("invalid hexadecimal field: {0}")]
    InvalidHex(String),
    #[error("evidence key plan is invalid")]
    InvalidPlan,
    #[error("evidence key plan digest does not match")]
    PlanDigestMismatch,
    #[error("evidence key plan is not active")]
    PlanNotActive,
    #[error("evidence key activation is invalid")]
    InvalidActivation,
    #[error("evidence key activation signature is invalid")]
    ActivationSignatureInvalid,
    #[error("evidence key provider identity does not match")]
    ProviderIdentityMismatch,
    #[error("evidence key provider begin failed: {0}")]
    ProviderBeginFailure(String),
    #[error("evidence key provider fetch failed: {0}")]
    ProviderFetchFailure(String),
    #[error("evidence key provider teardown failed: {0}")]
    ProviderTeardownFailure(String),
    #[error("evidence key material is invalid")]
    InvalidKeyMaterial,
    #[error("evidence sealer construction failed: {0}")]
    Sealer(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
}

impl EvidenceKeyProviderError {
    fn failure_code(&self) -> &'static str {
        match self {
            Self::InvalidIdentifier(_)
            | Self::InvalidSha256(_)
            | Self::InvalidHex(_)
            | Self::InvalidPlan
            | Self::PlanDigestMismatch
            | Self::PlanNotActive
            | Self::InvalidActivation
            | Self::ActivationSignatureInvalid => "activation_invalid",
            Self::ProviderIdentityMismatch => "provider_identity_mismatch",
            Self::ProviderBeginFailure(_) => "provider_begin_failure",
            Self::ProviderFetchFailure(_) => "provider_fetch_failure",
            Self::ProviderTeardownFailure(_) => "provider_teardown_failure",
            Self::InvalidKeyMaterial => "key_material_invalid",
            Self::Sealer(_) => "sealer_construction_failure",
            Self::Serialization(_) => "serialization_failure",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    #[derive(Debug)]
    struct FakeProvider {
        identity: EvidenceKeyProviderIdentity,
        material: Option<ProviderKeyMaterial>,
        begin_failure: Option<ProviderFailure>,
        fetch_failure: Option<ProviderFailure>,
        finish_failure: Option<ProviderFailure>,
        begin_count: usize,
        fetch_count: usize,
        outcomes: Vec<ProviderSessionOutcome>,
    }

    impl EvidenceKeyProvider for FakeProvider {
        fn identity(&self) -> EvidenceKeyProviderIdentity {
            self.identity.clone()
        }

        fn begin(&mut self, _request: &ProviderSessionRequest) -> Result<(), ProviderFailure> {
            self.begin_count += 1;
            match self.begin_failure.clone() {
                Some(failure) => Err(failure),
                None => Ok(()),
            }
        }

        fn fetch_key(
            &mut self,
            _request: &ProviderKeyRequest,
        ) -> Result<ProviderKeyMaterial, ProviderFailure> {
            self.fetch_count += 1;
            if let Some(failure) = self.fetch_failure.clone() {
                return Err(failure);
            }
            self.material
                .take()
                .ok_or_else(|| ProviderFailure::new("missing_key").expect("failure"))
        }

        fn finish(&mut self, outcome: &ProviderSessionOutcome) -> Result<(), ProviderFailure> {
            self.outcomes.push(outcome.clone());
            match self.finish_failure.clone() {
                Some(failure) => Err(failure),
                None => Ok(()),
            }
        }
    }

    fn provider_identity() -> EvidenceKeyProviderIdentity {
        EvidenceKeyProviderIdentity {
            provider_id: "evidence-provider-1".into(),
            backend_kind: "test-fixture".into(),
            capability_sha256: "a".repeat(64),
        }
    }

    fn signed_plan(now: i64) -> (EvidenceKeyPlan, EvidenceKeyActivation, Ed25519KeyPair) {
        let random = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("pkcs8");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("pair");
        let plan = EvidenceKeyPlan::create(EvidenceKeyPlanInput {
            provider_identity: provider_identity(),
            key_id: "evidence-key-1".into(),
            store_id: "evidence-store-1".into(),
            policy_snapshot_sha256: "b".repeat(64),
            activation_public_key_hex: lower_hex(key_pair.public_key().as_ref()),
            issued_at_epoch_seconds: now - 5,
            expires_at_epoch_seconds: now + 120,
        })
        .expect("plan");
        let message = EvidenceKeyActivation::signing_message(&plan.plan_sha256).expect("message");
        let activation = EvidenceKeyActivation::from_signature(
            plan.plan_sha256.clone(),
            key_pair.sign(&message).as_ref(),
        )
        .expect("activation");
        (plan, activation, key_pair)
    }

    fn provider(now: i64) -> FakeProvider {
        FakeProvider {
            identity: provider_identity(),
            material: Some(
                ProviderKeyMaterial::new(
                    "evidence-key-1",
                    "version-7",
                    now + 300,
                    vec![7; EVIDENCE_SEALING_KEY_BYTES],
                )
                .expect("material"),
            ),
            begin_failure: None,
            fetch_failure: None,
            finish_failure: None,
            begin_count: 0,
            fetch_count: 0,
            outcomes: Vec::new(),
        }
    }

    #[test]
    fn signed_plan_acquires_one_sealer_and_receipt() {
        let now = 2_000_000_000;
        let (plan, activation, _) = signed_plan(now);
        let mut provider = provider(now);
        let (sealer, receipt) =
            acquire_evidence_sealer(plan, activation, &mut provider, now).expect("acquire");
        assert_eq!(sealer.key_id(), "evidence-key-1");
        assert_eq!(receipt.key_version_id, "version-7");
        assert_eq!(provider.begin_count, 1);
        assert_eq!(provider.fetch_count, 1);
        assert_eq!(provider.outcomes.len(), 1);
        assert_eq!(
            provider.outcomes[0].disposition,
            ProviderSessionDisposition::Completed
        );
        assert!(provider.outcomes[0].receipt_sha256.is_some());
    }

    #[test]
    fn wrong_provider_identity_is_rejected_before_begin() {
        let now = 2_000_000_000;
        let (plan, activation, _) = signed_plan(now);
        let mut provider = provider(now);
        provider.identity.provider_id = "other-provider".into();
        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ProviderIdentityMismatch)
        ));
        assert_eq!(provider.begin_count, 0);
    }

    #[test]
    fn invalid_signature_is_rejected_before_begin() {
        let now = 2_000_000_000;
        let (plan, activation, _) = signed_plan(now);
        let mut signature = decode_hex(&activation.signature_hex, "signature").expect("signature");
        signature[0] ^= 0x01;
        let activation =
            EvidenceKeyActivation::from_signature(plan.plan_sha256.clone(), &signature)
                .expect("tampered activation");
        let mut provider = provider(now);
        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ActivationSignatureInvalid)
        ));
        assert_eq!(provider.begin_count, 0);
    }

    #[test]
    fn wrong_key_id_aborts_and_finishes() {
        let now = 2_000_000_000;
        let (plan, activation, _) = signed_plan(now);
        let mut provider = provider(now);
        provider.material = Some(
            ProviderKeyMaterial::new(
                "wrong-key",
                "version-8",
                now + 300,
                vec![8; EVIDENCE_SEALING_KEY_BYTES],
            )
            .expect("material"),
        );
        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::InvalidKeyMaterial)
        ));
        assert_eq!(provider.outcomes.len(), 1);
        assert_eq!(
            provider.outcomes[0].disposition,
            ProviderSessionDisposition::Aborted
        );
    }

    #[test]
    fn short_lived_key_aborts_and_finishes() {
        let now = 2_000_000_000;
        let (plan, activation, _) = signed_plan(now);
        let mut provider = provider(now);
        provider.material = Some(
            ProviderKeyMaterial::new(
                "evidence-key-1",
                "version-8",
                now + 60,
                vec![8; EVIDENCE_SEALING_KEY_BYTES],
            )
            .expect("material"),
        );
        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::InvalidKeyMaterial)
        ));
        assert_eq!(provider.outcomes.len(), 1);
    }

    #[test]
    fn fetch_failure_aborts_and_finishes() {
        let now = 2_000_000_000;
        let (plan, activation, _) = signed_plan(now);
        let mut provider = provider(now);
        provider.fetch_failure = Some(ProviderFailure::new("backend_failure").expect("failure"));
        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ProviderFetchFailure(code))
                if code == "backend_failure"
        ));
        assert_eq!(provider.outcomes.len(), 1);
        assert_eq!(
            provider.outcomes[0].failure_code.as_deref(),
            Some("provider_fetch_failure")
        );
    }

    #[test]
    fn teardown_failure_overrides_success() {
        let now = 2_000_000_000;
        let (plan, activation, _) = signed_plan(now);
        let mut provider = provider(now);
        provider.finish_failure = Some(ProviderFailure::new("teardown_failed").expect("failure"));
        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ProviderTeardownFailure(code))
                if code == "teardown_failed"
        ));
    }

    #[test]
    fn key_material_debug_is_redacted() {
        let material = ProviderKeyMaterial::new(
            "evidence-key-1",
            "version-1",
            2_000_000_100,
            vec![9; EVIDENCE_SEALING_KEY_BYTES],
        )
        .expect("material");
        assert!(!format!("{material:?}").contains("9, 9"));
        assert!(format!("{material:?}").contains("[REDACTED]"));
    }

    #[test]
    fn invalid_key_size_is_rejected() {
        assert!(matches!(
            ProviderKeyMaterial::new("key", "version", 100, vec![1; 31]),
            Err(EvidenceKeyProviderError::InvalidKeyMaterial)
        ));
    }

    #[test]
    fn plan_tampering_is_rejected() {
        let now = 2_000_000_000;
        let (mut plan, activation, _) = signed_plan(now);
        plan.store_id = "different-store".into();
        let mut provider = provider(now);
        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::PlanDigestMismatch)
        ));
    }

    #[test]
    fn material_bytes_are_zeroizable() {
        let mut bytes = [3_u8; EVIDENCE_SEALING_KEY_BYTES];
        bytes.fill(0);
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}
