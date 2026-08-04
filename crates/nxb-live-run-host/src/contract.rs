use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use nxb_live_adapter::LiveAdapterConfig;
use nxb_operator::OperatorConfig;
use nxb_policy::CompiledPolicy;
use nxb_resumable_runner::RunnerManifest;
use nxb_session_injection::SessionInjectionManifest;
use nxb_unified_operator::UnifiedOperatorPlan;
use nxb_vault_provider::{ExternalVaultBootstrapReceipt, ExternalVaultSessionPlan};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::LiveRunHostError;

pub const LIVE_RUN_LAUNCH_BUNDLE_VERSION: u32 = 1;
pub const LIVE_RUN_LAUNCH_ACTIVATION_VERSION: u32 = 1;
pub const MAX_LIVE_RUN_LIFETIME_SECONDS: i64 = 60 * 60;
pub const MAX_LIVE_RUN_ACTIVATION_SECONDS: i64 = 15 * 60;
pub const MAX_LIVE_RUN_DNS_ADDRESSES: u16 = 32;
pub const MAX_LIVE_RUN_DNS_TTL_SECONDS: u32 = 3_600;

#[derive(Debug, Clone)]
pub struct LiveRunLaunchBundleParameters {
    pub launch_id: String,
    pub dns_resolver_id: String,
    pub maximum_dns_addresses: u16,
    pub maximum_dns_ttl_seconds: u32,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub signer_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LiveRunLaunchBundle {
    pub version: u32,
    pub launch_id: String,
    pub unified_plan_sha256: String,
    pub unified_binding_sha256: String,
    pub runner_manifest_sha256: String,
    pub external_vault_plan_sha256: String,
    pub external_vault_bootstrap_receipt_sha256: String,
    pub session_injection_manifest_sha256: String,
    pub policy_snapshot_sha256: String,
    pub operator_config_sha256: String,
    pub live_adapter_config_sha256: String,
    pub discovery_plan_sha256: String,
    pub target_origin_sha256: String,
    pub authority: String,
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub provider_id: String,
    pub provider_instance_sha256: String,
    pub provider_capability_sha256: String,
    pub external_session_id_sha256: String,
    pub secret_binding_root_sha256: String,
    pub secret_count: u64,
    pub dns_resolver_id: String,
    pub maximum_dns_addresses: u16,
    pub maximum_dns_ttl_seconds: u32,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub signer_key_id_sha256: String,
    pub bundle_sha256: String,
}

impl LiveRunLaunchBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        parameters: LiveRunLaunchBundleParameters,
        plan: &UnifiedOperatorPlan,
        runner: &RunnerManifest,
        external_plan: &ExternalVaultSessionPlan,
        bootstrap: &ExternalVaultBootstrapReceipt,
        injection: &SessionInjectionManifest,
        policy: &CompiledPolicy,
        operator: &OperatorConfig,
        adapter: &LiveAdapterConfig,
    ) -> Result<Self, LiveRunHostError> {
        if parameters.signer_public_key.len() != 32 {
            return Err(LiveRunHostError::InvalidField("signer_public_key".into()));
        }
        let mut bundle = Self {
            version: LIVE_RUN_LAUNCH_BUNDLE_VERSION,
            launch_id: parameters.launch_id,
            unified_plan_sha256: plan.plan_sha256.clone(),
            unified_binding_sha256: plan.binding_sha256.clone(),
            runner_manifest_sha256: runner.manifest_sha256.clone(),
            external_vault_plan_sha256: external_plan.plan_sha256.clone(),
            external_vault_bootstrap_receipt_sha256: bootstrap.receipt_sha256.clone(),
            session_injection_manifest_sha256: injection.manifest_sha256.clone(),
            policy_snapshot_sha256: policy.policy_snapshot_sha256().to_string(),
            operator_config_sha256: hash_serializable(operator)?,
            live_adapter_config_sha256: hash_serializable(adapter)?,
            discovery_plan_sha256: plan.binding.discovery_plan_sha256.clone(),
            target_origin_sha256: plan.binding.target_origin_sha256.clone(),
            authority: plan.binding.authority.clone(),
            run_id: plan.binding.run_id.clone(),
            worker_id: plan.binding.worker_id.clone(),
            account_id: plan.binding.account_id.clone(),
            tenant_id: plan.binding.tenant_id.clone(),
            role_id: plan.binding.role_id.clone(),
            provider_id: plan.binding.provider_id.clone(),
            provider_instance_sha256: plan.binding.provider_instance_sha256.clone(),
            provider_capability_sha256: plan.binding.provider_capability_sha256.clone(),
            external_session_id_sha256: plan.binding.external_session_id_sha256.clone(),
            secret_binding_root_sha256: plan.binding.secret_binding_root_sha256.clone(),
            secret_count: plan.binding.secret_count,
            dns_resolver_id: parameters.dns_resolver_id,
            maximum_dns_addresses: parameters.maximum_dns_addresses,
            maximum_dns_ttl_seconds: parameters.maximum_dns_ttl_seconds,
            created_at_epoch_seconds: parameters.created_at_epoch_seconds,
            expires_at_epoch_seconds: parameters.expires_at_epoch_seconds,
            signer_key_id_sha256: hash_bytes(&parameters.signer_public_key),
            bundle_sha256: String::new(),
        };
        bundle.validate()?;
        bundle.bundle_sha256 = bundle.calculate_sha256()?;
        bundle.verify_artifacts(
            plan,
            runner,
            external_plan,
            bootstrap,
            injection,
            policy,
            operator,
            adapter,
            parameters.created_at_epoch_seconds,
        )?;
        Ok(bundle)
    }

    pub fn validate(&self) -> Result<(), LiveRunHostError> {
        if self.version != LIVE_RUN_LAUNCH_BUNDLE_VERSION {
            return Err(LiveRunHostError::UnsupportedBundleVersion);
        }
        for (value, field) in [
            (&self.launch_id, "launch_id"),
            (&self.dns_resolver_id, "dns_resolver_id"),
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
        for (value, field) in [
            (&self.unified_plan_sha256, "unified_plan_sha256"),
            (&self.unified_binding_sha256, "unified_binding_sha256"),
            (&self.runner_manifest_sha256, "runner_manifest_sha256"),
            (
                &self.external_vault_plan_sha256,
                "external_vault_plan_sha256",
            ),
            (
                &self.external_vault_bootstrap_receipt_sha256,
                "external_vault_bootstrap_receipt_sha256",
            ),
            (
                &self.session_injection_manifest_sha256,
                "session_injection_manifest_sha256",
            ),
            (&self.policy_snapshot_sha256, "policy_snapshot_sha256"),
            (&self.operator_config_sha256, "operator_config_sha256"),
            (
                &self.live_adapter_config_sha256,
                "live_adapter_config_sha256",
            ),
            (&self.discovery_plan_sha256, "discovery_plan_sha256"),
            (&self.target_origin_sha256, "target_origin_sha256"),
            (&self.provider_instance_sha256, "provider_instance_sha256"),
            (
                &self.provider_capability_sha256,
                "provider_capability_sha256",
            ),
            (
                &self.external_session_id_sha256,
                "external_session_id_sha256",
            ),
            (
                &self.secret_binding_root_sha256,
                "secret_binding_root_sha256",
            ),
            (&self.signer_key_id_sha256, "signer_key_id_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        if !self.bundle_sha256.is_empty() {
            validate_sha256(&self.bundle_sha256, "bundle_sha256")?;
        }
        if self.secret_count == 0
            || self.maximum_dns_addresses == 0
            || self.maximum_dns_addresses > MAX_LIVE_RUN_DNS_ADDRESSES
            || self.maximum_dns_ttl_seconds == 0
            || self.maximum_dns_ttl_seconds > MAX_LIVE_RUN_DNS_TTL_SECONDS
        {
            return Err(LiveRunHostError::InvalidField(
                "secret_or_dns_budget".into(),
            ));
        }
        if self.created_at_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.created_at_epoch_seconds
            || self
                .expires_at_epoch_seconds
                .saturating_sub(self.created_at_epoch_seconds)
                > MAX_LIVE_RUN_LIFETIME_SECONDS
        {
            return Err(LiveRunHostError::InvalidBundleWindow);
        }
        Ok(())
    }

    pub fn calculate_sha256(&self) -> Result<String, LiveRunHostError> {
        let mut material = self.clone();
        material.bundle_sha256.clear();
        hash_serializable(&material)
    }

    pub fn verify(&self, now_epoch_seconds: i64) -> Result<(), LiveRunHostError> {
        self.validate()?;
        if self.bundle_sha256 != self.calculate_sha256()? {
            return Err(LiveRunHostError::BundleDigestMismatch);
        }
        if now_epoch_seconds < self.created_at_epoch_seconds
            || now_epoch_seconds > self.expires_at_epoch_seconds
        {
            return Err(LiveRunHostError::InvalidBundleWindow);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_artifacts(
        &self,
        plan: &UnifiedOperatorPlan,
        runner: &RunnerManifest,
        external_plan: &ExternalVaultSessionPlan,
        bootstrap: &ExternalVaultBootstrapReceipt,
        injection: &SessionInjectionManifest,
        policy: &CompiledPolicy,
        operator: &OperatorConfig,
        adapter: &LiveAdapterConfig,
        now_epoch_seconds: i64,
    ) -> Result<(), LiveRunHostError> {
        self.verify(now_epoch_seconds)?;
        plan.verify(now_epoch_seconds)?;
        runner.validate(plan, now_epoch_seconds)?;
        external_plan.verify(now_epoch_seconds)?;
        bootstrap.verify()?;
        injection.verify(now_epoch_seconds)?;
        operator.validate()?;
        adapter.validate()?;

        require_equal(
            "unified_plan_sha256",
            &self.unified_plan_sha256,
            &plan.plan_sha256,
        )?;
        require_equal(
            "unified_binding_sha256",
            &self.unified_binding_sha256,
            &plan.binding_sha256,
        )?;
        require_equal(
            "runner_manifest_sha256",
            &self.runner_manifest_sha256,
            &runner.manifest_sha256,
        )?;
        require_equal(
            "external_vault_plan_sha256",
            &self.external_vault_plan_sha256,
            &external_plan.plan_sha256,
        )?;
        require_equal(
            "external_vault_bootstrap_receipt_sha256",
            &self.external_vault_bootstrap_receipt_sha256,
            &bootstrap.receipt_sha256,
        )?;
        require_equal(
            "session_injection_manifest_sha256",
            &self.session_injection_manifest_sha256,
            &injection.manifest_sha256,
        )?;
        require_equal(
            "policy_snapshot_sha256",
            &self.policy_snapshot_sha256,
            policy.policy_snapshot_sha256(),
        )?;
        require_equal(
            "operator_config_sha256",
            &self.operator_config_sha256,
            &hash_serializable(operator)?,
        )?;
        require_equal(
            "live_adapter_config_sha256",
            &self.live_adapter_config_sha256,
            &hash_serializable(adapter)?,
        )?;

        let binding = &plan.binding;
        for (field, actual, expected) in [
            (
                "discovery_plan_sha256",
                self.discovery_plan_sha256.as_str(),
                binding.discovery_plan_sha256.as_str(),
            ),
            (
                "target_origin_sha256",
                self.target_origin_sha256.as_str(),
                binding.target_origin_sha256.as_str(),
            ),
            (
                "authority",
                self.authority.as_str(),
                binding.authority.as_str(),
            ),
            ("run_id", self.run_id.as_str(), binding.run_id.as_str()),
            (
                "worker_id",
                self.worker_id.as_str(),
                binding.worker_id.as_str(),
            ),
            (
                "account_id",
                self.account_id.as_str(),
                binding.account_id.as_str(),
            ),
            (
                "tenant_id",
                self.tenant_id.as_str(),
                binding.tenant_id.as_str(),
            ),
            ("role_id", self.role_id.as_str(), binding.role_id.as_str()),
            (
                "provider_id",
                self.provider_id.as_str(),
                binding.provider_id.as_str(),
            ),
            (
                "provider_instance_sha256",
                self.provider_instance_sha256.as_str(),
                binding.provider_instance_sha256.as_str(),
            ),
            (
                "provider_capability_sha256",
                self.provider_capability_sha256.as_str(),
                binding.provider_capability_sha256.as_str(),
            ),
            (
                "external_session_id_sha256",
                self.external_session_id_sha256.as_str(),
                binding.external_session_id_sha256.as_str(),
            ),
            (
                "secret_binding_root_sha256",
                self.secret_binding_root_sha256.as_str(),
                binding.secret_binding_root_sha256.as_str(),
            ),
        ] {
            require_equal(field, actual, expected)?;
        }
        if self.secret_count != binding.secret_count
            || self.expires_at_epoch_seconds > plan.expires_at_epoch_seconds
            || self.signer_key_id_sha256 != plan.activation_key_id_sha256
        {
            return Err(binding_error("plan_budget_or_signer"));
        }

        verify_external_bindings(plan, external_plan, bootstrap)?;
        verify_injection_bindings(plan, bootstrap, injection)?;
        verify_execution_bounds(plan, runner, policy, operator, adapter)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LiveRunLaunchActivationPayload {
    pub version: u32,
    pub activation_id: String,
    pub bundle_sha256: String,
    pub unified_plan_sha256: String,
    pub runner_manifest_sha256: String,
    pub external_vault_bootstrap_receipt_sha256: String,
    pub not_before_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub signer_key_id_sha256: String,
}

impl LiveRunLaunchActivationPayload {
    pub fn template(
        activation_id: impl Into<String>,
        bundle: &LiveRunLaunchBundle,
        not_before_epoch_seconds: i64,
        expires_at_epoch_seconds: i64,
    ) -> Result<Self, LiveRunHostError> {
        bundle.validate()?;
        let payload = Self {
            version: LIVE_RUN_LAUNCH_ACTIVATION_VERSION,
            activation_id: activation_id.into(),
            bundle_sha256: bundle.bundle_sha256.clone(),
            unified_plan_sha256: bundle.unified_plan_sha256.clone(),
            runner_manifest_sha256: bundle.runner_manifest_sha256.clone(),
            external_vault_bootstrap_receipt_sha256: bundle
                .external_vault_bootstrap_receipt_sha256
                .clone(),
            not_before_epoch_seconds,
            expires_at_epoch_seconds,
            signer_key_id_sha256: bundle.signer_key_id_sha256.clone(),
        };
        payload.validate(bundle)?;
        Ok(payload)
    }

    pub fn validate(&self, bundle: &LiveRunLaunchBundle) -> Result<(), LiveRunHostError> {
        if self.version != LIVE_RUN_LAUNCH_ACTIVATION_VERSION {
            return Err(LiveRunHostError::UnsupportedActivationVersion);
        }
        validate_identifier(&self.activation_id, "activation_id")?;
        for (value, field) in [
            (&self.bundle_sha256, "bundle_sha256"),
            (&self.unified_plan_sha256, "unified_plan_sha256"),
            (&self.runner_manifest_sha256, "runner_manifest_sha256"),
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
                > MAX_LIVE_RUN_ACTIVATION_SECONDS
            || self.expires_at_epoch_seconds > bundle.expires_at_epoch_seconds
        {
            return Err(LiveRunHostError::InvalidActivationWindow);
        }
        if self.bundle_sha256 != bundle.bundle_sha256
            || self.unified_plan_sha256 != bundle.unified_plan_sha256
            || self.runner_manifest_sha256 != bundle.runner_manifest_sha256
            || self.external_vault_bootstrap_receipt_sha256
                != bundle.external_vault_bootstrap_receipt_sha256
            || self.signer_key_id_sha256 != bundle.signer_key_id_sha256
        {
            return Err(LiveRunHostError::ActivationBindingMismatch);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, LiveRunHostError> {
        serde_json::to_vec(self).map_err(|error| LiveRunHostError::Serialization(error.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LiveRunLaunchActivationCertificate {
    pub payload: LiveRunLaunchActivationPayload,
    pub signature_hex: String,
}

impl LiveRunLaunchActivationCertificate {
    pub fn verify(
        &self,
        bundle: &LiveRunLaunchBundle,
        public_key: &[u8],
        now_epoch_seconds: i64,
    ) -> Result<(), LiveRunHostError> {
        bundle.verify(now_epoch_seconds)?;
        self.payload.validate(bundle)?;
        if public_key.len() != 32 || hash_bytes(public_key) != bundle.signer_key_id_sha256 {
            return Err(LiveRunHostError::ActivationKeyMismatch);
        }
        if now_epoch_seconds < self.payload.not_before_epoch_seconds
            || now_epoch_seconds > self.payload.expires_at_epoch_seconds
        {
            return Err(LiveRunHostError::ActivationExpired);
        }
        let signature = decode_lower_hex(&self.signature_hex)?;
        if signature.len() != 64 {
            return Err(LiveRunHostError::InvalidSignature);
        }
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&self.payload.signing_bytes()?, &signature)
            .map_err(|_| LiveRunHostError::InvalidSignature)
    }

    pub fn certificate_sha256(&self) -> Result<String, LiveRunHostError> {
        hash_serializable(self)
    }
}

#[derive(Debug)]
pub struct ConsumedLiveRunLaunchActivation {
    bundle_sha256: String,
    activation_certificate_sha256: String,
    expires_at_epoch_seconds: i64,
    marker_path: PathBuf,
}

impl ConsumedLiveRunLaunchActivation {
    pub fn bundle_sha256(&self) -> &str {
        &self.bundle_sha256
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

#[derive(Debug, Serialize)]
struct LiveRunLaunchUseMarker {
    version: u32,
    launch_id_sha256: String,
    activation_id_sha256: String,
    bundle_sha256: String,
    activation_certificate_sha256: String,
    consumed_at_epoch_seconds: i64,
    state: String,
}

pub fn consume_launch_activation_once(
    state_directory: &Path,
    bundle: &LiveRunLaunchBundle,
    certificate: &LiveRunLaunchActivationCertificate,
    public_key: &[u8],
    now_epoch_seconds: i64,
) -> Result<ConsumedLiveRunLaunchActivation, LiveRunHostError> {
    certificate.verify(bundle, public_key, now_epoch_seconds)?;
    fs::create_dir_all(state_directory).map_err(|error| LiveRunHostError::Io(error.to_string()))?;
    let certificate_sha256 = certificate.certificate_sha256()?;
    let marker_path = state_directory.join(format!(
        "live-run-launch-{}.json",
        hash_bytes(certificate.payload.activation_id.as_bytes())
    ));
    let marker = LiveRunLaunchUseMarker {
        version: 1,
        launch_id_sha256: hash_bytes(bundle.launch_id.as_bytes()),
        activation_id_sha256: hash_bytes(certificate.payload.activation_id.as_bytes()),
        bundle_sha256: bundle.bundle_sha256.clone(),
        activation_certificate_sha256: certificate_sha256.clone(),
        consumed_at_epoch_seconds: now_epoch_seconds,
        state: "consumed_fail_closed_no_replay".into(),
    };
    let mut bytes = serde_json::to_vec_pretty(&marker)
        .map_err(|error| LiveRunHostError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                LiveRunHostError::ActivationReplay
            } else {
                LiveRunHostError::Io(error.to_string())
            }
        })?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&marker_path);
        return Err(LiveRunHostError::Io(error.to_string()));
    }
    Ok(ConsumedLiveRunLaunchActivation {
        bundle_sha256: bundle.bundle_sha256.clone(),
        activation_certificate_sha256: certificate_sha256,
        expires_at_epoch_seconds: certificate.payload.expires_at_epoch_seconds,
        marker_path,
    })
}

fn verify_external_bindings(
    plan: &UnifiedOperatorPlan,
    external: &ExternalVaultSessionPlan,
    receipt: &ExternalVaultBootstrapReceipt,
) -> Result<(), LiveRunHostError> {
    let binding = &plan.binding;
    for (field, actual, expected) in [
        (
            "external.plan",
            external.plan_sha256.as_str(),
            binding.external_vault_plan_sha256.as_str(),
        ),
        (
            "external.discovery",
            external.discovery_plan_sha256.as_str(),
            binding.discovery_plan_sha256.as_str(),
        ),
        (
            "external.origin",
            external.target_origin_sha256.as_str(),
            binding.target_origin_sha256.as_str(),
        ),
        (
            "external.authority",
            external.authority.as_str(),
            binding.authority.as_str(),
        ),
        (
            "external.run",
            external.run_id.as_str(),
            binding.run_id.as_str(),
        ),
        (
            "external.worker",
            external.worker_id.as_str(),
            binding.worker_id.as_str(),
        ),
        (
            "external.account",
            external.account_id.as_str(),
            binding.account_id.as_str(),
        ),
        (
            "external.tenant",
            external.tenant_id.as_str(),
            binding.tenant_id.as_str(),
        ),
        (
            "external.role",
            external.role_id.as_str(),
            binding.role_id.as_str(),
        ),
        (
            "external.provider",
            external.provider.provider_id.as_str(),
            binding.provider_id.as_str(),
        ),
        (
            "receipt.plan",
            receipt.plan_sha256.as_str(),
            external.plan_sha256.as_str(),
        ),
        (
            "receipt.discovery",
            receipt.discovery_plan_sha256.as_str(),
            binding.discovery_plan_sha256.as_str(),
        ),
        (
            "receipt.origin",
            receipt.target_origin_sha256.as_str(),
            binding.target_origin_sha256.as_str(),
        ),
        (
            "receipt.provider",
            receipt.provider_id.as_str(),
            binding.provider_id.as_str(),
        ),
        (
            "receipt.provider_instance",
            receipt.provider_instance_sha256.as_str(),
            binding.provider_instance_sha256.as_str(),
        ),
        (
            "receipt.capability",
            receipt.capability_sha256.as_str(),
            binding.provider_capability_sha256.as_str(),
        ),
        (
            "receipt.session",
            receipt.session_id_sha256.as_str(),
            binding.external_session_id_sha256.as_str(),
        ),
        (
            "receipt.secret_root",
            receipt.secret_binding_root_sha256.as_str(),
            binding.secret_binding_root_sha256.as_str(),
        ),
    ] {
        require_equal(field, actual, expected)?;
    }
    if external.provider.provider_instance_sha256 != binding.provider_instance_sha256
        || external.provider.capability_sha256 != binding.provider_capability_sha256
        || receipt.secret_count != binding.secret_count
        || external.secrets.len() as u64 != binding.secret_count
    {
        return Err(binding_error("external_secret_or_provider_count"));
    }
    Ok(())
}

fn verify_injection_bindings(
    plan: &UnifiedOperatorPlan,
    receipt: &ExternalVaultBootstrapReceipt,
    injection: &SessionInjectionManifest,
) -> Result<(), LiveRunHostError> {
    let binding = &plan.binding;
    for (field, actual, expected) in [
        (
            "injection.discovery",
            injection.discovery_plan_sha256.as_str(),
            binding.discovery_plan_sha256.as_str(),
        ),
        (
            "injection.origin",
            injection.target_origin_sha256.as_str(),
            binding.target_origin_sha256.as_str(),
        ),
        (
            "injection.authority",
            injection.authority.as_str(),
            binding.authority.as_str(),
        ),
        (
            "injection.run",
            injection.run_id.as_str(),
            binding.run_id.as_str(),
        ),
        (
            "injection.worker",
            injection.worker_id.as_str(),
            binding.worker_id.as_str(),
        ),
        (
            "injection.account",
            injection.account_id.as_str(),
            binding.account_id.as_str(),
        ),
        (
            "injection.tenant",
            injection.tenant_id.as_str(),
            binding.tenant_id.as_str(),
        ),
        (
            "injection.role",
            injection.role_id.as_str(),
            binding.role_id.as_str(),
        ),
    ] {
        require_equal(field, actual, expected)?;
    }
    if hash_bytes(injection.session_id.as_bytes()) != receipt.session_id_sha256 {
        return Err(binding_error("injection_session"));
    }
    let manifest_handles = injection
        .bootstrap_secret_handles
        .iter()
        .map(|handle| hash_bytes(handle.as_str().as_bytes()))
        .collect::<BTreeSet<_>>();
    let receipt_handles = receipt
        .provisioned_secrets
        .iter()
        .map(|secret| secret.vault_handle_sha256.clone())
        .collect::<BTreeSet<_>>();
    if manifest_handles != receipt_handles || manifest_handles.len() as u64 != binding.secret_count
    {
        return Err(binding_error("injection_secret_handles"));
    }
    if injection.allowed_path_prefixes.iter().any(|path| {
        !binding
            .allowed_path_prefixes
            .iter()
            .any(|parent| path_is_within(path, parent))
    }) {
        return Err(binding_error("injection_path_scope"));
    }
    Ok(())
}

fn verify_execution_bounds(
    plan: &UnifiedOperatorPlan,
    runner: &RunnerManifest,
    policy: &CompiledPolicy,
    operator: &OperatorConfig,
    adapter: &LiveAdapterConfig,
) -> Result<(), LiveRunHostError> {
    let binding = &plan.binding;
    if !operator.passive_only
        || operator.follow_redirects
        || operator.allow_session_mutation
        || operator
            .probe_capabilities
            .iter()
            .any(|probe| probe.is_active())
        || operator.maximum_requests > binding.maximum_requests
        || operator.maximum_depth > binding.maximum_depth
        || operator.maximum_endpoints > runner.maximum_queue_entries
        || operator.maximum_body_bytes > binding.maximum_response_body_bytes
        || runner.maximum_requests != binding.maximum_requests
        || runner.maximum_depth != binding.maximum_depth
        || runner.maximum_response_body_bytes != binding.maximum_response_body_bytes
        || adapter.limits.http.maximum_response_body_bytes > binding.maximum_response_body_bytes
        || policy.maximum_total_requests() < binding.maximum_requests
        || policy.maximum_concurrency() < binding.maximum_concurrency
        || binding.maximum_concurrency != 1
        || policy.active_testing_enabled()
        || policy.oob_callbacks_enabled()
    {
        return Err(binding_error("execution_bounds"));
    }
    let effective_rps = 1_000_f64 / binding.minimum_request_interval_milliseconds as f64;
    if effective_rps > policy.maximum_requests_per_second() + f64::EPSILON {
        return Err(binding_error("request_rate"));
    }
    let seed_url = url::Url::parse(&format!(
        "https://{}{}",
        binding.authority, runner.seed.target
    ))
    .map_err(|_| binding_error("runner_seed_url"))?;
    if !policy.allows_request(&seed_url, runner.seed.method.code()) {
        return Err(binding_error("runner_seed_policy"));
    }
    Ok(())
}

fn path_is_within(candidate: &str, parent: &str) -> bool {
    candidate == parent
        || parent == "/"
        || candidate
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn require_equal(field: &str, actual: &str, expected: &str) -> Result<(), LiveRunHostError> {
    if actual != expected {
        return Err(binding_error(field));
    }
    Ok(())
}

fn binding_error(field: &str) -> LiveRunHostError {
    LiveRunHostError::ArtifactBindingMismatch(field.into())
}

pub(crate) fn hash_serializable<T: Serialize>(value: &T) -> Result<String, LiveRunHostError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| LiveRunHostError::Serialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

pub(crate) fn validate_identifier(value: &str, field: &str) -> Result<(), LiveRunHostError> {
    if !(1..=128).contains(&value.len())
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
    {
        return Err(LiveRunHostError::InvalidField(field.into()));
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, field: &str) -> Result<(), LiveRunHostError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LiveRunHostError::InvalidField(field.into()));
    }
    Ok(())
}

fn validate_authority(value: &str) -> Result<(), LiveRunHostError> {
    if value.is_empty()
        || value.len() > 253
        || value != value.to_ascii_lowercase()
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains(':')
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
    {
        return Err(LiveRunHostError::InvalidField("authority".into()));
    }
    Ok(())
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, LiveRunHostError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LiveRunHostError::InvalidSignature);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0]).ok_or(LiveRunHostError::InvalidSignature)?;
            let low = decode_nibble(pair[1]).ok_or(LiveRunHostError::InvalidSignature)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
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
