#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalVaultActivationPayload {
    pub version: u32,
    pub activation_id: String,
    pub plan_sha256: String,
    pub bootstrap_id_sha256: String,
    pub discovery_plan_sha256: String,
    pub target_origin_sha256: String,
    pub provider_instance_sha256: String,
    pub not_before_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
}

impl ExternalVaultActivationPayload {
    pub fn template(
        activation_id: impl Into<String>,
        plan: &ExternalVaultSessionPlan,
        not_before_epoch_seconds: i64,
        expires_at_epoch_seconds: i64,
    ) -> Result<Self, VaultProviderError> {
        plan.validate()?;
        let payload = Self {
            version: EXTERNAL_VAULT_ACTIVATION_VERSION,
            activation_id: activation_id.into(),
            plan_sha256: plan.plan_sha256.clone(),
            bootstrap_id_sha256: sha256_bytes(plan.bootstrap_id.as_bytes()),
            discovery_plan_sha256: plan.discovery_plan_sha256.clone(),
            target_origin_sha256: plan.target_origin_sha256.clone(),
            provider_instance_sha256: plan.provider.provider_instance_sha256.clone(),
            not_before_epoch_seconds,
            expires_at_epoch_seconds,
        };
        payload.validate(plan)?;
        Ok(payload)
    }

    fn validate(&self, plan: &ExternalVaultSessionPlan) -> Result<(), VaultProviderError> {
        if self.version != EXTERNAL_VAULT_ACTIVATION_VERSION {
            return Err(VaultProviderError::UnsupportedActivationVersion);
        }
        validate_identifier(&self.activation_id, "activation_id")?;
        for (value, field) in [
            (&self.plan_sha256, "plan_sha256"),
            (&self.bootstrap_id_sha256, "bootstrap_id_sha256"),
            (&self.discovery_plan_sha256, "discovery_plan_sha256"),
            (&self.target_origin_sha256, "target_origin_sha256"),
            (
                &self.provider_instance_sha256,
                "provider_instance_sha256",
            ),
        ] {
            validate_sha256(value, field)?;
        }
        if self.not_before_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.not_before_epoch_seconds
            || self.expires_at_epoch_seconds > plan.expires_at_epoch_seconds
        {
            return Err(VaultProviderError::InvalidActivationWindow);
        }
        if self.plan_sha256 != plan.plan_sha256
            || self.bootstrap_id_sha256 != sha256_bytes(plan.bootstrap_id.as_bytes())
            || self.discovery_plan_sha256 != plan.discovery_plan_sha256
            || self.target_origin_sha256 != plan.target_origin_sha256
            || self.provider_instance_sha256 != plan.provider.provider_instance_sha256
        {
            return Err(VaultProviderError::ActivationBindingMismatch);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, VaultProviderError> {
        serde_json::to_vec(self).map_err(|error| VaultProviderError::Serialization(error.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalVaultActivationCertificate {
    pub payload: ExternalVaultActivationPayload,
    pub signature_hex: String,
}

impl ExternalVaultActivationCertificate {
    pub fn verify(
        &self,
        plan: &ExternalVaultSessionPlan,
        public_key: &[u8],
        now_epoch_seconds: i64,
    ) -> Result<(), VaultProviderError> {
        plan.verify(now_epoch_seconds)?;
        if public_key.len() != 32
            || sha256_bytes(public_key) != plan.activation_key_id_sha256
        {
            return Err(VaultProviderError::ActivationKeyMismatch);
        }
        self.payload.validate(plan)?;
        if now_epoch_seconds < self.payload.not_before_epoch_seconds
            || now_epoch_seconds > self.payload.expires_at_epoch_seconds
        {
            return Err(VaultProviderError::ActivationExpired);
        }
        let signature = decode_lower_hex(&self.signature_hex, "signature_hex")?;
        if signature.len() != 64 {
            return Err(VaultProviderError::InvalidSignature);
        }
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&self.payload.signing_bytes()?, &signature)
            .map_err(|_| VaultProviderError::InvalidSignature)
    }

    pub fn certificate_sha256(&self) -> Result<String, VaultProviderError> {
        hash_serializable(self)
    }
}

#[derive(Debug, Serialize)]
struct ExternalVaultUseMarker {
    version: u32,
    bootstrap_id_sha256: String,
    activation_id_sha256: String,
    activation_certificate_sha256: String,
    plan_sha256: String,
    provider_instance_sha256: String,
    consumed_at_epoch_seconds: i64,
    state: String,
}

pub struct ConsumedExternalVaultActivation {
    plan_sha256: String,
    discovery_plan_sha256: String,
    target_origin_sha256: String,
    provider_instance_sha256: String,
    activation_certificate_sha256: String,
    not_before_epoch_seconds: i64,
    expires_at_epoch_seconds: i64,
}

impl fmt::Debug for ConsumedExternalVaultActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumedExternalVaultActivation")
            .field("plan_sha256", &self.plan_sha256)
            .field("provider_instance_sha256", &self.provider_instance_sha256)
            .field(
                "activation_certificate_sha256",
                &self.activation_certificate_sha256,
            )
            .field("not_before_epoch_seconds", &self.not_before_epoch_seconds)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

pub fn consume_activation_once(
    state_directory: &Path,
    plan: &ExternalVaultSessionPlan,
    certificate: &ExternalVaultActivationCertificate,
    public_key: &[u8],
    now_epoch_seconds: i64,
) -> Result<ConsumedExternalVaultActivation, VaultProviderError> {
    certificate.verify(plan, public_key, now_epoch_seconds)?;
    fs::create_dir_all(state_directory).map_err(|error| {
        VaultProviderError::StateIo(format!(
            "could not create external-vault state directory {}: {error}",
            state_directory.display()
        ))
    })?;
    let certificate_sha256 = certificate.certificate_sha256()?;
    let bootstrap_id_sha256 = sha256_bytes(plan.bootstrap_id.as_bytes());
    let activation_id_sha256 = sha256_bytes(certificate.payload.activation_id.as_bytes());
    let marker_path = state_directory.join(format!(
        "external-vault-{bootstrap_id_sha256}-{activation_id_sha256}.used.json"
    ));
    let marker = ExternalVaultUseMarker {
        version: 1,
        bootstrap_id_sha256,
        activation_id_sha256,
        activation_certificate_sha256: certificate_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        provider_instance_sha256: plan.provider.provider_instance_sha256.clone(),
        consumed_at_epoch_seconds: now_epoch_seconds,
        state: "consumed_fail_closed_no_replay".into(),
    };
    let bytes = serde_json::to_vec_pretty(&marker)
        .map_err(|error| VaultProviderError::Serialization(error.to_string()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .map_err(|error| {
            VaultProviderError::StateIo(format!(
                "external-vault activation already used or marker creation failed {}: {error}",
                marker_path.display()
            ))
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| VaultProviderError::StateIo(error.to_string()))?;
    Ok(ConsumedExternalVaultActivation {
        plan_sha256: plan.plan_sha256.clone(),
        discovery_plan_sha256: plan.discovery_plan_sha256.clone(),
        target_origin_sha256: plan.target_origin_sha256.clone(),
        provider_instance_sha256: plan.provider.provider_instance_sha256.clone(),
        activation_certificate_sha256: certificate_sha256,
        not_before_epoch_seconds: certificate.payload.not_before_epoch_seconds,
        expires_at_epoch_seconds: certificate.payload.expires_at_epoch_seconds,
    })
}
