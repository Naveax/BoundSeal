#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentity {
    pub provider_id: String,
    pub provider_instance_sha256: String,
    pub capability_sha256: String,
}

impl ProviderIdentity {
    pub fn validate(&self) -> Result<(), VaultProviderError> {
        validate_identifier(&self.provider_id, "provider_id")?;
        validate_sha256(
            &self.provider_instance_sha256,
            "provider_instance_sha256",
        )?;
        validate_sha256(&self.capability_sha256, "capability_sha256")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "delivery", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderDeliverySpec {
    Header {
        name: String,
        prefix_hex: String,
    },
    Cookie {
        cookie: CookieMetadata,
    },
}

impl ProviderDeliverySpec {
    fn validate(
        &self,
        authority: &str,
        session_expires_at_epoch_seconds: i64,
    ) -> Result<(), VaultProviderError> {
        match self {
            Self::Header { name, prefix_hex } => {
                let normalized = normalize_header_name(name)?;
                if normalized != *name || PROTOCOL_MANAGED_HEADERS.contains(&normalized.as_str()) {
                    return Err(VaultProviderError::InvalidDeliverySpec);
                }
                let prefix = decode_lower_hex(prefix_hex, "prefix_hex")?;
                if prefix.len() > MAX_PROVIDER_PREFIX_BYTES || !valid_header_value(&prefix) {
                    return Err(VaultProviderError::InvalidDeliverySpec);
                }
            }
            Self::Cookie { cookie } => {
                if !cookie.secure
                    || normalize_host(&cookie.domain)? != authority
                    || cookie.domain != authority
                    || !valid_cookie_name(&cookie.name)
                    || cookie.expires_at_epoch_seconds.is_some_and(|expires| {
                        expires < session_expires_at_epoch_seconds
                    })
                {
                    return Err(VaultProviderError::InvalidDeliverySpec);
                }
                validate_passive_path(&cookie.path)?;
            }
        }
        Ok(())
    }

    fn secret_delivery(&self) -> Result<SecretDelivery, VaultProviderError> {
        match self {
            Self::Header { name, prefix_hex } => Ok(SecretDelivery::Header {
                name: name.clone(),
                prefix: decode_lower_hex(prefix_hex, "prefix_hex")?,
            }),
            Self::Cookie { cookie } => Ok(SecretDelivery::Cookie(cookie.clone())),
        }
    }

    fn kind_matches(&self, kind: SecretKind) -> bool {
        matches!((self, kind), (Self::Cookie { .. }, SecretKind::Cookie))
            || matches!(self, Self::Header { .. }) && kind != SecretKind::Cookie
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSecretSpec {
    pub logical_id: String,
    pub provider_handle: String,
    pub kind: SecretKind,
    pub delivery: ProviderDeliverySpec,
    pub maximum_value_bytes: u64,
    pub required_version_sha256: Option<String>,
}

impl ProviderSecretSpec {
    fn validate(
        &self,
        authority: &str,
        session_expires_at_epoch_seconds: i64,
    ) -> Result<(), VaultProviderError> {
        validate_identifier(&self.logical_id, "logical_id")?;
        validate_provider_handle(&self.provider_handle)?;
        if self.maximum_value_bytes == 0 || self.maximum_value_bytes > MAX_SECRET_BYTES as u64 {
            return Err(VaultProviderError::InvalidSecretSpec);
        }
        if let Some(version) = &self.required_version_sha256 {
            validate_sha256(version, "required_version_sha256")?;
        }
        if !self.delivery.kind_matches(self.kind) {
            return Err(VaultProviderError::InvalidSecretSpec);
        }
        self.delivery
            .validate(authority, session_expires_at_epoch_seconds)
    }
}

#[derive(Debug, Clone)]
pub struct ExternalVaultPlanParameters {
    pub bootstrap_id: String,
    pub discovery_plan_sha256: String,
    pub target_origin_sha256: String,
    pub authority: String,
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub provider: ProviderIdentity,
    pub secrets: Vec<ProviderSecretSpec>,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub session_expires_at_epoch_seconds: i64,
    pub activation_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalVaultSessionPlan {
    pub version: u32,
    pub bootstrap_id: String,
    pub discovery_plan_sha256: String,
    pub target_origin_sha256: String,
    pub authority: String,
    pub scheme: String,
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub provider: ProviderIdentity,
    pub secrets: Vec<ProviderSecretSpec>,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub session_expires_at_epoch_seconds: i64,
    pub activation_key_id_sha256: String,
    pub plan_sha256: String,
}

impl ExternalVaultSessionPlan {
    pub fn build(parameters: ExternalVaultPlanParameters) -> Result<Self, VaultProviderError> {
        if parameters.activation_public_key.len() != 32 {
            return Err(VaultProviderError::InvalidActivationPublicKey);
        }
        let mut plan = Self {
            version: EXTERNAL_VAULT_PLAN_VERSION,
            bootstrap_id: parameters.bootstrap_id,
            discovery_plan_sha256: parameters.discovery_plan_sha256,
            target_origin_sha256: parameters.target_origin_sha256,
            authority: normalize_host(&parameters.authority)?,
            scheme: "https".into(),
            run_id: parameters.run_id,
            worker_id: parameters.worker_id,
            account_id: parameters.account_id,
            tenant_id: parameters.tenant_id,
            role_id: parameters.role_id,
            provider: parameters.provider,
            secrets: parameters.secrets,
            created_at_epoch_seconds: parameters.created_at_epoch_seconds,
            expires_at_epoch_seconds: parameters.expires_at_epoch_seconds,
            session_expires_at_epoch_seconds: parameters.session_expires_at_epoch_seconds,
            activation_key_id_sha256: sha256_bytes(&parameters.activation_public_key),
            plan_sha256: String::new(),
        };
        plan.validate()?;
        plan.plan_sha256 = plan.calculate_sha256()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), VaultProviderError> {
        if self.version != EXTERNAL_VAULT_PLAN_VERSION {
            return Err(VaultProviderError::UnsupportedPlanVersion);
        }
        for (value, field) in [
            (&self.bootstrap_id, "bootstrap_id"),
            (&self.run_id, "run_id"),
            (&self.worker_id, "worker_id"),
            (&self.account_id, "account_id"),
            (&self.tenant_id, "tenant_id"),
            (&self.role_id, "role_id"),
        ] {
            validate_identifier(value, field)?;
        }
        for (value, field) in [
            (&self.discovery_plan_sha256, "discovery_plan_sha256"),
            (&self.target_origin_sha256, "target_origin_sha256"),
            (&self.activation_key_id_sha256, "activation_key_id_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        if !self.plan_sha256.is_empty() {
            validate_sha256(&self.plan_sha256, "plan_sha256")?;
        }
        if normalize_host(&self.authority)? != self.authority || self.scheme != "https" {
            return Err(VaultProviderError::InvalidOrigin);
        }
        if sha256_bytes(format!("https://{}:443", self.authority).as_bytes())
            != self.target_origin_sha256
        {
            return Err(VaultProviderError::OriginDigestMismatch);
        }
        if self.created_at_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.created_at_epoch_seconds
            || self
                .expires_at_epoch_seconds
                .saturating_sub(self.created_at_epoch_seconds)
                > MAX_EXTERNAL_VAULT_PLAN_SECONDS
        {
            return Err(VaultProviderError::InvalidPlanWindow);
        }
        if self.session_expires_at_epoch_seconds <= self.created_at_epoch_seconds
            || self
                .session_expires_at_epoch_seconds
                .saturating_sub(self.created_at_epoch_seconds)
                > MAX_EXTERNAL_SESSION_SECONDS
            || self.session_expires_at_epoch_seconds < self.expires_at_epoch_seconds
        {
            return Err(VaultProviderError::InvalidSessionWindow);
        }
        self.provider.validate()?;
        if self.secrets.is_empty() || self.secrets.len() > MAX_EXTERNAL_SECRET_COUNT {
            return Err(VaultProviderError::InvalidSecretCount);
        }
        let mut logical_ids = BTreeSet::new();
        let mut provider_handles = BTreeSet::new();
        for secret in &self.secrets {
            secret.validate(&self.authority, self.session_expires_at_epoch_seconds)?;
            if !logical_ids.insert(secret.logical_id.clone())
                || !provider_handles.insert(secret.provider_handle.clone())
            {
                return Err(VaultProviderError::DuplicateSecretSpec);
            }
        }
        Ok(())
    }

    pub fn calculate_sha256(&self) -> Result<String, VaultProviderError> {
        let mut material = self.clone();
        material.plan_sha256.clear();
        hash_serializable(&material)
    }

    pub fn verify(&self, now_epoch_seconds: i64) -> Result<(), VaultProviderError> {
        self.validate()?;
        if self.plan_sha256 != self.calculate_sha256()? {
            return Err(VaultProviderError::PlanDigestMismatch);
        }
        if now_epoch_seconds < self.created_at_epoch_seconds
            || now_epoch_seconds > self.expires_at_epoch_seconds
        {
            return Err(VaultProviderError::PlanExpired);
        }
        Ok(())
    }
}
