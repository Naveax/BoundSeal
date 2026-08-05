#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSessionOutcome {
    Committed,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFailure {
    code: String,
}

impl ProviderFailure {
    pub fn new(code: impl Into<String>) -> Result<Self, VaultProviderError> {
        let code = code.into();
        validate_identifier(&code, "provider_failure_code")?;
        Ok(Self { code })
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

impl fmt::Display for ProviderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.code)
    }
}

impl std::error::Error for ProviderFailure {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSessionRequest {
    pub bootstrap_id_sha256: String,
    pub plan_sha256: String,
    pub discovery_plan_sha256: String,
    pub target_origin_sha256: String,
    pub authority: String,
    pub scheme: String,
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub requested_secret_count: u64,
    pub session_expires_at_epoch_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSecretRequest {
    pub logical_id: String,
    pub provider_handle: String,
    pub kind: SecretKind,
    pub maximum_value_bytes: u64,
    pub required_version_sha256: Option<String>,
}

pub struct ProviderSecretMaterial {
    version_id: String,
    value: Zeroizing<Vec<u8>>,
    expires_at_epoch_seconds: i64,
}

impl ProviderSecretMaterial {
    pub fn new(
        version_id: impl Into<String>,
        value: Vec<u8>,
        expires_at_epoch_seconds: i64,
    ) -> Result<Self, VaultProviderError> {
        let value = Zeroizing::new(value);
        let version_id = version_id.into();
        validate_identifier(&version_id, "provider_version_id")?;
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(VaultProviderError::SecretValueSize);
        }
        Ok(Self {
            version_id,
            value,
            expires_at_epoch_seconds,
        })
    }

    pub fn into_parts(mut self) -> (String, Zeroizing<Vec<u8>>, i64) {
        let value = Zeroizing::new(std::mem::take(&mut *self.value));
        (self.version_id, value, self.expires_at_epoch_seconds)
    }
}

impl fmt::Debug for ProviderSecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSecretMaterial")
            .field("version_id_sha256", &sha256_bytes(self.version_id.as_bytes()))
            .field("value", &"<redacted>")
            .field("value_bytes", &self.value.len())
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

pub trait ExternalVaultProvider {
    type Session;

    fn identity(&self) -> ProviderIdentity;

    fn begin(
        &mut self,
        request: &ProviderSessionRequest,
    ) -> Result<Self::Session, ProviderFailure>;

    fn fetch(
        &mut self,
        session: &mut Self::Session,
        request: &ProviderSecretRequest,
    ) -> Result<ProviderSecretMaterial, ProviderFailure>;

    fn finish(
        &mut self,
        session: Self::Session,
        outcome: ProviderSessionOutcome,
    ) -> Result<(), ProviderFailure>;
}
