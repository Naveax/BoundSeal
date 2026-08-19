fn validate_consumed_activation(
    plan: &ExternalVaultSessionPlan,
    activation: &ConsumedExternalVaultActivation,
    now_epoch_seconds: i64,
) -> Result<(), VaultProviderError> {
    if activation.plan_sha256 != plan.plan_sha256
        || activation.discovery_plan_sha256 != plan.discovery_plan_sha256
        || activation.target_origin_sha256 != plan.target_origin_sha256
        || activation.provider_instance_sha256 != plan.provider.provider_instance_sha256
    {
        return Err(VaultProviderError::ActivationBindingMismatch);
    }
    if now_epoch_seconds < activation.not_before_epoch_seconds
        || now_epoch_seconds > activation.expires_at_epoch_seconds
    {
        return Err(VaultProviderError::ActivationExpired);
    }
    Ok(())
}

fn validate_material(
    plan: &ExternalVaultSessionPlan,
    spec: &ProviderSecretSpec,
    material: &ProviderSecretMaterial,
    now_epoch_seconds: i64,
) -> Result<(), VaultProviderError> {
    validate_identifier(&material.version_id, "provider_version_id")?;
    if material.value.is_empty()
        || material.value.len() as u64 > spec.maximum_value_bytes
        || material.value.len() > MAX_SECRET_BYTES
    {
        return Err(VaultProviderError::SecretValueSize);
    }
    let version_sha256 = sha256_bytes(material.version_id.as_bytes());
    if spec
        .required_version_sha256
        .as_ref()
        .is_some_and(|required| required != &version_sha256)
    {
        return Err(VaultProviderError::SecretVersionMismatch);
    }
    if material.expires_at_epoch_seconds <= now_epoch_seconds
        || material.expires_at_epoch_seconds < plan.session_expires_at_epoch_seconds
    {
        return Err(VaultProviderError::SecretExpiryMismatch);
    }
    Ok(())
}

fn rollback_provisioning(
    session: Option<&SessionMetadata>,
    handles: &[SecretHandle],
    broker: &mut SessionBroker,
    vault: &mut InMemorySecretVault,
) -> Result<(), String> {
    let mut failures = Vec::new();
    if let Some(session) = session {
        if let Err(error) = broker.revoke_session(&session.session_id) {
            failures.push(format!("session:{}", error_code(&error)));
        }
    }
    for handle in handles.iter().rev() {
        if let Err(error) = vault.revoke_secret(handle) {
            failures.push(format!("vault:{}", vault_error_code(&error)));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join(","))
    }
}

fn error_code(error: &SessionError) -> &'static str {
    match error {
        SessionError::UnknownSession => "unknown_session",
        SessionError::SessionExpired => "session_expired",
        SessionError::SessionRevoked => "session_revoked",
        _ => "session_error",
    }
}

fn vault_error_code(error: &VaultError) -> &'static str {
    match error {
        VaultError::UnknownSecret => "unknown_secret",
        VaultError::SecretExpired => "secret_expired",
        VaultError::AccessDenied => "access_denied",
        _ => "vault_error",
    }
}

#[derive(Debug, Error)]
pub enum VaultProviderError {
    #[error("unsupported external-vault plan version")]
    UnsupportedPlanVersion,
    #[error("unsupported external-vault activation version")]
    UnsupportedActivationVersion,
    #[error("external-vault identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("external-vault digest is invalid: {0}")]
    InvalidDigest(String),
    #[error("external-vault provider handle is invalid")]
    InvalidProviderHandle,
    #[error("external-vault origin is invalid")]
    InvalidOrigin,
    #[error("external-vault origin digest does not match")]
    OriginDigestMismatch,
    #[error("external-vault plan window is invalid")]
    InvalidPlanWindow,
    #[error("external-vault session window is invalid")]
    InvalidSessionWindow,
    #[error("external-vault plan is outside its validity window")]
    PlanExpired,
    #[error("external-vault plan digest mismatch")]
    PlanDigestMismatch,
    #[error("external-vault provider identity is invalid")]
    InvalidProviderIdentity,
    #[error("external-vault provider identity does not match the signed plan")]
    ProviderIdentityMismatch,
    #[error("external-vault secret count is invalid")]
    InvalidSecretCount,
    #[error("external-vault secret specification is invalid")]
    InvalidSecretSpec,
    #[error("external-vault secret specifications contain duplicates")]
    DuplicateSecretSpec,
    #[error("external-vault delivery specification is invalid")]
    InvalidDeliverySpec,
    #[error("external-vault activation public key is invalid")]
    InvalidActivationPublicKey,
    #[error("external-vault activation window is invalid")]
    InvalidActivationWindow,
    #[error("external-vault activation does not match the signed plan")]
    ActivationBindingMismatch,
    #[error("external-vault activation key does not match")]
    ActivationKeyMismatch,
    #[error("external-vault activation is outside its validity window")]
    ActivationExpired,
    #[error("external-vault signature is invalid")]
    InvalidSignature,
    #[error("external-vault provider begin failed: {0}")]
    ProviderBegin(String),
    #[error("external-vault provider fetch failed for {logical_id_sha256}: {code}")]
    ProviderFetch {
        logical_id_sha256: String,
        code: String,
    },
    #[error("external-vault provider abort failed: {0}")]
    ProviderAbort(String),
    #[error("external-vault provider commit failed: {0}")]
    ProviderCommit(String),
    #[error("external-vault secret value size is invalid")]
    SecretValueSize,
    #[error("external-vault secret version does not match the signed plan")]
    SecretVersionMismatch,
    #[error("external-vault secret expires before the provisioned session")]
    SecretExpiryMismatch,
    #[error("external-vault session was not created")]
    SessionNotCreated,
    #[error("external-vault rollback failed: {0}")]
    RollbackFailed(String),
    #[error("external-vault bootstrap receipt is invalid")]
    InvalidReceipt,
    #[error("external-vault bootstrap receipt binding root mismatch")]
    ReceiptBindingMismatch,
    #[error("external-vault bootstrap receipt digest mismatch")]
    ReceiptDigestMismatch,
    #[error("external-vault teardown failed after attempting all revocations: {0}")]
    TeardownFailed(String),
    #[error("external-vault teardown receipt is invalid")]
    InvalidTeardownReceipt,
    #[error("external-vault teardown receipt digest mismatch")]
    TeardownDigestMismatch,
    #[error("external-vault serialization failed: {0}")]
    Serialization(String),
    #[error("external-vault state operation failed: {0}")]
    StateIo(String),
    #[error("external-vault vault operation failed: {0}")]
    Vault(#[from] VaultError),
    #[error("external-vault session operation failed: {0}")]
    Session(#[from] SessionError),
}

fn normalize_host(value: &str) -> Result<String, VaultProviderError> {
    let normalized = value.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || !normalized.contains('.')
        || normalized.starts_with('.')
        || normalized.ends_with('.')
        || normalized.parse::<std::net::IpAddr>().is_ok()
        || normalized.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
        })
        || normalized
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
    {
        return Err(VaultProviderError::InvalidOrigin);
    }
    Ok(normalized)
}

fn normalize_header_name(value: &str) -> Result<String, VaultProviderError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 256 || !normalized.bytes().all(is_token_byte) {
        return Err(VaultProviderError::InvalidDeliverySpec);
    }
    Ok(normalized)
}

fn valid_cookie_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(is_token_byte)
}

fn valid_header_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| matches!(byte, b'\t' | 0x20..=0x7e))
}

fn validate_passive_path(value: &str) -> Result<(), VaultProviderError> {
    if value.is_empty()
        || value.len() > 4 * 1024
        || !value.starts_with('/')
        || value.contains("//")
        || value.contains('?')
        || value.contains('#')
        || value.contains('%')
        || value.contains(';')
        || value.contains('\\')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || value.split('/').any(|segment| segment == "." || segment == "..")
    {
        return Err(VaultProviderError::InvalidDeliverySpec);
    }
    Ok(())
}

fn validate_provider_handle(value: &str) -> Result<(), VaultProviderError> {
    if value.is_empty()
        || value.len() > 512
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains("..")
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\\')
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(VaultProviderError::InvalidProviderHandle);
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &str) -> Result<(), VaultProviderError> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(VaultProviderError::InvalidIdentifier(field.into()));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), VaultProviderError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VaultProviderError::InvalidDigest(field.into()));
    }
    Ok(())
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, VaultProviderError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| VaultProviderError::Serialization(error.to_string()))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

pub fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_lower_hex(value: &str, field: &str) -> Result<Vec<u8>, VaultProviderError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VaultProviderError::InvalidDigest(field.into()));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])
                .ok_or_else(|| VaultProviderError::InvalidDigest(field.into()))?;
            let low = decode_nibble(pair[1])
                .ok_or_else(|| VaultProviderError::InvalidDigest(field.into()))?;
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
