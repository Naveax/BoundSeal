pub(crate) fn validate_hash_map(
    values: &BTreeMap<String, String>,
    name: &str,
    maximum: usize,
) -> Result<(), LifecycleError> {
    if values.is_empty() || values.len() > maximum {
        return Err(LifecycleError::BindingDenied(format!(
            "{name} count is invalid"
        )));
    }
    for (key, value) in values {
        validate_identifier(key, name)?;
        validate_sha256(value, name)?;
    }
    Ok(())
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

pub(crate) fn hash_serializable<T: Serialize>(value: &T) -> Result<String, LifecycleError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| LifecycleError::AuditSerialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
}

pub(crate) fn contains_secret_like_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization:",
        "proxy-authorization:",
        "cookie:",
        "set-cookie:",
        "bearer ",
        "password=",
        "token=",
        "secret=",
        "private_key",
        "http://",
        "https://",
        "file://",
        "ssh://",
    ]
    .iter()
    .any(|forbidden| lower.contains(forbidden))
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
