#[derive(Debug, Clone, Copy)]
struct ValidatedSessionState {
    static_secret_count: u64,
    cookie_secret_count: u64,
}

fn validate_session_state(
    manifest: &SessionInjectionManifest,
    session: &SessionMetadata,
    vault: &InMemorySecretVault,
    request_target: Option<&str>,
    now_epoch_seconds: i64,
) -> Result<ValidatedSessionState, SessionInjectionError> {
    if session.status != SessionStatus::Active {
        return Err(SessionInjectionError::SessionRevoked);
    }
    if session.session_id != manifest.session_id
        || session.profile.run_id != manifest.run_id
        || session.profile.worker_id != manifest.worker_id
        || session.profile.account_id != manifest.account_id
        || session.profile.tenant_id != manifest.tenant_id
        || session.profile.role_id != manifest.role_id
    {
        return Err(SessionInjectionError::SessionIdentityMismatch);
    }
    if session.profile.expires_at_epoch_seconds <= now_epoch_seconds
        || session.profile.expires_at_epoch_seconds < manifest.expires_at_epoch_seconds
    {
        return Err(SessionInjectionError::SessionExpired);
    }
    if session.profile.allowed_hosts != BTreeSet::from([manifest.authority.clone()])
        || session.profile.allowed_schemes != BTreeSet::from([manifest.scheme.clone()])
    {
        return Err(SessionInjectionError::SessionAuthorityTooBroad);
    }

    let bootstrap = manifest
        .bootstrap_secret_handles
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let current = session
        .profile
        .secret_handles
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if current.len() != session.profile.secret_handles.len() {
        return Err(SessionInjectionError::DuplicateSessionHandle);
    }

    let mut required_static = BTreeSet::new();
    for handle in &manifest.bootstrap_secret_handles {
        let metadata = vault
            .metadata(handle)
            .map_err(|_| SessionInjectionError::UnknownSecretHandle)?;
        validate_secret_identity(manifest, &metadata, now_epoch_seconds)?;
        if matches!(metadata.delivery, SecretDeliveryMetadata::Header { .. }) {
            required_static.insert(handle.clone());
        }
    }

    let mut static_secret_count = 0_u64;
    let mut cookie_secret_count = 0_u64;
    let mut cookies = BTreeMap::<String, Vec<CookieMetadata>>::new();
    for handle in &session.profile.secret_handles {
        let metadata = vault
            .metadata(handle)
            .map_err(|_| SessionInjectionError::UnknownSecretHandle)?;
        validate_secret_identity(manifest, &metadata, now_epoch_seconds)?;
        match metadata.delivery {
            SecretDeliveryMetadata::Cookie { cookie } => {
                let name = normalize_cookie_name(&cookie.name)?;
                let domain = normalize_host(&cookie.domain)?;
                validate_passive_path(&cookie.path)?;
                if metadata.kind != SecretKind::Cookie
                    || !manifest.allowed_cookie_names.contains(&name)
                    || !cookie.secure
                    || domain != manifest.authority
                    || !manifest
                        .allowed_path_prefixes
                        .iter()
                        .any(|prefix| path_matches_prefix(&cookie.path, prefix))
                {
                    return Err(SessionInjectionError::CookieDenied);
                }
                if cookie
                    .expires_at_epoch_seconds
                    .is_some_and(|expires| now_epoch_seconds >= expires)
                {
                    return Err(SessionInjectionError::CookieExpired);
                }
                cookies.entry(name).or_default().push(cookie);
                cookie_secret_count = cookie_secret_count.saturating_add(1);
            }
            SecretDeliveryMetadata::Header { name, .. } => {
                let name = normalize_header_name(&name)?;
                if metadata.kind == SecretKind::Cookie
                    || !bootstrap.contains(handle)
                    || !manifest.allowed_header_names.contains(&name)
                    || is_forbidden_secret_header(&name)
                {
                    return Err(SessionInjectionError::HeaderDenied);
                }
                static_secret_count = static_secret_count.saturating_add(1);
            }
        }
    }
    if !required_static.is_subset(&current) {
        return Err(SessionInjectionError::RequiredStaticSecretMissing);
    }

    for binding in &manifest.csrf_bindings {
        let token = vault
            .metadata(&binding.token_handle)
            .map_err(|_| SessionInjectionError::UnknownSecretHandle)?;
        validate_secret_identity(manifest, &token, now_epoch_seconds)?;
        match token.delivery {
            SecretDeliveryMetadata::Header { name, .. }
                if token.kind == SecretKind::CsrfToken
                    && normalize_header_name(&name)? == binding.header_name
                    && current.contains(&binding.token_handle) => {}
            _ => return Err(SessionInjectionError::InvalidCsrfBinding),
        }
        let matching_cookies = cookies
            .get(&binding.cookie_name)
            .ok_or(SessionInjectionError::CsrfCookieMissing)?;
        if let Some(target) = request_target {
            if !matching_cookies
                .iter()
                .any(|cookie| cookie_path_matches(target, &cookie.path))
            {
                return Err(SessionInjectionError::CsrfCookiePathMismatch);
            }
        }
    }

    Ok(ValidatedSessionState {
        static_secret_count,
        cookie_secret_count,
    })
}

fn validate_secret_identity(
    manifest: &SessionInjectionManifest,
    metadata: &bsl_vault::SecretMetadata,
    now_epoch_seconds: i64,
) -> Result<(), SessionInjectionError> {
    if metadata
        .expires_at_epoch_seconds
        .is_some_and(|expires| now_epoch_seconds >= expires)
    {
        return Err(SessionInjectionError::SecretExpired);
    }
    let binding = &metadata.binding;
    if binding.run_id != manifest.run_id
        || binding.worker_id != manifest.worker_id
        || binding.account_id != manifest.account_id
        || binding.tenant_id != manifest.tenant_id
        || binding.role_id != manifest.role_id
        || binding.allowed_hosts != BTreeSet::from([manifest.authority.clone()])
        || binding.allowed_schemes != BTreeSet::from([manifest.scheme.clone()])
    {
        return Err(SessionInjectionError::SecretBindingMismatch);
    }
    Ok(())
}

fn normalize_paths(values: BTreeSet<String>) -> Result<BTreeSet<String>, SessionInjectionError> {
    values
        .into_iter()
        .map(|path| {
            validate_passive_path(&path)?;
            Ok(path)
        })
        .collect()
}

fn normalize_header_names(
    values: BTreeSet<String>,
) -> Result<BTreeSet<String>, SessionInjectionError> {
    values
        .into_iter()
        .map(|name| normalize_header_name(&name))
        .collect()
}

fn normalize_cookie_names(
    values: BTreeSet<String>,
) -> Result<BTreeSet<String>, SessionInjectionError> {
    values
        .into_iter()
        .map(|name| normalize_cookie_name(&name))
        .collect()
}

fn normalize_host(value: &str) -> Result<String, SessionInjectionError> {
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
        return Err(SessionInjectionError::InvalidOrigin);
    }
    Ok(normalized)
}

fn normalized_origin(authority: &str) -> String {
    format!("https://{authority}:443")
}

fn validate_passive_path(value: &str) -> Result<(), SessionInjectionError> {
    let invalid_segment = value.split('/').any(|segment| {
        segment == "."
            || segment == ".."
            || segment.split(['-', '_', '.']).any(|token| {
                DENIED_PATH_TOKENS
                    .iter()
                    .any(|denied| token.eq_ignore_ascii_case(denied))
            })
    });
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
        || invalid_segment
    {
        return Err(SessionInjectionError::InvalidPathScope);
    }
    Ok(())
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" || path == prefix {
        return true;
    }
    if prefix.ends_with('/') {
        return path.starts_with(prefix);
    }
    path.strip_prefix(prefix)
        .is_some_and(|remainder| remainder.starts_with('/'))
}

fn cookie_path_matches(target: &str, cookie_path: &str) -> bool {
    target == cookie_path
        || target
            .strip_prefix(cookie_path)
            .is_some_and(|suffix| cookie_path.ends_with('/') || suffix.starts_with('/'))
}

fn normalize_header_name(value: &str) -> Result<String, SessionInjectionError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 256 || !normalized.bytes().all(is_token_byte) {
        return Err(SessionInjectionError::InvalidHeaderAllowlist);
    }
    Ok(normalized)
}

fn normalize_cookie_name(value: &str) -> Result<String, SessionInjectionError> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(is_token_byte) {
        return Err(SessionInjectionError::InvalidCookieAllowlist);
    }
    Ok(value.to_string())
}

fn is_forbidden_secret_header(name: &str) -> bool {
    FORBIDDEN_SECRET_HEADERS.contains(&name)
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

fn validate_identifier(value: &str, field: &str) -> Result<(), SessionInjectionError> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(SessionInjectionError::InvalidIdentifier(field.into()));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), SessionInjectionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SessionInjectionError::InvalidDigest(field.into()));
    }
    Ok(())
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, SessionInjectionError> {
    serde_json::to_vec(value)
        .map(|bytes| hash_bytes(&bytes))
        .map_err(|error| SessionInjectionError::Serialization(error.to_string()))
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

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, SessionInjectionError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SessionInjectionError::InvalidSignature);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0]).ok_or(SessionInjectionError::InvalidSignature)?;
            let low = decode_nibble(pair[1]).ok_or(SessionInjectionError::InvalidSignature)?;
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
