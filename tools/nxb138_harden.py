from pathlib import Path

SOURCE = Path("crates/nxb-session-injection/src/lib.rs")
text = SOURCE.read_text()


def replace_once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, observed {count}")
    text = text.replace(old, new, 1)


replace_once(
    '''    pub fn build(
        parameters: SessionInjectionManifestParameters,
    ) -> Result<Self, SessionInjectionError> {
        let mut manifest = Self {''',
    '''    pub fn build(
        parameters: SessionInjectionManifestParameters,
    ) -> Result<Self, SessionInjectionError> {
        if parameters.activation_public_key.len() != 32 {
            return Err(SessionInjectionError::InvalidActivationPublicKey);
        }
        let mut manifest = Self {''',
    "manifest public key length",
)

activation_marker = '''pub fn consume_activation_once(
    state_directory: &Path,'''
consumed_type = '''#[derive(Debug)]
pub struct ConsumedSessionInjectionActivation {
    manifest_sha256: String,
    discovery_plan_sha256: String,
    target_origin_sha256: String,
    session_id_sha256: String,
    certificate_sha256: String,
    not_before_epoch_seconds: i64,
    expires_at_epoch_seconds: i64,
}

impl ConsumedSessionInjectionActivation {
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }
}

'''
if activation_marker not in text:
    raise SystemExit("consumed activation insertion marker missing")
text = text.replace(activation_marker, consumed_type + activation_marker, 1)

replace_once(
    ''') -> Result<String, SessionInjectionError> {
    certificate.verify(manifest, public_key, now_epoch_seconds)?;''',
    ''') -> Result<ConsumedSessionInjectionActivation, SessionInjectionError> {
    certificate.verify(manifest, public_key, now_epoch_seconds)?;''',
    "activation consume return type",
)

replace_once(
    '''    Ok(certificate_sha256)
}

#[derive(Debug, Clone)]
pub struct BoundSessionInjection {''',
    '''    Ok(ConsumedSessionInjectionActivation {
        manifest_sha256: manifest.manifest_sha256.clone(),
        discovery_plan_sha256: manifest.discovery_plan_sha256.clone(),
        target_origin_sha256: manifest.target_origin_sha256.clone(),
        session_id_sha256: hash_bytes(manifest.session_id.as_bytes()),
        certificate_sha256,
        not_before_epoch_seconds: certificate.payload.not_before_epoch_seconds,
        expires_at_epoch_seconds: certificate.payload.expires_at_epoch_seconds,
    })
}

#[derive(Debug, Clone)]
pub struct BoundSessionInjection {''',
    "activation consume result",
)

replace_once(
    '''pub struct BoundSessionInjection {
    manifest: SessionInjectionManifest,
    activation_expires_at_epoch_seconds: i64,
    activation_certificate_sha256: String,
    initial_session_generation: u64,
}''',
    '''pub struct BoundSessionInjection {
    manifest: SessionInjectionManifest,
    activation_not_before_epoch_seconds: i64,
    activation_expires_at_epoch_seconds: i64,
    activation_certificate_sha256: String,
    initial_session_generation: u64,
}''',
    "bound injection fields",
)

bind_start = text.index("    pub fn bind(\n", text.index("impl BoundSessionInjection"))
bind_end = text.index("\n    pub fn manifest(&self)", bind_start)
new_bind = '''    pub fn bind(
        manifest: SessionInjectionManifest,
        consumed_activation: ConsumedSessionInjectionActivation,
        expected_discovery_plan_sha256: &str,
        expected_target_origin_sha256: &str,
        session: &SessionMetadata,
        vault: &InMemorySecretVault,
        now_epoch_seconds: i64,
    ) -> Result<Self, SessionInjectionError> {
        manifest.verify(now_epoch_seconds)?;
        if consumed_activation.manifest_sha256 != manifest.manifest_sha256
            || consumed_activation.discovery_plan_sha256 != manifest.discovery_plan_sha256
            || consumed_activation.target_origin_sha256 != manifest.target_origin_sha256
            || consumed_activation.session_id_sha256 != hash_bytes(manifest.session_id.as_bytes())
        {
            return Err(SessionInjectionError::ActivationBindingMismatch);
        }
        if now_epoch_seconds < consumed_activation.not_before_epoch_seconds
            || now_epoch_seconds > consumed_activation.expires_at_epoch_seconds
        {
            return Err(SessionInjectionError::ActivationExpired);
        }
        if manifest.discovery_plan_sha256 != expected_discovery_plan_sha256
            || manifest.target_origin_sha256 != expected_target_origin_sha256
        {
            return Err(SessionInjectionError::DiscoverySessionBindingMismatch);
        }
        validate_session_state(&manifest, session, vault, None, now_epoch_seconds)?;
        Ok(Self {
            activation_not_before_epoch_seconds: consumed_activation.not_before_epoch_seconds,
            activation_expires_at_epoch_seconds: consumed_activation.expires_at_epoch_seconds,
            activation_certificate_sha256: consumed_activation.certificate_sha256,
            initial_session_generation: session.generation,
            manifest,
        })
    }
'''
text = text[:bind_start] + new_bind + text[bind_end:]

replace_once(
    '''        if now_epoch_seconds > self.activation_expires_at_epoch_seconds {
            return Err(SessionInjectionError::ActivationExpired);
        }''',
    '''        if now_epoch_seconds < self.activation_not_before_epoch_seconds
            || now_epoch_seconds > self.activation_expires_at_epoch_seconds
        {
            return Err(SessionInjectionError::ActivationExpired);
        }''',
    "per-request activation window",
)

replace_once(
    '''impl InjectionUseAuthorization {
    pub fn verify(&self) -> Result<(), SessionInjectionError> {
        let mut material = self.clone();
        material.authorization_sha256.clear();
        if self.authorization_sha256 != hash_serializable(&material)? {
            return Err(SessionInjectionError::AuthorizationDigestMismatch);
        }
        Ok(())
    }
}''',
    '''impl InjectionUseAuthorization {
    pub fn verify(&self) -> Result<(), SessionInjectionError> {
        if self.version != 1
            || !matches!(self.request_method.as_str(), "GET" | "HEAD")
            || self.lease_seconds <= 0
            || self.lease_seconds > MAX_SESSION_INJECTION_LEASE_SECONDS
            || self.authorized_at_epoch_seconds <= 0
        {
            return Err(SessionInjectionError::InvalidAuthorization);
        }
        for (value, field) in [
            (&self.manifest_sha256, "manifest_sha256"),
            (
                &self.activation_certificate_sha256,
                "activation_certificate_sha256",
            ),
            (&self.discovery_plan_sha256, "discovery_plan_sha256"),
            (&self.session_id_sha256, "session_id_sha256"),
            (&self.request_target_sha256, "request_target_sha256"),
            (&self.authorization_sha256, "authorization_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        let mut material = self.clone();
        material.authorization_sha256.clear();
        if self.authorization_sha256 != hash_serializable(&material)? {
            return Err(SessionInjectionError::AuthorizationDigestMismatch);
        }
        Ok(())
    }
}''',
    "authorization verification",
)

text = text.replace(
    "validate_secret_identity(manifest, &metadata)?;",
    "validate_secret_identity(manifest, &metadata, now_epoch_seconds)?;",
)

replace_once(
    '''            SecretDeliveryMetadata::Cookie { cookie } => {
                let name = normalize_cookie_name(&cookie.name)?;
                if !manifest.allowed_cookie_names.contains(&name)
                    || !cookie.secure
                    || !domain_matches(&manifest.authority, &normalize_host(&cookie.domain)?)
                {
                    return Err(SessionInjectionError::CookieDenied);
                }
                if cookie
                    .expires_at_epoch_seconds
                    .is_some_and(|expires| now_epoch_seconds >= expires)
                {
                    return Err(SessionInjectionError::CookieExpired);
                }
                cookie_records.entry(name).or_default().push(cookie);
                cookie_secret_count = cookie_secret_count.saturating_add(1);
            }''',
    '''            SecretDeliveryMetadata::Cookie { cookie } => {
                let name = normalize_cookie_name(&cookie.name)?;
                let domain = normalize_host(&cookie.domain)?;
                validate_passive_path(&cookie.path)?;
                if !manifest.allowed_cookie_names.contains(&name)
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
                cookie_records.entry(name).or_default().push(cookie);
                cookie_secret_count = cookie_secret_count.saturating_add(1);
            }''',
    "cookie exact scope",
)

old_identity_start = text.index("fn validate_secret_identity(")
old_identity_end = text.index("\nfn normalize_paths", old_identity_start)
new_identity = '''fn validate_secret_identity(
    manifest: &SessionInjectionManifest,
    metadata: &nxb_vault::SecretMetadata,
    now_epoch_seconds: i64,
) -> Result<(), SessionInjectionError> {
    let binding = &metadata.binding;
    if metadata
        .expires_at_epoch_seconds
        .is_some_and(|expires| now_epoch_seconds >= expires)
    {
        return Err(SessionInjectionError::SecretExpired);
    }
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
'''
text = text[:old_identity_start] + new_identity + text[old_identity_end:]

replace_once(
    '''        || normalized
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)''',
    '''        || normalized.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
        })''',
    "host label validation",
)

path_start = text.index("fn validate_passive_path(value: &str) -> Result<(), SessionInjectionError> {")
path_end = text.index("\nfn path_matches_prefix", path_start)
new_path = '''fn validate_passive_path(value: &str) -> Result<(), SessionInjectionError> {
    let invalid_segment = value.split('/').any(|segment| {
        segment == "."
            || segment == ".."
            || segment
                .split(|character: char| matches!(character, '-' | '_' | '.'))
                .any(|token| {
                    DENIED_PATH_SEGMENTS
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
'''
text = text[:path_start] + new_path + text[path_end:]

domain_start = text.index("fn domain_matches(host: &str, domain: &str) -> bool {")
domain_end = text.index("\nfn normalize_header_name", domain_start)
text = text[:domain_start] + text[domain_end:]

replace_once(
    '''    #[error("session-injection activation key does not match")]
    ActivationKeyMismatch,''',
    '''    #[error("session-injection activation public key is invalid")]
    InvalidActivationPublicKey,
    #[error("session-injection activation key does not match")]
    ActivationKeyMismatch,''',
    "activation key error",
)
replace_once(
    '''    #[error("secret identity or authority binding does not match")]
    SecretBindingMismatch,''',
    '''    #[error("secret identity or authority binding does not match")]
    SecretBindingMismatch,
    #[error("secret expired before injection authorization")]
    SecretExpired,''',
    "secret expiry error",
)
replace_once(
    '''    #[error("session-injection authorization digest mismatch")]
    AuthorizationDigestMismatch,''',
    '''    #[error("session-injection authorization is invalid")]
    InvalidAuthorization,
    #[error("session-injection authorization digest mismatch")]
    AuthorizationDigestMismatch,''',
    "authorization error",
)

TEST_MARKER = "#[cfg(test)]\nmod tests {"
head, tests = text.split(TEST_MARKER, 1)
tests = tests.replace("BoundSessionInjection::bind(", "bind_for_test(")

first_test = tests.index(
    "    #[test]\n    fn exact_manifest_authorizes_only_bounded_get_and_head_requests()"
)
helper = '''    fn unique_state_directory(label: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!(
            "nxb-session-injection-{label}-{}-{unique}",
            std::process::id()
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn bind_for_test(
        manifest: SessionInjectionManifest,
        certificate: &SessionInjectionActivationCertificate,
        public_key: &[u8],
        expected_discovery_plan_sha256: &str,
        expected_target_origin_sha256: &str,
        session: &SessionMetadata,
        vault: &InMemorySecretVault,
        now_epoch_seconds: i64,
    ) -> Result<BoundSessionInjection, SessionInjectionError> {
        let directory = unique_state_directory("bind");
        let consumed = consume_activation_once(
            &directory,
            &manifest,
            certificate,
            public_key,
            now_epoch_seconds,
        )?;
        let result = BoundSessionInjection::bind(
            manifest,
            consumed,
            expected_discovery_plan_sha256,
            expected_target_origin_sha256,
            session,
            vault,
            now_epoch_seconds,
        );
        if directory.exists() {
            fs::remove_dir_all(directory).unwrap();
        }
        result
    }

'''
tests = tests[:first_test] + helper + tests[first_test:]

replace_test = '''        assert!(bound
            .authorize_request(
                &session,
                &vault,
                "app.example.com",
                "https",
                "/app/api/me",
                "POST",
                NOW + 2,
            )
            .is_err());
    }'''
replacement_test = '''        assert!(bound
            .authorize_request(
                &session,
                &vault,
                "app.example.com",
                "https",
                "/app/api/me",
                "POST",
                NOW + 2,
            )
            .is_err());
        for unsafe_path in ["/app/../admin", "/app//admin", "/app/logout.json"] {
            assert!(bound
                .authorize_request(
                    &session,
                    &vault,
                    "app.example.com",
                    "https",
                    unsafe_path,
                    "GET",
                    NOW + 2,
                )
                .is_err());
        }
    }'''
if tests.count(replace_test) != 1:
    raise SystemExit("unsafe path test insertion marker mismatch")
tests = tests.replace(replace_test, replacement_test, 1)

serial_test = tests.index(
    "    #[test]\n    fn serialized_and_debug_material_never_contains_secret_values()"
)
additional_tests = '''    #[test]
    fn consumed_activation_is_required_and_cannot_be_replayed() {
        let (vault, session, manifest, certificate, key_pair) = fixture();
        let directory = unique_state_directory("mandatory-replay");
        let consumed = consume_activation_once(
            &directory,
            &manifest,
            &certificate,
            key_pair.public_key().as_ref(),
            NOW + 1,
        )
        .unwrap();
        BoundSessionInjection::bind(
            manifest.clone(),
            consumed,
            &"b".repeat(64),
            &hash_bytes(b"https://app.example.com:443"),
            &session,
            &vault,
            NOW + 1,
        )
        .unwrap();
        assert!(consume_activation_once(
            &directory,
            &manifest,
            &certificate,
            key_pair.public_key().as_ref(),
            NOW + 1,
        )
        .is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn broad_secret_authority_binding_is_denied() {
        let (mut vault, mut session, manifest, certificate, key_pair) = fixture();
        let mut broad = binding();
        broad.allowed_hosts.insert("other.example.com".into());
        let handle = vault
            .insert(
                SecretInput {
                    kind: SecretKind::ApiKey,
                    value: b"broad-secret".to_vec(),
                    binding: broad,
                    delivery: SecretDelivery::Header {
                        name: "X-Broad-Key".into(),
                        prefix: Vec::new(),
                    },
                    expires_at_epoch_seconds: Some(NOW + 3_600),
                },
                NOW,
            )
            .unwrap();
        session.profile.secret_handles.push(handle);
        assert!(matches!(
            bind_for_test(
                manifest,
                &certificate,
                key_pair.public_key().as_ref(),
                &"b".repeat(64),
                &hash_bytes(b"https://app.example.com:443"),
                &session,
                &vault,
                NOW + 1,
            ),
            Err(SessionInjectionError::SecretBindingMismatch)
        ));
    }

    #[test]
    fn invalid_activation_key_length_is_rejected() {
        let (vault, session, manifest, certificate, key_pair) = fixture();
        let mut parameters = SessionInjectionManifestParameters {
            injection_id: "invalid-key-manifest".into(),
            discovery_plan_sha256: "b".repeat(64),
            target_origin_sha256: hash_bytes(b"https://app.example.com:443"),
            authority: "app.example.com".into(),
            session_id: session.session_id.clone(),
            run_id: session.profile.run_id.clone(),
            worker_id: session.profile.worker_id.clone(),
            account_id: session.profile.account_id.clone(),
            tenant_id: session.profile.tenant_id.clone(),
            role_id: session.profile.role_id.clone(),
            bootstrap_secret_handles: session.profile.secret_handles.clone(),
            allowed_path_prefixes: BTreeSet::from(["/app".into()]),
            allowed_header_names: BTreeSet::from([
                "authorization".into(),
                "x-csrf-token".into(),
            ]),
            allowed_cookie_names: BTreeSet::from(["sid".into()]),
            csrf_bindings: manifest.csrf_bindings.clone(),
            maximum_lease_seconds: 10,
            created_at_epoch_seconds: NOW,
            expires_at_epoch_seconds: NOW + 600,
            activation_public_key: vec![1_u8; 31],
        };
        assert!(matches!(
            SessionInjectionManifest::build(parameters),
            Err(SessionInjectionError::InvalidActivationPublicKey)
        ));
        parameters.activation_public_key = key_pair.public_key().as_ref().to_vec();
        let rebuilt = SessionInjectionManifest::build(parameters).unwrap();
        assert!(certificate.verify(&rebuilt, key_pair.public_key().as_ref(), NOW + 1).is_err());
        drop(vault);
    }

'''
tests = tests[:serial_test] + additional_tests + tests[serial_test:]

SOURCE.write_text(head + TEST_MARKER + tests)
