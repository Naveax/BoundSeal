#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CsrfBinding {
    pub cookie_name: String,
    pub header_name: String,
    pub token_handle: SecretHandle,
}

#[derive(Debug, Clone)]
pub struct SessionInjectionManifestParameters {
    pub injection_id: String,
    pub discovery_plan_sha256: String,
    pub target_origin_sha256: String,
    pub authority: String,
    pub session_id: String,
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub bootstrap_secret_handles: Vec<SecretHandle>,
    pub allowed_path_prefixes: BTreeSet<String>,
    pub allowed_header_names: BTreeSet<String>,
    pub allowed_cookie_names: BTreeSet<String>,
    pub csrf_bindings: Vec<CsrfBinding>,
    pub maximum_lease_seconds: i64,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub activation_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionInjectionManifest {
    pub version: u32,
    pub injection_id: String,
    pub discovery_plan_sha256: String,
    pub target_origin_sha256: String,
    pub authority: String,
    pub scheme: String,
    pub session_id: String,
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub bootstrap_secret_handles: Vec<SecretHandle>,
    pub allowed_path_prefixes: BTreeSet<String>,
    pub allowed_header_names: BTreeSet<String>,
    pub allowed_cookie_names: BTreeSet<String>,
    pub csrf_bindings: Vec<CsrfBinding>,
    pub maximum_lease_seconds: i64,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub activation_key_id_sha256: String,
    pub manifest_sha256: String,
}

impl SessionInjectionManifest {
    pub fn build(
        parameters: SessionInjectionManifestParameters,
    ) -> Result<Self, SessionInjectionError> {
        if parameters.activation_public_key.len() != 32 {
            return Err(SessionInjectionError::InvalidActivationPublicKey);
        }
        let csrf_bindings = parameters
            .csrf_bindings
            .into_iter()
            .map(|binding| {
                Ok(CsrfBinding {
                    cookie_name: normalize_cookie_name(&binding.cookie_name)?,
                    header_name: normalize_header_name(&binding.header_name)?,
                    token_handle: binding.token_handle,
                })
            })
            .collect::<Result<Vec<_>, SessionInjectionError>>()?;
        let mut manifest = Self {
            version: SESSION_INJECTION_MANIFEST_VERSION,
            injection_id: parameters.injection_id,
            discovery_plan_sha256: parameters.discovery_plan_sha256,
            target_origin_sha256: parameters.target_origin_sha256,
            authority: normalize_host(&parameters.authority)?,
            scheme: "https".into(),
            session_id: parameters.session_id,
            run_id: parameters.run_id,
            worker_id: parameters.worker_id,
            account_id: parameters.account_id,
            tenant_id: parameters.tenant_id,
            role_id: parameters.role_id,
            bootstrap_secret_handles: parameters.bootstrap_secret_handles,
            allowed_path_prefixes: normalize_paths(parameters.allowed_path_prefixes)?,
            allowed_header_names: normalize_header_names(parameters.allowed_header_names)?,
            allowed_cookie_names: normalize_cookie_names(parameters.allowed_cookie_names)?,
            csrf_bindings,
            maximum_lease_seconds: parameters.maximum_lease_seconds,
            created_at_epoch_seconds: parameters.created_at_epoch_seconds,
            expires_at_epoch_seconds: parameters.expires_at_epoch_seconds,
            activation_key_id_sha256: hash_bytes(&parameters.activation_public_key),
            manifest_sha256: String::new(),
        };
        manifest.validate()?;
        manifest.manifest_sha256 = manifest.calculate_sha256()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), SessionInjectionError> {
        if self.version != SESSION_INJECTION_MANIFEST_VERSION {
            return Err(SessionInjectionError::UnsupportedManifestVersion);
        }
        for (value, field) in [
            (&self.injection_id, "injection_id"),
            (&self.session_id, "session_id"),
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
        if !self.manifest_sha256.is_empty() {
            validate_sha256(&self.manifest_sha256, "manifest_sha256")?;
        }
        if normalize_host(&self.authority)? != self.authority || self.scheme != "https" {
            return Err(SessionInjectionError::InvalidOrigin);
        }
        if hash_bytes(normalized_origin(&self.authority).as_bytes()) != self.target_origin_sha256 {
            return Err(SessionInjectionError::OriginDigestMismatch);
        }
        if self.created_at_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.created_at_epoch_seconds
            || self
                .expires_at_epoch_seconds
                .saturating_sub(self.created_at_epoch_seconds)
                > MAX_SESSION_INJECTION_LIFETIME_SECONDS
        {
            return Err(SessionInjectionError::InvalidManifestWindow);
        }
        if self.maximum_lease_seconds <= 0
            || self.maximum_lease_seconds > MAX_SESSION_INJECTION_LEASE_SECONDS
        {
            return Err(SessionInjectionError::InvalidLeaseDuration);
        }
        if self.bootstrap_secret_handles.is_empty()
            || self.bootstrap_secret_handles.len() > MAX_SESSION_INJECTION_HANDLES
            || self
                .bootstrap_secret_handles
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.bootstrap_secret_handles.len()
        {
            return Err(SessionInjectionError::InvalidSecretHandleSet);
        }
        if self.allowed_path_prefixes.is_empty()
            || self.allowed_path_prefixes.len() > MAX_SESSION_INJECTION_PATH_PREFIXES
        {
            return Err(SessionInjectionError::InvalidPathScope);
        }
        for path in &self.allowed_path_prefixes {
            validate_passive_path(path)?;
        }
        if self.allowed_header_names.len() > MAX_SESSION_INJECTION_HEADER_NAMES
            || self.allowed_cookie_names.len() > MAX_SESSION_INJECTION_COOKIE_NAMES
        {
            return Err(SessionInjectionError::AllowlistTooLarge);
        }
        for name in &self.allowed_header_names {
            if normalize_header_name(name)? != *name || is_forbidden_secret_header(name) {
                return Err(SessionInjectionError::InvalidHeaderAllowlist);
            }
        }
        for name in &self.allowed_cookie_names {
            if normalize_cookie_name(name)? != *name {
                return Err(SessionInjectionError::InvalidCookieAllowlist);
            }
        }
        if self.csrf_bindings.len() > MAX_SESSION_INJECTION_CSRF_BINDINGS {
            return Err(SessionInjectionError::TooManyCsrfBindings);
        }
        let handles = self
            .bootstrap_secret_handles
            .iter()
            .collect::<BTreeSet<_>>();
        let mut unique = BTreeSet::new();
        for binding in &self.csrf_bindings {
            if normalize_cookie_name(&binding.cookie_name)? != binding.cookie_name
                || normalize_header_name(&binding.header_name)? != binding.header_name
                || !self.allowed_cookie_names.contains(&binding.cookie_name)
                || !self.allowed_header_names.contains(&binding.header_name)
                || !handles.contains(&binding.token_handle)
                || !unique.insert((
                    binding.cookie_name.clone(),
                    binding.header_name.clone(),
                    binding.token_handle.as_str(),
                ))
            {
                return Err(SessionInjectionError::InvalidCsrfBinding);
            }
        }
        Ok(())
    }

    pub fn calculate_sha256(&self) -> Result<String, SessionInjectionError> {
        let mut material = self.clone();
        material.manifest_sha256.clear();
        hash_serializable(&material)
    }

    pub fn verify(&self, now_epoch_seconds: i64) -> Result<(), SessionInjectionError> {
        self.validate()?;
        if self.manifest_sha256 != self.calculate_sha256()? {
            return Err(SessionInjectionError::ManifestDigestMismatch);
        }
        if now_epoch_seconds < self.created_at_epoch_seconds
            || now_epoch_seconds > self.expires_at_epoch_seconds
        {
            return Err(SessionInjectionError::ManifestExpired);
        }
        Ok(())
    }
}
