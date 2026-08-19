#[derive(Debug, Clone)]
pub struct BoundSessionInjection {
    manifest: SessionInjectionManifest,
    activation_not_before_epoch_seconds: i64,
    activation_expires_at_epoch_seconds: i64,
    activation_certificate_sha256: String,
    initial_session_generation: u64,
}

impl BoundSessionInjection {
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
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

    pub fn manifest(&self) -> &SessionInjectionManifest {
        &self.manifest
    }

    pub fn session_id(&self) -> &str {
        &self.manifest.session_id
    }

    pub fn activation_certificate_sha256(&self) -> &str {
        &self.activation_certificate_sha256
    }

    pub fn session_context(&self) -> SessionUseContext {
        SessionUseContext {
            run_id: self.manifest.run_id.clone(),
            worker_id: self.manifest.worker_id.clone(),
            account_id: self.manifest.account_id.clone(),
            tenant_id: self.manifest.tenant_id.clone(),
            role_id: self.manifest.role_id.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_request(
        &self,
        session: &SessionMetadata,
        vault: &InMemorySecretVault,
        authority: &str,
        scheme: &str,
        request_target: &str,
        method: &str,
        now_epoch_seconds: i64,
    ) -> Result<InjectionUseAuthorization, SessionInjectionError> {
        self.manifest.verify(now_epoch_seconds)?;
        if now_epoch_seconds < self.activation_not_before_epoch_seconds
            || now_epoch_seconds > self.activation_expires_at_epoch_seconds
        {
            return Err(SessionInjectionError::ActivationExpired);
        }
        if normalize_host(authority)? != self.manifest.authority
            || scheme.to_ascii_lowercase() != self.manifest.scheme
        {
            return Err(SessionInjectionError::RequestOriginMismatch);
        }
        let method = method.trim().to_ascii_uppercase();
        if !matches!(method.as_str(), "GET" | "HEAD") {
            return Err(SessionInjectionError::MethodDenied);
        }
        validate_passive_path(request_target)?;
        if !self
            .manifest
            .allowed_path_prefixes
            .iter()
            .any(|prefix| path_matches_prefix(request_target, prefix))
        {
            return Err(SessionInjectionError::RequestPathDenied);
        }
        let state = validate_session_state(
            &self.manifest,
            session,
            vault,
            Some(request_target),
            now_epoch_seconds,
        )?;
        if session.generation < self.initial_session_generation {
            return Err(SessionInjectionError::SessionGenerationRegression);
        }
        let remaining = [
            self.manifest
                .expires_at_epoch_seconds
                .saturating_sub(now_epoch_seconds),
            self.activation_expires_at_epoch_seconds
                .saturating_sub(now_epoch_seconds),
            session
                .profile
                .expires_at_epoch_seconds
                .saturating_sub(now_epoch_seconds),
            self.manifest.maximum_lease_seconds,
        ]
        .into_iter()
        .min()
        .unwrap_or(0);
        if remaining <= 0 {
            return Err(SessionInjectionError::LeaseExpired);
        }
        let mut authorization = InjectionUseAuthorization {
            version: 1,
            manifest_sha256: self.manifest.manifest_sha256.clone(),
            activation_certificate_sha256: self.activation_certificate_sha256.clone(),
            discovery_plan_sha256: self.manifest.discovery_plan_sha256.clone(),
            session_id_sha256: hash_bytes(self.manifest.session_id.as_bytes()),
            request_method: method,
            request_target_sha256: hash_bytes(request_target.as_bytes()),
            session_generation: session.generation,
            lease_seconds: remaining,
            static_secret_count: state.static_secret_count,
            cookie_secret_count: state.cookie_secret_count,
            csrf_binding_count: self.manifest.csrf_bindings.len() as u64,
            authorized_at_epoch_seconds: now_epoch_seconds,
            authorization_sha256: String::new(),
        };
        authorization.authorization_sha256 = hash_serializable(&authorization)?;
        authorization.verify()?;
        Ok(authorization)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InjectionUseAuthorization {
    pub version: u32,
    pub manifest_sha256: String,
    pub activation_certificate_sha256: String,
    pub discovery_plan_sha256: String,
    pub session_id_sha256: String,
    pub request_method: String,
    pub request_target_sha256: String,
    pub session_generation: u64,
    pub lease_seconds: i64,
    pub static_secret_count: u64,
    pub cookie_secret_count: u64,
    pub csrf_binding_count: u64,
    pub authorized_at_epoch_seconds: i64,
    pub authorization_sha256: String,
}

impl InjectionUseAuthorization {
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
}
