use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use nxb_session::{SessionMetadata, SessionStatus, SessionUseContext};
use nxb_vault::{
    CookieMetadata, InMemorySecretVault, SecretDeliveryMetadata, SecretHandle, SecretKind,
};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub const SESSION_INJECTION_MANIFEST_VERSION: u32 = 1;
pub const SESSION_INJECTION_ACTIVATION_VERSION: u32 = 1;
pub const MAX_SESSION_INJECTION_LIFETIME_SECONDS: i64 = 60 * 60;
pub const MAX_SESSION_INJECTION_ACTIVATION_SECONDS: i64 = 15 * 60;
pub const MAX_SESSION_INJECTION_LEASE_SECONDS: i64 = 30;
pub const MAX_SESSION_INJECTION_HANDLES: usize = 64;
pub const MAX_SESSION_INJECTION_PATH_PREFIXES: usize = 32;
pub const MAX_SESSION_INJECTION_HEADER_NAMES: usize = 32;
pub const MAX_SESSION_INJECTION_COOKIE_NAMES: usize = 64;
pub const MAX_SESSION_INJECTION_CSRF_BINDINGS: usize = 16;

const DENIED_PATH_SEGMENTS: &[&str] = &[
    "delete",
    "destroy",
    "disable",
    "drop",
    "logoff",
    "logout",
    "remove",
    "reset",
    "revoke",
    "shutdown",
    "signout",
    "terminate",
    "unsubscribe",
];

const FORBIDDEN_SECRET_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "cookie",
    "expect",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

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
            csrf_bindings: parameters.csrf_bindings,
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
        validate_sha256(&self.discovery_plan_sha256, "discovery_plan_sha256")?;
        validate_sha256(&self.target_origin_sha256, "target_origin_sha256")?;
        validate_sha256(&self.activation_key_id_sha256, "activation_key_id_sha256")?;
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
        for prefix in &self.allowed_path_prefixes {
            validate_passive_path(prefix)?;
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
        let mut unique_csrf = BTreeSet::new();
        for binding in &self.csrf_bindings {
            let cookie_name = normalize_cookie_name(&binding.cookie_name)?;
            let header_name = normalize_header_name(&binding.header_name)?;
            if cookie_name != binding.cookie_name
                || header_name != binding.header_name
                || !self.allowed_cookie_names.contains(&cookie_name)
                || !self.allowed_header_names.contains(&header_name)
                || !handles.contains(&binding.token_handle)
                || !unique_csrf.insert((cookie_name, header_name, binding.token_handle.as_str()))
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionInjectionActivationPayload {
    pub version: u32,
    pub activation_id: String,
    pub manifest_sha256: String,
    pub discovery_plan_sha256: String,
    pub target_origin_sha256: String,
    pub session_id_sha256: String,
    pub not_before_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub signer_key_id_sha256: String,
}

impl SessionInjectionActivationPayload {
    pub fn template(
        activation_id: impl Into<String>,
        manifest: &SessionInjectionManifest,
        not_before_epoch_seconds: i64,
        expires_at_epoch_seconds: i64,
    ) -> Result<Self, SessionInjectionError> {
        manifest.validate()?;
        let payload = Self {
            version: SESSION_INJECTION_ACTIVATION_VERSION,
            activation_id: activation_id.into(),
            manifest_sha256: manifest.manifest_sha256.clone(),
            discovery_plan_sha256: manifest.discovery_plan_sha256.clone(),
            target_origin_sha256: manifest.target_origin_sha256.clone(),
            session_id_sha256: hash_bytes(manifest.session_id.as_bytes()),
            not_before_epoch_seconds,
            expires_at_epoch_seconds,
            signer_key_id_sha256: manifest.activation_key_id_sha256.clone(),
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<(), SessionInjectionError> {
        if self.version != SESSION_INJECTION_ACTIVATION_VERSION {
            return Err(SessionInjectionError::UnsupportedActivationVersion);
        }
        validate_identifier(&self.activation_id, "activation_id")?;
        for (value, field) in [
            (&self.manifest_sha256, "manifest_sha256"),
            (&self.discovery_plan_sha256, "discovery_plan_sha256"),
            (&self.target_origin_sha256, "target_origin_sha256"),
            (&self.session_id_sha256, "session_id_sha256"),
            (&self.signer_key_id_sha256, "signer_key_id_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        if self.not_before_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.not_before_epoch_seconds
            || self
                .expires_at_epoch_seconds
                .saturating_sub(self.not_before_epoch_seconds)
                > MAX_SESSION_INJECTION_ACTIVATION_SECONDS
        {
            return Err(SessionInjectionError::InvalidActivationWindow);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, SessionInjectionError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| SessionInjectionError::Serialization(error.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionInjectionActivationCertificate {
    pub payload: SessionInjectionActivationPayload,
    pub signature_hex: String,
}

impl SessionInjectionActivationCertificate {
    pub fn verify(
        &self,
        manifest: &SessionInjectionManifest,
        public_key: &[u8],
        now_epoch_seconds: i64,
    ) -> Result<(), SessionInjectionError> {
        manifest.verify(now_epoch_seconds)?;
        self.payload.validate()?;
        if public_key.len() != 32
            || hash_bytes(public_key) != self.payload.signer_key_id_sha256
            || self.payload.signer_key_id_sha256 != manifest.activation_key_id_sha256
        {
            return Err(SessionInjectionError::ActivationKeyMismatch);
        }
        if self.payload.manifest_sha256 != manifest.manifest_sha256
            || self.payload.discovery_plan_sha256 != manifest.discovery_plan_sha256
            || self.payload.target_origin_sha256 != manifest.target_origin_sha256
            || self.payload.session_id_sha256 != hash_bytes(manifest.session_id.as_bytes())
        {
            return Err(SessionInjectionError::ActivationBindingMismatch);
        }
        if now_epoch_seconds < self.payload.not_before_epoch_seconds
            || now_epoch_seconds > self.payload.expires_at_epoch_seconds
            || self.payload.expires_at_epoch_seconds > manifest.expires_at_epoch_seconds
        {
            return Err(SessionInjectionError::ActivationExpired);
        }
        let signature = decode_lower_hex(&self.signature_hex)?;
        if signature.len() != 64 {
            return Err(SessionInjectionError::InvalidSignature);
        }
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&self.payload.signing_bytes()?, &signature)
            .map_err(|_| SessionInjectionError::InvalidSignature)
    }

    pub fn certificate_sha256(&self) -> Result<String, SessionInjectionError> {
        hash_serializable(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SessionInjectionUseMarker {
    version: u32,
    injection_id_sha256: String,
    activation_id_sha256: String,
    activation_certificate_sha256: String,
    manifest_sha256: String,
    discovery_plan_sha256: String,
    consumed_at_epoch_seconds: i64,
    state: String,
}

pub fn consume_activation_once(
    state_directory: &Path,
    manifest: &SessionInjectionManifest,
    certificate: &SessionInjectionActivationCertificate,
    public_key: &[u8],
    now_epoch_seconds: i64,
) -> Result<String, SessionInjectionError> {
    certificate.verify(manifest, public_key, now_epoch_seconds)?;
    fs::create_dir_all(state_directory).map_err(|error| {
        SessionInjectionError::StateIo(format!(
            "could not create session-injection state directory {}: {error}",
            state_directory.display()
        ))
    })?;
    let certificate_sha256 = certificate.certificate_sha256()?;
    let injection_id_sha256 = hash_bytes(manifest.injection_id.as_bytes());
    let activation_id_sha256 = hash_bytes(certificate.payload.activation_id.as_bytes());
    let marker_path = state_directory.join(format!(
        "session-injection-{injection_id_sha256}-{activation_id_sha256}.used.json"
    ));
    let marker = SessionInjectionUseMarker {
        version: 1,
        injection_id_sha256,
        activation_id_sha256,
        activation_certificate_sha256: certificate_sha256.clone(),
        manifest_sha256: manifest.manifest_sha256.clone(),
        discovery_plan_sha256: manifest.discovery_plan_sha256.clone(),
        consumed_at_epoch_seconds: now_epoch_seconds,
        state: "consumed_fail_closed_no_replay".into(),
    };
    let bytes = serde_json::to_vec_pretty(&marker)
        .map_err(|error| SessionInjectionError::Serialization(error.to_string()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .map_err(|error| {
            SessionInjectionError::StateIo(format!(
                "session-injection activation was already used or marker creation failed {}: {error}",
                marker_path.display()
            ))
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| SessionInjectionError::StateIo(error.to_string()))?;
    Ok(certificate_sha256)
}

#[derive(Debug, Clone)]
pub struct BoundSessionInjection {
    manifest: SessionInjectionManifest,
    activation_expires_at_epoch_seconds: i64,
    activation_certificate_sha256: String,
    initial_session_generation: u64,
}

impl BoundSessionInjection {
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        manifest: SessionInjectionManifest,
        certificate: &SessionInjectionActivationCertificate,
        public_key: &[u8],
        expected_discovery_plan_sha256: &str,
        expected_target_origin_sha256: &str,
        session: &SessionMetadata,
        vault: &InMemorySecretVault,
        now_epoch_seconds: i64,
    ) -> Result<Self, SessionInjectionError> {
        manifest.verify(now_epoch_seconds)?;
        certificate.verify(&manifest, public_key, now_epoch_seconds)?;
        if manifest.discovery_plan_sha256 != expected_discovery_plan_sha256
            || manifest.target_origin_sha256 != expected_target_origin_sha256
        {
            return Err(SessionInjectionError::DiscoverySessionBindingMismatch);
        }
        validate_session_state(&manifest, session, vault, None, now_epoch_seconds)?;
        Ok(Self {
            activation_expires_at_epoch_seconds: certificate.payload.expires_at_epoch_seconds,
            activation_certificate_sha256: certificate.certificate_sha256()?,
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
        if now_epoch_seconds > self.activation_expires_at_epoch_seconds {
            return Err(SessionInjectionError::ActivationExpired);
        }
        let authority = normalize_host(authority)?;
        let scheme = scheme.to_ascii_lowercase();
        if authority != self.manifest.authority || scheme != self.manifest.scheme {
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
        let mut material = self.clone();
        material.authorization_sha256.clear();
        if self.authorization_sha256 != hash_serializable(&material)? {
            return Err(SessionInjectionError::AuthorizationDigestMismatch);
        }
        Ok(())
    }
}

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
    if session.metadata_identity_mismatch(manifest) {
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
        validate_secret_identity(manifest, &metadata)?;
        if !matches!(metadata.delivery, SecretDeliveryMetadata::Cookie { .. }) {
            required_static.insert(handle.clone());
        }
    }

    let mut static_secret_count = 0_u64;
    let mut cookie_secret_count = 0_u64;
    let mut cookie_records = BTreeMap::<String, Vec<CookieMetadata>>::new();
    for handle in &session.profile.secret_handles {
        let metadata = vault
            .metadata(handle)
            .map_err(|_| SessionInjectionError::UnknownSecretHandle)?;
        validate_secret_identity(manifest, &metadata)?;
        match metadata.delivery {
            SecretDeliveryMetadata::Cookie { cookie } => {
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
            }
            SecretDeliveryMetadata::Header { name, .. } => {
                let name = normalize_header_name(&name)?;
                if !bootstrap.contains(handle)
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
        match token.delivery {
            SecretDeliveryMetadata::Header { name, .. }
                if token.kind == SecretKind::CsrfToken
                    && normalize_header_name(&name)? == binding.header_name
                    && current.contains(&binding.token_handle) => {}
            _ => return Err(SessionInjectionError::InvalidCsrfBinding),
        }
        let cookies = cookie_records
            .get(&binding.cookie_name)
            .ok_or(SessionInjectionError::CsrfCookieMissing)?;
        if let Some(target) = request_target {
            if !cookies
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

trait SessionMetadataExt {
    fn metadata_identity_mismatch(&self, manifest: &SessionInjectionManifest) -> bool;
}

impl SessionMetadataExt for SessionMetadata {
    fn metadata_identity_mismatch(&self, manifest: &SessionInjectionManifest) -> bool {
        self.session_id != manifest.session_id
            || self.profile.run_id != manifest.run_id
            || self.profile.worker_id != manifest.worker_id
            || self.profile.account_id != manifest.account_id
            || self.profile.tenant_id != manifest.tenant_id
            || self.profile.role_id != manifest.role_id
    }
}

fn validate_secret_identity(
    manifest: &SessionInjectionManifest,
    metadata: &nxb_vault::SecretMetadata,
) -> Result<(), SessionInjectionError> {
    let binding = &metadata.binding;
    if binding.run_id != manifest.run_id
        || binding.worker_id != manifest.worker_id
        || binding.account_id != manifest.account_id
        || binding.tenant_id != manifest.tenant_id
        || binding.role_id != manifest.role_id
        || !binding.allowed_hosts.contains(&manifest.authority)
        || !binding.allowed_schemes.contains(&manifest.scheme)
    {
        return Err(SessionInjectionError::SecretBindingMismatch);
    }
    Ok(())
}

fn normalize_paths(values: BTreeSet<String>) -> Result<BTreeSet<String>, SessionInjectionError> {
    values
        .into_iter()
        .map(|value| {
            validate_passive_path(&value)?;
            Ok(value)
        })
        .collect()
}

fn normalize_header_names(
    values: BTreeSet<String>,
) -> Result<BTreeSet<String>, SessionInjectionError> {
    values
        .into_iter()
        .map(|value| normalize_header_name(&value))
        .collect()
}

fn normalize_cookie_names(
    values: BTreeSet<String>,
) -> Result<BTreeSet<String>, SessionInjectionError> {
    values
        .into_iter()
        .map(|value| normalize_cookie_name(&value))
        .collect()
}

fn normalize_host(value: &str) -> Result<String, SessionInjectionError> {
    let normalized = value.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.starts_with('.')
        || normalized.ends_with('.')
        || normalized.parse::<std::net::IpAddr>().is_ok()
        || normalized
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
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
    if value.is_empty()
        || value.len() > 4 * 1024
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('?')
        || value.contains('#')
        || value.contains('%')
        || value.contains('\\')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || value.split('/').any(|segment| {
            DENIED_PATH_SEGMENTS
                .iter()
                .any(|denied| segment.eq_ignore_ascii_case(denied))
        })
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

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
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

fn is_forbidden_secret_header(value: &str) -> bool {
    FORBIDDEN_SECRET_HEADERS.contains(&value)
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionInjectionError {
    #[error("unsupported session-injection manifest version")]
    UnsupportedManifestVersion,
    #[error("unsupported session-injection activation version")]
    UnsupportedActivationVersion,
    #[error("session-injection identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("session-injection digest is invalid: {0}")]
    InvalidDigest(String),
    #[error("session-injection origin is invalid")]
    InvalidOrigin,
    #[error("session-injection origin digest does not match")]
    OriginDigestMismatch,
    #[error("session-injection manifest validity window is invalid")]
    InvalidManifestWindow,
    #[error("session-injection manifest is outside its validity window")]
    ManifestExpired,
    #[error("session-injection manifest digest mismatch")]
    ManifestDigestMismatch,
    #[error("session-injection lease duration is invalid")]
    InvalidLeaseDuration,
    #[error("session-injection lease expired before use")]
    LeaseExpired,
    #[error("session-injection secret handle set is invalid")]
    InvalidSecretHandleSet,
    #[error("session-injection path scope is invalid")]
    InvalidPathScope,
    #[error("session-injection allowlist is too large")]
    AllowlistTooLarge,
    #[error("session-injection header allowlist is invalid")]
    InvalidHeaderAllowlist,
    #[error("session-injection cookie allowlist is invalid")]
    InvalidCookieAllowlist,
    #[error("session-injection contains too many CSRF bindings")]
    TooManyCsrfBindings,
    #[error("session-injection CSRF binding is invalid")]
    InvalidCsrfBinding,
    #[error("session-injection activation window is invalid")]
    InvalidActivationWindow,
    #[error("session-injection activation key does not match")]
    ActivationKeyMismatch,
    #[error("session-injection activation does not match the manifest")]
    ActivationBindingMismatch,
    #[error("session-injection activation is outside its validity window")]
    ActivationExpired,
    #[error("session-injection signature is invalid")]
    InvalidSignature,
    #[error("session-injection does not match the discovery session")]
    DiscoverySessionBindingMismatch,
    #[error("session-injection request origin does not match")]
    RequestOriginMismatch,
    #[error("session-injection method is denied")]
    MethodDenied,
    #[error("session-injection request path is denied")]
    RequestPathDenied,
    #[error("session is revoked")]
    SessionRevoked,
    #[error("session identity does not match injection identity")]
    SessionIdentityMismatch,
    #[error("session is expired or expires before the injection manifest")]
    SessionExpired,
    #[error("session authority is broader than the injection origin")]
    SessionAuthorityTooBroad,
    #[error("session generation regressed")]
    SessionGenerationRegression,
    #[error("session contains duplicate secret handles")]
    DuplicateSessionHandle,
    #[error("secret handle is unknown or revoked")]
    UnknownSecretHandle,
    #[error("secret identity or authority binding does not match")]
    SecretBindingMismatch,
    #[error("session contains a header secret outside the manifest")]
    HeaderDenied,
    #[error("session contains a cookie outside the manifest")]
    CookieDenied,
    #[error("session cookie is expired")]
    CookieExpired,
    #[error("required static secret is missing")]
    RequiredStaticSecretMissing,
    #[error("CSRF cookie is missing")]
    CsrfCookieMissing,
    #[error("CSRF cookie does not apply to the request path")]
    CsrfCookiePathMismatch,
    #[error("session-injection authorization digest mismatch")]
    AuthorizationDigestMismatch,
    #[error("session-injection serialization failed: {0}")]
    Serialization(String),
    #[error("session-injection state operation failed: {0}")]
    StateIo(String),
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    use nxb_session::{SessionProfile, SessionStatus};
    use nxb_vault::{CookieMetadata, SameSitePolicy, SecretBinding, SecretDelivery, SecretInput};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    const NOW: i64 = 1_900_000_000;

    fn binding() -> SecretBinding {
        SecretBinding {
            run_id: "run-138".into(),
            worker_id: "worker-138".into(),
            account_id: "account-a".into(),
            tenant_id: "tenant-a".into(),
            role_id: "admin".into(),
            allowed_hosts: BTreeSet::from(["app.example.com".into()]),
            allowed_schemes: BTreeSet::from(["https".into()]),
        }
    }

    fn insert_header(
        vault: &mut InMemorySecretVault,
        kind: SecretKind,
        name: &str,
        value: &[u8],
    ) -> SecretHandle {
        vault
            .insert(
                SecretInput {
                    kind,
                    value: value.to_vec(),
                    binding: binding(),
                    delivery: SecretDelivery::Header {
                        name: name.into(),
                        prefix: if name.eq_ignore_ascii_case("authorization") {
                            b"Bearer ".to_vec()
                        } else {
                            Vec::new()
                        },
                    },
                    expires_at_epoch_seconds: Some(NOW + 3_600),
                },
                NOW,
            )
            .unwrap()
    }

    fn insert_cookie(
        vault: &mut InMemorySecretVault,
        name: &str,
        path: &str,
        value: &[u8],
    ) -> SecretHandle {
        vault
            .insert(
                SecretInput {
                    kind: SecretKind::Cookie,
                    value: value.to_vec(),
                    binding: binding(),
                    delivery: SecretDelivery::Cookie(CookieMetadata {
                        name: name.into(),
                        domain: "app.example.com".into(),
                        path: path.into(),
                        expires_at_epoch_seconds: Some(NOW + 3_600),
                        secure: true,
                        http_only: true,
                        same_site: SameSitePolicy::Strict,
                    }),
                    expires_at_epoch_seconds: Some(NOW + 3_600),
                },
                NOW,
            )
            .unwrap()
    }

    fn session(handles: Vec<SecretHandle>) -> SessionMetadata {
        SessionMetadata {
            session_id: "session-138".into(),
            profile: SessionProfile {
                run_id: "run-138".into(),
                worker_id: "worker-138".into(),
                account_id: "account-a".into(),
                tenant_id: "tenant-a".into(),
                role_id: "admin".into(),
                allowed_hosts: BTreeSet::from(["app.example.com".into()]),
                allowed_schemes: BTreeSet::from(["https".into()]),
                secret_handles: handles,
                expires_at_epoch_seconds: NOW + 1_800,
            },
            status: SessionStatus::Active,
            created_at_epoch_seconds: NOW,
            generation: 1,
            cookie_jar_audit_tail: "a".repeat(64),
        }
    }

    fn manifest(
        key: &[u8],
        handles: Vec<SecretHandle>,
        csrf: SecretHandle,
    ) -> SessionInjectionManifest {
        SessionInjectionManifest::build(SessionInjectionManifestParameters {
            injection_id: "injection-138".into(),
            discovery_plan_sha256: "b".repeat(64),
            target_origin_sha256: hash_bytes(b"https://app.example.com:443"),
            authority: "app.example.com".into(),
            session_id: "session-138".into(),
            run_id: "run-138".into(),
            worker_id: "worker-138".into(),
            account_id: "account-a".into(),
            tenant_id: "tenant-a".into(),
            role_id: "admin".into(),
            bootstrap_secret_handles: handles,
            allowed_path_prefixes: BTreeSet::from(["/app".into()]),
            allowed_header_names: BTreeSet::from(["authorization".into(), "x-csrf-token".into()]),
            allowed_cookie_names: BTreeSet::from(["sid".into()]),
            csrf_bindings: vec![CsrfBinding {
                cookie_name: "sid".into(),
                header_name: "x-csrf-token".into(),
                token_handle: csrf,
            }],
            maximum_lease_seconds: 10,
            created_at_epoch_seconds: NOW,
            expires_at_epoch_seconds: NOW + 600,
            activation_public_key: key.to_vec(),
        })
        .unwrap()
    }

    fn signed(
        manifest: &SessionInjectionManifest,
        key_pair: &Ed25519KeyPair,
    ) -> SessionInjectionActivationCertificate {
        let payload =
            SessionInjectionActivationPayload::template("activation-138", manifest, NOW, NOW + 300)
                .unwrap();
        let signature = key_pair.sign(&payload.signing_bytes().unwrap());
        SessionInjectionActivationCertificate {
            payload,
            signature_hex: lower_hex(signature.as_ref()),
        }
    }

    fn fixture() -> (
        InMemorySecretVault,
        SessionMetadata,
        SessionInjectionManifest,
        SessionInjectionActivationCertificate,
        Ed25519KeyPair,
    ) {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[31_u8; 32]).unwrap();
        let mut vault = InMemorySecretVault::new("vault-138").unwrap();
        let bearer = insert_header(
            &mut vault,
            SecretKind::BearerToken,
            "Authorization",
            b"bearer-secret",
        );
        let csrf = insert_header(
            &mut vault,
            SecretKind::CsrfToken,
            "X-CSRF-Token",
            b"csrf-secret",
        );
        let cookie = insert_cookie(&mut vault, "sid", "/app", b"cookie-secret");
        let handles = vec![bearer, csrf.clone(), cookie];
        let session = session(handles.clone());
        let manifest = manifest(key_pair.public_key().as_ref(), handles, csrf);
        let certificate = signed(&manifest, &key_pair);
        (vault, session, manifest, certificate, key_pair)
    }

    #[test]
    fn exact_manifest_authorizes_only_bounded_get_and_head_requests() {
        let (vault, session, manifest, certificate, key_pair) = fixture();
        let bound = BoundSessionInjection::bind(
            manifest,
            &certificate,
            key_pair.public_key().as_ref(),
            &"b".repeat(64),
            &hash_bytes(b"https://app.example.com:443"),
            &session,
            &vault,
            NOW + 1,
        )
        .unwrap();
        let authorization = bound
            .authorize_request(
                &session,
                &vault,
                "app.example.com",
                "https",
                "/app/api/me",
                "GET",
                NOW + 2,
            )
            .unwrap();
        authorization.verify().unwrap();
        assert_eq!(authorization.static_secret_count, 2);
        assert_eq!(authorization.cookie_secret_count, 1);
        assert!(bound
            .authorize_request(
                &session,
                &vault,
                "app.example.com",
                "https",
                "/application",
                "GET",
                NOW + 2,
            )
            .is_err());
        assert!(bound
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
    }

    #[test]
    fn tenant_mismatch_and_unapproved_static_secret_fail_closed() {
        let (mut vault, mut session, manifest, certificate, key_pair) = fixture();
        let bound = BoundSessionInjection::bind(
            manifest,
            &certificate,
            key_pair.public_key().as_ref(),
            &"b".repeat(64),
            &hash_bytes(b"https://app.example.com:443"),
            &session,
            &vault,
            NOW + 1,
        )
        .unwrap();
        session.profile.tenant_id = "tenant-b".into();
        assert!(matches!(
            bound.authorize_request(
                &session,
                &vault,
                "app.example.com",
                "https",
                "/app/api/me",
                "GET",
                NOW + 2,
            ),
            Err(SessionInjectionError::SessionIdentityMismatch)
        ));
        session.profile.tenant_id = "tenant-a".into();
        let extra = insert_header(
            &mut vault,
            SecretKind::ApiKey,
            "X-Extra-Key",
            b"extra-secret",
        );
        session.profile.secret_handles.push(extra);
        assert!(matches!(
            bound.authorize_request(
                &session,
                &vault,
                "app.example.com",
                "https",
                "/app/api/me",
                "GET",
                NOW + 2,
            ),
            Err(SessionInjectionError::HeaderDenied)
        ));
    }

    #[test]
    fn allowlisted_cookie_rotation_is_accepted_without_static_secret_broadening() {
        let (mut vault, mut session, manifest, certificate, key_pair) = fixture();
        let bound = BoundSessionInjection::bind(
            manifest,
            &certificate,
            key_pair.public_key().as_ref(),
            &"b".repeat(64),
            &hash_bytes(b"https://app.example.com:443"),
            &session,
            &vault,
            NOW + 1,
        )
        .unwrap();
        let old_cookie = session
            .profile
            .secret_handles
            .iter()
            .find(|handle| {
                matches!(
                    vault.metadata(handle).unwrap().delivery,
                    SecretDeliveryMetadata::Cookie { .. }
                )
            })
            .cloned()
            .unwrap();
        let rotated = insert_cookie(&mut vault, "sid", "/app", b"rotated-cookie");
        session
            .profile
            .secret_handles
            .retain(|handle| handle != &old_cookie);
        session.profile.secret_handles.push(rotated);
        session.generation += 1;
        bound
            .authorize_request(
                &session,
                &vault,
                "app.example.com",
                "https",
                "/app/api/me",
                "HEAD",
                NOW + 2,
            )
            .unwrap();
    }

    #[test]
    fn csrf_cookie_must_apply_to_the_current_request_path() {
        let (mut vault, mut session, manifest, certificate, key_pair) = fixture();
        let cookie = session
            .profile
            .secret_handles
            .iter()
            .find(|handle| {
                matches!(
                    vault.metadata(handle).unwrap().delivery,
                    SecretDeliveryMetadata::Cookie { .. }
                )
            })
            .cloned()
            .unwrap();
        session
            .profile
            .secret_handles
            .retain(|handle| handle != &cookie);
        session.profile.secret_handles.push(insert_cookie(
            &mut vault,
            "sid",
            "/app/admin",
            b"cookie-admin",
        ));
        let bound = BoundSessionInjection::bind(
            manifest,
            &certificate,
            key_pair.public_key().as_ref(),
            &"b".repeat(64),
            &hash_bytes(b"https://app.example.com:443"),
            &session,
            &vault,
            NOW + 1,
        )
        .unwrap();
        assert!(matches!(
            bound.authorize_request(
                &session,
                &vault,
                "app.example.com",
                "https",
                "/app/profile",
                "GET",
                NOW + 2,
            ),
            Err(SessionInjectionError::CsrfCookiePathMismatch)
        ));
    }

    #[test]
    fn activation_is_signature_bound_and_single_use() {
        let (_vault, _session, manifest, certificate, key_pair) = fixture();
        certificate
            .verify(&manifest, key_pair.public_key().as_ref(), NOW + 1)
            .unwrap();
        let mut tampered = manifest.clone();
        tampered.maximum_lease_seconds += 1;
        tampered.manifest_sha256 = tampered.calculate_sha256().unwrap();
        assert!(certificate
            .verify(&tampered, key_pair.public_key().as_ref(), NOW + 1)
            .is_err());

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "nxb-session-injection-{}-{unique}",
            std::process::id()
        ));
        consume_activation_once(
            &directory,
            &manifest,
            &certificate,
            key_pair.public_key().as_ref(),
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
    fn serialized_and_debug_material_never_contains_secret_values() {
        let (vault, session, manifest, certificate, key_pair) = fixture();
        let bound = BoundSessionInjection::bind(
            manifest,
            &certificate,
            key_pair.public_key().as_ref(),
            &"b".repeat(64),
            &hash_bytes(b"https://app.example.com:443"),
            &session,
            &vault,
            NOW + 1,
        )
        .unwrap();
        let material = format!(
            "{:?}{}{}",
            bound,
            serde_json::to_string(bound.manifest()).unwrap(),
            serde_json::to_string(&certificate).unwrap()
        );
        for secret in ["bearer-secret", "csrf-secret", "cookie-secret"] {
            assert!(!material.contains(secret));
        }
    }
}
