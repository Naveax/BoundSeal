use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use nxb_cookie_jar::{
    CookieCommit, CookieJar, CookieJarAuditChain, CookieJarConfig, CookieJarError, CookieOrigin,
};
use nxb_http1::{Http1Codec, Http1Error, Http1Exchange, Http1Request};
use nxb_stream::{ByteStreamBackend, StreamControl};
use nxb_vault::{
    InMemorySecretVault, SecretBinding, SecretHandle, SecretHeaderLease, SecretKind,
    VaultAccessContext, VaultError, MAX_SECRET_HANDLES_PER_LEASE, MAX_SECRET_LEASE_SECONDS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionProfile {
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub allowed_hosts: BTreeSet<String>,
    pub allowed_schemes: BTreeSet<String>,
    pub secret_handles: Vec<SecretHandle>,
    pub expires_at_epoch_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionUseContext {
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionExchangeOptions {
    pub lease_seconds: i64,
    pub now_epoch_seconds: i64,
    pub control: StreamControl,
}

#[derive(Debug, Clone, Copy)]
struct CookieResponseContext<'a> {
    authority: &'a str,
    scheme: &'a str,
    request_target: &'a str,
    now_epoch_seconds: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionMetadata {
    pub session_id: String,
    pub profile: SessionProfile,
    pub status: SessionStatus,
    pub created_at_epoch_seconds: i64,
    pub generation: u64,
    pub cookie_jar_audit_tail: String,
}

struct SessionState {
    metadata: SessionMetadata,
    cookie_jar: CookieJar,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionAuditEvent {
    pub action: String,
    pub outcome: String,
    pub broker_id: String,
    pub session_id: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: SessionAuditEvent,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct SessionAuditChain {
    genesis_hash: String,
    records: Vec<SessionAuditRecord>,
    tail_hash: String,
}

impl SessionAuditChain {
    fn new(broker_id: &str) -> Self {
        let genesis_hash = lower_hex(&Sha256::digest(
            format!("nxb-session:{broker_id}").as_bytes(),
        ));
        Self {
            tail_hash: genesis_hash.clone(),
            genesis_hash,
            records: Vec::new(),
        }
    }

    fn append(&mut self, event: SessionAuditEvent) -> Result<(), SessionError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let bytes = serde_json::to_vec(&(sequence, &previous_hash, &event))
            .map_err(|error| SessionError::AuditSerialization(error.to_string()))?;
        let record_hash = lower_hex(&Sha256::digest(bytes));
        self.records.push(SessionAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(())
    }

    pub fn records(&self) -> &[SessionAuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), SessionError> {
        let mut previous = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(SessionError::AuditSequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous {
                return Err(SessionError::AuditPreviousHashMismatch {
                    record_index: index,
                });
            }
            let bytes =
                serde_json::to_vec(&(record.sequence, &record.previous_hash, &record.event))
                    .map_err(|error| SessionError::AuditSerialization(error.to_string()))?;
            let expected = lower_hex(&Sha256::digest(bytes));
            if record.record_hash != expected {
                return Err(SessionError::AuditRecordHashMismatch {
                    record_index: index,
                });
            }
            previous = expected;
        }
        if self.tail_hash != previous {
            return Err(SessionError::AuditTailMismatch);
        }
        Ok(())
    }
}

pub struct SessionBroker {
    broker_id: String,
    sessions: BTreeMap<String, SessionState>,
    next_session_id: u64,
    audit: SessionAuditChain,
}

impl fmt::Debug for SessionBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionBroker")
            .field("broker_id", &self.broker_id)
            .field("session_count", &self.sessions.len())
            .field("sessions", &"<opaque handles only>")
            .finish()
    }
}

impl SessionBroker {
    pub fn new(broker_id: impl Into<String>) -> Result<Self, SessionError> {
        let broker_id = broker_id.into();
        validate_identifier(&broker_id, "broker_id")?;
        Ok(Self {
            audit: SessionAuditChain::new(&broker_id),
            broker_id,
            sessions: BTreeMap::new(),
            next_session_id: 1,
        })
    }

    pub fn create_session(
        &mut self,
        profile: SessionProfile,
        vault: &InMemorySecretVault,
        now_epoch_seconds: i64,
    ) -> Result<SessionMetadata, SessionError> {
        let profile = normalize_profile(profile, now_epoch_seconds)?;
        if profile.secret_handles.is_empty()
            || profile.secret_handles.len() > MAX_SECRET_HANDLES_PER_LEASE
        {
            return Err(SessionError::InvalidProfile(
                "secret handle count is outside the supported range".into(),
            ));
        }
        let unique_handles = profile.secret_handles.iter().collect::<BTreeSet<_>>();
        if unique_handles.len() != profile.secret_handles.len() {
            return Err(SessionError::InvalidProfile(
                "secret handles must be unique".into(),
            ));
        }
        for handle in &profile.secret_handles {
            let secret = vault.metadata(handle)?;
            let binding = secret.binding;
            if binding.run_id != profile.run_id
                || binding.worker_id != profile.worker_id
                || binding.account_id != profile.account_id
                || binding.tenant_id != profile.tenant_id
                || binding.role_id != profile.role_id
                || !profile.allowed_hosts.is_subset(&binding.allowed_hosts)
                || !profile.allowed_schemes.is_subset(&binding.allowed_schemes)
            {
                return Err(SessionError::SecretBindingMismatch);
            }
            if secret
                .expires_at_epoch_seconds
                .is_some_and(|expires| expires < profile.expires_at_epoch_seconds)
            {
                return Err(SessionError::SecretExpiresBeforeSession);
            }
        }

        let session_id = format!("{}-session-{:020}", self.broker_id, self.next_session_id);
        self.next_session_id = self.next_session_id.saturating_add(1);
        let non_cookie_handle_count = profile
            .secret_handles
            .iter()
            .map(|handle| vault.metadata(handle))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|metadata| metadata.kind != SecretKind::Cookie)
            .count();
        let maximum_cookie_records = MAX_SECRET_HANDLES_PER_LEASE
            .checked_sub(non_cookie_handle_count)
            .ok_or_else(|| {
                SessionError::InvalidProfile(
                    "non-cookie secret handles exceed the session limit".into(),
                )
            })?;
        let mut cookie_jar = CookieJar::new(
            format!("{session_id}-cookie-jar"),
            CookieJarConfig {
                maximum_cookie_records,
                ..CookieJarConfig::default()
            },
        )?;
        cookie_jar.seed_from_vault(&profile.secret_handles, vault)?;
        let metadata = SessionMetadata {
            session_id: session_id.clone(),
            profile,
            status: SessionStatus::Active,
            created_at_epoch_seconds: now_epoch_seconds,
            generation: cookie_jar.generation(),
            cookie_jar_audit_tail: cookie_jar.audit().tail_hash().to_string(),
        };
        self.sessions.insert(
            session_id.clone(),
            SessionState {
                metadata: metadata.clone(),
                cookie_jar,
            },
        );
        if let Err(error) = self.audit.append(SessionAuditEvent {
            action: "session_created".into(),
            outcome: "active".into(),
            broker_id: self.broker_id.clone(),
            session_id: Some(session_id.clone()),
            metadata: BTreeMap::from([
                (
                    "secret_handle_count".into(),
                    metadata.profile.secret_handles.len().to_string(),
                ),
                (
                    "expires_at".into(),
                    metadata.profile.expires_at_epoch_seconds.to_string(),
                ),
            ]),
        }) {
            self.sessions.remove(&session_id);
            return Err(error);
        }
        Ok(metadata)
    }

    pub fn metadata(&self, session_id: &str) -> Result<SessionMetadata, SessionError> {
        self.sessions
            .get(session_id)
            .map(|session| session.metadata.clone())
            .ok_or(SessionError::UnknownSession)
    }

    pub fn exchange<B: ByteStreamBackend>(
        &mut self,
        session_id: &str,
        context: &SessionUseContext,
        vault: &mut InMemorySecretVault,
        codec: &mut Http1Codec<B>,
        request: &Http1Request,
        options: SessionExchangeOptions,
    ) -> Result<Http1Exchange, SessionError> {
        let metadata = self
            .sessions
            .get(session_id)
            .map(|state| state.metadata.clone())
            .ok_or(SessionError::UnknownSession)?;
        let authority = codec.stream().grant().http_host().to_ascii_lowercase();
        let scheme = codec.stream().grant().scheme().to_ascii_lowercase();
        let mut result = (|| {
            validate_session_use(
                &metadata,
                context,
                &authority,
                &scheme,
                options.now_epoch_seconds,
            )?;
            if options.lease_seconds <= 0 || options.lease_seconds > MAX_SECRET_LEASE_SECONDS {
                return Err(SessionError::InvalidLeaseDuration);
            }
            let access = VaultAccessContext {
                run_id: context.run_id.clone(),
                worker_id: context.worker_id.clone(),
                account_id: context.account_id.clone(),
                tenant_id: context.tenant_id.clone(),
                role_id: context.role_id.clone(),
                authority: authority.clone(),
                scheme: scheme.clone(),
            };
            let mut secret_lease = vault.lease(
                &metadata.profile.secret_handles,
                access,
                options.lease_seconds,
                options.now_epoch_seconds,
            )?;
            let mut header_lease: SecretHeaderLease = vault.materialize_http_headers(
                &mut secret_lease,
                session_id,
                &request.target,
                options.now_epoch_seconds,
            )?;
            codec
                .exchange_with_secret_headers(
                    request,
                    &mut header_lease,
                    options.now_epoch_seconds,
                    options.control,
                )
                .map_err(SessionError::Http)
        })();

        let cookie_result = match result.as_ref() {
            Ok(exchange) => self.apply_response_cookies(
                session_id,
                vault,
                exchange,
                CookieResponseContext {
                    authority: &authority,
                    scheme: &scheme,
                    request_target: &request.target,
                    now_epoch_seconds: options.now_epoch_seconds,
                },
            ),
            Err(_) => Ok(None),
        };
        let cookie_commit = match cookie_result {
            Ok(commit) => commit,
            Err(error) => {
                result = Err(error);
                None
            }
        };
        let (cookie_inserted, cookie_replaced, cookie_deleted, generation) = cookie_commit
            .as_ref()
            .map(|commit| {
                (
                    commit.inserted,
                    commit.replaced,
                    commit.deleted,
                    commit.generation_after,
                )
            })
            .unwrap_or((0, 0, 0, metadata.generation));

        let (outcome, result_code, response_status) = match &result {
            Ok(exchange) => (
                "completed".to_string(),
                "ok".to_string(),
                exchange.response.status_code.to_string(),
            ),
            Err(error) => (
                "rejected".to_string(),
                error.code().to_string(),
                "none".to_string(),
            ),
        };
        self.audit.append(SessionAuditEvent {
            action: "authenticated_http1_exchange".into(),
            outcome,
            broker_id: self.broker_id.clone(),
            session_id: Some(session_id.into()),
            metadata: BTreeMap::from([
                ("authority".into(), authority),
                ("scheme".into(), scheme),
                ("request_method".into(), request.method.clone()),
                (
                    "request_target_sha256".into(),
                    hash(request.target.as_bytes()),
                ),
                ("result_code".into(), result_code),
                ("response_status".into(), response_status),
                ("cookie_inserted".into(), cookie_inserted.to_string()),
                ("cookie_replaced".into(), cookie_replaced.to_string()),
                ("cookie_deleted".into(), cookie_deleted.to_string()),
                ("session_generation".into(), generation.to_string()),
            ]),
        })?;
        result
    }

    fn apply_response_cookies(
        &mut self,
        session_id: &str,
        vault: &mut InMemorySecretVault,
        exchange: &Http1Exchange,
        context: CookieResponseContext<'_>,
    ) -> Result<Option<CookieCommit>, SessionError> {
        let set_cookie_values = exchange
            .response
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("set-cookie"))
            .map(|header| header.value.clone())
            .collect::<Vec<_>>();
        if set_cookie_values.is_empty() {
            return Ok(None);
        }
        let state = self
            .sessions
            .get_mut(session_id)
            .ok_or(SessionError::UnknownSession)?;
        let binding = secret_binding_from_profile(&state.metadata.profile);
        let origin = CookieOrigin::new(context.authority, context.scheme)?;
        let previous_cookie_handles = state
            .cookie_jar
            .active_handles()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let commit = state.cookie_jar.apply_response(
            vault,
            &binding,
            &origin,
            context.request_target,
            &set_cookie_values,
            context.now_epoch_seconds,
        )?;
        state
            .metadata
            .profile
            .secret_handles
            .retain(|handle| !previous_cookie_handles.contains(handle));
        state
            .metadata
            .profile
            .secret_handles
            .extend(commit.active_handles.iter().cloned());
        state.metadata.profile.secret_handles = state
            .metadata
            .profile
            .secret_handles
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        state.metadata.generation = commit.generation_after;
        state.metadata.cookie_jar_audit_tail = commit.audit_tail.clone();
        Ok(Some(commit))
    }

    pub fn logout_session(
        &mut self,
        session_id: &str,
        vault: &mut InMemorySecretVault,
    ) -> Result<(), SessionError> {
        let state = self
            .sessions
            .get_mut(session_id)
            .ok_or(SessionError::UnknownSession)?;
        let cookie_handles = state
            .cookie_jar
            .active_handles()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let commit = state.cookie_jar.purge(vault, "logout")?;
        state
            .metadata
            .profile
            .secret_handles
            .retain(|handle| !cookie_handles.contains(handle));
        state.metadata.status = SessionStatus::Revoked;
        state.metadata.generation = commit.generation_after;
        state.metadata.cookie_jar_audit_tail = commit.audit_tail.clone();
        self.audit.append(SessionAuditEvent {
            action: "session_logout".into(),
            outcome: "revoked".into(),
            broker_id: self.broker_id.clone(),
            session_id: Some(session_id.into()),
            metadata: BTreeMap::from([
                ("cookie_deleted".into(), commit.deleted.to_string()),
                ("generation".into(), commit.generation_after.to_string()),
            ]),
        })?;
        Ok(())
    }

    pub fn cookie_jar_audit(&self, session_id: &str) -> Result<&CookieJarAuditChain, SessionError> {
        self.sessions
            .get(session_id)
            .map(|state| state.cookie_jar.audit())
            .ok_or(SessionError::UnknownSession)
    }

    pub fn revoke_session(&mut self, session_id: &str) -> Result<(), SessionError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or(SessionError::UnknownSession)?;
        session.metadata.status = SessionStatus::Revoked;
        self.audit.append(SessionAuditEvent {
            action: "session_revoked".into(),
            outcome: "revoked".into(),
            broker_id: self.broker_id.clone(),
            session_id: Some(session_id.into()),
            metadata: BTreeMap::new(),
        })?;
        Ok(())
    }

    pub fn emergency_purge(&mut self, vault: &mut InMemorySecretVault) -> Result<(), SessionError> {
        let session_count = self.sessions.len();
        for session in self.sessions.values_mut() {
            session.metadata.status = SessionStatus::Revoked;
        }
        vault.emergency_purge()?;
        self.audit.append(SessionAuditEvent {
            action: "session_emergency_purge".into(),
            outcome: "purged".into(),
            broker_id: self.broker_id.clone(),
            session_id: None,
            metadata: BTreeMap::from([("session_count".into(), session_count.to_string())]),
        })?;
        Ok(())
    }

    pub fn audit(&self) -> &SessionAuditChain {
        &self.audit
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("session identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("session profile is invalid: {0}")]
    InvalidProfile(String),
    #[error("session is unknown")]
    UnknownSession,
    #[error("session has expired")]
    SessionExpired,
    #[error("session has been revoked")]
    SessionRevoked,
    #[error("session use context does not match account, tenant, role, run or worker")]
    SessionContextMismatch,
    #[error("session is not authorized for the stream authority")]
    SessionAuthorityMismatch,
    #[error("secret binding cannot be broadened by the session")]
    SecretBindingMismatch,
    #[error("secret expires before the requested session")]
    SecretExpiresBeforeSession,
    #[error("session lease duration is outside the supported range")]
    InvalidLeaseDuration,
    #[error("vault operation failed: {0}")]
    Vault(#[from] VaultError),
    #[error("cookie jar operation failed: {0}")]
    CookieJar(#[from] CookieJarError),
    #[error("authenticated HTTP/1 exchange failed: {0}")]
    Http(#[from] Http1Error),
    #[error("session audit material could not be serialized: {0}")]
    AuditSerialization(String),
    #[error("session audit sequence mismatch at record {record_index}")]
    AuditSequenceMismatch { record_index: usize },
    #[error("session audit previous hash mismatch at record {record_index}")]
    AuditPreviousHashMismatch { record_index: usize },
    #[error("session audit record hash mismatch at record {record_index}")]
    AuditRecordHashMismatch { record_index: usize },
    #[error("session audit tail hash mismatch")]
    AuditTailMismatch,
}

impl SessionError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidIdentifier(_) => "invalid_identifier",
            Self::InvalidProfile(_) => "invalid_profile",
            Self::UnknownSession => "unknown_session",
            Self::SessionExpired => "session_expired",
            Self::SessionRevoked => "session_revoked",
            Self::SessionContextMismatch => "session_context_mismatch",
            Self::SessionAuthorityMismatch => "session_authority_mismatch",
            Self::SecretBindingMismatch => "secret_binding_mismatch",
            Self::SecretExpiresBeforeSession => "secret_expires_before_session",
            Self::InvalidLeaseDuration => "invalid_lease_duration",
            Self::Vault(_) => "vault_rejected",
            Self::CookieJar(_) => "cookie_jar_rejected",
            Self::Http(_) => "http1_rejected",
            Self::AuditSerialization(_) => "audit_serialization",
            Self::AuditSequenceMismatch { .. } => "audit_sequence_mismatch",
            Self::AuditPreviousHashMismatch { .. } => "audit_previous_hash_mismatch",
            Self::AuditRecordHashMismatch { .. } => "audit_record_hash_mismatch",
            Self::AuditTailMismatch => "audit_tail_mismatch",
        }
    }
}

fn secret_binding_from_profile(profile: &SessionProfile) -> SecretBinding {
    SecretBinding {
        run_id: profile.run_id.clone(),
        worker_id: profile.worker_id.clone(),
        account_id: profile.account_id.clone(),
        tenant_id: profile.tenant_id.clone(),
        role_id: profile.role_id.clone(),
        allowed_hosts: profile.allowed_hosts.clone(),
        allowed_schemes: profile.allowed_schemes.clone(),
    }
}

fn normalize_profile(
    mut profile: SessionProfile,
    now_epoch_seconds: i64,
) -> Result<SessionProfile, SessionError> {
    validate_identifier(&profile.run_id, "run_id")?;
    validate_identifier(&profile.worker_id, "worker_id")?;
    validate_identifier(&profile.account_id, "account_id")?;
    validate_identifier(&profile.tenant_id, "tenant_id")?;
    validate_identifier(&profile.role_id, "role_id")?;
    if profile.expires_at_epoch_seconds <= now_epoch_seconds {
        return Err(SessionError::InvalidProfile(
            "session expiry must be in the future".into(),
        ));
    }
    if profile.allowed_hosts.is_empty() || profile.allowed_schemes.is_empty() {
        return Err(SessionError::InvalidProfile(
            "host and scheme sets must not be empty".into(),
        ));
    }
    profile.allowed_hosts = profile
        .allowed_hosts
        .into_iter()
        .map(|host| normalize_host(&host))
        .collect::<Result<_, _>>()?;
    profile.allowed_schemes = profile
        .allowed_schemes
        .into_iter()
        .map(|scheme| normalize_scheme(&scheme))
        .collect::<Result<_, _>>()?;
    Ok(profile)
}

fn validate_session_use(
    session: &SessionMetadata,
    context: &SessionUseContext,
    authority: &str,
    scheme: &str,
    now_epoch_seconds: i64,
) -> Result<(), SessionError> {
    if session.status == SessionStatus::Revoked {
        return Err(SessionError::SessionRevoked);
    }
    if now_epoch_seconds >= session.profile.expires_at_epoch_seconds {
        return Err(SessionError::SessionExpired);
    }
    if session.profile.run_id != context.run_id
        || session.profile.worker_id != context.worker_id
        || session.profile.account_id != context.account_id
        || session.profile.tenant_id != context.tenant_id
        || session.profile.role_id != context.role_id
    {
        return Err(SessionError::SessionContextMismatch);
    }
    if !session.profile.allowed_hosts.contains(authority)
        || !session.profile.allowed_schemes.contains(scheme)
    {
        return Err(SessionError::SessionAuthorityMismatch);
    }
    Ok(())
}

fn validate_identifier(value: &str, name: &str) -> Result<(), SessionError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(SessionError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

fn normalize_host(host: &str) -> Result<String, SessionError> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
    {
        return Err(SessionError::InvalidProfile("host is invalid".into()));
    }
    Ok(host)
}

fn normalize_scheme(scheme: &str) -> Result<String, SessionError> {
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err(SessionError::InvalidProfile("scheme is invalid".into()));
    }
    Ok(scheme)
}

fn hash(bytes: &[u8]) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use nxb_executor::{
        ExecutionControl, ExecutionLimits, ExecutorConfig, PermitExecutor, SyntheticBackend,
        SyntheticScenario,
    };
    use nxb_http1::{Http1Header, Http1Limits};
    use nxb_stream::{BoundedByteStream, StreamLimits};
    use nxb_stream_fixture::{FixtureReadEvent, FixtureWriteEvent, InMemoryDuplex};
    use nxb_transport::{TransportPermit, TransportScheme};
    use nxb_vault::{SecretBinding, SecretDelivery, SecretInput, SecretKind};

    fn secret_binding() -> SecretBinding {
        SecretBinding {
            run_id: "run-1".into(),
            worker_id: "worker-1".into(),
            account_id: "account-a".into(),
            tenant_id: "tenant-a".into(),
            role_id: "admin".into(),
            allowed_hosts: BTreeSet::from(["app.example.com".into()]),
            allowed_schemes: BTreeSet::from(["https".into()]),
        }
    }

    fn profile(handle: SecretHandle) -> SessionProfile {
        SessionProfile {
            run_id: "run-1".into(),
            worker_id: "worker-1".into(),
            account_id: "account-a".into(),
            tenant_id: "tenant-a".into(),
            role_id: "admin".into(),
            allowed_hosts: BTreeSet::from(["app.example.com".into()]),
            allowed_schemes: BTreeSet::from(["https".into()]),
            secret_handles: vec![handle],
            expires_at_epoch_seconds: 1_000,
        }
    }

    fn use_context() -> SessionUseContext {
        SessionUseContext {
            run_id: "run-1".into(),
            worker_id: "worker-1".into(),
            account_id: "account-a".into(),
            tenant_id: "tenant-a".into(),
            role_id: "admin".into(),
        }
    }

    fn permit() -> TransportPermit {
        TransportPermit {
            ticket_id: "ticket-session-0001".into(),
            decision_id: "decision-session-0001".into(),
            dns_context_id: "navigation-session-1".into(),
            scheme: TransportScheme::Https,
            remote_ip: "1.1.1.1".parse().unwrap(),
            port: 443,
            sni: Some("app.example.com".into()),
            http_host: "app.example.com".into(),
            redirect_depth: 0,
            binding_hash: "a".repeat(64),
        }
    }

    fn codec() -> Http1Codec<InMemoryDuplex> {
        let permit = permit();
        let mut executor = PermitExecutor::new(
            ExecutorConfig {
                executor_id: "session-fixture-executor".into(),
            },
            SyntheticBackend::new([SyntheticScenario::success(1, 2, 0, 0)]),
        )
        .unwrap();
        let execution = executor
            .execute(
                &permit,
                &"b".repeat(64),
                ExecutionLimits::default(),
                ExecutionControl::default(),
            )
            .unwrap();
        let backend = InMemoryDuplex::new(
            [
                FixtureReadEvent::Bytes {
                    bytes: b"HTTP/1.1 200 OK\r\nSet-Cookie: session=rotated; Secure; HttpOnly; Path=/\r\nContent-Length: 2\r\n\r\nok".to_vec(),
                    elapsed_milliseconds: 1,
                },
                FixtureReadEvent::Eof {
                    elapsed_milliseconds: 0,
                },
            ],
            [FixtureWriteEvent::Accept {
                maximum_bytes: u64::MAX,
                elapsed_milliseconds: 1,
            }],
        );
        let stream = BoundedByteStream::open(
            &permit,
            &execution,
            executor.audit(),
            StreamLimits::default(),
            backend,
        )
        .unwrap();
        Http1Codec::new(stream, Http1Limits::default()).unwrap()
    }

    fn vault_with_bearer(secret: &[u8]) -> (InMemorySecretVault, SecretHandle) {
        let mut vault = InMemorySecretVault::new("session-vault").unwrap();
        let handle = vault
            .insert(
                SecretInput {
                    kind: SecretKind::BearerToken,
                    value: secret.to_vec(),
                    binding: secret_binding(),
                    delivery: SecretDelivery::Header {
                        name: "Authorization".into(),
                        prefix: b"Bearer ".to_vec(),
                    },
                    expires_at_epoch_seconds: Some(2_000),
                },
                100,
            )
            .unwrap();
        (vault, handle)
    }

    #[test]
    fn authenticated_exchange_injects_secret_without_audit_disclosure() {
        let secret = b"session-secret-value";
        let (mut vault, handle) = vault_with_bearer(secret);
        let mut broker = SessionBroker::new("broker-1").unwrap();
        let session = broker.create_session(profile(handle), &vault, 100).unwrap();
        let mut codec = codec();
        let request = Http1Request::new("GET", "/api/me");
        let exchange = broker
            .exchange(
                &session.session_id,
                &use_context(),
                &mut vault,
                &mut codec,
                &request,
                SessionExchangeOptions {
                    lease_seconds: 30,
                    now_epoch_seconds: 101,
                    control: StreamControl::default(),
                },
            )
            .unwrap();
        assert_eq!(exchange.response.status_code, 200);
        let captured = codec
            .stream()
            .backend()
            .captured_writes()
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        assert!(String::from_utf8_lossy(&captured).contains("Bearer session-secret-value"));
        let http_audit = serde_json::to_string(codec.audit().records()).unwrap();
        let vault_audit = serde_json::to_string(vault.audit().records()).unwrap();
        let session_audit = serde_json::to_string(broker.audit().records()).unwrap();
        assert!(!http_audit.contains("session-secret-value"));
        assert!(!vault_audit.contains("session-secret-value"));
        assert!(!session_audit.contains("session-secret-value"));
        let updated = broker.metadata(&session.session_id).unwrap();
        assert_eq!(updated.generation, 2);
        assert_eq!(updated.profile.secret_handles.len(), 2);
        broker
            .cookie_jar_audit(&session.session_id)
            .unwrap()
            .verify()
            .unwrap();
    }

    #[test]
    fn public_http_headers_cannot_bypass_vault_managed_authorization() {
        let mut codec = codec();
        let mut request = Http1Request::new("GET", "/api/me");
        request
            .headers
            .push(Http1Header::new("Authorization", b"Bearer bypass".to_vec()));
        assert!(matches!(
            codec.exchange(&request, StreamControl::default()),
            Err(Http1Error::InvalidRequest(_))
        ));
    }

    #[test]
    fn session_cannot_broaden_account_or_tenant_binding() {
        let (vault, handle) = vault_with_bearer(b"token");
        let mut broker = SessionBroker::new("broker-1").unwrap();
        let mut wrong = profile(handle);
        wrong.tenant_id = "tenant-b".into();
        assert!(matches!(
            broker.create_session(wrong, &vault, 100),
            Err(SessionError::SecretBindingMismatch)
        ));
    }

    #[test]
    fn revoked_session_cannot_issue_new_secret_lease() {
        let (mut vault, handle) = vault_with_bearer(b"token");
        let mut broker = SessionBroker::new("broker-1").unwrap();
        let session = broker.create_session(profile(handle), &vault, 100).unwrap();
        broker.revoke_session(&session.session_id).unwrap();
        let mut codec = codec();
        assert!(matches!(
            broker.exchange(
                &session.session_id,
                &use_context(),
                &mut vault,
                &mut codec,
                &Http1Request::new("GET", "/"),
                SessionExchangeOptions {
                    lease_seconds: 30,
                    now_epoch_seconds: 101,
                    control: StreamControl::default(),
                },
            ),
            Err(SessionError::SessionRevoked)
        ));
    }

    #[test]
    fn emergency_purge_revokes_sessions_and_clears_vault() {
        let (mut vault, handle) = vault_with_bearer(b"token");
        let mut broker = SessionBroker::new("broker-1").unwrap();
        let session = broker.create_session(profile(handle), &vault, 100).unwrap();
        broker.emergency_purge(&mut vault).unwrap();
        assert_eq!(vault.secret_count(), 0);
        assert_eq!(
            broker.metadata(&session.session_id).unwrap().status,
            SessionStatus::Revoked
        );
        broker.audit().verify().unwrap();
        vault.audit().verify().unwrap();
    }
}
