use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_SECRET_BYTES: usize = 64 * 1024;
pub const MAX_SECRET_LEASE_SECONDS: i64 = 300;
pub const MAX_SECRET_HANDLES_PER_LEASE: usize = 256;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretHandle(String);

impl SecretHandle {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretHandle")
            .field(&self.0)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Cookie,
    BearerToken,
    ApiKey,
    CsrfToken,
}

impl SecretKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::Cookie => "cookie",
            Self::BearerToken => "bearer_token",
            Self::ApiKey => "api_key",
            Self::CsrfToken => "csrf_token",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SameSitePolicy {
    Strict,
    Lax,
    None,
    Unspecified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CookieMetadata {
    pub name: String,
    pub domain: String,
    pub path: String,
    pub expires_at_epoch_seconds: Option<i64>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSitePolicy,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretBinding {
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub allowed_hosts: BTreeSet<String>,
    pub allowed_schemes: BTreeSet<String>,
}

impl fmt::Debug for SecretBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBinding")
            .field("run_id", &self.run_id)
            .field("worker_id", &self.worker_id)
            .field("account_id", &self.account_id)
            .field("tenant_id", &self.tenant_id)
            .field("role_id", &self.role_id)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_schemes", &self.allowed_schemes)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultAccessContext {
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub authority: String,
    pub scheme: String,
}

impl fmt::Debug for VaultAccessContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultAccessContext")
            .field("run_id", &self.run_id)
            .field("worker_id", &self.worker_id)
            .field("account_id", &self.account_id)
            .field("tenant_id", &self.tenant_id)
            .field("role_id", &self.role_id)
            .field("authority", &self.authority)
            .field("scheme", &self.scheme)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum SecretDelivery {
    Cookie(CookieMetadata),
    Header { name: String, prefix: Vec<u8> },
}

impl fmt::Debug for SecretDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cookie(cookie) => formatter.debug_tuple("Cookie").field(cookie).finish(),
            Self::Header { name, prefix } => formatter
                .debug_struct("Header")
                .field("name", name)
                .field("prefix_bytes", &prefix.len())
                .finish(),
        }
    }
}

pub struct SecretInput {
    pub kind: SecretKind,
    pub value: Vec<u8>,
    pub binding: SecretBinding,
    pub delivery: SecretDelivery,
    pub expires_at_epoch_seconds: Option<i64>,
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretInput")
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .field("value_bytes", &self.value.len())
            .field("binding", &self.binding)
            .field("delivery", &self.delivery)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretDeliveryMetadata {
    Cookie { cookie: CookieMetadata },
    Header { name: String, prefix_bytes: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMetadata {
    pub handle: SecretHandle,
    pub kind: SecretKind,
    pub binding: SecretBinding,
    pub delivery: SecretDeliveryMetadata,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: Option<i64>,
}

struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn duplicate(&self) -> Self {
        Self::new(self.0.to_vec())
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue(<redacted>)")
    }
}

struct SecretEntry {
    metadata: SecretMetadata,
    delivery: SecretDelivery,
    value: SecretValue,
}

impl fmt::Debug for SecretEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretEntry")
            .field("metadata", &self.metadata)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
struct LeaseState {
    handles: Vec<SecretHandle>,
    context: VaultAccessContext,
    expires_at_epoch_seconds: i64,
    consumed: bool,
    revoked: bool,
}

pub struct SecretLease {
    lease_id: String,
    context: VaultAccessContext,
    expires_at_epoch_seconds: i64,
    consumed: bool,
}

impl SecretLease {
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub fn expires_at_epoch_seconds(&self) -> i64 {
        self.expires_at_epoch_seconds
    }
}

impl fmt::Debug for SecretLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretLease")
            .field("lease_id", &self.lease_id)
            .field("context", &self.context)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("consumed", &self.consumed)
            .finish()
    }
}

struct MaterializedHeader {
    normalized_name: String,
    wire_name: String,
    value: SecretValue,
}

impl fmt::Debug for MaterializedHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedHeader")
            .field("name", &self.wire_name)
            .field("value", &"<redacted>")
            .field("value_bytes", &self.value.bytes().len())
            .finish()
    }
}

pub struct SecretHeaderLease {
    lease_id: String,
    session_id: String,
    authority: String,
    scheme: String,
    expires_at_epoch_seconds: i64,
    fingerprint: String,
    headers: Vec<MaterializedHeader>,
    consumed: bool,
}

impl SecretHeaderLease {
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn header_count(&self) -> u64 {
        self.headers.len() as u64
    }

    pub fn take_for(
        &mut self,
        authority: &str,
        scheme: &str,
        now_epoch_seconds: i64,
    ) -> Result<SecretHeaderBatch, VaultError> {
        if self.consumed {
            return Err(VaultError::HeaderLeaseConsumed);
        }
        self.consumed = true;
        if now_epoch_seconds >= self.expires_at_epoch_seconds {
            return Err(VaultError::LeaseExpired);
        }
        if normalize_host(authority)? != self.authority || normalize_scheme(scheme)? != self.scheme
        {
            return Err(VaultError::HeaderLeaseBindingMismatch);
        }
        Ok(SecretHeaderBatch {
            lease_fingerprint: self.fingerprint.clone(),
            headers: std::mem::take(&mut self.headers),
            emitted: false,
        })
    }
}

impl fmt::Debug for SecretHeaderLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretHeaderLease")
            .field("lease_id", &self.lease_id)
            .field("session_id", &self.session_id)
            .field("authority", &self.authority)
            .field("scheme", &self.scheme)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("fingerprint", &self.fingerprint)
            .field("header_count", &self.headers.len())
            .field("headers", &"<redacted>")
            .field("consumed", &self.consumed)
            .finish()
    }
}

pub struct SecretHeaderBatch {
    lease_fingerprint: String,
    headers: Vec<MaterializedHeader>,
    emitted: bool,
}

impl SecretHeaderBatch {
    pub fn lease_fingerprint(&self) -> &str {
        &self.lease_fingerprint
    }

    pub fn header_count(&self) -> u64 {
        self.headers.len() as u64
    }

    pub fn contains_name(&self, normalized_name: &str) -> bool {
        self.headers
            .iter()
            .any(|header| header.normalized_name == normalized_name)
    }

    pub fn append_http1(
        &mut self,
        wire: &mut Vec<u8>,
        redacted_wire: &mut Vec<u8>,
    ) -> Result<(), VaultError> {
        if self.emitted {
            return Err(VaultError::HeaderBatchConsumed);
        }
        self.emitted = true;
        for header in &self.headers {
            validate_header_name(&header.wire_name)?;
            validate_header_value(header.value.bytes())?;
            wire.extend_from_slice(header.wire_name.as_bytes());
            wire.extend_from_slice(b": ");
            wire.extend_from_slice(header.value.bytes());
            wire.extend_from_slice(b"\r\n");

            redacted_wire.extend_from_slice(header.wire_name.as_bytes());
            redacted_wire.extend_from_slice(b": <redacted:");
            redacted_wire.extend_from_slice(header.value.bytes().len().to_string().as_bytes());
            redacted_wire.extend_from_slice(b">\r\n");
        }
        Ok(())
    }
}

impl fmt::Debug for SecretHeaderBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretHeaderBatch")
            .field("lease_fingerprint", &self.lease_fingerprint)
            .field("header_count", &self.headers.len())
            .field("headers", &"<redacted>")
            .field("emitted", &self.emitted)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultAuditEvent {
    pub action: String,
    pub outcome: String,
    pub vault_id: String,
    pub handle: Option<String>,
    pub lease_id: Option<String>,
    pub session_id: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: VaultAuditEvent,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct VaultAuditChain {
    genesis_hash: String,
    records: Vec<VaultAuditRecord>,
    tail_hash: String,
}

impl VaultAuditChain {
    fn new(vault_id: &str) -> Self {
        let genesis_hash = lower_hex(&Sha256::digest(format!("nxb-vault:{vault_id}").as_bytes()));
        Self {
            tail_hash: genesis_hash.clone(),
            genesis_hash,
            records: Vec::new(),
        }
    }

    fn append(&mut self, event: VaultAuditEvent) -> Result<(), VaultError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let material = serde_json::to_vec(&(sequence, &previous_hash, &event))
            .map_err(|error| VaultError::AuditSerialization(error.to_string()))?;
        let record_hash = lower_hex(&Sha256::digest(material));
        self.records.push(VaultAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(())
    }

    pub fn records(&self) -> &[VaultAuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), VaultError> {
        let mut previous = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(VaultError::AuditSequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous {
                return Err(VaultError::AuditPreviousHashMismatch {
                    record_index: index,
                });
            }
            let material =
                serde_json::to_vec(&(record.sequence, &record.previous_hash, &record.event))
                    .map_err(|error| VaultError::AuditSerialization(error.to_string()))?;
            let expected = lower_hex(&Sha256::digest(material));
            if record.record_hash != expected {
                return Err(VaultError::AuditRecordHashMismatch {
                    record_index: index,
                });
            }
            previous = expected;
        }
        if self.tail_hash != previous {
            return Err(VaultError::AuditTailMismatch);
        }
        Ok(())
    }
}

pub struct InMemorySecretVault {
    vault_id: String,
    entries: BTreeMap<SecretHandle, SecretEntry>,
    leases: BTreeMap<String, LeaseState>,
    next_secret_id: u64,
    next_lease_id: u64,
    audit: VaultAuditChain,
}

impl fmt::Debug for InMemorySecretVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemorySecretVault")
            .field("vault_id", &self.vault_id)
            .field("secret_count", &self.entries.len())
            .field("lease_count", &self.leases.len())
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl InMemorySecretVault {
    pub fn new(vault_id: impl Into<String>) -> Result<Self, VaultError> {
        let vault_id = vault_id.into();
        validate_identifier(&vault_id, "vault_id")?;
        Ok(Self {
            audit: VaultAuditChain::new(&vault_id),
            vault_id,
            entries: BTreeMap::new(),
            leases: BTreeMap::new(),
            next_secret_id: 1,
            next_lease_id: 1,
        })
    }

    pub fn insert(
        &mut self,
        mut input: SecretInput,
        now_epoch_seconds: i64,
    ) -> Result<SecretHandle, VaultError> {
        validate_secret_input(&input, now_epoch_seconds)?;
        let handle = SecretHandle(format!(
            "{}-secret-{:020}",
            self.vault_id, self.next_secret_id
        ));
        self.next_secret_id = self.next_secret_id.saturating_add(1);
        let delivery_metadata = match &input.delivery {
            SecretDelivery::Cookie(cookie) => SecretDeliveryMetadata::Cookie {
                cookie: cookie.clone(),
            },
            SecretDelivery::Header { name, prefix } => SecretDeliveryMetadata::Header {
                name: name.clone(),
                prefix_bytes: prefix.len() as u64,
            },
        };
        let metadata = SecretMetadata {
            handle: handle.clone(),
            kind: input.kind,
            binding: normalized_binding(&input.binding)?,
            delivery: delivery_metadata,
            created_at_epoch_seconds: now_epoch_seconds,
            expires_at_epoch_seconds: input.expires_at_epoch_seconds,
        };
        let value = SecretValue::new(std::mem::take(&mut input.value));
        self.entries.insert(
            handle.clone(),
            SecretEntry {
                metadata,
                delivery: input.delivery.clone(),
                value,
            },
        );
        if let Err(error) = self.audit.append(VaultAuditEvent {
            action: "secret_inserted".into(),
            outcome: "stored".into(),
            vault_id: self.vault_id.clone(),
            handle: Some(handle.0.clone()),
            lease_id: None,
            session_id: None,
            metadata: BTreeMap::from([("kind".into(), input.kind.code().into())]),
        }) {
            self.entries.remove(&handle);
            return Err(error);
        }
        Ok(handle)
    }

    pub fn metadata(&self, handle: &SecretHandle) -> Result<SecretMetadata, VaultError> {
        self.entries
            .get(handle)
            .map(|entry| entry.metadata.clone())
            .ok_or(VaultError::UnknownSecret)
    }

    pub fn lease(
        &mut self,
        handles: &[SecretHandle],
        context: VaultAccessContext,
        lease_seconds: i64,
        now_epoch_seconds: i64,
    ) -> Result<SecretLease, VaultError> {
        if handles.is_empty() || handles.len() > MAX_SECRET_HANDLES_PER_LEASE {
            return Err(VaultError::InvalidLeaseSize);
        }
        if lease_seconds <= 0 || lease_seconds > MAX_SECRET_LEASE_SECONDS {
            return Err(VaultError::InvalidLeaseDuration);
        }
        let context = normalized_context(&context)?;
        for handle in handles {
            let entry = self.entries.get(handle).ok_or(VaultError::UnknownSecret)?;
            match &entry.delivery {
                SecretDelivery::Cookie(_) => {
                    validate_entry_identity(entry, &context, now_epoch_seconds)?;
                }
                SecretDelivery::Header { .. } => {
                    validate_entry_access(entry, &context, now_epoch_seconds)?;
                }
            }
        }
        let lease_id = format!("{}-lease-{:020}", self.vault_id, self.next_lease_id);
        self.next_lease_id = self.next_lease_id.saturating_add(1);
        let expires_at_epoch_seconds = now_epoch_seconds.saturating_add(lease_seconds);
        self.leases.insert(
            lease_id.clone(),
            LeaseState {
                handles: handles.to_vec(),
                context: context.clone(),
                expires_at_epoch_seconds,
                consumed: false,
                revoked: false,
            },
        );
        self.audit.append(VaultAuditEvent {
            action: "secret_lease_issued".into(),
            outcome: "issued".into(),
            vault_id: self.vault_id.clone(),
            handle: None,
            lease_id: Some(lease_id.clone()),
            session_id: None,
            metadata: BTreeMap::from([
                ("handle_count".into(), handles.len().to_string()),
                ("authority".into(), context.authority.clone()),
                ("scheme".into(), context.scheme.clone()),
                ("expires_at".into(), expires_at_epoch_seconds.to_string()),
            ]),
        })?;
        Ok(SecretLease {
            lease_id,
            context,
            expires_at_epoch_seconds,
            consumed: false,
        })
    }

    pub fn materialize_http_headers(
        &mut self,
        lease: &mut SecretLease,
        session_id: &str,
        request_target: &str,
        now_epoch_seconds: i64,
    ) -> Result<SecretHeaderLease, VaultError> {
        validate_identifier(session_id, "session_id")?;
        validate_request_target(request_target)?;
        if lease.consumed {
            return Err(VaultError::LeaseConsumed);
        }
        lease.consumed = true;
        let state = self
            .leases
            .get(&lease.lease_id)
            .cloned()
            .ok_or(VaultError::UnknownLease)?;
        if state.revoked {
            return Err(VaultError::LeaseRevoked);
        }
        if state.consumed {
            return Err(VaultError::LeaseConsumed);
        }
        if now_epoch_seconds >= state.expires_at_epoch_seconds {
            return Err(VaultError::LeaseExpired);
        }
        if state.context != lease.context {
            return Err(VaultError::LeaseContextMismatch);
        }

        let mut headers = Vec::new();
        let mut cookie_pairs: Vec<(String, SecretValue)> = Vec::new();
        for handle in &state.handles {
            let entry = self.entries.get(handle).ok_or(VaultError::UnknownSecret)?;
            match &entry.delivery {
                SecretDelivery::Cookie(cookie) => {
                    validate_entry_identity(entry, &state.context, now_epoch_seconds)?;
                    let binding = &entry.metadata.binding;
                    if binding.allowed_hosts.contains(&state.context.authority)
                        && binding.allowed_schemes.contains(&state.context.scheme)
                        && cookie_applies(
                            cookie,
                            &state.context,
                            request_target,
                            now_epoch_seconds,
                        )?
                    {
                        cookie_pairs.push((cookie.name.clone(), entry.value.duplicate()));
                    }
                }
                SecretDelivery::Header { name, prefix } => {
                    validate_entry_access(entry, &state.context, now_epoch_seconds)?;
                    let mut value = Vec::with_capacity(prefix.len() + entry.value.bytes().len());
                    value.extend_from_slice(prefix);
                    value.extend_from_slice(entry.value.bytes());
                    validate_header_value(&value)?;
                    headers.push(MaterializedHeader {
                        normalized_name: name.to_ascii_lowercase(),
                        wire_name: name.clone(),
                        value: SecretValue::new(value),
                    });
                }
            }
        }
        if !cookie_pairs.is_empty() {
            let mut combined = Vec::new();
            for (index, (name, value)) in cookie_pairs.iter().enumerate() {
                if index > 0 {
                    combined.extend_from_slice(b"; ");
                }
                combined.extend_from_slice(name.as_bytes());
                combined.push(b'=');
                combined.extend_from_slice(value.bytes());
            }
            headers.push(MaterializedHeader {
                normalized_name: "cookie".into(),
                wire_name: "Cookie".into(),
                value: SecretValue::new(combined),
            });
        }
        let state_mut = self
            .leases
            .get_mut(&lease.lease_id)
            .ok_or(VaultError::UnknownLease)?;
        state_mut.consumed = true;
        let fingerprint = header_lease_fingerprint(
            &lease.lease_id,
            session_id,
            &state.context,
            state.expires_at_epoch_seconds,
            &headers,
        );
        self.audit.append(VaultAuditEvent {
            action: "http_headers_materialized".into(),
            outcome: "materialized".into(),
            vault_id: self.vault_id.clone(),
            handle: None,
            lease_id: Some(lease.lease_id.clone()),
            session_id: Some(session_id.into()),
            metadata: BTreeMap::from([
                ("header_count".into(), headers.len().to_string()),
                ("authority".into(), state.context.authority.clone()),
                ("scheme".into(), state.context.scheme.clone()),
                ("fingerprint".into(), fingerprint.clone()),
            ]),
        })?;
        Ok(SecretHeaderLease {
            lease_id: lease.lease_id.clone(),
            session_id: session_id.into(),
            authority: state.context.authority,
            scheme: state.context.scheme,
            expires_at_epoch_seconds: state.expires_at_epoch_seconds,
            fingerprint,
            headers,
            consumed: false,
        })
    }

    pub fn revoke_secret(&mut self, handle: &SecretHandle) -> Result<(), VaultError> {
        if self.entries.remove(handle).is_none() {
            return Err(VaultError::UnknownSecret);
        }
        for lease in self.leases.values_mut() {
            if lease.handles.contains(handle) {
                lease.revoked = true;
            }
        }
        self.audit.append(VaultAuditEvent {
            action: "secret_revoked".into(),
            outcome: "revoked".into(),
            vault_id: self.vault_id.clone(),
            handle: Some(handle.0.clone()),
            lease_id: None,
            session_id: None,
            metadata: BTreeMap::new(),
        })?;
        Ok(())
    }

    pub fn revoke_lease(&mut self, lease_id: &str) -> Result<(), VaultError> {
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or(VaultError::UnknownLease)?;
        lease.revoked = true;
        self.audit.append(VaultAuditEvent {
            action: "secret_lease_revoked".into(),
            outcome: "revoked".into(),
            vault_id: self.vault_id.clone(),
            handle: None,
            lease_id: Some(lease_id.into()),
            session_id: None,
            metadata: BTreeMap::new(),
        })?;
        Ok(())
    }

    pub fn emergency_purge(&mut self) -> Result<(), VaultError> {
        let secret_count = self.entries.len();
        let lease_count = self.leases.len();
        self.entries.clear();
        self.leases.clear();
        self.audit.append(VaultAuditEvent {
            action: "emergency_purge".into(),
            outcome: "purged".into(),
            vault_id: self.vault_id.clone(),
            handle: None,
            lease_id: None,
            session_id: None,
            metadata: BTreeMap::from([
                ("secret_count".into(), secret_count.to_string()),
                ("lease_count".into(), lease_count.to_string()),
            ]),
        })?;
        Ok(())
    }

    pub fn audit(&self) -> &VaultAuditChain {
        &self.audit
    }

    pub fn secret_count(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("vault identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("secret value size is outside the supported range")]
    InvalidSecretSize,
    #[error("secret binding is invalid: {0}")]
    InvalidBinding(String),
    #[error("secret delivery is invalid: {0}")]
    InvalidDelivery(String),
    #[error("secret is unknown or has been revoked")]
    UnknownSecret,
    #[error("secret is expired")]
    SecretExpired,
    #[error("secret access context does not match its binding")]
    AccessDenied,
    #[error("secret lease size is outside the supported range")]
    InvalidLeaseSize,
    #[error("secret lease duration is outside the supported range")]
    InvalidLeaseDuration,
    #[error("secret lease is unknown")]
    UnknownLease,
    #[error("secret lease has already been consumed")]
    LeaseConsumed,
    #[error("secret lease has expired")]
    LeaseExpired,
    #[error("secret lease has been revoked")]
    LeaseRevoked,
    #[error("secret lease context does not match")]
    LeaseContextMismatch,
    #[error("secret header lease has already been consumed")]
    HeaderLeaseConsumed,
    #[error("secret header lease does not match stream authority")]
    HeaderLeaseBindingMismatch,
    #[error("secret header batch has already been emitted")]
    HeaderBatchConsumed,
    #[error("HTTP header name is invalid")]
    InvalidHeaderName,
    #[error("HTTP header value is invalid")]
    InvalidHeaderValue,
    #[error("request target is invalid for cookie selection")]
    InvalidRequestTarget,
    #[error("vault audit material could not be serialized: {0}")]
    AuditSerialization(String),
    #[error("vault audit sequence mismatch at record {record_index}")]
    AuditSequenceMismatch { record_index: usize },
    #[error("vault audit previous hash mismatch at record {record_index}")]
    AuditPreviousHashMismatch { record_index: usize },
    #[error("vault audit record hash mismatch at record {record_index}")]
    AuditRecordHashMismatch { record_index: usize },
    #[error("vault audit tail hash mismatch")]
    AuditTailMismatch,
}

fn validate_secret_input(input: &SecretInput, now_epoch_seconds: i64) -> Result<(), VaultError> {
    if input.value.is_empty() || input.value.len() > MAX_SECRET_BYTES {
        return Err(VaultError::InvalidSecretSize);
    }
    validate_header_value(&input.value)?;
    normalized_binding(&input.binding)?;
    if input
        .expires_at_epoch_seconds
        .is_some_and(|expires| expires <= now_epoch_seconds)
    {
        return Err(VaultError::SecretExpired);
    }
    match (&input.kind, &input.delivery) {
        (SecretKind::Cookie, SecretDelivery::Cookie(cookie)) => validate_cookie(cookie),
        (SecretKind::Cookie, SecretDelivery::Header { .. }) => Err(VaultError::InvalidDelivery(
            "cookie secrets must use cookie delivery".into(),
        )),
        (_, SecretDelivery::Cookie(_)) => Err(VaultError::InvalidDelivery(
            "non-cookie secrets must use header delivery".into(),
        )),
        (_, SecretDelivery::Header { name, prefix }) => {
            validate_header_name(name)?;
            if is_protocol_managed_header(&name.to_ascii_lowercase()) {
                return Err(VaultError::InvalidDelivery(
                    "framing and authority headers cannot contain secrets".into(),
                ));
            }
            validate_header_value(prefix)
        }
    }
}

fn validate_cookie(cookie: &CookieMetadata) -> Result<(), VaultError> {
    if cookie.name.is_empty()
        || !cookie.name.bytes().all(is_token_byte)
        || cookie.path.is_empty()
        || !cookie.path.starts_with('/')
        || cookie.path.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(VaultError::InvalidDelivery(
            "cookie name or path is invalid".into(),
        ));
    }
    normalize_host(&cookie.domain)?;
    Ok(())
}

fn normalized_binding(binding: &SecretBinding) -> Result<SecretBinding, VaultError> {
    validate_identifier(&binding.run_id, "run_id")?;
    validate_identifier(&binding.worker_id, "worker_id")?;
    validate_identifier(&binding.account_id, "account_id")?;
    validate_identifier(&binding.tenant_id, "tenant_id")?;
    validate_identifier(&binding.role_id, "role_id")?;
    if binding.allowed_hosts.is_empty() || binding.allowed_schemes.is_empty() {
        return Err(VaultError::InvalidBinding(
            "host and scheme sets must not be empty".into(),
        ));
    }
    Ok(SecretBinding {
        run_id: binding.run_id.clone(),
        worker_id: binding.worker_id.clone(),
        account_id: binding.account_id.clone(),
        tenant_id: binding.tenant_id.clone(),
        role_id: binding.role_id.clone(),
        allowed_hosts: binding
            .allowed_hosts
            .iter()
            .map(|host| normalize_host(host))
            .collect::<Result<_, _>>()?,
        allowed_schemes: binding
            .allowed_schemes
            .iter()
            .map(|scheme| normalize_scheme(scheme))
            .collect::<Result<_, _>>()?,
    })
}

fn normalized_context(context: &VaultAccessContext) -> Result<VaultAccessContext, VaultError> {
    validate_identifier(&context.run_id, "run_id")?;
    validate_identifier(&context.worker_id, "worker_id")?;
    validate_identifier(&context.account_id, "account_id")?;
    validate_identifier(&context.tenant_id, "tenant_id")?;
    validate_identifier(&context.role_id, "role_id")?;
    Ok(VaultAccessContext {
        run_id: context.run_id.clone(),
        worker_id: context.worker_id.clone(),
        account_id: context.account_id.clone(),
        tenant_id: context.tenant_id.clone(),
        role_id: context.role_id.clone(),
        authority: normalize_host(&context.authority)?,
        scheme: normalize_scheme(&context.scheme)?,
    })
}

fn validate_entry_identity(
    entry: &SecretEntry,
    context: &VaultAccessContext,
    now_epoch_seconds: i64,
) -> Result<(), VaultError> {
    if entry
        .metadata
        .expires_at_epoch_seconds
        .is_some_and(|expires| now_epoch_seconds >= expires)
    {
        return Err(VaultError::SecretExpired);
    }
    let binding = &entry.metadata.binding;
    if binding.run_id != context.run_id
        || binding.worker_id != context.worker_id
        || binding.account_id != context.account_id
        || binding.tenant_id != context.tenant_id
        || binding.role_id != context.role_id
    {
        return Err(VaultError::AccessDenied);
    }
    Ok(())
}

fn validate_entry_access(
    entry: &SecretEntry,
    context: &VaultAccessContext,
    now_epoch_seconds: i64,
) -> Result<(), VaultError> {
    validate_entry_identity(entry, context, now_epoch_seconds)?;
    let binding = &entry.metadata.binding;
    if !binding.allowed_hosts.contains(&context.authority)
        || !binding.allowed_schemes.contains(&context.scheme)
    {
        return Err(VaultError::AccessDenied);
    }
    Ok(())
}

fn cookie_applies(
    cookie: &CookieMetadata,
    context: &VaultAccessContext,
    request_target: &str,
    now_epoch_seconds: i64,
) -> Result<bool, VaultError> {
    let domain = normalize_host(&cookie.domain)?;
    if !domain_matches(&context.authority, &domain)
        || !cookie_path_matches(request_target, &cookie.path)
        || (cookie.secure && context.scheme != "https")
        || cookie
            .expires_at_epoch_seconds
            .is_some_and(|expires| now_epoch_seconds >= expires)
    {
        return Ok(false);
    }
    Ok(true)
}

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn cookie_path_matches(target: &str, cookie_path: &str) -> bool {
    let request_path = target.split('?').next().unwrap_or(target);
    request_path == cookie_path
        || request_path
            .strip_prefix(cookie_path)
            .is_some_and(|suffix| cookie_path.ends_with('/') || suffix.starts_with('/'))
}

fn validate_request_target(target: &str) -> Result<(), VaultError> {
    if target == "*" {
        return Ok(());
    }
    if target.is_empty()
        || !target.starts_with('/')
        || target.contains('#')
        || target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(VaultError::InvalidRequestTarget);
    }
    Ok(())
}

fn validate_identifier(value: &str, name: &str) -> Result<(), VaultError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(VaultError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

fn normalize_host(host: &str) -> Result<String, VaultError> {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.starts_with('.')
        || normalized.ends_with('.')
        || normalized
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
    {
        return Err(VaultError::InvalidBinding("host is invalid".into()));
    }
    Ok(normalized)
}

fn normalize_scheme(scheme: &str) -> Result<String, VaultError> {
    let normalized = scheme.to_ascii_lowercase();
    if !matches!(normalized.as_str(), "http" | "https") {
        return Err(VaultError::InvalidBinding("scheme is invalid".into()));
    }
    Ok(normalized)
}

fn validate_header_name(name: &str) -> Result<(), VaultError> {
    if name.is_empty() || name.len() > 256 || !name.bytes().all(is_token_byte) {
        return Err(VaultError::InvalidHeaderName);
    }
    Ok(())
}

fn validate_header_value(value: &[u8]) -> Result<(), VaultError> {
    if value
        .iter()
        .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(VaultError::InvalidHeaderValue);
    }
    Ok(())
}

fn is_protocol_managed_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-connection"
            | "expect"
            | "upgrade"
            | "trailer"
            | "te"
    )
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

fn header_lease_fingerprint(
    lease_id: &str,
    session_id: &str,
    context: &VaultAccessContext,
    expires_at_epoch_seconds: i64,
    headers: &[MaterializedHeader],
) -> String {
    let names = headers
        .iter()
        .map(|header| (&header.normalized_name, header.value.bytes().len()))
        .collect::<Vec<_>>();
    let material = serde_json::to_vec(&(
        lease_id,
        session_id,
        context,
        expires_at_epoch_seconds,
        names,
    ))
    .expect("vault lease fingerprint material contains only serializable fields");
    lower_hex(&Sha256::digest(material))
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

    fn binding() -> SecretBinding {
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

    fn context() -> VaultAccessContext {
        VaultAccessContext {
            run_id: "run-1".into(),
            worker_id: "worker-1".into(),
            account_id: "account-a".into(),
            tenant_id: "tenant-a".into(),
            role_id: "admin".into(),
            authority: "app.example.com".into(),
            scheme: "https".into(),
        }
    }

    fn bearer(secret: &[u8]) -> SecretInput {
        SecretInput {
            kind: SecretKind::BearerToken,
            value: secret.to_vec(),
            binding: binding(),
            delivery: SecretDelivery::Header {
                name: "Authorization".into(),
                prefix: b"Bearer ".to_vec(),
            },
            expires_at_epoch_seconds: Some(10_000),
        }
    }

    #[test]
    fn debug_serde_and_audit_do_not_contain_secret_values() {
        let secret = b"highly-sensitive-token";
        let input = bearer(secret);
        assert!(!format!("{input:?}").contains("highly-sensitive-token"));

        let mut vault = InMemorySecretVault::new("fixture-vault").unwrap();
        let handle = vault.insert(input, 100).unwrap();
        assert!(!format!("{vault:?}").contains("highly-sensitive-token"));
        let metadata = serde_json::to_string(&vault.metadata(&handle).unwrap()).unwrap();
        assert!(!metadata.contains("highly-sensitive-token"));
        let audit = serde_json::to_string(vault.audit().records()).unwrap();
        assert!(!audit.contains("highly-sensitive-token"));
    }

    #[test]
    fn exact_account_tenant_worker_host_and_scheme_binding_is_enforced() {
        let mut vault = InMemorySecretVault::new("fixture-vault").unwrap();
        let handle = vault.insert(bearer(b"token"), 100).unwrap();
        let mut wrong = context();
        wrong.tenant_id = "tenant-b".into();
        assert!(matches!(
            vault.lease(&[handle], wrong, 30, 101),
            Err(VaultError::AccessDenied)
        ));
    }

    #[test]
    fn header_lease_and_batch_are_single_use_and_redacted() {
        let mut vault = InMemorySecretVault::new("fixture-vault").unwrap();
        let handle = vault.insert(bearer(b"token-value"), 100).unwrap();
        let mut lease = vault.lease(&[handle], context(), 30, 101).unwrap();
        let mut headers = vault
            .materialize_http_headers(&mut lease, "session-1", "/api/me", 102)
            .unwrap();
        assert!(!format!("{headers:?}").contains("token-value"));
        let mut batch = headers.take_for("app.example.com", "https", 103).unwrap();
        assert!(matches!(
            headers.take_for("app.example.com", "https", 103),
            Err(VaultError::HeaderLeaseConsumed)
        ));
        let mut wire = Vec::new();
        let mut redacted = Vec::new();
        batch.append_http1(&mut wire, &mut redacted).unwrap();
        assert!(String::from_utf8_lossy(&wire).contains("Bearer token-value"));
        assert!(!String::from_utf8_lossy(&redacted).contains("token-value"));
        assert_eq!(
            batch.append_http1(&mut Vec::new(), &mut Vec::new()),
            Err(VaultError::HeaderBatchConsumed)
        );
    }

    #[test]
    fn cookie_path_secure_and_expiry_metadata_are_enforced() {
        let mut vault = InMemorySecretVault::new("fixture-vault").unwrap();
        let handle = vault
            .insert(
                SecretInput {
                    kind: SecretKind::Cookie,
                    value: b"session-value".to_vec(),
                    binding: binding(),
                    delivery: SecretDelivery::Cookie(CookieMetadata {
                        name: "sid".into(),
                        domain: "example.com".into(),
                        path: "/admin".into(),
                        expires_at_epoch_seconds: Some(500),
                        secure: true,
                        http_only: true,
                        same_site: SameSitePolicy::Strict,
                    }),
                    expires_at_epoch_seconds: Some(500),
                },
                100,
            )
            .unwrap();
        let mut lease = vault.lease(&[handle], context(), 30, 101).unwrap();
        let headers = vault
            .materialize_http_headers(&mut lease, "session-1", "/public", 102)
            .unwrap();
        assert_eq!(headers.header_count(), 0);
    }

    #[test]
    fn emergency_purge_drops_all_secret_and_lease_state() {
        let mut vault = InMemorySecretVault::new("fixture-vault").unwrap();
        let handle = vault.insert(bearer(b"token"), 100).unwrap();
        let _lease = vault.lease(&[handle], context(), 30, 101).unwrap();
        vault.emergency_purge().unwrap();
        assert_eq!(vault.secret_count(), 0);
        vault.audit().verify().unwrap();
    }
}
