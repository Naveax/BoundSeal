use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use nxb_vault::{
    CookieMetadata, InMemorySecretVault, SameSitePolicy, SecretBinding, SecretDelivery,
    SecretDeliveryMetadata, SecretHandle, SecretInput, SecretKind, VaultError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const MAX_SET_COOKIE_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_SET_COOKIE_HEADERS: usize = 128;
pub const MAX_COOKIE_NAME_BYTES: usize = 256;
pub const MAX_COOKIE_VALUE_BYTES: usize = 4 * 1024;
pub const MAX_COOKIE_PATH_BYTES: usize = 2 * 1024;
pub const MAX_COOKIE_LIFETIME_SECONDS: i64 = 400 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CookieJarConfig {
    pub maximum_set_cookie_headers: usize,
    pub maximum_cookie_records: usize,
    pub rotation_cookie_names: BTreeSet<String>,
}

impl CookieJarConfig {
    pub fn conservative_default() -> Self {
        Self {
            maximum_set_cookie_headers: 64,
            maximum_cookie_records: 512,
            rotation_cookie_names: [
                "session",
                "sessionid",
                "sid",
                "auth",
                "auth_token",
                "access_token",
                "jwt",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        }
    }

    pub fn validate(mut self) -> Result<Self, CookieJarError> {
        if self.maximum_set_cookie_headers == 0
            || self.maximum_set_cookie_headers > MAX_SET_COOKIE_HEADERS
        {
            return Err(CookieJarError::InvalidConfig(
                "set-cookie header limit is outside the supported range".into(),
            ));
        }
        if self.maximum_cookie_records == 0 || self.maximum_cookie_records > 16_384 {
            return Err(CookieJarError::InvalidConfig(
                "cookie record limit is outside the supported range".into(),
            ));
        }
        self.rotation_cookie_names = self
            .rotation_cookie_names
            .into_iter()
            .map(|name| normalize_rotation_name(&name))
            .collect::<Result<_, _>>()?;
        Ok(self)
    }
}

impl Default for CookieJarConfig {
    fn default() -> Self {
        Self::conservative_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CookieOrigin {
    pub host: String,
    pub scheme: String,
}

impl CookieOrigin {
    pub fn new(authority: &str, scheme: &str) -> Result<Self, CookieJarError> {
        Ok(Self {
            host: normalize_authority_host(authority)?,
            scheme: normalize_scheme(scheme)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CookieKey {
    pub name: String,
    pub domain: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CookieRecord {
    pub key: CookieKey,
    pub handle: SecretHandle,
    pub host_only: bool,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSitePolicy,
    pub expires_at_epoch_seconds: Option<i64>,
    pub value_sha256: Option<String>,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CookieCommit {
    pub transaction_id: String,
    pub generation_before: u64,
    pub generation_after: u64,
    pub inserted: u64,
    pub replaced: u64,
    pub deleted: u64,
    pub ignored_deletions: u64,
    pub superseded_headers: u64,
    pub rotation_detected: bool,
    pub active_handles: Vec<SecretHandle>,
    pub audit_tail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CookieJarAuditEvent {
    pub action: String,
    pub outcome: String,
    pub jar_id: String,
    pub transaction_id: Option<String>,
    pub generation_before: u64,
    pub generation_after: u64,
    pub inserted: u64,
    pub replaced: u64,
    pub deleted: u64,
    pub ignored_deletions: u64,
    pub superseded_headers: u64,
    pub rotation_detected: bool,
    pub origin_host: Option<String>,
    pub origin_scheme: Option<String>,
    pub mutated_key_sha256: Vec<String>,
    pub vault_audit_before: String,
    pub vault_audit_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CookieJarAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: CookieJarAuditEvent,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct CookieJarAuditChain {
    genesis_hash: String,
    records: Vec<CookieJarAuditRecord>,
    tail_hash: String,
}

impl CookieJarAuditChain {
    fn new(jar_id: &str) -> Self {
        let genesis_hash = lower_hex(&Sha256::digest(
            format!("nxb-cookie-jar:{jar_id}").as_bytes(),
        ));
        Self {
            tail_hash: genesis_hash.clone(),
            genesis_hash,
            records: Vec::new(),
        }
    }

    fn append(&mut self, event: CookieJarAuditEvent) -> Result<String, CookieJarError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let material = serde_json::to_vec(&(sequence, &previous_hash, &event))
            .map_err(|error| CookieJarError::AuditSerialization(error.to_string()))?;
        let record_hash = lower_hex(&Sha256::digest(material));
        self.records.push(CookieJarAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash.clone();
        Ok(record_hash)
    }

    pub fn records(&self) -> &[CookieJarAuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), CookieJarError> {
        let mut previous_hash = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(CookieJarError::AuditSequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous_hash {
                return Err(CookieJarError::AuditPreviousHashMismatch {
                    record_index: index,
                });
            }
            let material =
                serde_json::to_vec(&(record.sequence, &record.previous_hash, &record.event))
                    .map_err(|error| CookieJarError::AuditSerialization(error.to_string()))?;
            let expected = lower_hex(&Sha256::digest(material));
            if record.record_hash != expected {
                return Err(CookieJarError::AuditRecordHashMismatch {
                    record_index: index,
                });
            }
            previous_hash = expected;
        }
        if self.tail_hash != previous_hash {
            return Err(CookieJarError::AuditTailMismatch);
        }
        Ok(())
    }
}

pub struct CookieJar {
    jar_id: String,
    config: CookieJarConfig,
    records: BTreeMap<CookieKey, CookieRecord>,
    generation: u64,
    next_transaction_id: u64,
    audit: CookieJarAuditChain,
}

impl fmt::Debug for CookieJar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CookieJar")
            .field("jar_id", &self.jar_id)
            .field("record_count", &self.records.len())
            .field("generation", &self.generation)
            .field("records", &"<opaque secret handles only>")
            .finish()
    }
}

impl CookieJar {
    pub fn new(jar_id: impl Into<String>, config: CookieJarConfig) -> Result<Self, CookieJarError> {
        let jar_id = jar_id.into();
        validate_identifier(&jar_id, "jar_id")?;
        let config = config.validate()?;
        Ok(Self {
            audit: CookieJarAuditChain::new(&jar_id),
            jar_id,
            config,
            records: BTreeMap::new(),
            generation: 1,
            next_transaction_id: 1,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn records(&self) -> &BTreeMap<CookieKey, CookieRecord> {
        &self.records
    }

    pub fn active_handles(&self) -> Vec<SecretHandle> {
        self.records
            .values()
            .map(|record| record.handle.clone())
            .collect()
    }

    pub fn audit(&self) -> &CookieJarAuditChain {
        &self.audit
    }

    pub fn seed_from_vault(
        &mut self,
        handles: &[SecretHandle],
        vault: &InMemorySecretVault,
    ) -> Result<(), CookieJarError> {
        for handle in handles {
            let metadata = vault.metadata(handle)?;
            if metadata.kind != SecretKind::Cookie {
                continue;
            }
            let SecretDeliveryMetadata::Cookie { cookie } = metadata.delivery else {
                return Err(CookieJarError::VaultCookieMetadataMismatch);
            };
            let key = CookieKey {
                name: cookie.name.clone(),
                domain: normalize_host(&cookie.domain)?,
                path: normalize_cookie_path(&cookie.path)?,
            };
            let host_only = metadata.binding.allowed_hosts.len() == 1
                && metadata.binding.allowed_hosts.contains(&key.domain);
            self.records.insert(
                key.clone(),
                CookieRecord {
                    key,
                    handle: handle.clone(),
                    host_only,
                    secure: cookie.secure,
                    http_only: cookie.http_only,
                    same_site: cookie.same_site,
                    expires_at_epoch_seconds: cookie.expires_at_epoch_seconds,
                    value_sha256: None,
                    generation: self.generation,
                },
            );
        }
        if self.records.len() > self.config.maximum_cookie_records {
            return Err(CookieJarError::CookieRecordLimitExceeded);
        }
        Ok(())
    }

    pub fn apply_response(
        &mut self,
        vault: &mut InMemorySecretVault,
        binding: &SecretBinding,
        origin: &CookieOrigin,
        request_target: &str,
        set_cookie_values: &[Vec<u8>],
        now_epoch_seconds: i64,
    ) -> Result<CookieCommit, CookieJarError> {
        if set_cookie_values.len() > self.config.maximum_set_cookie_headers {
            return Err(CookieJarError::SetCookieHeaderLimitExceeded);
        }
        let origin = CookieOrigin::new(&origin.host, &origin.scheme)?;
        validate_request_target(request_target)?;
        validate_binding_identity(binding)?;
        if !binding.allowed_hosts.contains(&origin.host)
            || !binding.allowed_schemes.contains(&origin.scheme)
        {
            return Err(CookieJarError::OriginOutsideBinding);
        }

        let mut mutations = BTreeMap::<CookieKey, CookieMutation>::new();
        let mut superseded_headers = 0u64;
        for header in set_cookie_values {
            let parsed = parse_set_cookie(header, &origin, request_target, now_epoch_seconds)?;
            let key = parsed.key();
            if mutations
                .insert(key, CookieMutation::from_parsed(parsed))
                .is_some()
            {
                superseded_headers = superseded_headers.saturating_add(1);
            }
        }

        let prospective_count = self
            .records
            .len()
            .saturating_add(
                mutations
                    .iter()
                    .filter(|(key, mutation)| mutation.is_set() && !self.records.contains_key(*key))
                    .count(),
            )
            .saturating_sub(
                mutations
                    .iter()
                    .filter(|(key, mutation)| {
                        mutation.is_delete() && self.records.contains_key(*key)
                    })
                    .count(),
            );
        if prospective_count > self.config.maximum_cookie_records {
            return Err(CookieJarError::CookieRecordLimitExceeded);
        }

        for key in mutations.keys() {
            if let Some(existing) = self.records.get(key) {
                vault.metadata(&existing.handle)?;
            }
        }

        let vault_audit_before = vault.audit().tail_hash().to_string();
        let transaction_id = format!(
            "{}-transaction-{:020}",
            self.jar_id, self.next_transaction_id
        );
        self.next_transaction_id = self.next_transaction_id.saturating_add(1);
        let generation_before = self.generation;
        let mut staged = BTreeMap::<CookieKey, CookieRecord>::new();

        for (key, mutation) in &mut mutations {
            let CookieMutation::Set(parsed) = mutation else {
                continue;
            };
            let allowed_hosts = allowed_hosts_for_cookie(binding, &origin, parsed)?;
            let mut allowed_schemes = binding.allowed_schemes.clone();
            if parsed.secure {
                allowed_schemes.retain(|scheme| scheme == "https");
            }
            if allowed_schemes.is_empty() {
                rollback_staged(vault, staged.values())?;
                return Err(CookieJarError::CookieScopeEmpty);
            }
            let input = SecretInput {
                kind: SecretKind::Cookie,
                value: parsed.value.to_vec(),
                binding: SecretBinding {
                    run_id: binding.run_id.clone(),
                    worker_id: binding.worker_id.clone(),
                    account_id: binding.account_id.clone(),
                    tenant_id: binding.tenant_id.clone(),
                    role_id: binding.role_id.clone(),
                    allowed_hosts,
                    allowed_schemes,
                },
                delivery: SecretDelivery::Cookie(CookieMetadata {
                    name: parsed.name.clone(),
                    domain: parsed.domain.clone(),
                    path: parsed.path.clone(),
                    expires_at_epoch_seconds: parsed.expires_at_epoch_seconds,
                    secure: parsed.secure,
                    http_only: parsed.http_only,
                    same_site: parsed.same_site,
                }),
                expires_at_epoch_seconds: parsed.expires_at_epoch_seconds,
            };
            let handle = match vault.insert(input, now_epoch_seconds) {
                Ok(handle) => handle,
                Err(error) => {
                    rollback_staged(vault, staged.values())?;
                    return Err(CookieJarError::Vault(error));
                }
            };
            staged.insert(
                key.clone(),
                CookieRecord {
                    key: key.clone(),
                    handle,
                    host_only: parsed.host_only,
                    secure: parsed.secure,
                    http_only: parsed.http_only,
                    same_site: parsed.same_site,
                    expires_at_epoch_seconds: parsed.expires_at_epoch_seconds,
                    value_sha256: Some(parsed.value_sha256.clone()),
                    generation: generation_before,
                },
            );
        }

        let old_handles = mutations
            .keys()
            .filter_map(|key| self.records.get(key).map(|record| record.handle.clone()))
            .collect::<Vec<_>>();
        for handle in &old_handles {
            if let Err(error) = vault.revoke_secret(handle) {
                rollback_staged(vault, staged.values())?;
                return Err(CookieJarError::CommitInvariant(error.to_string()));
            }
        }

        let mut inserted = 0u64;
        let mut replaced = 0u64;
        let mut deleted = 0u64;
        let mut ignored_deletions = 0u64;
        let mut rotation_detected = false;
        let mut mutated_key_sha256 = Vec::new();

        for (key, mutation) in mutations {
            mutated_key_sha256.push(cookie_key_hash(&key));
            let previous = self.records.remove(&key);
            match mutation {
                CookieMutation::Delete => {
                    if previous.is_some() {
                        deleted = deleted.saturating_add(1);
                        rotation_detected = true;
                    } else {
                        ignored_deletions = ignored_deletions.saturating_add(1);
                    }
                }
                CookieMutation::Set(parsed) => {
                    let mut record = staged.remove(&key).ok_or_else(|| {
                        CookieJarError::CommitInvariant("staged cookie missing".into())
                    })?;
                    if let Some(previous) = previous {
                        replaced = replaced.saturating_add(1);
                        if previous.value_sha256.as_deref() != Some(parsed.value_sha256.as_str()) {
                            rotation_detected = true;
                        }
                    } else {
                        inserted = inserted.saturating_add(1);
                        if self
                            .config
                            .rotation_cookie_names
                            .contains(&parsed.name.to_ascii_lowercase())
                        {
                            rotation_detected = true;
                        }
                    }
                    record.generation = if rotation_detected {
                        generation_before.saturating_add(1)
                    } else {
                        generation_before
                    };
                    self.records.insert(key, record);
                }
            }
        }

        if rotation_detected {
            self.generation = self.generation.saturating_add(1);
            for record in self.records.values_mut() {
                record.generation = self.generation;
            }
        }
        let generation_after = self.generation;
        let vault_audit_after = vault.audit().tail_hash().to_string();
        let audit_tail = self.audit.append(CookieJarAuditEvent {
            action: "set_cookie_transaction".into(),
            outcome: "committed".into(),
            jar_id: self.jar_id.clone(),
            transaction_id: Some(transaction_id.clone()),
            generation_before,
            generation_after,
            inserted,
            replaced,
            deleted,
            ignored_deletions,
            superseded_headers,
            rotation_detected,
            origin_host: Some(origin.host),
            origin_scheme: Some(origin.scheme),
            mutated_key_sha256,
            vault_audit_before,
            vault_audit_after,
        })?;
        let active_handles = self.active_handles();
        Ok(CookieCommit {
            transaction_id,
            generation_before,
            generation_after,
            inserted,
            replaced,
            deleted,
            ignored_deletions,
            superseded_headers,
            rotation_detected,
            active_handles,
            audit_tail,
        })
    }

    pub fn purge(
        &mut self,
        vault: &mut InMemorySecretVault,
        reason: &str,
    ) -> Result<CookieCommit, CookieJarError> {
        validate_identifier(reason, "reason")?;
        let vault_audit_before = vault.audit().tail_hash().to_string();
        let generation_before = self.generation;
        let records = std::mem::take(&mut self.records);
        for record in records.values() {
            vault.revoke_secret(&record.handle)?;
        }
        let deleted = records.len() as u64;
        if deleted > 0 {
            self.generation = self.generation.saturating_add(1);
        }
        let transaction_id = format!(
            "{}-transaction-{:020}",
            self.jar_id, self.next_transaction_id
        );
        self.next_transaction_id = self.next_transaction_id.saturating_add(1);
        let vault_audit_after = vault.audit().tail_hash().to_string();
        let audit_tail = self.audit.append(CookieJarAuditEvent {
            action: "cookie_jar_purge".into(),
            outcome: reason.into(),
            jar_id: self.jar_id.clone(),
            transaction_id: Some(transaction_id.clone()),
            generation_before,
            generation_after: self.generation,
            inserted: 0,
            replaced: 0,
            deleted,
            ignored_deletions: 0,
            superseded_headers: 0,
            rotation_detected: deleted > 0,
            origin_host: None,
            origin_scheme: None,
            mutated_key_sha256: records.keys().map(cookie_key_hash).collect(),
            vault_audit_before,
            vault_audit_after,
        })?;
        Ok(CookieCommit {
            transaction_id,
            generation_before,
            generation_after: self.generation,
            inserted: 0,
            replaced: 0,
            deleted,
            ignored_deletions: 0,
            superseded_headers: 0,
            rotation_detected: deleted > 0,
            active_handles: Vec::new(),
            audit_tail,
        })
    }
}

struct ParsedSetCookie {
    name: String,
    value: Zeroizing<Vec<u8>>,
    domain: String,
    path: String,
    host_only: bool,
    expires_at_epoch_seconds: Option<i64>,
    secure: bool,
    http_only: bool,
    same_site: SameSitePolicy,
    delete: bool,
    value_sha256: String,
}

impl fmt::Debug for ParsedSetCookie {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedSetCookie")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("value_bytes", &self.value.len())
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("host_only", &self.host_only)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .field("delete", &self.delete)
            .field("value_sha256", &self.value_sha256)
            .finish()
    }
}

impl ParsedSetCookie {
    fn key(&self) -> CookieKey {
        CookieKey {
            name: self.name.clone(),
            domain: self.domain.clone(),
            path: self.path.clone(),
        }
    }
}

enum CookieMutation {
    Set(ParsedSetCookie),
    Delete,
}

impl CookieMutation {
    fn from_parsed(parsed: ParsedSetCookie) -> Self {
        if parsed.delete {
            Self::Delete
        } else {
            Self::Set(parsed)
        }
    }

    fn is_set(&self) -> bool {
        matches!(self, Self::Set(_))
    }

    fn is_delete(&self) -> bool {
        matches!(self, Self::Delete)
    }
}

fn parse_set_cookie(
    header: &[u8],
    origin: &CookieOrigin,
    request_target: &str,
    now_epoch_seconds: i64,
) -> Result<ParsedSetCookie, CookieJarError> {
    if header.is_empty() || header.len() > MAX_SET_COOKIE_HEADER_BYTES {
        return Err(CookieJarError::InvalidSetCookie(
            "header size is outside the supported range".into(),
        ));
    }
    if header
        .iter()
        .any(|byte| *byte == b'\r' || *byte == b'\n' || *byte == 0)
    {
        return Err(CookieJarError::InvalidSetCookie(
            "header contains a prohibited control byte".into(),
        ));
    }
    let mut segments = header.split(|byte| *byte == b';');
    let pair = trim_ascii(segments.next().unwrap_or_default());
    let equals = pair.iter().position(|byte| *byte == b'=').ok_or_else(|| {
        CookieJarError::InvalidSetCookie("cookie pair does not contain '='".into())
    })?;
    let name_bytes = trim_ascii(&pair[..equals]);
    let value_bytes = trim_ascii(&pair[equals + 1..]);
    let name = std::str::from_utf8(name_bytes)
        .map_err(|_| CookieJarError::InvalidSetCookie("cookie name is not ASCII".into()))?
        .to_string();
    validate_cookie_name(&name)?;
    validate_cookie_value(value_bytes)?;

    let mut seen = BTreeSet::new();
    let mut domain_attribute: Option<String> = None;
    let mut path_attribute: Option<String> = None;
    let mut max_age: Option<i64> = None;
    let mut expires: Option<i64> = None;
    let mut secure = false;
    let mut http_only = false;
    let mut same_site = SameSitePolicy::Unspecified;

    for raw_segment in segments {
        let segment = trim_ascii(raw_segment);
        if segment.is_empty() {
            return Err(CookieJarError::InvalidSetCookie(
                "empty attribute segment is prohibited".into(),
            ));
        }
        let (raw_name, raw_value) = match segment.iter().position(|byte| *byte == b'=') {
            Some(index) => (&segment[..index], Some(trim_ascii(&segment[index + 1..]))),
            None => (segment, None),
        };
        let attribute_name = std::str::from_utf8(trim_ascii(raw_name))
            .map_err(|_| CookieJarError::InvalidSetCookie("attribute name is not ASCII".into()))?
            .to_ascii_lowercase();
        if !seen.insert(attribute_name.clone()) {
            return Err(CookieJarError::InvalidSetCookie(format!(
                "duplicate attribute: {attribute_name}"
            )));
        }
        match attribute_name.as_str() {
            "domain" => {
                let value = required_attribute_value(raw_value, "domain")?;
                domain_attribute = Some(normalize_domain_attribute(value)?);
            }
            "path" => {
                let value = required_attribute_value(raw_value, "path")?;
                let text = std::str::from_utf8(value).map_err(|_| {
                    CookieJarError::InvalidSetCookie("path is not valid UTF-8".into())
                })?;
                path_attribute = Some(normalize_cookie_path(text)?);
            }
            "max-age" => {
                let value = required_attribute_value(raw_value, "max-age")?;
                max_age = Some(parse_max_age(value)?);
            }
            "expires" => {
                let value = required_attribute_value(raw_value, "expires")?;
                let text = std::str::from_utf8(value).map_err(|_| {
                    CookieJarError::InvalidSetCookie("expires is not valid ASCII".into())
                })?;
                let parsed = httpdate::parse_http_date(text).map_err(|_| {
                    CookieJarError::InvalidSetCookie("expires is not a valid HTTP date".into())
                })?;
                expires = Some(system_time_to_epoch(parsed));
            }
            "secure" => {
                if raw_value.is_some() {
                    return Err(CookieJarError::InvalidSetCookie(
                        "Secure must not have a value".into(),
                    ));
                }
                secure = true;
            }
            "httponly" => {
                if raw_value.is_some() {
                    return Err(CookieJarError::InvalidSetCookie(
                        "HttpOnly must not have a value".into(),
                    ));
                }
                http_only = true;
            }
            "samesite" => {
                let value = required_attribute_value(raw_value, "samesite")?;
                let text = std::str::from_utf8(value)
                    .map_err(|_| CookieJarError::InvalidSetCookie("SameSite is invalid".into()))?;
                same_site = match text.to_ascii_lowercase().as_str() {
                    "strict" => SameSitePolicy::Strict,
                    "lax" => SameSitePolicy::Lax,
                    "none" => SameSitePolicy::None,
                    _ => {
                        return Err(CookieJarError::InvalidSetCookie(
                            "SameSite value is unsupported".into(),
                        ))
                    }
                };
            }
            _ => {
                return Err(CookieJarError::InvalidSetCookie(format!(
                    "unsupported attribute: {attribute_name}"
                )))
            }
        }
    }

    if secure && origin.scheme != "https" {
        return Err(CookieJarError::SecureCookieOverInsecureOrigin);
    }
    if same_site == SameSitePolicy::None && !secure {
        return Err(CookieJarError::SameSiteNoneWithoutSecure);
    }

    let (domain, host_only) = if let Some(domain) = domain_attribute {
        if origin.host.parse::<IpAddr>().is_ok() || domain.parse::<IpAddr>().is_ok() {
            return Err(CookieJarError::DomainAttributeOnIpOrigin);
        }
        if is_public_suffix_like(&domain) {
            return Err(CookieJarError::PublicSuffixLikeDomain);
        }
        if !domain_matches(&origin.host, &domain) {
            return Err(CookieJarError::DomainOutsideOrigin);
        }
        (domain, false)
    } else {
        (origin.host.clone(), true)
    };
    let path = path_attribute.unwrap_or_else(|| default_cookie_path(request_target));

    if name.starts_with("__Secure-") && (!secure || origin.scheme != "https") {
        return Err(CookieJarError::SecurePrefixViolation);
    }
    if name.starts_with("__Host-")
        && (!secure || origin.scheme != "https" || !host_only || path != "/")
    {
        return Err(CookieJarError::HostPrefixViolation);
    }

    let (expires_at_epoch_seconds, delete) = if let Some(max_age) = max_age {
        if max_age <= 0 {
            (Some(now_epoch_seconds), true)
        } else {
            let bounded = max_age.min(MAX_COOKIE_LIFETIME_SECONDS);
            (Some(now_epoch_seconds.saturating_add(bounded)), false)
        }
    } else if let Some(expires) = expires {
        (Some(expires), expires <= now_epoch_seconds)
    } else {
        (None, false)
    };

    Ok(ParsedSetCookie {
        name,
        value: Zeroizing::new(value_bytes.to_vec()),
        domain,
        path,
        host_only,
        expires_at_epoch_seconds,
        secure,
        http_only,
        same_site,
        delete,
        value_sha256: lower_hex(&Sha256::digest(value_bytes)),
    })
}

fn required_attribute_value<'a>(
    value: Option<&'a [u8]>,
    name: &str,
) -> Result<&'a [u8], CookieJarError> {
    let value = value
        .ok_or_else(|| CookieJarError::InvalidSetCookie(format!("{name} requires a value")))?;
    if value.is_empty() {
        return Err(CookieJarError::InvalidSetCookie(format!(
            "{name} value is empty"
        )));
    }
    Ok(value)
}

fn parse_max_age(value: &[u8]) -> Result<i64, CookieJarError> {
    let text = std::str::from_utf8(value)
        .map_err(|_| CookieJarError::InvalidSetCookie("Max-Age is not ASCII".into()))?;
    if text.starts_with('+')
        || text.is_empty()
        || !text
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_digit() || (index == 0 && byte == b'-'))
    {
        return Err(CookieJarError::InvalidSetCookie(
            "Max-Age is not a strict decimal integer".into(),
        ));
    }
    text.parse::<i64>()
        .map_err(|_| CookieJarError::InvalidSetCookie("Max-Age is out of range".into()))
}

fn allowed_hosts_for_cookie(
    binding: &SecretBinding,
    origin: &CookieOrigin,
    cookie: &ParsedSetCookie,
) -> Result<BTreeSet<String>, CookieJarError> {
    let allowed_hosts: BTreeSet<String> = if cookie.host_only {
        [origin.host.clone()].into_iter().collect()
    } else {
        binding
            .allowed_hosts
            .iter()
            .filter(|host| domain_matches(host, &cookie.domain))
            .cloned()
            .collect()
    };
    if allowed_hosts.is_empty() {
        return Err(CookieJarError::CookieScopeEmpty);
    }
    Ok(allowed_hosts)
}

fn rollback_staged<'a>(
    vault: &mut InMemorySecretVault,
    records: impl IntoIterator<Item = &'a CookieRecord>,
) -> Result<(), CookieJarError> {
    for record in records {
        vault
            .revoke_secret(&record.handle)
            .map_err(|error| CookieJarError::RollbackFailed(error.to_string()))?;
    }
    Ok(())
}

fn validate_binding_identity(binding: &SecretBinding) -> Result<(), CookieJarError> {
    validate_identifier(&binding.run_id, "run_id")?;
    validate_identifier(&binding.worker_id, "worker_id")?;
    validate_identifier(&binding.account_id, "account_id")?;
    validate_identifier(&binding.tenant_id, "tenant_id")?;
    validate_identifier(&binding.role_id, "role_id")?;
    if binding.allowed_hosts.is_empty() || binding.allowed_schemes.is_empty() {
        return Err(CookieJarError::OriginOutsideBinding);
    }
    Ok(())
}

fn validate_identifier(value: &str, name: &str) -> Result<(), CookieJarError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(CookieJarError::InvalidIdentifier(name.into()));
    }
    Ok(())
}

fn validate_cookie_name(name: &str) -> Result<(), CookieJarError> {
    if name.is_empty() || name.len() > MAX_COOKIE_NAME_BYTES || !name.bytes().all(is_token_byte) {
        return Err(CookieJarError::InvalidSetCookie(
            "cookie name is not a bounded token".into(),
        ));
    }
    Ok(())
}

fn validate_cookie_value(value: &[u8]) -> Result<(), CookieJarError> {
    if value.len() > MAX_COOKIE_VALUE_BYTES
        || !value.iter().all(|byte| {
            matches!(
                byte,
                0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E
            )
        })
    {
        return Err(CookieJarError::InvalidSetCookie(
            "cookie value contains unsupported bytes".into(),
        ));
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

fn normalize_rotation_name(value: &str) -> Result<String, CookieJarError> {
    validate_cookie_name(value)?;
    Ok(value.to_ascii_lowercase())
}

fn normalize_authority_host(authority: &str) -> Result<String, CookieJarError> {
    let authority = authority.trim();
    if authority.is_empty()
        || authority.contains('@')
        || authority.contains('/')
        || authority.contains('\\')
    {
        return Err(CookieJarError::InvalidOrigin);
    }
    let host = if let Some(rest) = authority.strip_prefix('[') {
        let closing = rest.find(']').ok_or(CookieJarError::InvalidOrigin)?;
        let host = &rest[..closing];
        let suffix = &rest[closing + 1..];
        if !suffix.is_empty()
            && (!suffix.starts_with(':')
                || suffix[1..].is_empty()
                || !suffix[1..].bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(CookieJarError::InvalidOrigin);
        }
        host
    } else if authority.matches(':').count() == 1 {
        let (candidate, port) = authority.rsplit_once(':').unwrap_or((authority, ""));
        if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) {
            candidate
        } else {
            authority
        }
    } else {
        authority
    };
    normalize_host(host)
}

fn normalize_host(host: &str) -> Result<String, CookieJarError> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.starts_with('.')
        || normalized.ends_with('.')
        || normalized.contains("..")
        || normalized
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(CookieJarError::InvalidOrigin);
    }
    Ok(normalized)
}

fn normalize_domain_attribute(value: &[u8]) -> Result<String, CookieJarError> {
    let text = std::str::from_utf8(value)
        .map_err(|_| CookieJarError::InvalidSetCookie("domain is not ASCII".into()))?;
    let text = text.trim().trim_start_matches('.');
    if text.ends_with('.') {
        return Err(CookieJarError::InvalidSetCookie(
            "domain must not have a trailing dot".into(),
        ));
    }
    normalize_host(text)
}

fn normalize_cookie_path(path: &str) -> Result<String, CookieJarError> {
    if path.is_empty()
        || !path.starts_with('/')
        || path.len() > MAX_COOKIE_PATH_BYTES
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b';')
    {
        return Err(CookieJarError::InvalidSetCookie(
            "cookie path is invalid".into(),
        ));
    }
    Ok(path.to_string())
}

fn normalize_scheme(scheme: &str) -> Result<String, CookieJarError> {
    let normalized = scheme.trim().to_ascii_lowercase();
    if !matches!(normalized.as_str(), "http" | "https") {
        return Err(CookieJarError::InvalidOrigin);
    }
    Ok(normalized)
}

fn validate_request_target(target: &str) -> Result<(), CookieJarError> {
    if target.is_empty()
        || target.len() > 8 * 1024
        || !target.starts_with('/')
        || target.contains('#')
        || target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(CookieJarError::InvalidRequestTarget);
    }
    Ok(())
}

fn default_cookie_path(request_target: &str) -> String {
    let path = request_target.split('?').next().unwrap_or("/");
    if !path.starts_with('/') || path == "/" {
        return "/".into();
    }
    match path.rfind('/') {
        Some(0) | None => "/".into(),
        Some(index) => path[..index].to_string(),
    }
}

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn is_public_suffix_like(domain: &str) -> bool {
    const DENIED: &[&str] = &[
        "com", "net", "org", "edu", "gov", "mil", "int", "io", "dev", "app", "co.uk", "org.uk",
        "ac.uk", "gov.uk", "com.tr", "org.tr", "net.tr", "gen.tr", "biz.tr", "info.tr", "web.tr",
        "com.au", "net.au", "org.au", "co.jp", "ne.jp", "co.nz",
    ];
    !domain.contains('.') || DENIED.contains(&domain)
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn system_time_to_epoch(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(error) => -i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

fn cookie_key_hash(key: &CookieKey) -> String {
    lower_hex(&Sha256::digest(
        serde_json::to_vec(key).expect("cookie keys are always serializable"),
    ))
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CookieJarError {
    #[error("cookie jar configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("cookie jar identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("cookie origin is invalid")]
    InvalidOrigin,
    #[error("request target is invalid")]
    InvalidRequestTarget,
    #[error("Set-Cookie header limit was exceeded")]
    SetCookieHeaderLimitExceeded,
    #[error("cookie record limit was exceeded")]
    CookieRecordLimitExceeded,
    #[error("Set-Cookie header is invalid: {0}")]
    InvalidSetCookie(String),
    #[error("cookie Domain attribute is outside the response origin")]
    DomainOutsideOrigin,
    #[error("cookie Domain attribute resembles a public suffix")]
    PublicSuffixLikeDomain,
    #[error("cookie Domain attribute is prohibited for IP origins")]
    DomainAttributeOnIpOrigin,
    #[error("Secure cookie was received from an insecure origin")]
    SecureCookieOverInsecureOrigin,
    #[error("SameSite=None requires Secure")]
    SameSiteNoneWithoutSecure,
    #[error("__Secure- cookie prefix requirements were not met")]
    SecurePrefixViolation,
    #[error("__Host- cookie prefix requirements were not met")]
    HostPrefixViolation,
    #[error("response origin is outside the session binding")]
    OriginOutsideBinding,
    #[error("cookie scope became empty after binding intersection")]
    CookieScopeEmpty,
    #[error("vault cookie metadata does not match cookie secret kind")]
    VaultCookieMetadataMismatch,
    #[error("cookie transaction rollback failed: {0}")]
    RollbackFailed(String),
    #[error("cookie transaction invariant failed: {0}")]
    CommitInvariant(String),
    #[error("cookie audit serialization failed: {0}")]
    AuditSerialization(String),
    #[error("cookie audit sequence mismatch at record {record_index}")]
    AuditSequenceMismatch { record_index: usize },
    #[error("cookie audit previous-hash mismatch at record {record_index}")]
    AuditPreviousHashMismatch { record_index: usize },
    #[error("cookie audit record-hash mismatch at record {record_index}")]
    AuditRecordHashMismatch { record_index: usize },
    #[error("cookie audit tail hash mismatch")]
    AuditTailMismatch,
    #[error("vault operation failed: {0}")]
    Vault(#[from] VaultError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> SecretBinding {
        SecretBinding {
            run_id: "run-1".into(),
            worker_id: "worker-1".into(),
            account_id: "account-1".into(),
            tenant_id: "tenant-1".into(),
            role_id: "role-1".into(),
            allowed_hosts: ["app.example.com", "api.example.com"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            allowed_schemes: ["https"].into_iter().map(str::to_string).collect(),
        }
    }

    fn origin() -> CookieOrigin {
        CookieOrigin::new("app.example.com:443", "https").unwrap()
    }

    #[test]
    fn host_prefix_requires_secure_host_only_root_path() {
        let error = parse_set_cookie(
            b"__Host-session=value; Secure; Domain=example.com; Path=/",
            &origin(),
            "/login",
            100,
        )
        .unwrap_err();
        assert_eq!(error, CookieJarError::HostPrefixViolation);
    }

    #[test]
    fn max_age_takes_precedence_over_future_expires_for_deletion() {
        let parsed = parse_set_cookie(
            b"session=gone; Max-Age=0; Expires=Wed, 21 Oct 2099 07:28:00 GMT; Secure; Path=/",
            &origin(),
            "/logout",
            100,
        )
        .unwrap();
        assert!(parsed.delete);
        assert_eq!(parsed.expires_at_epoch_seconds, Some(100));
    }

    #[test]
    fn rejects_public_suffix_like_domain() {
        let error = parse_set_cookie(
            b"session=value; Domain=com; Secure; Path=/",
            &origin(),
            "/",
            100,
        )
        .unwrap_err();
        assert_eq!(error, CookieJarError::PublicSuffixLikeDomain);
    }

    #[test]
    fn transaction_replaces_cookie_and_rotates_generation() {
        let mut vault = InMemorySecretVault::new("vault-cookie").unwrap();
        let mut jar = CookieJar::new("jar-1", CookieJarConfig::default()).unwrap();
        let first = jar
            .apply_response(
                &mut vault,
                &binding(),
                &origin(),
                "/login",
                &[b"session=first; Secure; HttpOnly; Path=/".to_vec()],
                100,
            )
            .unwrap();
        assert!(first.rotation_detected);
        assert_eq!(first.generation_after, 2);
        let first_handle = first.active_handles[0].clone();

        let second = jar
            .apply_response(
                &mut vault,
                &binding(),
                &origin(),
                "/login",
                &[b"session=second; Secure; HttpOnly; Path=/".to_vec()],
                101,
            )
            .unwrap();
        assert_eq!(second.replaced, 1);
        assert_eq!(second.generation_after, 3);
        assert!(matches!(
            vault.metadata(&first_handle),
            Err(VaultError::UnknownSecret)
        ));
    }

    #[test]
    fn last_header_for_same_key_wins_without_partial_state() {
        let mut vault = InMemorySecretVault::new("vault-cookie").unwrap();
        let mut jar = CookieJar::new("jar-1", CookieJarConfig::default()).unwrap();
        let commit = jar
            .apply_response(
                &mut vault,
                &binding(),
                &origin(),
                "/",
                &[
                    b"session=first; Secure; Path=/".to_vec(),
                    b"session=second; Secure; Path=/".to_vec(),
                ],
                100,
            )
            .unwrap();
        assert_eq!(commit.superseded_headers, 1);
        assert_eq!(commit.inserted, 1);
        assert_eq!(jar.records().len(), 1);
        assert_eq!(vault.secret_count(), 1);
    }

    #[test]
    fn host_only_cookie_is_bound_only_to_origin_host() {
        let mut vault = InMemorySecretVault::new("vault-cookie").unwrap();
        let mut jar = CookieJar::new("jar-1", CookieJarConfig::default()).unwrap();
        let commit = jar
            .apply_response(
                &mut vault,
                &binding(),
                &origin(),
                "/",
                &[b"pref=value; Secure; Path=/".to_vec()],
                100,
            )
            .unwrap();
        let metadata = vault.metadata(&commit.active_handles[0]).unwrap();
        assert_eq!(
            metadata.binding.allowed_hosts,
            ["app.example.com"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
    }

    #[test]
    fn audit_never_contains_cookie_value() {
        let secret = "highly-sensitive-cookie-value";
        let mut vault = InMemorySecretVault::new("vault-cookie").unwrap();
        let mut jar = CookieJar::new("jar-1", CookieJarConfig::default()).unwrap();
        jar.apply_response(
            &mut vault,
            &binding(),
            &origin(),
            "/",
            &[format!("session={secret}; Secure; HttpOnly; Path=/").into_bytes()],
            100,
        )
        .unwrap();
        let jar_audit = serde_json::to_string(jar.audit().records()).unwrap();
        let vault_audit = serde_json::to_string(vault.audit().records()).unwrap();
        assert!(!jar_audit.contains(secret));
        assert!(!vault_audit.contains(secret));
        jar.audit().verify().unwrap();
        vault.audit().verify().unwrap();
    }

    #[test]
    fn deletion_revokes_cookie_and_advances_generation() {
        let mut vault = InMemorySecretVault::new("vault-cookie").unwrap();
        let mut jar = CookieJar::new("jar-1", CookieJarConfig::default()).unwrap();
        jar.apply_response(
            &mut vault,
            &binding(),
            &origin(),
            "/",
            &[b"session=value; Secure; Path=/".to_vec()],
            100,
        )
        .unwrap();
        let commit = jar
            .apply_response(
                &mut vault,
                &binding(),
                &origin(),
                "/logout",
                &[b"session=; Max-Age=0; Secure; Path=/".to_vec()],
                101,
            )
            .unwrap();
        assert_eq!(commit.deleted, 1);
        assert!(commit.active_handles.is_empty());
        assert_eq!(vault.secret_count(), 0);
        assert_eq!(commit.generation_after, 3);
    }
}
