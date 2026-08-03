use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use nxb_content_analysis::{
    extract_structured, ContentClassification, ContentTypeAssessment, DiscoveryDisposition,
    DiscoveryGraph, ExtractionLimits,
};
use nxb_passive_analyzers::{Confidence, Finding, Severity};
use nxb_policy::CompiledPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub const OPERATOR_SCHEMA_VERSION: u32 = 1;
pub const REPORT_SCHEMA_VERSION: u32 = 1;
pub const MAX_OPERATOR_DEPTH: u16 = 8;
pub const MAX_OPERATOR_ENDPOINTS: u64 = 10_000;
pub const MAX_OPERATOR_REQUESTS: u64 = 10_000;
pub const MAX_OPERATOR_BODY_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_OPERATOR_FINDINGS: usize = 10_000;
pub const MAX_OPERATOR_UNTESTED_AREAS: usize = 10_000;

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

#[derive(Debug, Error)]
pub enum OperatorError {
    #[error("operator configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("target URL is invalid or outside the safe operator boundary: {0}")]
    InvalidTarget(String),
    #[error("session manifest is invalid: {0}")]
    InvalidSession(String),
    #[error("discovery input is invalid: {0}")]
    InvalidDiscovery(String),
    #[error("probe authorization was denied: {0}")]
    ProbeDenied(String),
    #[error("report input is invalid or contains secret-like material: {0}")]
    InvalidReport(String),
    #[error("operator serialization failed: {0}")]
    Serialization(String),
    #[error("operator filesystem operation failed: {0}")]
    Filesystem(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    SecurityHeaders,
    CookieFlags,
    Cors,
    CachePolicy,
    RedirectSafety,
    TlsMetadata,
    RateLimitObservation,
    ReflectionValidation,
    AuthorizationDifferential,
}

impl ProbeKind {
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::RateLimitObservation
                | Self::ReflectionValidation
                | Self::AuthorizationDifferential
        )
    }

    pub fn default_request_cost(self) -> u64 {
        match self {
            Self::SecurityHeaders
            | Self::CookieFlags
            | Self::Cors
            | Self::CachePolicy
            | Self::RedirectSafety
            | Self::TlsMetadata => 0,
            Self::RateLimitObservation => 2,
            Self::ReflectionValidation | Self::AuthorizationDifferential => 2,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_depth() -> u16 {
    2
}

fn default_max_endpoints() -> u64 {
    256
}

fn default_max_requests() -> u64 {
    128
}

fn default_max_body_bytes() -> u64 {
    2 * 1024 * 1024
}

fn default_probe_capabilities() -> BTreeSet<ProbeKind> {
    BTreeSet::from([
        ProbeKind::SecurityHeaders,
        ProbeKind::CookieFlags,
        ProbeKind::Cors,
        ProbeKind::CachePolicy,
        ProbeKind::RedirectSafety,
        ProbeKind::TlsMetadata,
    ])
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorConfig {
    #[serde(default = "operator_schema_version")]
    pub schema_version: u32,
    #[serde(default = "default_true")]
    pub passive_only: bool,
    #[serde(default = "default_max_depth")]
    pub maximum_depth: u16,
    #[serde(default = "default_max_endpoints")]
    pub maximum_endpoints: u64,
    #[serde(default = "default_max_requests")]
    pub maximum_requests: u64,
    #[serde(default = "default_max_body_bytes")]
    pub maximum_body_bytes: u64,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default)]
    pub allow_session_mutation: bool,
    #[serde(default = "default_probe_capabilities")]
    pub probe_capabilities: BTreeSet<ProbeKind>,
}

fn operator_schema_version() -> u32 {
    OPERATOR_SCHEMA_VERSION
}

impl Default for OperatorConfig {
    fn default() -> Self {
        Self {
            schema_version: OPERATOR_SCHEMA_VERSION,
            passive_only: true,
            maximum_depth: default_max_depth(),
            maximum_endpoints: default_max_endpoints(),
            maximum_requests: default_max_requests(),
            maximum_body_bytes: default_max_body_bytes(),
            follow_redirects: false,
            allow_session_mutation: false,
            probe_capabilities: default_probe_capabilities(),
        }
    }
}

impl OperatorConfig {
    pub fn validate(&self) -> Result<(), OperatorError> {
        if self.schema_version != OPERATOR_SCHEMA_VERSION {
            return Err(OperatorError::InvalidConfig(format!(
                "unsupported schema_version {}; expected {OPERATOR_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.maximum_depth > MAX_OPERATOR_DEPTH {
            return Err(OperatorError::InvalidConfig(format!(
                "maximum_depth must be at most {MAX_OPERATOR_DEPTH}"
            )));
        }
        if self.maximum_endpoints == 0 || self.maximum_endpoints > MAX_OPERATOR_ENDPOINTS {
            return Err(OperatorError::InvalidConfig(format!(
                "maximum_endpoints must be between 1 and {MAX_OPERATOR_ENDPOINTS}"
            )));
        }
        if self.maximum_requests == 0
            || self.maximum_requests > MAX_OPERATOR_REQUESTS
            || self.maximum_requests > self.maximum_endpoints
        {
            return Err(OperatorError::InvalidConfig(
                "maximum_requests must be non-zero and no greater than maximum_endpoints".into(),
            ));
        }
        if self.maximum_body_bytes == 0 || self.maximum_body_bytes > MAX_OPERATOR_BODY_BYTES {
            return Err(OperatorError::InvalidConfig(format!(
                "maximum_body_bytes must be between 1 and {MAX_OPERATOR_BODY_BYTES}"
            )));
        }
        if self.follow_redirects {
            return Err(OperatorError::InvalidConfig(
                "redirect following is hard-disabled; redirects must be re-authorized".into(),
            ));
        }
        if self.allow_session_mutation {
            return Err(OperatorError::InvalidConfig(
                "session mutation and logout flows are hard-disabled".into(),
            ));
        }
        if self.passive_only
            && self
                .probe_capabilities
                .iter()
                .any(|capability| capability.is_active())
        {
            return Err(OperatorError::InvalidConfig(
                "passive_only configuration cannot grant active probe capabilities".into(),
            ));
        }
        Ok(())
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, OperatorError> {
        let config: Self = serde_json::from_slice(bytes)
            .map_err(|error| OperatorError::Serialization(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn migrate_json(bytes: &[u8]) -> Result<Self, OperatorError> {
        let mut value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| OperatorError::Serialization(error.to_string()))?;
        let object = value.as_object_mut().ok_or_else(|| {
            OperatorError::InvalidConfig("configuration root must be an object".into())
        })?;
        let version = object
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        match version {
            0 => {
                object.insert(
                    "schema_version".into(),
                    serde_json::Value::from(OPERATOR_SCHEMA_VERSION),
                );
                object
                    .entry("passive_only")
                    .or_insert_with(|| serde_json::Value::Bool(true));
                object
                    .entry("follow_redirects")
                    .or_insert_with(|| serde_json::Value::Bool(false));
                object
                    .entry("allow_session_mutation")
                    .or_insert_with(|| serde_json::Value::Bool(false));
            }
            1 => {}
            other => {
                return Err(OperatorError::InvalidConfig(format!(
                    "no migration path exists for schema_version {other}"
                )))
            }
        }
        let config: Self = serde_json::from_value(value)
            .map_err(|error| OperatorError::Serialization(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VaultReferenceKind {
    Cookie,
    BearerToken,
    ApiKey,
    CsrfToken,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SessionSameSite {
    Strict,
    Lax,
    None,
    Unspecified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CookieReferenceMetadata {
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SessionSameSite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultReference {
    pub handle: String,
    pub kind: VaultReferenceKind,
    pub account_id: String,
    pub tenant_id: String,
    pub allowed_hosts: BTreeSet<String>,
    pub allowed_schemes: BTreeSet<String>,
    pub header_name: Option<String>,
    pub cookie: Option<CookieReferenceMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionManifest {
    pub schema_version: u32,
    pub session_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub expires_at_epoch_seconds: i64,
    pub references: Vec<VaultReference>,
}

impl SessionManifest {
    pub fn from_json(bytes: &[u8]) -> Result<Self, OperatorError> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| OperatorError::InvalidSession(error.to_string()))?;
        Ok(manifest)
    }

    pub fn validate_for_target(
        &self,
        target: &Url,
        now_epoch_seconds: i64,
    ) -> Result<(), OperatorError> {
        if self.schema_version != 1 {
            return Err(OperatorError::InvalidSession(
                "unsupported session schema_version".into(),
            ));
        }
        validate_identifier(&self.session_id, "session_id")?;
        validate_identifier(&self.account_id, "account_id")?;
        validate_identifier(&self.tenant_id, "tenant_id")?;
        if self.expires_at_epoch_seconds <= now_epoch_seconds {
            return Err(OperatorError::InvalidSession(
                "session manifest is expired".into(),
            ));
        }
        if target.scheme() != "https" {
            return Err(OperatorError::InvalidSession(
                "authenticated sessions require HTTPS".into(),
            ));
        }
        let target_host = target
            .host_str()
            .ok_or_else(|| OperatorError::InvalidSession("target host is missing".into()))?
            .to_ascii_lowercase();
        if self.references.is_empty() || self.references.len() > 256 {
            return Err(OperatorError::InvalidSession(
                "vault reference count must be between 1 and 256".into(),
            ));
        }
        let mut handles = BTreeSet::new();
        for reference in &self.references {
            validate_identifier(&reference.handle, "vault handle")?;
            if !handles.insert(reference.handle.clone()) {
                return Err(OperatorError::InvalidSession(
                    "vault handles must be unique".into(),
                ));
            }
            if reference.account_id != self.account_id || reference.tenant_id != self.tenant_id {
                return Err(OperatorError::InvalidSession(
                    "vault partition does not match session account/tenant".into(),
                ));
            }
            if !reference
                .allowed_hosts
                .iter()
                .map(|host| normalize_host(host))
                .collect::<Result<BTreeSet<_>, _>>()?
                .contains(&target_host)
            {
                return Err(OperatorError::InvalidSession(
                    "vault reference is not bound to the target host".into(),
                ));
            }
            let schemes = reference
                .allowed_schemes
                .iter()
                .map(|scheme| scheme.to_ascii_lowercase())
                .collect::<BTreeSet<_>>();
            if schemes != BTreeSet::from(["https".to_string()]) {
                return Err(OperatorError::InvalidSession(
                    "vault references must be bound only to HTTPS".into(),
                ));
            }
            match reference.kind {
                VaultReferenceKind::Cookie => {
                    if reference.header_name.is_some() {
                        return Err(OperatorError::InvalidSession(
                            "cookie references cannot declare header_name".into(),
                        ));
                    }
                    let cookie = reference.cookie.as_ref().ok_or_else(|| {
                        OperatorError::InvalidSession(
                            "cookie reference requires cookie metadata".into(),
                        )
                    })?;
                    validate_cookie_reference(cookie, &target_host)?;
                }
                _ => {
                    if reference.cookie.is_some() {
                        return Err(OperatorError::InvalidSession(
                            "non-cookie references cannot contain cookie metadata".into(),
                        ));
                    }
                    let header = reference.header_name.as_deref().ok_or_else(|| {
                        OperatorError::InvalidSession(
                            "header-delivered secret requires header_name".into(),
                        )
                    })?;
                    validate_secret_header_name(header)?;
                }
            }
        }
        Ok(())
    }
}

fn validate_cookie_reference(
    cookie: &CookieReferenceMetadata,
    target_host: &str,
) -> Result<(), OperatorError> {
    let domain = normalize_host(cookie.domain.trim_start_matches('.'))?;
    if domain != target_host {
        return Err(OperatorError::InvalidSession(
            "cookie domain must exactly match the target host in operator v1".into(),
        ));
    }
    if !cookie.path.starts_with('/')
        || cookie.path.contains('\\')
        || cookie.path.split('/').any(|segment| segment == "..")
        || cookie
            .path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(OperatorError::InvalidSession(
            "cookie path is invalid".into(),
        ));
    }
    if !cookie.secure {
        return Err(OperatorError::InvalidSession(
            "session cookies must be Secure".into(),
        ));
    }
    if cookie.same_site == SessionSameSite::None && !cookie.secure {
        return Err(OperatorError::InvalidSession(
            "SameSite=None requires Secure".into(),
        ));
    }
    Ok(())
}

fn validate_secret_header_name(value: &str) -> Result<(), OperatorError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 128
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || matches!(
            normalized.as_str(),
            "host"
                | "connection"
                | "content-length"
                | "transfer-encoding"
                | "cookie"
                | "set-cookie"
        )
    {
        return Err(OperatorError::InvalidSession(
            "secret header name is invalid or transport-controlled".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryDecision {
    Scheduled,
    PassiveMetadata,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryObservation {
    pub node_id: String,
    pub canonical_url: Option<String>,
    pub canonical_url_sha256: String,
    pub method: String,
    pub depth: u16,
    pub source_kind: String,
    pub parameter_names: BTreeSet<String>,
    pub decision: DiscoveryDecision,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryCandidate {
    pub canonical_url: String,
    pub canonical_url_sha256: String,
    pub method: String,
    pub depth: u16,
    pub source_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryBatch {
    pub base_url_sha256: String,
    pub content_classification: ContentClassification,
    pub body_sha256: String,
    pub duplicate_count: usize,
    pub observations: Vec<DiscoveryObservation>,
    pub candidates: Vec<DiscoveryCandidate>,
}

pub fn discover_response(
    config: &OperatorConfig,
    policy: &CompiledPolicy,
    base: &Url,
    current_depth: u16,
    content_type: Option<&[u8]>,
    body: &[u8],
) -> Result<DiscoveryBatch, OperatorError> {
    config.validate()?;
    validate_scan_target(base, policy, "GET")?;
    if current_depth >= config.maximum_depth {
        return Ok(DiscoveryBatch {
            base_url_sha256: hash_bytes(base.as_str().as_bytes()),
            content_classification: ContentClassification::Binary,
            body_sha256: hash_bytes(body),
            duplicate_count: 0,
            observations: Vec::new(),
            candidates: Vec::new(),
        });
    }
    if body.len() as u64 > config.maximum_body_bytes {
        return Err(OperatorError::InvalidDiscovery(
            "response body exceeds the configured discovery limit".into(),
        ));
    }
    let assessment = ContentTypeAssessment::strict(content_type, body)
        .map_err(|error| OperatorError::InvalidDiscovery(error.to_string()))?;
    let limits = ExtractionLimits {
        maximum_bytes: body.len().max(1),
        maximum_nodes: 20_000,
        maximum_depth: 128,
        maximum_links: usize::try_from(config.maximum_endpoints)
            .unwrap_or(usize::MAX)
            .min(10_000),
        maximum_forms: usize::try_from(config.maximum_endpoints)
            .unwrap_or(usize::MAX)
            .min(2_000),
        maximum_tokens: 200_000,
    };
    let document = extract_structured(assessment.classification, body, limits)
        .map_err(|error| OperatorError::InvalidDiscovery(error.to_string()))?;
    let graph = DiscoveryGraph::build(base, &document)
        .map_err(|error| OperatorError::InvalidDiscovery(error.to_string()))?;

    let mut observations = Vec::new();
    let mut candidates = BTreeMap::new();
    for node in graph.nodes {
        let mut observation = DiscoveryObservation {
            node_id: node.node_id,
            canonical_url: node.canonical_url.clone(),
            canonical_url_sha256: node.canonical_url_sha256.clone(),
            method: node.method.to_ascii_uppercase(),
            depth: current_depth.saturating_add(1),
            source_kind: node.source_kind,
            parameter_names: node.parameter_names,
            decision: DiscoveryDecision::Rejected,
            reason: node.reason,
        };
        if node.disposition == DiscoveryDisposition::CrossOriginPassive {
            observation.decision = DiscoveryDecision::PassiveMetadata;
            observation.reason = "cross_origin_metadata_only".into();
            observations.push(observation);
            continue;
        }
        if node.disposition == DiscoveryDisposition::Rejected {
            observations.push(observation);
            continue;
        }
        if observation.source_kind == "form" {
            observation.decision = DiscoveryDecision::PassiveMetadata;
            observation.reason = "form_action_uses_form_metadata_contract".into();
            observations.push(observation);
            continue;
        }
        let Some(url_text) = node.canonical_url else {
            observation.reason = "missing_canonical_url".into();
            observations.push(observation);
            continue;
        };
        let mut url = match Url::parse(&url_text) {
            Ok(url) => url,
            Err(error) => {
                observation.reason = format!("canonical_url_parse:{error}");
                observations.push(observation);
                continue;
            }
        };
        url.set_fragment(None);
        let method = observation.method.as_str();
        let rejection = if url.scheme() != "https" {
            Some("https_required")
        } else if url.query().is_some() {
            Some("query_targets_are_metadata_only_in_operator_v1")
        } else if !matches!(method, "GET" | "HEAD") {
            Some("method_not_passive")
        } else if dangerous_path(url.path()) {
            Some("dangerous_path_segment")
        } else if !policy.allows_request(&url, method) {
            Some("policy_scope_denied")
        } else if observation.depth > config.maximum_depth {
            Some("depth_limit")
        } else {
            None
        };
        if let Some(reason) = rejection {
            observation.decision = if reason == "query_targets_are_metadata_only_in_operator_v1"
                || reason == "method_not_passive"
            {
                DiscoveryDecision::PassiveMetadata
            } else {
                DiscoveryDecision::Rejected
            };
            observation.reason = reason.into();
            observations.push(observation);
            continue;
        }
        let canonical_url = url.to_string();
        let canonical_url_sha256 = hash_bytes(canonical_url.as_bytes());
        observation.canonical_url = Some(canonical_url.clone());
        observation.canonical_url_sha256 = canonical_url_sha256.clone();
        observation.decision = DiscoveryDecision::Scheduled;
        observation.reason = "same_origin_scope_allowed".into();
        candidates
            .entry((canonical_url.clone(), method.to_string()))
            .or_insert(DiscoveryCandidate {
                canonical_url,
                canonical_url_sha256,
                method: method.to_string(),
                depth: observation.depth,
                source_kind: observation.source_kind.clone(),
            });
        observations.push(observation);
    }
    let maximum = usize::try_from(config.maximum_endpoints).unwrap_or(usize::MAX);
    let candidates = candidates.into_values().take(maximum).collect();
    Ok(DiscoveryBatch {
        base_url_sha256: graph.base_url_sha256,
        content_classification: assessment.classification,
        body_sha256: document.body_sha256,
        duplicate_count: graph.duplicate_count,
        observations,
        candidates,
    })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Completed,
    RequestBudgetExhausted,
    EndpointLimitReached,
    DepthLimitReached,
    EmergencyStop,
    Cancelled,
    Saturated,
    OperatorDenied,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchedulerReceipt {
    pub pending: u64,
    pub seen: u64,
    pub issued: u64,
    pub duplicate_count: u64,
    pub rejected_count: u64,
    pub stop_reason: Option<StopReason>,
    pub receipt_sha256: String,
}

#[derive(Debug)]
pub struct DiscoveryScheduler {
    config: OperatorConfig,
    pending: BTreeMap<(u16, String, String), DiscoveryCandidate>,
    seen: BTreeSet<(String, String)>,
    issued: u64,
    duplicate_count: u64,
    rejected_count: u64,
    stop_reason: Option<StopReason>,
}

impl DiscoveryScheduler {
    pub fn new(config: OperatorConfig) -> Result<Self, OperatorError> {
        config.validate()?;
        Ok(Self {
            config,
            pending: BTreeMap::new(),
            seen: BTreeSet::new(),
            issued: 0,
            duplicate_count: 0,
            rejected_count: 0,
            stop_reason: None,
        })
    }

    pub fn enqueue(&mut self, candidate: DiscoveryCandidate) -> bool {
        if self.stop_reason.is_some() {
            self.rejected_count = self.rejected_count.saturating_add(1);
            return false;
        }
        if candidate.depth > self.config.maximum_depth {
            self.rejected_count = self.rejected_count.saturating_add(1);
            self.stop_reason
                .get_or_insert(StopReason::DepthLimitReached);
            return false;
        }
        let identity = (candidate.canonical_url.clone(), candidate.method.clone());
        if self.seen.contains(&identity)
            || self.pending.values().any(|queued| {
                queued.canonical_url == candidate.canonical_url && queued.method == candidate.method
            })
        {
            self.duplicate_count = self.duplicate_count.saturating_add(1);
            return false;
        }
        if (self.seen.len() + self.pending.len()) as u64 >= self.config.maximum_endpoints {
            self.rejected_count = self.rejected_count.saturating_add(1);
            self.stop_reason
                .get_or_insert(StopReason::EndpointLimitReached);
            return false;
        }
        self.pending.insert(
            (
                candidate.depth,
                candidate.canonical_url.clone(),
                candidate.method.clone(),
            ),
            candidate,
        );
        true
    }

    pub fn enqueue_batch(&mut self, batch: DiscoveryBatch) -> u64 {
        batch
            .candidates
            .into_iter()
            .filter(|candidate| self.enqueue(candidate.clone()))
            .count() as u64
    }

    pub fn next_candidate(&mut self) -> Option<DiscoveryCandidate> {
        if self.stop_reason.is_some() {
            return None;
        }
        if self.issued >= self.config.maximum_requests {
            self.stop_reason = Some(StopReason::RequestBudgetExhausted);
            return None;
        }
        let (_, candidate) = self.pending.pop_first()?;
        self.seen
            .insert((candidate.canonical_url.clone(), candidate.method.clone()));
        self.issued = self.issued.saturating_add(1);
        Some(candidate)
    }

    pub fn emergency_stop(&mut self) {
        self.pending.clear();
        self.stop_reason = Some(StopReason::EmergencyStop);
    }

    pub fn cancel(&mut self) {
        self.pending.clear();
        self.stop_reason = Some(StopReason::Cancelled);
    }

    pub fn receipt(&self) -> Result<SchedulerReceipt, OperatorError> {
        let mut receipt = SchedulerReceipt {
            pending: self.pending.len() as u64,
            seen: self.seen.len() as u64,
            issued: self.issued,
            duplicate_count: self.duplicate_count,
            rejected_count: self.rejected_count,
            stop_reason: self.stop_reason,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = hash_serializable(&receipt)?;
        Ok(receipt)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    pub probe: ProbeKind,
    pub endpoint: String,
    pub method: String,
    pub request_cost: u64,
    pub capability_reference: Option<String>,
    pub account_partition: Option<String>,
    pub tenant_partition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeAuthorization {
    pub probe: ProbeKind,
    pub endpoint_sha256: String,
    pub method: String,
    pub request_cost: u64,
    pub active: bool,
    pub authorization_sha256: String,
}

pub fn authorize_probe(
    config: &OperatorConfig,
    policy: &CompiledPolicy,
    request: &ProbeRequest,
    remaining_request_budget: u64,
) -> Result<ProbeAuthorization, OperatorError> {
    config.validate()?;
    if !config.probe_capabilities.contains(&request.probe) {
        return Err(OperatorError::ProbeDenied(
            "probe capability is not granted by operator configuration".into(),
        ));
    }
    let url = Url::parse(&request.endpoint)
        .map_err(|error| OperatorError::ProbeDenied(error.to_string()))?;
    let method = request.method.to_ascii_uppercase();
    validate_scan_target(&url, policy, &method)
        .map_err(|error| OperatorError::ProbeDenied(error.to_string()))?;
    if url.query().is_some() || dangerous_path(url.path()) {
        return Err(OperatorError::ProbeDenied(
            "query-bearing and dangerous-path probes are disabled in operator v1".into(),
        ));
    }
    if request.request_cost != request.probe.default_request_cost() {
        return Err(OperatorError::ProbeDenied(
            "probe request cost does not match the fixed capability contract".into(),
        ));
    }
    if request.request_cost > remaining_request_budget {
        return Err(OperatorError::ProbeDenied(
            "probe exceeds the remaining request budget".into(),
        ));
    }
    if request.probe.is_active() {
        if config.passive_only || !policy.active_testing_enabled() {
            return Err(OperatorError::ProbeDenied(
                "active probe requires both operator and program authorization".into(),
            ));
        }
        let capability = request
            .capability_reference
            .as_deref()
            .ok_or_else(|| OperatorError::ProbeDenied("capability reference is required".into()))?;
        validate_identifier(capability, "capability_reference")
            .map_err(|error| OperatorError::ProbeDenied(error.to_string()))?;
        if request.probe == ProbeKind::AuthorizationDifferential
            && (request.account_partition.is_none() || request.tenant_partition.is_none())
        {
            return Err(OperatorError::ProbeDenied(
                "authorization differential requires explicit account and tenant partitions".into(),
            ));
        }
    }
    let mut authorization = ProbeAuthorization {
        probe: request.probe,
        endpoint_sha256: hash_bytes(url.as_str().as_bytes()),
        method,
        request_cost: request.request_cost,
        active: request.probe.is_active(),
        authorization_sha256: String::new(),
    };
    authorization.authorization_sha256 = hash_serializable(&authorization)?;
    Ok(authorization)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingDisposition {
    Confirmed,
    Candidate,
    Inconclusive,
    FalsePositive,
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorFinding {
    pub finding_id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub origin: String,
    pub endpoint_sha256: String,
    pub evidence_sha256: String,
    pub summary: String,
    pub disposition: FindingDisposition,
    pub affected_endpoints: BTreeSet<String>,
    pub reproduction_metadata: BTreeMap<String, String>,
}

impl OperatorFinding {
    pub fn from_passive(finding: &Finding) -> Result<Self, OperatorError> {
        validate_sha256(&finding.endpoint_sha256, "finding endpoint")?;
        validate_sha256(&finding.evidence_sha256, "finding evidence")?;
        validate_report_text(&finding.title, "finding title")?;
        validate_report_text(&finding.summary, "finding summary")?;
        let mut reproduction_metadata = finding.metadata.clone();
        reproduction_metadata.insert("source".into(), "passive_analyzer".into());
        validate_metadata(&reproduction_metadata)?;
        Ok(Self {
            finding_id: finding.finding_id.clone(),
            rule_id: finding.rule_id.clone(),
            title: finding.title.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            origin: finding.origin.clone(),
            endpoint_sha256: finding.endpoint_sha256.clone(),
            evidence_sha256: finding.evidence_sha256.clone(),
            summary: finding.summary.clone(),
            disposition: FindingDisposition::Candidate,
            affected_endpoints: BTreeSet::from([finding.endpoint_sha256.clone()]),
            reproduction_metadata,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootCauseGroup {
    pub group_id: String,
    pub rule_id: String,
    pub origin: String,
    pub finding_ids: BTreeSet<String>,
    pub affected_endpoints: BTreeSet<String>,
    pub evidence_sha256: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageSummary {
    pub discovered_endpoints: u64,
    pub tested_endpoints: u64,
    pub requests_issued: u64,
    pub request_budget: u64,
    pub depth_reached: u16,
    pub maximum_depth: u16,
    pub saturation_reached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorReport {
    pub schema_version: u32,
    pub run_id: String,
    pub program_name: String,
    pub policy_snapshot_sha256: String,
    pub target_origin_sha256: String,
    pub generated_at_epoch_seconds: i64,
    pub findings: Vec<OperatorFinding>,
    pub root_cause_groups: Vec<RootCauseGroup>,
    pub affected_endpoints: BTreeSet<String>,
    pub evidence_hashes: BTreeSet<String>,
    pub coverage: CoverageSummary,
    pub untested_areas: Vec<String>,
    pub stop_reason: StopReason,
    pub automatic_submission: bool,
    pub report_sha256: String,
}

impl OperatorReport {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        run_id: impl Into<String>,
        program_name: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        target: &Url,
        generated_at_epoch_seconds: i64,
        findings: Vec<OperatorFinding>,
        coverage: CoverageSummary,
        untested_areas: Vec<String>,
        stop_reason: StopReason,
    ) -> Result<Self, OperatorError> {
        let run_id = run_id.into();
        let program_name = program_name.into();
        validate_identifier(&run_id, "run_id")?;
        validate_report_text(&program_name, "program_name")?;
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "policy snapshot")?;
        if generated_at_epoch_seconds <= 0 {
            return Err(OperatorError::InvalidReport(
                "generated_at_epoch_seconds must be positive".into(),
            ));
        }
        if findings.len() > MAX_OPERATOR_FINDINGS {
            return Err(OperatorError::InvalidReport(
                "finding count exceeds the report limit".into(),
            ));
        }
        if untested_areas.len() > MAX_OPERATOR_UNTESTED_AREAS {
            return Err(OperatorError::InvalidReport(
                "untested area count exceeds the report limit".into(),
            ));
        }
        for area in &untested_areas {
            validate_report_text(area, "untested area")?;
        }
        let mut findings = findings;
        findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
        let root_cause_groups = group_root_causes(&findings)?;
        let affected_endpoints = findings
            .iter()
            .flat_map(|finding| finding.affected_endpoints.iter().cloned())
            .collect();
        let evidence_hashes = findings
            .iter()
            .map(|finding| finding.evidence_sha256.clone())
            .collect();
        let mut report = Self {
            schema_version: REPORT_SCHEMA_VERSION,
            run_id,
            program_name,
            policy_snapshot_sha256,
            target_origin_sha256: hash_bytes(origin(target)?.as_bytes()),
            generated_at_epoch_seconds,
            findings,
            root_cause_groups,
            affected_endpoints,
            evidence_hashes,
            coverage,
            untested_areas,
            stop_reason,
            automatic_submission: false,
            report_sha256: String::new(),
        };
        report.report_sha256 = hash_serializable(&report)?;
        Ok(report)
    }

    pub fn verify(&self) -> Result<(), OperatorError> {
        if self.automatic_submission {
            return Err(OperatorError::InvalidReport(
                "automatic report submission must remain disabled".into(),
            ));
        }
        let mut material = self.clone();
        material.report_sha256.clear();
        let expected = hash_serializable(&material)?;
        if expected != self.report_sha256 {
            return Err(OperatorError::InvalidReport(
                "report digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

fn group_root_causes(findings: &[OperatorFinding]) -> Result<Vec<RootCauseGroup>, OperatorError> {
    let mut groups: BTreeMap<(String, String), RootCauseGroup> = BTreeMap::new();
    for finding in findings {
        let key = (finding.rule_id.clone(), finding.origin.clone());
        let group = groups.entry(key.clone()).or_insert_with(|| RootCauseGroup {
            group_id: String::new(),
            rule_id: key.0.clone(),
            origin: key.1.clone(),
            finding_ids: BTreeSet::new(),
            affected_endpoints: BTreeSet::new(),
            evidence_sha256: BTreeSet::new(),
        });
        group.finding_ids.insert(finding.finding_id.clone());
        group
            .affected_endpoints
            .extend(finding.affected_endpoints.iter().cloned());
        group
            .evidence_sha256
            .insert(finding.evidence_sha256.clone());
    }
    for group in groups.values_mut() {
        group.group_id = format!(
            "root-cause-{}",
            &hash_serializable(&(
                &group.rule_id,
                &group.origin,
                &group.finding_ids,
                &group.affected_endpoints,
            ))?[..24]
        );
    }
    Ok(groups.into_values().collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportBundle {
    pub report: OperatorReport,
    pub json: String,
    pub markdown: String,
    pub hackerone_draft: String,
    pub json_sha256: String,
    pub markdown_sha256: String,
    pub hackerone_sha256: String,
}

impl ReportBundle {
    pub fn build(report: OperatorReport) -> Result<Self, OperatorError> {
        report.verify()?;
        let json = serde_json::to_string_pretty(&report)
            .map_err(|error| OperatorError::Serialization(error.to_string()))?;
        let markdown = render_markdown(&report);
        let hackerone_draft = render_hackerone_draft(&report);
        for (name, value) in [
            ("json", json.as_str()),
            ("markdown", markdown.as_str()),
            ("hackerone", hackerone_draft.as_str()),
        ] {
            if contains_secret_like(value) {
                return Err(OperatorError::InvalidReport(format!(
                    "{name} export contains secret-like material"
                )));
            }
        }
        Ok(Self {
            json_sha256: hash_bytes(json.as_bytes()),
            markdown_sha256: hash_bytes(markdown.as_bytes()),
            hackerone_sha256: hash_bytes(hackerone_draft.as_bytes()),
            report,
            json,
            markdown,
            hackerone_draft,
        })
    }
}

fn render_markdown(report: &OperatorReport) -> String {
    let mut output = String::new();
    output.push_str("# NXB operator report\n\n");
    output.push_str(&format!("- Run: `{}`\n", report.run_id));
    output.push_str(&format!(
        "- Program: {}\n",
        markdown_escape(&report.program_name)
    ));
    output.push_str(&format!(
        "- Policy snapshot: `{}`\n",
        report.policy_snapshot_sha256
    ));
    output.push_str(&format!("- Stop reason: `{:?}`\n", report.stop_reason));
    output.push_str("- Automatic submission: `disabled`\n\n");
    output.push_str("## Coverage\n\n");
    output.push_str(&format!(
        "- Endpoints: tested {} / discovered {}\n",
        report.coverage.tested_endpoints, report.coverage.discovered_endpoints
    ));
    output.push_str(&format!(
        "- Requests: {} / {}\n",
        report.coverage.requests_issued, report.coverage.request_budget
    ));
    output.push_str(&format!(
        "- Depth: {} / {}\n\n",
        report.coverage.depth_reached, report.coverage.maximum_depth
    ));
    output.push_str("## Root-cause groups\n\n");
    if report.root_cause_groups.is_empty() {
        output.push_str("No findings were grouped.\n\n");
    }
    for group in &report.root_cause_groups {
        output.push_str(&format!(
            "### {} — `{}`\n\n",
            markdown_escape(&group.rule_id),
            group.group_id
        ));
        output.push_str(&format!("- Origin: `{}`\n", markdown_escape(&group.origin)));
        output.push_str(&format!("- Findings: {}\n", group.finding_ids.len()));
        output.push_str(&format!(
            "- Affected endpoints: {}\n\n",
            group.affected_endpoints.len()
        ));
    }
    output.push_str("## Findings\n\n");
    for finding in &report.findings {
        output.push_str(&format!("### {}\n\n", markdown_escape(&finding.title)));
        output.push_str(&format!("- ID: `{}`\n", finding.finding_id));
        output.push_str(&format!("- Rule: `{}`\n", finding.rule_id));
        output.push_str(&format!("- Severity: `{:?}`\n", finding.severity));
        output.push_str(&format!("- Confidence: `{:?}`\n", finding.confidence));
        output.push_str(&format!("- Disposition: `{:?}`\n", finding.disposition));
        output.push_str(&format!(
            "- Evidence SHA-256: `{}`\n\n",
            finding.evidence_sha256
        ));
        output.push_str(&markdown_escape(&finding.summary));
        output.push_str("\n\n");
    }
    output.push_str("## Untested areas\n\n");
    if report.untested_areas.is_empty() {
        output.push_str("None recorded.\n");
    } else {
        for area in &report.untested_areas {
            output.push_str(&format!("- {}\n", markdown_escape(area)));
        }
    }
    output
}

fn render_hackerone_draft(report: &OperatorReport) -> String {
    let mut output = String::new();
    output.push_str("# HackerOne draft — manual review required\n\n");
    output.push_str("This file is a draft only. NXB does not submit reports automatically.\n\n");
    if report.findings.is_empty() {
        output.push_str("No candidate findings are available for submission.\n");
        return output;
    }
    for finding in &report.findings {
        output.push_str(&format!("## {}\n\n", markdown_escape(&finding.title)));
        output.push_str("### Summary\n\n");
        output.push_str(&markdown_escape(&finding.summary));
        output.push_str("\n\n### Scope and endpoint\n\n");
        output.push_str(&format!(
            "- Origin: `{}`\n",
            markdown_escape(&finding.origin)
        ));
        output.push_str(&format!(
            "- Endpoint SHA-256: `{}`\n",
            finding.endpoint_sha256
        ));
        output.push_str("\n### Evidence\n\n");
        output.push_str(&format!(
            "- Evidence SHA-256: `{}`\n",
            finding.evidence_sha256
        ));
        output.push_str("- Raw secrets and response bodies are intentionally excluded.\n\n");
        output.push_str("### Triage state\n\n");
        output.push_str(&format!("- `{:?}`\n\n", finding.disposition));
    }
    output
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportEntry {
    pub logical_path: String,
    pub content_sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportManifest {
    pub version: u32,
    pub entries: BTreeMap<String, ExportEntry>,
    pub root_sha256: String,
}

pub fn write_report_bundle(
    output_directory: &Path,
    bundle: &ReportBundle,
) -> Result<ExportManifest, OperatorError> {
    fs::create_dir_all(output_directory)
        .map_err(|error| OperatorError::Filesystem(error.to_string()))?;
    let artifacts = [
        ("report.json", bundle.json.as_bytes()),
        ("report.md", bundle.markdown.as_bytes()),
        ("hackerone-draft.md", bundle.hackerone_draft.as_bytes()),
    ];
    let mut entries = BTreeMap::new();
    for (name, bytes) in artifacts {
        if contains_secret_like(std::str::from_utf8(bytes).unwrap_or_default()) {
            return Err(OperatorError::InvalidReport(format!(
                "refusing to write secret-like export {name}"
            )));
        }
        let path = output_directory.join(name);
        atomic_write(&path, bytes)?;
        entries.insert(
            name.to_string(),
            ExportEntry {
                logical_path: name.to_string(),
                content_sha256: hash_bytes(bytes),
                bytes: bytes.len() as u64,
            },
        );
    }
    let mut manifest = ExportManifest {
        version: 1,
        entries,
        root_sha256: String::new(),
    };
    manifest.root_sha256 = hash_serializable(&manifest)?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| OperatorError::Serialization(error.to_string()))?;
    atomic_write(&output_directory.join("manifest.json"), &manifest_bytes)?;
    Ok(manifest)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), OperatorError> {
    let parent = path
        .parent()
        .ok_or_else(|| OperatorError::Filesystem("output path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|error| OperatorError::Filesystem(error.to_string()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| OperatorError::Filesystem("output file name is invalid".into()))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", &hash_bytes(bytes)[..16]));
    if temporary.exists() {
        fs::remove_file(&temporary)
            .map_err(|error| OperatorError::Filesystem(error.to_string()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| OperatorError::Filesystem(error.to_string()))?;
    file.write_all(bytes)
        .map_err(|error| OperatorError::Filesystem(error.to_string()))?;
    file.sync_all()
        .map_err(|error| OperatorError::Filesystem(error.to_string()))?;
    drop(file);
    if path.exists() {
        fs::remove_file(path).map_err(|error| OperatorError::Filesystem(error.to_string()))?;
    }
    fs::rename(&temporary, path).map_err(|error| OperatorError::Filesystem(error.to_string()))?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseArtifact {
    pub logical_path: String,
    pub content_sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseManifest {
    pub version: u32,
    pub artifacts: Vec<ReleaseArtifact>,
    pub sbom_sha256: String,
    pub root_sha256: String,
}

impl ReleaseManifest {
    pub fn build(
        mut artifacts: Vec<ReleaseArtifact>,
        sbom_bytes: &[u8],
    ) -> Result<Self, OperatorError> {
        if artifacts.is_empty() || artifacts.len() > 10_000 {
            return Err(OperatorError::InvalidReport(
                "release artifact count is outside the supported range".into(),
            ));
        }
        artifacts.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
        let mut seen = BTreeSet::new();
        for artifact in &artifacts {
            validate_logical_path(&artifact.logical_path)?;
            validate_sha256(&artifact.content_sha256, "release artifact")?;
            if !seen.insert(artifact.logical_path.clone()) {
                return Err(OperatorError::InvalidReport(
                    "release artifact paths must be unique".into(),
                ));
            }
        }
        let mut manifest = Self {
            version: 1,
            artifacts,
            sbom_sha256: hash_bytes(sbom_bytes),
            root_sha256: String::new(),
        };
        manifest.root_sha256 = hash_serializable(&manifest)?;
        Ok(manifest)
    }

    pub fn checksum_lines(&self) -> String {
        let mut output = self
            .artifacts
            .iter()
            .map(|artifact| format!("{}  {}", artifact.content_sha256, artifact.logical_path))
            .collect::<Vec<_>>();
        output.push(format!("{}  SBOM", self.sbom_sha256));
        output.join("\n") + "\n"
    }
}

fn validate_scan_target(
    target: &Url,
    policy: &CompiledPolicy,
    method: &str,
) -> Result<(), OperatorError> {
    if target.scheme() != "https"
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
        || !matches!(method, "GET" | "HEAD")
        || dangerous_path(target.path())
        || !policy.allows_request(target, method)
    {
        return Err(OperatorError::InvalidTarget(
            "target must be scoped HTTPS GET/HEAD without credentials, fragment, or dangerous path"
                .into(),
        ));
    }
    Ok(())
}

fn dangerous_path(path: &str) -> bool {
    path.split('/').any(|segment| {
        DENIED_PATH_SEGMENTS
            .iter()
            .any(|denied| segment.eq_ignore_ascii_case(denied))
    })
}

fn normalize_host(value: &str) -> Result<String, OperatorError> {
    let host = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.contains('*')
        || host.contains('/')
        || host.contains('\\')
        || host.contains(':')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(OperatorError::InvalidSession(
            "vault allowed_hosts contains an invalid DNS host".into(),
        ));
    }
    Ok(host)
}

fn origin(url: &Url) -> Result<String, OperatorError> {
    let host = url
        .host_str()
        .ok_or_else(|| OperatorError::InvalidTarget("URL host is missing".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| OperatorError::InvalidTarget("URL port is missing".into()))?;
    Ok(format!(
        "{}://{}:{port}",
        url.scheme(),
        host.to_ascii_lowercase()
    ))
}

fn validate_identifier(value: &str, name: &str) -> Result<(), OperatorError> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(OperatorError::InvalidConfig(format!(
            "{name} is not a bounded identifier"
        )));
    }
    Ok(())
}

fn validate_sha256(value: &str, name: &str) -> Result<(), OperatorError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OperatorError::InvalidReport(format!(
            "{name} is not a lowercase SHA-256 value"
        )));
    }
    Ok(())
}

fn validate_report_text(value: &str, name: &str) -> Result<(), OperatorError> {
    if value.is_empty()
        || value.len() > 8192
        || value.bytes().any(|byte| byte == 0)
        || contains_secret_like(value)
    {
        return Err(OperatorError::InvalidReport(format!(
            "{name} is empty, oversized, invalid, or secret-like"
        )));
    }
    Ok(())
}

fn validate_metadata(metadata: &BTreeMap<String, String>) -> Result<(), OperatorError> {
    if metadata.len() > 256 {
        return Err(OperatorError::InvalidReport(
            "finding metadata exceeds the limit".into(),
        ));
    }
    for (key, value) in metadata {
        if key.is_empty()
            || key.len() > 128
            || value.len() > 2048
            || contains_secret_like(key)
            || contains_secret_like(value)
        {
            return Err(OperatorError::InvalidReport(
                "finding metadata is invalid or secret-like".into(),
            ));
        }
    }
    Ok(())
}

fn contains_secret_like(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization: bearer",
        "proxy-authorization:",
        "set-cookie:",
        "cookie:",
        "password=",
        "passwd=",
        "token=",
        "api_key=",
        "apikey=",
        "client_secret=",
        "private_key=",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn validate_logical_path(path: &str) -> Result<(), OperatorError> {
    let candidate = PathBuf::from(path);
    if path.is_empty()
        || path.len() > 512
        || candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(OperatorError::InvalidReport(
            "release logical path is unsafe".into(),
        ));
    }
    Ok(())
}

fn markdown_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, OperatorError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| OperatorError::Serialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs};

    use chrono::Utc;
    use nxb_policy::TargetPolicy;

    use super::*;

    fn compiled_policy(active_testing: bool) -> CompiledPolicy {
        let input = format!(
            r#"
schema_version = 1

[program]
name = "Operator Fixture"
platform = "local"
policy_url = "https://example.com/policy"

[scope]
include_hosts = ["example.com"]
exclude_hosts = []
allowed_schemes = ["https"]
allowed_methods = ["GET", "HEAD"]
allow_subdomains = false

[automation]
active_testing = {active_testing}
credential_bruteforce = false
destructive_testing = false
oob_callbacks = false
max_requests_per_second = 1.0
max_concurrency = 1
max_total_requests = 100

[authorization]
confirmed = true
researcher = "fixture"
policy_snapshot_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
expires_at = "2099-01-01T00:00:00Z"
"#
        );
        TargetPolicy::from_toml(&input)
            .unwrap()
            .compile(Utc::now())
            .unwrap()
    }

    #[test]
    fn discovery_schedules_only_safe_same_origin_passive_targets() {
        let config = OperatorConfig::default();
        let policy = compiled_policy(false);
        let base = Url::parse("https://example.com/root").unwrap();
        let body = br#"
            <a href="/safe">safe</a>
            <script src="/app.js"></script>
            <a href="/logout">logout</a>
            <a href="https://other.example/path">external</a>
            <form action="/submit" method="post"><input name="item"></form>
        "#;
        let batch = discover_response(
            &config,
            &policy,
            &base,
            0,
            Some(b"text/html; charset=utf-8"),
            body,
        )
        .unwrap();
        let urls = batch
            .candidates
            .iter()
            .map(|candidate| candidate.canonical_url.as_str())
            .collect::<BTreeSet<_>>();
        assert!(urls.contains("https://example.com/safe"));
        assert!(urls.contains("https://example.com/app.js"));
        assert!(!urls.iter().any(|url| url.contains("logout")));
        assert!(!urls.iter().any(|url| url.contains("other.example")));
        assert!(batch.observations.iter().any(|observation| {
            observation.reason == "form_action_uses_form_metadata_contract"
        }));
    }

    #[test]
    fn plaintext_secret_fields_are_rejected_by_manifest_schema() {
        let document = br#"{
            "schema_version":1,
            "session_id":"s1",
            "account_id":"a1",
            "tenant_id":"t1",
            "expires_at_epoch_seconds":4102444800,
            "references":[{
                "handle":"vault-1",
                "kind":"bearer_token",
                "account_id":"a1",
                "tenant_id":"t1",
                "allowed_hosts":["example.com"],
                "allowed_schemes":["https"],
                "header_name":"Authorization",
                "cookie":null,
                "value":"secret"
            }]
        }"#;
        assert!(SessionManifest::from_json(document).is_err());
    }

    #[test]
    fn active_probe_requires_program_and_operator_capability() {
        let config = OperatorConfig::default();
        let request = ProbeRequest {
            probe: ProbeKind::ReflectionValidation,
            endpoint: "https://example.com/reflect".into(),
            method: "GET".into(),
            request_cost: 2,
            capability_reference: Some("capability-1".into()),
            account_partition: None,
            tenant_partition: None,
        };
        assert!(authorize_probe(&config, &compiled_policy(false), &request, 10).is_err());

        let mut active = config;
        active.passive_only = false;
        active
            .probe_capabilities
            .insert(ProbeKind::ReflectionValidation);
        assert!(authorize_probe(&active, &compiled_policy(true), &request, 10).is_ok());
    }

    #[test]
    fn report_is_deterministic_and_never_auto_submits() {
        let finding = OperatorFinding {
            finding_id: "finding-1".into(),
            rule_id: "security_headers".into(),
            title: "Missing security header".into(),
            severity: Severity::Low,
            confidence: Confidence::High,
            origin: "https://example.com:443".into(),
            endpoint_sha256: "b".repeat(64),
            evidence_sha256: "c".repeat(64),
            summary: "The response did not include the expected header.".into(),
            disposition: FindingDisposition::Candidate,
            affected_endpoints: BTreeSet::from(["b".repeat(64)]),
            reproduction_metadata: BTreeMap::new(),
        };
        let report = OperatorReport::build(
            "run-1",
            "Fixture",
            "a".repeat(64),
            &Url::parse("https://example.com/").unwrap(),
            1_800_000_000,
            vec![finding],
            CoverageSummary {
                discovered_endpoints: 1,
                tested_endpoints: 1,
                requests_issued: 1,
                request_budget: 10,
                depth_reached: 0,
                maximum_depth: 2,
                saturation_reached: false,
            },
            vec!["Authenticated areas were not tested.".into()],
            StopReason::Completed,
        )
        .unwrap();
        assert!(!report.automatic_submission);
        report.verify().unwrap();
        let first = ReportBundle::build(report.clone()).unwrap();
        let second = ReportBundle::build(report).unwrap();
        assert_eq!(first.json_sha256, second.json_sha256);
        assert!(first.hackerone_draft.contains("manual review required"));
    }

    #[test]
    fn atomic_report_export_replaces_complete_files() {
        let root = std::env::temp_dir().join(format!("nxb-operator-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let report = OperatorReport::build(
            "run-export",
            "Fixture",
            "a".repeat(64),
            &Url::parse("https://example.com/").unwrap(),
            1_800_000_000,
            Vec::new(),
            CoverageSummary {
                discovered_endpoints: 0,
                tested_endpoints: 0,
                requests_issued: 0,
                request_budget: 1,
                depth_reached: 0,
                maximum_depth: 0,
                saturation_reached: true,
            },
            Vec::new(),
            StopReason::Completed,
        )
        .unwrap();
        let bundle = ReportBundle::build(report).unwrap();
        let manifest = write_report_bundle(&root, &bundle).unwrap();
        assert!(root.join("report.json").is_file());
        assert!(root.join("manifest.json").is_file());
        assert_eq!(manifest.entries.len(), 3);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_configuration_migrates_to_fail_closed_defaults() {
        let migrated = OperatorConfig::migrate_json(
            br#"{
                "maximum_depth":1,
                "maximum_endpoints":10,
                "maximum_requests":5,
                "maximum_body_bytes":1024
            }"#,
        )
        .unwrap();
        assert_eq!(migrated.schema_version, 1);
        assert!(migrated.passive_only);
        assert!(!migrated.follow_redirects);
        assert!(!migrated.allow_session_mutation);
    }
}
