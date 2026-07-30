use std::{collections::BTreeSet, fmt, net::IpAddr, time::Duration};

use nxb_gateway::{DecisionOutcome, GatewayDecision, RequestIntent};
use nxb_http1::Http1Response;
use nxb_pinned_transport::{
    ConnectionAuthorization, PinnedTransportCoordinator, PinnedTransportError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub const MAX_LOCATION_BYTES: usize = 8 * 1024;
pub const MAX_REDIRECT_CHAIN_LENGTH: u8 = 20;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedirectLimits {
    pub maximum_redirects: u8,
}

impl RedirectLimits {
    pub fn conservative_default() -> Self {
        Self {
            maximum_redirects: 8,
        }
    }

    pub fn validate(self) -> Result<Self, RedirectError> {
        if self.maximum_redirects == 0 || self.maximum_redirects > MAX_REDIRECT_CHAIN_LENGTH {
            return Err(RedirectError::InvalidLimits);
        }
        Ok(self)
    }
}

impl Default for RedirectLimits {
    fn default() -> Self {
        Self::conservative_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedirectSessionSnapshot {
    pub session_id: String,
    pub run_id: String,
    pub worker_id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub generation: u64,
}

impl RedirectSessionSnapshot {
    fn validate(&self) -> Result<(), RedirectError> {
        validate_identifier(&self.session_id, "session_id")?;
        validate_identifier(&self.run_id, "run_id")?;
        validate_identifier(&self.worker_id, "worker_id")?;
        validate_identifier(&self.account_id, "account_id")?;
        validate_identifier(&self.tenant_id, "tenant_id")?;
        validate_identifier(&self.role_id, "role_id")?;
        if self.generation == 0 {
            return Err(RedirectError::InvalidSessionGeneration);
        }
        Ok(())
    }

    fn identity_matches(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.run_id == other.run_id
            && self.worker_id == other.worker_id
            && self.account_id == other.account_id
            && self.tenant_id == other.tenant_id
            && self.role_id == other.role_id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedirectSessionUpdate {
    pub snapshot: RedirectSessionSnapshot,
    pub response_state_changed: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RedirectRequestState {
    pub url: Url,
    pub method: String,
    pub body_sha256: String,
    pub body_bytes: u64,
    pub session: RedirectSessionSnapshot,
}

impl fmt::Debug for RedirectRequestState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedirectRequestState")
            .field("origin", &Origin::from_url(&self.url).ok())
            .field("target_sha256", &target_hash(&self.url))
            .field("method", &self.method)
            .field("body_sha256", &self.body_sha256)
            .field("body_bytes", &self.body_bytes)
            .field("session", &self.session)
            .finish()
    }
}

impl RedirectRequestState {
    pub fn new(
        mut url: Url,
        method: impl Into<String>,
        body_sha256: impl Into<String>,
        body_bytes: u64,
        session: RedirectSessionSnapshot,
    ) -> Result<Self, RedirectError> {
        validate_http_url(&url)?;
        url.set_fragment(None);
        let method = normalize_method(&method.into())?;
        let body_sha256 = body_sha256.into();
        validate_sha256(&body_sha256, "body_sha256")?;
        session.validate()?;
        Ok(Self {
            url,
            method,
            body_sha256,
            body_bytes,
            session,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedirectDnsInput {
    pub resolved_ips: Vec<IpAddr>,
    pub selected_ip: IpAddr,
    pub context_id: String,
    pub resolver_id: String,
    pub ttl_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Origin {
    pub fn from_url(url: &Url) -> Result<Self, RedirectError> {
        validate_http_url(url)?;
        let host = url
            .host_str()
            .ok_or(RedirectError::MissingHost)?
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or(RedirectError::MissingPort)?;
        Ok(Self {
            scheme: url.scheme().to_ascii_lowercase(),
            host,
            port,
        })
    }

    pub fn authority(&self) -> String {
        let default_port = match self.scheme.as_str() {
            "http" => 80,
            "https" => 443,
            _ => self.port,
        };
        if self.port == default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OriginTransition {
    SameOrigin,
    CrossOrigin,
}

impl OriginTransition {
    fn code(self) -> &'static str {
        match self {
            Self::SameOrigin => "same_origin",
            Self::CrossOrigin => "cross_origin",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RedirectBodyDisposition {
    Preserve,
    Drop,
}

impl RedirectBodyDisposition {
    fn code(self) -> &'static str {
        match self {
            Self::Preserve => "preserve",
            Self::Drop => "drop",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RedirectSecretDisposition {
    ReissueBoundSecrets,
    RematerializeCookiesOnly,
}

impl RedirectSecretDisposition {
    fn code(self) -> &'static str {
        match self {
            Self::ReissueBoundSecrets => "reissue_bound_secrets",
            Self::RematerializeCookiesOnly => "rematerialize_cookies_only",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RedirectNextRequest {
    pub url: Url,
    pub method: String,
    pub body_disposition: RedirectBodyDisposition,
    pub body_sha256: String,
    pub body_bytes: u64,
}

impl fmt::Debug for RedirectNextRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedirectNextRequest")
            .field("origin", &Origin::from_url(&self.url).ok())
            .field("target_sha256", &target_hash(&self.url))
            .field("method", &self.method)
            .field("body_disposition", &self.body_disposition)
            .field("body_sha256", &self.body_sha256)
            .field("body_bytes", &self.body_bytes)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectStep {
    pub redirect_depth: u8,
    pub status_code: u16,
    pub from_origin: Origin,
    pub to_origin: Origin,
    pub origin_transition: OriginTransition,
    pub secret_disposition: RedirectSecretDisposition,
    pub session_generation: u64,
    pub next_request: RedirectNextRequest,
    pub authorization: ConnectionAuthorization,
}

impl RedirectStep {
    pub fn is_authorized(&self) -> bool {
        self.authorization.decision.outcome == DecisionOutcome::Allow
            && self.authorization.ticket.is_some()
    }
}
