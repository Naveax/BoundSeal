use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub const MAX_OBSERVED_HEADERS: usize = 512;
pub const MAX_OBSERVED_HEADER_BYTES: usize = 256 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AnalyzerError {
    #[error("response observation is invalid: {0}")]
    InvalidObservation(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub finding_id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub origin: String,
    pub endpoint_sha256: String,
    pub evidence_sha256: String,
    pub summary: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedHeader {
    pub name: String,
    value: Vec<u8>,
}

impl ObservedHeader {
    pub fn new(name: impl Into<String>, value: impl Into<Vec<u8>>) -> Result<Self, AnalyzerError> {
        let name = name.into().to_ascii_lowercase();
        let value = value.into();
        if name.is_empty()
            || name.len() > 128
            || !name.bytes().all(valid_token_byte)
            || value.len() > 32 * 1024
            || value
                .iter()
                .any(|byte| matches!(*byte, 0 | b'\r' | b'\n'))
        {
            return Err(AnalyzerError::InvalidObservation(
                "header name or value".into(),
            ));
        }
        Ok(Self { name, value })
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn value_text(&self) -> String {
        String::from_utf8_lossy(&self.value).into_owned()
    }

    pub fn value_sha256(&self) -> String {
        hash_bytes(&self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseObservation {
    pub url: Url,
    pub status: u16,
    pub authenticated: bool,
    pub headers: Vec<ObservedHeader>,
    pub body_sha256: String,
    pub body_bytes: u64,
    pub tls: Option<TlsObservation>,
}

impl ResponseObservation {
    pub fn validate(&self) -> Result<(), AnalyzerError> {
        if !matches!(self.url.scheme(), "http" | "https")
            || self.url.host_str().is_none()
            || !self.url.username().is_empty()
            || self.url.password().is_some()
            || !(100..=599).contains(&self.status)
            || self.headers.len() > MAX_OBSERVED_HEADERS
            || self
                .headers
                .iter()
                .map(|header| header.name.len() + header.value.len() + 4)
                .sum::<usize>()
                > MAX_OBSERVED_HEADER_BYTES
            || !is_sha256(&self.body_sha256)
            || self.body_bytes > 128 * 1024 * 1024
        {
            return Err(AnalyzerError::InvalidObservation(
                "response bounds or identity".into(),
            ));
        }
        Ok(())
    }

    pub fn origin(&self) -> Result<String, AnalyzerError> {
        let host = self
            .url
            .host_str()
            .ok_or_else(|| AnalyzerError::InvalidObservation("missing host".into()))?
            .to_ascii_lowercase();
        let port = self
            .url
            .port_or_known_default()
            .ok_or_else(|| AnalyzerError::InvalidObservation("missing port".into()))?;
        Ok(format!("{}://{}:{}", self.url.scheme(), host, port))
    }

    pub fn endpoint_sha256(&self) -> String {
        hash_bytes(self.url.as_str().as_bytes())
    }

    pub fn values(&self, name: &str) -> Vec<&[u8]> {
        self.headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(name))
            .map(ObservedHeader::value)
            .collect()
    }

    pub fn first_text(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(ObservedHeader::value_text)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsObservation {
    pub verified: bool,
    pub protocol: String,
    pub alpn: String,
    pub leaf_not_after_epoch_seconds: i64,
    pub observed_at_epoch_seconds: i64,
    pub hostname_covered: bool,
    pub wildcard_san: bool,
    pub chain_depth: usize,
    pub trusted_root_sha256: String,
    pub session_resumed: bool,
    pub early_data_accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedirectObservation {
    pub from_url: String,
    pub to_url: String,
    pub status: u16,
    pub original_method: String,
    pub next_method: String,
    pub body_preserved: bool,
    pub credential_headers_forwarded: bool,
    pub cookie_rematerialized: bool,
    pub session_generation_before: u64,
    pub session_generation_after: u64,
    pub chain_depth: u8,
    pub loop_detected: bool,
}

pub trait PassiveAnalyzer {
    fn analyze(&self, response: &ResponseObservation) -> Result<Vec<Finding>, AnalyzerError>;
}

#[derive(Debug, Default)]
pub struct HeaderSecurityAnalyzer;
