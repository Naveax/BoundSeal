use std::{collections::BTreeSet, net::IpAddr};

use serde::{Deserialize, Serialize};

use crate::{
    contract::{validate_identifier, LiveRunLaunchBundle},
    LiveRunHostError,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsResolutionRequest {
    pub resolver_id: String,
    pub context_id: String,
    pub authority: String,
    pub port: u16,
    pub request_index: u64,
    pub request_target_sha256: String,
}

impl DnsResolutionRequest {
    pub fn validate(&self, bundle: &LiveRunLaunchBundle) -> Result<(), LiveRunHostError> {
        validate_identifier(&self.resolver_id, "resolver_id")?;
        validate_identifier(&self.context_id, "context_id")?;
        if self.resolver_id != bundle.dns_resolver_id
            || self.authority != bundle.authority
            || self.port != 443
            || self.request_target_sha256.len() != 64
        {
            return Err(LiveRunHostError::InvalidDnsResult(
                "request binding mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LiveDnsResolution {
    pub resolver_id: String,
    pub context_id: String,
    pub addresses: BTreeSet<IpAddr>,
    pub selected_ip: IpAddr,
    pub ttl_seconds: u32,
}

impl LiveDnsResolution {
    pub fn validate(
        &self,
        bundle: &LiveRunLaunchBundle,
        request: &DnsResolutionRequest,
    ) -> Result<(), LiveRunHostError> {
        request.validate(bundle)?;
        validate_identifier(&self.resolver_id, "resolution.resolver_id")?;
        validate_identifier(&self.context_id, "resolution.context_id")?;
        if self.resolver_id != request.resolver_id
            || self.context_id != request.context_id
            || self.addresses.is_empty()
            || self.addresses.len() > bundle.maximum_dns_addresses as usize
            || !self.addresses.contains(&self.selected_ip)
            || self.ttl_seconds == 0
            || self.ttl_seconds > bundle.maximum_dns_ttl_seconds
        {
            return Err(LiveRunHostError::InvalidDnsResult(
                "resolution exceeds the signed launch bounds".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResolutionFailure {
    code: String,
}

impl DnsResolutionFailure {
    pub fn new(code: impl Into<String>) -> Result<Self, LiveRunHostError> {
        let code = code.into();
        validate_identifier(&code, "dns_failure_code")?;
        Ok(Self { code })
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

impl std::fmt::Display for DnsResolutionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.code)
    }
}

impl std::error::Error for DnsResolutionFailure {}

pub trait LiveDnsResolver {
    fn resolve(
        &mut self,
        request: &DnsResolutionRequest,
    ) -> Result<LiveDnsResolution, DnsResolutionFailure>;
}

#[derive(Debug, Clone)]
pub struct StaticDnsResolver {
    resolver_id: String,
    addresses: BTreeSet<IpAddr>,
    selected_ip: IpAddr,
    ttl_seconds: u32,
}

impl StaticDnsResolver {
    pub fn new(
        resolver_id: impl Into<String>,
        addresses: BTreeSet<IpAddr>,
        selected_ip: IpAddr,
        ttl_seconds: u32,
    ) -> Result<Self, LiveRunHostError> {
        let resolver_id = resolver_id.into();
        validate_identifier(&resolver_id, "resolver_id")?;
        if addresses.is_empty() || !addresses.contains(&selected_ip) || ttl_seconds == 0 {
            return Err(LiveRunHostError::InvalidDnsResult(
                "static resolver configuration".into(),
            ));
        }
        Ok(Self {
            resolver_id,
            addresses,
            selected_ip,
            ttl_seconds,
        })
    }
}

impl LiveDnsResolver for StaticDnsResolver {
    fn resolve(
        &mut self,
        request: &DnsResolutionRequest,
    ) -> Result<LiveDnsResolution, DnsResolutionFailure> {
        if request.resolver_id != self.resolver_id {
            return Err(DnsResolutionFailure {
                code: "resolver_id_mismatch".into(),
            });
        }
        Ok(LiveDnsResolution {
            resolver_id: self.resolver_id.clone(),
            context_id: request.context_id.clone(),
            addresses: self.addresses.clone(),
            selected_ip: self.selected_ip,
            ttl_seconds: self.ttl_seconds,
        })
    }
}
