use std::{collections::BTreeSet, net::IpAddr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

const POLICY_SCHEMA_VERSION: u32 = 1;
const MAX_REQUESTS_PER_SECOND: f64 = 5.0;
const MAX_CONCURRENCY: u16 = 8;
const MAX_TOTAL_REQUESTS: u64 = 100_000;
const ALLOWED_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetPolicy {
    pub schema_version: u32,
    pub program: ProgramPolicy,
    pub scope: ScopePolicy,
    pub automation: AutomationPolicy,
    pub authorization: AuthorizationPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramPolicy {
    pub name: String,
    pub platform: String,
    pub policy_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePolicy {
    pub include_hosts: BTreeSet<String>,
    #[serde(default)]
    pub exclude_hosts: BTreeSet<String>,
    pub allowed_schemes: BTreeSet<String>,
    pub allowed_methods: BTreeSet<String>,
    #[serde(default)]
    pub allow_subdomains: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationPolicy {
    pub active_testing: bool,
    pub credential_bruteforce: bool,
    pub destructive_testing: bool,
    pub oob_callbacks: bool,
    pub max_requests_per_second: f64,
    pub max_concurrency: u16,
    pub max_total_requests: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationPolicy {
    pub confirmed: bool,
    pub researcher: String,
    pub policy_snapshot_sha256: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    inner: TargetPolicy,
    include_hosts: BTreeSet<String>,
    exclude_hosts: BTreeSet<String>,
    allowed_schemes: BTreeSet<String>,
    allowed_methods: BTreeSet<String>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy TOML could not be parsed: {0}")]
    Parse(String),
    #[error("policy is invalid: {0}")]
    Invalid(String),
}

impl TargetPolicy {
    pub fn from_toml(input: &str) -> Result<Self, PolicyError> {
        toml::from_str(input).map_err(|error| PolicyError::Parse(error.to_string()))
    }

    pub fn compile(self, now: DateTime<Utc>) -> Result<CompiledPolicy, PolicyError> {
        validate_top_level(&self, now)?;

        let include_hosts = normalize_host_set(&self.scope.include_hosts, "include_hosts")?;
        let exclude_hosts = normalize_host_set(&self.scope.exclude_hosts, "exclude_hosts")?;
        let allowed_schemes = normalize_schemes(&self.scope.allowed_schemes)?;
        let allowed_methods = normalize_methods(&self.scope.allowed_methods)?;

        if include_hosts
            .iter()
            .any(|host| exclude_hosts.contains(host))
        {
            return Err(PolicyError::Invalid(
                "a host cannot be present in both include_hosts and exclude_hosts".into(),
            ));
        }

        Ok(CompiledPolicy {
            inner: self,
            include_hosts,
            exclude_hosts,
            allowed_schemes,
            allowed_methods,
        })
    }
}

impl CompiledPolicy {
    pub fn program_name(&self) -> &str {
        &self.inner.program.name
    }

    pub fn included_host_count(&self) -> usize {
        self.include_hosts.len()
    }

    pub fn maximum_total_requests(&self) -> u64 {
        self.inner.automation.max_total_requests
    }

    pub fn allows_host(&self, candidate: &str) -> bool {
        let candidate = candidate.trim().to_ascii_lowercase();

        if matches_host_set(&candidate, &self.exclude_hosts, true) {
            return false;
        }

        matches_host_set(
            &candidate,
            &self.include_hosts,
            self.inner.scope.allow_subdomains,
        )
    }

    pub fn allows_request(&self, url: &Url, method: &str) -> bool {
        if !url.username().is_empty() || url.password().is_some() {
            return false;
        }

        let Some(host) = url.host_str() else {
            return false;
        };

        self.allowed_schemes.contains(url.scheme())
            && self.allowed_methods.contains(&method.to_ascii_uppercase())
            && self.allows_host(host)
    }
}

fn validate_top_level(policy: &TargetPolicy, now: DateTime<Utc>) -> Result<(), PolicyError> {
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        return Err(PolicyError::Invalid(format!(
            "unsupported schema_version {}; expected {POLICY_SCHEMA_VERSION}",
            policy.schema_version
        )));
    }

    if policy.program.name.trim().is_empty() || policy.program.platform.trim().is_empty() {
        return Err(PolicyError::Invalid(
            "program name and platform must be non-empty".into(),
        ));
    }

    if policy.scope.include_hosts.is_empty() {
        return Err(PolicyError::Invalid(
            "at least one include host is required".into(),
        ));
    }

    if !policy.authorization.confirmed {
        return Err(PolicyError::Invalid(
            "explicit authorization confirmation is required".into(),
        ));
    }

    if policy.authorization.researcher.trim().is_empty() {
        return Err(PolicyError::Invalid(
            "authorization researcher must be non-empty".into(),
        ));
    }

    if policy.authorization.expires_at <= now {
        return Err(PolicyError::Invalid(
            "authorization has expired or is not in the future".into(),
        ));
    }

    if !is_lower_hex_sha256(&policy.authorization.policy_snapshot_sha256) {
        return Err(PolicyError::Invalid(
            "policy_snapshot_sha256 must be exactly 64 lowercase hexadecimal characters".into(),
        ));
    }

    if policy.automation.credential_bruteforce {
        return Err(PolicyError::Invalid(
            "credential brute force is hard-denied".into(),
        ));
    }

    if policy.automation.destructive_testing {
        return Err(PolicyError::Invalid(
            "destructive testing is hard-denied".into(),
        ));
    }

    if !policy.automation.max_requests_per_second.is_finite()
        || policy.automation.max_requests_per_second <= 0.0
        || policy.automation.max_requests_per_second > MAX_REQUESTS_PER_SECOND
    {
        return Err(PolicyError::Invalid(format!(
            "max_requests_per_second must be greater than 0 and at most {MAX_REQUESTS_PER_SECOND}"
        )));
    }

    if policy.automation.max_concurrency == 0 || policy.automation.max_concurrency > MAX_CONCURRENCY
    {
        return Err(PolicyError::Invalid(format!(
            "max_concurrency must be between 1 and {MAX_CONCURRENCY}"
        )));
    }

    if policy.automation.max_total_requests == 0
        || policy.automation.max_total_requests > MAX_TOTAL_REQUESTS
    {
        return Err(PolicyError::Invalid(format!(
            "max_total_requests must be between 1 and {MAX_TOTAL_REQUESTS}"
        )));
    }

    Ok(())
}

fn normalize_host_set(
    hosts: &BTreeSet<String>,
    field_name: &str,
) -> Result<BTreeSet<String>, PolicyError> {
    hosts
        .iter()
        .map(|host| normalize_dns_host(host, field_name))
        .collect()
}

fn normalize_dns_host(host: &str, field_name: &str) -> Result<String, PolicyError> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();

    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.contains("://")
        || normalized.contains('/')
        || normalized.contains('\\')
        || normalized.contains('*')
        || normalized.contains(':')
    {
        return Err(PolicyError::Invalid(format!(
            "{field_name} contains an invalid DNS host: {host}"
        )));
    }

    for label in normalized.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(PolicyError::Invalid(format!(
                "{field_name} contains an invalid DNS label in host: {host}"
            )));
        }
    }

    Ok(normalized)
}

fn normalize_schemes(schemes: &BTreeSet<String>) -> Result<BTreeSet<String>, PolicyError> {
    if schemes.is_empty() {
        return Err(PolicyError::Invalid(
            "allowed_schemes must not be empty".into(),
        ));
    }

    schemes
        .iter()
        .map(|scheme| {
            let normalized = scheme.trim().to_ascii_lowercase();
            if normalized != "http" && normalized != "https" {
                return Err(PolicyError::Invalid(format!(
                    "unsupported scheme: {scheme}"
                )));
            }
            Ok(normalized)
        })
        .collect()
}

fn normalize_methods(methods: &BTreeSet<String>) -> Result<BTreeSet<String>, PolicyError> {
    if methods.is_empty() {
        return Err(PolicyError::Invalid(
            "allowed_methods must not be empty".into(),
        ));
    }

    methods
        .iter()
        .map(|method| {
            let normalized = method.trim().to_ascii_uppercase();
            if !ALLOWED_METHODS.contains(&normalized.as_str()) {
                return Err(PolicyError::Invalid(format!(
                    "unsupported HTTP method: {method}"
                )));
            }
            Ok(normalized)
        })
        .collect()
}

fn matches_host_set(candidate: &str, hosts: &BTreeSet<String>, allow_subdomains: bool) -> bool {
    hosts.iter().any(|host| {
        candidate == host
            || (allow_subdomains
                && candidate.len() > host.len()
                && candidate.ends_with(host)
                && candidate.as_bytes()[candidate.len() - host.len() - 1] == b'.')
    })
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn is_public_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_unspecified()
                && !ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            let unique_local = first & 0xfe00 == 0xfc00;
            let link_local = first & 0xffc0 == 0xfe80;

            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !unique_local
                && !link_local
                && ip
                    .to_ipv4_mapped()
                    .map(is_public_destination_v4)
                    .unwrap_or(true)
        }
    }
}

fn is_public_destination_v4(ip: std::net::Ipv4Addr) -> bool {
    is_public_destination(IpAddr::V4(ip))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use chrono::{Duration, Utc};
    use url::Url;

    use super::*;

    fn valid_policy() -> TargetPolicy {
        TargetPolicy {
            schema_version: 1,
            program: ProgramPolicy {
                name: "Example Program".into(),
                platform: "hackerone".into(),
                policy_url: Some("https://hackerone.com/example".into()),
            },
            scope: ScopePolicy {
                include_hosts: BTreeSet::from(["app.example.com".into()]),
                exclude_hosts: BTreeSet::from(["status.app.example.com".into()]),
                allowed_schemes: BTreeSet::from(["https".into()]),
                allowed_methods: BTreeSet::from(["GET".into(), "HEAD".into()]),
                allow_subdomains: true,
            },
            automation: AutomationPolicy {
                active_testing: false,
                credential_bruteforce: false,
                destructive_testing: false,
                oob_callbacks: false,
                max_requests_per_second: 1.0,
                max_concurrency: 2,
                max_total_requests: 1_000,
            },
            authorization: AuthorizationPolicy {
                confirmed: true,
                researcher: "naveax".into(),
                policy_snapshot_sha256: "a".repeat(64),
                expires_at: Utc::now() + Duration::days(7),
            },
        }
    }

    #[test]
    fn compiles_and_checks_scope() {
        let compiled = valid_policy().compile(Utc::now()).unwrap();
        assert!(compiled.allows_request(
            &Url::parse("https://api.app.example.com/v1/me").unwrap(),
            "GET"
        ));
        assert!(!compiled.allows_request(
            &Url::parse("https://status.app.example.com/").unwrap(),
            "GET"
        ));
        assert!(
            !compiled.allows_request(&Url::parse("https://app.example.com/").unwrap(), "DELETE")
        );
    }

    #[test]
    fn rejects_credential_bruteforce() {
        let mut policy = valid_policy();
        policy.automation.credential_bruteforce = true;
        let error = policy.compile(Utc::now()).unwrap_err();
        assert!(error.to_string().contains("hard-denied"));
    }

    #[test]
    fn rejects_expired_authorization() {
        let mut policy = valid_policy();
        policy.authorization.expires_at = Utc::now() - Duration::seconds(1);
        assert!(policy.compile(Utc::now()).is_err());
    }

    #[test]
    fn destination_guard_rejects_non_public_ranges() {
        for value in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.10",
            "169.254.1.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(!is_public_destination(value.parse::<IpAddr>().unwrap()));
        }
        assert!(is_public_destination("8.8.8.8".parse().unwrap()));
        assert!(is_public_destination(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }
}
