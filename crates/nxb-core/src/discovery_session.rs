use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::Path,
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::live_orchestrator::PlannedMethod;

pub const DISCOVERY_SESSION_PLAN_VERSION: u32 = 1;
pub const DISCOVERY_SESSION_ACTIVATION_VERSION: u32 = 1;
pub const MAX_DISCOVERY_SESSION_LIFETIME_SECONDS: i64 = 4 * 60 * 60;
pub const MAX_DISCOVERY_SESSION_ACTIVATION_SECONDS: i64 = 60 * 60;
pub const MAX_DISCOVERY_SESSION_REQUESTS: u64 = 128;
pub const MAX_DISCOVERY_SESSION_DEPTH: u16 = 4;
pub const MAX_DISCOVERY_SESSION_RESPONSE_BODY_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_DISCOVERY_SESSION_TOTAL_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_DISCOVERY_SESSION_PATH_PREFIXES: usize = 32;
pub const MIN_DISCOVERY_SESSION_INTERVAL_MILLISECONDS: u64 = 200;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySessionPlan {
    pub version: u32,
    pub session_id: String,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub policy_sha256: String,
    pub seed_url: String,
    pub seed_method: PlannedMethod,
    pub target_origin_sha256: String,
    pub selected_ip: IpAddr,
    pub resolved_ips: BTreeSet<IpAddr>,
    pub allowed_methods: BTreeSet<PlannedMethod>,
    pub allowed_path_prefixes: BTreeSet<String>,
    pub dns_context_id: String,
    pub dns_resolver_id: String,
    pub dns_ttl_seconds: u32,
    pub maximum_requests: u64,
    pub maximum_depth: u16,
    pub maximum_response_body_bytes: u64,
    pub maximum_total_response_bytes: u64,
    pub minimum_request_interval_milliseconds: u64,
    pub maximum_concurrency: u16,
    pub activation_key_id_sha256: String,
    pub plan_sha256: String,
}

impl DiscoverySessionPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        session_id: impl Into<String>,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        policy_bytes: &[u8],
        seed_url: impl Into<String>,
        seed_method: PlannedMethod,
        selected_ip: IpAddr,
        resolved_ips: BTreeSet<IpAddr>,
        allowed_methods: BTreeSet<PlannedMethod>,
        allowed_path_prefixes: BTreeSet<String>,
        dns_context_id: impl Into<String>,
        dns_resolver_id: impl Into<String>,
        dns_ttl_seconds: u32,
        maximum_requests: u64,
        maximum_depth: u16,
        maximum_response_body_bytes: u64,
        maximum_total_response_bytes: u64,
        minimum_request_interval_milliseconds: u64,
        activation_public_key: &[u8],
    ) -> Result<Self> {
        let seed_url = seed_url.into();
        let seed = validate_candidate_url(&seed_url)?;
        let mut plan = Self {
            version: DISCOVERY_SESSION_PLAN_VERSION,
            session_id: session_id.into(),
            created_at_epoch_seconds: created_at.timestamp(),
            expires_at_epoch_seconds: expires_at.timestamp(),
            policy_sha256: hash_bytes(policy_bytes),
            seed_url,
            seed_method,
            target_origin_sha256: hash_bytes(normalized_origin(&seed)?.as_bytes()),
            selected_ip,
            resolved_ips,
            allowed_methods,
            allowed_path_prefixes,
            dns_context_id: dns_context_id.into(),
            dns_resolver_id: dns_resolver_id.into(),
            dns_ttl_seconds,
            maximum_requests,
            maximum_depth,
            maximum_response_body_bytes,
            maximum_total_response_bytes,
            minimum_request_interval_milliseconds,
            maximum_concurrency: 1,
            activation_key_id_sha256: hash_bytes(activation_public_key),
            plan_sha256: String::new(),
        };
        plan.validate()?;
        plan.plan_sha256 = plan.calculate_sha256()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != DISCOVERY_SESSION_PLAN_VERSION {
            bail!("unsupported discovery-session plan version");
        }
        validate_identifier(&self.session_id, "session_id")?;
        validate_identifier(&self.dns_context_id, "dns_context_id")?;
        validate_identifier(&self.dns_resolver_id, "dns_resolver_id")?;
        validate_sha256(&self.policy_sha256, "policy_sha256")?;
        validate_sha256(&self.target_origin_sha256, "target_origin_sha256")?;
        validate_sha256(&self.activation_key_id_sha256, "activation_key_id_sha256")?;
        if !self.plan_sha256.is_empty() {
            validate_sha256(&self.plan_sha256, "plan_sha256")?;
        }
        if self.created_at_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.created_at_epoch_seconds
            || self
                .expires_at_epoch_seconds
                .saturating_sub(self.created_at_epoch_seconds)
                > MAX_DISCOVERY_SESSION_LIFETIME_SECONDS
        {
            bail!("discovery-session validity window is invalid");
        }
        if self.maximum_requests == 0 || self.maximum_requests > MAX_DISCOVERY_SESSION_REQUESTS {
            bail!("discovery-session request budget is outside supported bounds");
        }
        if self.maximum_depth > MAX_DISCOVERY_SESSION_DEPTH {
            bail!("discovery-session depth exceeds the supported bound");
        }
        if self.maximum_response_body_bytes == 0
            || self.maximum_response_body_bytes > MAX_DISCOVERY_SESSION_RESPONSE_BODY_BYTES
        {
            bail!("per-response body budget is outside supported bounds");
        }
        if self.maximum_total_response_bytes < self.maximum_response_body_bytes
            || self.maximum_total_response_bytes > MAX_DISCOVERY_SESSION_TOTAL_RESPONSE_BYTES
        {
            bail!("total response byte budget is outside supported bounds");
        }
        if self.minimum_request_interval_milliseconds < MIN_DISCOVERY_SESSION_INTERVAL_MILLISECONDS
        {
            bail!("discovery-session request interval is too aggressive");
        }
        if self.maximum_concurrency != 1 {
            bail!("discovery-session v1 requires sequential request execution");
        }
        if self.dns_ttl_seconds == 0 || self.dns_ttl_seconds > 86_400 {
            bail!("DNS TTL is outside discovery-session bounds");
        }
        if self.resolved_ips.is_empty()
            || !self.resolved_ips.contains(&self.selected_ip)
            || self
                .resolved_ips
                .iter()
                .any(|ip| !nxb_policy::is_public_destination(*ip))
        {
            bail!("resolved IP set is empty, non-public, or omits the selected IP");
        }
        if self.allowed_methods.is_empty()
            || self.allowed_methods.len() > 2
            || !self.allowed_methods.contains(&self.seed_method)
        {
            bail!("allowed methods must contain the seed GET/HEAD method");
        }
        if self.allowed_path_prefixes.is_empty()
            || self.allowed_path_prefixes.len() > MAX_DISCOVERY_SESSION_PATH_PREFIXES
        {
            bail!("allowed path-prefix set is empty or oversized");
        }
        for prefix in &self.allowed_path_prefixes {
            validate_path(prefix, "allowed path prefix")?;
        }
        let seed = validate_candidate_url(&self.seed_url)?;
        if hash_bytes(normalized_origin(&seed)?.as_bytes()) != self.target_origin_sha256 {
            bail!("seed origin digest does not match the discovery-session plan");
        }
        self.authorize_candidate(&seed, self.seed_method, 0)
    }

    pub fn calculate_sha256(&self) -> Result<String> {
        let mut material = self.clone();
        material.plan_sha256.clear();
        hash_serializable(&material)
    }

    pub fn verify(&self, now: DateTime<Utc>) -> Result<()> {
        self.validate()?;
        if self.plan_sha256 != self.calculate_sha256()? {
            bail!("discovery-session plan digest mismatch");
        }
        let now = now.timestamp();
        if now < self.created_at_epoch_seconds || now > self.expires_at_epoch_seconds {
            bail!("discovery-session plan is outside its validity window");
        }
        Ok(())
    }

    pub fn seed(&self) -> Result<Url> {
        validate_candidate_url(&self.seed_url)
    }

    pub fn authorize_candidate(
        &self,
        candidate: &Url,
        method: PlannedMethod,
        depth: u16,
    ) -> Result<()> {
        let candidate = validate_candidate_url(candidate.as_str())?;
        if hash_bytes(normalized_origin(&candidate)?.as_bytes()) != self.target_origin_sha256 {
            bail!("candidate origin is outside the signed discovery session");
        }
        if !self.allowed_methods.contains(&method) {
            bail!("candidate method is outside the signed discovery session");
        }
        if depth > self.maximum_depth {
            bail!("candidate depth exceeds the signed discovery session");
        }
        let path = request_target(&candidate)?;
        if !self
            .allowed_path_prefixes
            .iter()
            .any(|prefix| path_matches_prefix(&path, prefix))
        {
            bail!("candidate path is outside the signed discovery session");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySessionActivationPayload {
    pub version: u32,
    pub activation_id: String,
    pub plan_sha256: String,
    pub policy_sha256: String,
    pub target_origin_sha256: String,
    pub maximum_requests: u64,
    pub maximum_total_response_bytes: u64,
    pub not_before_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub signer_key_id_sha256: String,
}

impl DiscoverySessionActivationPayload {
    pub fn template(
        activation_id: impl Into<String>,
        plan: &DiscoverySessionPlan,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        plan.validate()?;
        let payload = Self {
            version: DISCOVERY_SESSION_ACTIVATION_VERSION,
            activation_id: activation_id.into(),
            plan_sha256: plan.plan_sha256.clone(),
            policy_sha256: plan.policy_sha256.clone(),
            target_origin_sha256: plan.target_origin_sha256.clone(),
            maximum_requests: plan.maximum_requests,
            maximum_total_response_bytes: plan.maximum_total_response_bytes,
            not_before_epoch_seconds: not_before.timestamp(),
            expires_at_epoch_seconds: expires_at.timestamp(),
            signer_key_id_sha256: plan.activation_key_id_sha256.clone(),
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != DISCOVERY_SESSION_ACTIVATION_VERSION {
            bail!("unsupported discovery-session activation version");
        }
        validate_identifier(&self.activation_id, "activation_id")?;
        for (value, field) in [
            (&self.plan_sha256, "plan_sha256"),
            (&self.policy_sha256, "policy_sha256"),
            (&self.target_origin_sha256, "target_origin_sha256"),
            (&self.signer_key_id_sha256, "signer_key_id_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        if self.maximum_requests == 0
            || self.maximum_requests > MAX_DISCOVERY_SESSION_REQUESTS
            || self.maximum_total_response_bytes == 0
            || self.maximum_total_response_bytes > MAX_DISCOVERY_SESSION_TOTAL_RESPONSE_BYTES
        {
            bail!("discovery-session activation budget is invalid");
        }
        if self.not_before_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.not_before_epoch_seconds
            || self
                .expires_at_epoch_seconds
                .saturating_sub(self.not_before_epoch_seconds)
                > MAX_DISCOVERY_SESSION_ACTIVATION_SECONDS
        {
            bail!("discovery-session activation window is invalid");
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).context("could not serialize discovery-session activation")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySessionActivationCertificate {
    pub payload: DiscoverySessionActivationPayload,
    pub signature_hex: String,
}

impl DiscoverySessionActivationCertificate {
    pub fn verify(
        &self,
        plan: &DiscoverySessionPlan,
        public_key: &[u8],
        now: DateTime<Utc>,
    ) -> Result<()> {
        plan.verify(now)?;
        self.payload.validate()?;
        if public_key.len() != 32 {
            bail!("Ed25519 discovery-session key must contain 32 bytes");
        }
        if hash_bytes(public_key) != self.payload.signer_key_id_sha256
            || self.payload.signer_key_id_sha256 != plan.activation_key_id_sha256
        {
            bail!("discovery-session signer key does not match the plan");
        }
        if self.payload.plan_sha256 != plan.plan_sha256
            || self.payload.policy_sha256 != plan.policy_sha256
            || self.payload.target_origin_sha256 != plan.target_origin_sha256
            || self.payload.maximum_requests != plan.maximum_requests
            || self.payload.maximum_total_response_bytes != plan.maximum_total_response_bytes
        {
            bail!("discovery-session activation does not match the plan");
        }
        let now = now.timestamp();
        if now < self.payload.not_before_epoch_seconds
            || now > self.payload.expires_at_epoch_seconds
            || self.payload.expires_at_epoch_seconds > plan.expires_at_epoch_seconds
        {
            bail!("discovery-session activation is outside its validity window");
        }
        let signature = decode_lower_hex(&self.signature_hex, "signature_hex")?;
        if signature.len() != 64 {
            bail!("Ed25519 discovery-session signature must contain 64 bytes");
        }
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&self.payload.signing_bytes()?, &signature)
            .map_err(|_| anyhow::anyhow!("discovery-session signature verification failed"))
    }

    pub fn certificate_sha256(&self) -> Result<String> {
        hash_serializable(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DiscoverySessionUseMarker {
    version: u32,
    session_id_sha256: String,
    activation_id_sha256: String,
    activation_certificate_sha256: String,
    plan_sha256: String,
    consumed_at_epoch_seconds: i64,
    state: String,
}

pub fn consume_activation_once(
    state_directory: &Path,
    plan: &DiscoverySessionPlan,
    activation: &DiscoverySessionActivationCertificate,
    now: DateTime<Utc>,
) -> Result<String> {
    fs::create_dir_all(state_directory).with_context(|| {
        format!(
            "could not create discovery-session state directory {}",
            state_directory.display()
        )
    })?;
    let certificate_sha256 = activation.certificate_sha256()?;
    let session_id_sha256 = hash_bytes(plan.session_id.as_bytes());
    let activation_id_sha256 = hash_bytes(activation.payload.activation_id.as_bytes());
    let marker_path = state_directory.join(format!(
        "discovery-session-{session_id_sha256}-{activation_id_sha256}.used.json"
    ));
    let marker = DiscoverySessionUseMarker {
        version: 1,
        session_id_sha256,
        activation_id_sha256,
        activation_certificate_sha256: certificate_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        consumed_at_epoch_seconds: now.timestamp(),
        state: "consumed_fail_closed_no_resume".into(),
    };
    let bytes = serde_json::to_vec_pretty(&marker)
        .context("could not serialize discovery-session use marker")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .with_context(|| {
            format!(
                "discovery-session activation was already used or marker could not be created: {}",
                marker_path.display()
            )
        })?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(certificate_sha256)
}

pub fn validate_request_interval_against_policy(
    plan: &DiscoverySessionPlan,
    maximum_requests_per_second: f64,
) -> Result<()> {
    if !maximum_requests_per_second.is_finite() || maximum_requests_per_second <= 0.0 {
        bail!("compiled policy request rate is invalid");
    }
    let policy_interval = (1000.0 / maximum_requests_per_second).ceil() as u64;
    if plan.minimum_request_interval_milliseconds < policy_interval {
        bail!("signed discovery-session interval exceeds the program policy rate");
    }
    Ok(())
}

pub fn method_from_code(value: &str) -> Result<PlannedMethod> {
    match value {
        "GET" => Ok(PlannedMethod::Get),
        "HEAD" => Ok(PlannedMethod::Head),
        _ => bail!("discovery-session candidate method is not GET or HEAD"),
    }
}

pub fn hash_serializable<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).context("could not serialize digest material")?;
    Ok(hash_bytes(&bytes))
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

pub fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn validate_candidate_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("discovery-session URL is invalid")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("discovery-session URLs must be credential-free HTTPS/443 without query or fragment");
    }
    let host = url
        .host_str()
        .context("discovery-session URL has no host")?;
    if host.parse::<IpAddr>().is_ok()
        || host.ends_with('.')
        || !host.is_ascii()
        || host
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        bail!("discovery-session URLs require a normalized DNS hostname");
    }
    validate_path(
        if url.path().is_empty() {
            "/"
        } else {
            url.path()
        },
        "request path",
    )?;
    Ok(url)
}

fn request_target(url: &Url) -> Result<String> {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    validate_path(path, "request path")?;
    Ok(path.to_string())
}

fn normalized_origin(url: &Url) -> Result<String> {
    let host = url
        .host_str()
        .context("discovery-session URL has no host")?
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .context("discovery-session URL has no usable port")?;
    Ok(format!("{}://{}:{}", url.scheme(), host, port))
}

fn validate_path(value: &str, field: &str) -> Result<()> {
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
    {
        bail!("{field} is outside the passive discovery-session contract");
    }
    if value.split('/').any(|segment| {
        DENIED_PATH_SEGMENTS
            .iter()
            .any(|denied| segment.eq_ignore_ascii_case(denied))
    }) {
        bail!("{field} contains a denied action segment");
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

fn validate_identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("{field} is invalid");
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} is not lowercase SHA-256");
    }
    Ok(())
}

fn decode_lower_hex(value: &str, field: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} is not canonical lowercase hexadecimal");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0]).context("invalid hexadecimal")?;
            let low = decode_nibble(pair[1]).context("invalid hexadecimal")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn test_plan(public_key: &[u8]) -> DiscoverySessionPlan {
        DiscoverySessionPlan::build(
            "session-test-1",
            DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            DateTime::from_timestamp(1_800_003_600, 0).unwrap(),
            b"policy-fixture",
            "https://example.com/app/",
            PlannedMethod::Get,
            "93.184.216.34".parse().unwrap(),
            BTreeSet::from(["93.184.216.34".parse().unwrap()]),
            BTreeSet::from([PlannedMethod::Get, PlannedMethod::Head]),
            BTreeSet::from(["/app".to_string()]),
            "dns-context-session-1",
            "operator-signed-dns-observation",
            60,
            16,
            2,
            1024 * 1024,
            8 * 1024 * 1024,
            1000,
            public_key,
        )
        .unwrap()
    }

    #[test]
    fn plan_rejects_cross_origin_and_prefix_escape() {
        let plan = test_plan(&[7_u8; 32]);
        plan.verify(DateTime::from_timestamp(1_800_000_100, 0).unwrap())
            .unwrap();
        assert!(plan
            .authorize_candidate(
                &Url::parse("https://other.example/app/health").unwrap(),
                PlannedMethod::Get,
                1,
            )
            .is_err());
        assert!(plan
            .authorize_candidate(
                &Url::parse("https://example.com/application").unwrap(),
                PlannedMethod::Get,
                1,
            )
            .is_err());
        plan.authorize_candidate(
            &Url::parse("https://example.com/app/health").unwrap(),
            PlannedMethod::Head,
            2,
        )
        .unwrap();
    }

    #[test]
    fn activation_binds_exact_session_budget() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[11_u8; 32]).unwrap();
        let plan = test_plan(key_pair.public_key().as_ref());
        let payload = DiscoverySessionActivationPayload::template(
            "session-activation-1",
            &plan,
            DateTime::from_timestamp(1_800_000_050, 0).unwrap(),
            DateTime::from_timestamp(1_800_000_600, 0).unwrap(),
        )
        .unwrap();
        let signature = key_pair.sign(&payload.signing_bytes().unwrap());
        let certificate = DiscoverySessionActivationCertificate {
            payload,
            signature_hex: lower_hex(signature.as_ref()),
        };
        certificate
            .verify(
                &plan,
                key_pair.public_key().as_ref(),
                DateTime::from_timestamp(1_800_000_100, 0).unwrap(),
            )
            .unwrap();
        let mut tampered = plan.clone();
        tampered.maximum_requests += 1;
        tampered.plan_sha256 = tampered.calculate_sha256().unwrap();
        assert!(certificate
            .verify(
                &tampered,
                key_pair.public_key().as_ref(),
                DateTime::from_timestamp(1_800_000_100, 0).unwrap(),
            )
            .is_err());
    }
}
