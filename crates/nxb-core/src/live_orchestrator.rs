use std::{collections::BTreeSet, fs, net::IpAddr, path::Path};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

pub const LIVE_PLAN_VERSION: u32 = 1;
pub const LIVE_ACTIVATION_VERSION: u32 = 1;
pub const MAX_LIVE_PLAN_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
pub const MAX_ACTIVATION_LIFETIME_SECONDS: i64 = 60 * 60;
pub const LIVE_MVP_MAXIMUM_REQUESTS: u64 = 1;

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum PlannedMethod {
    Get,
    Head,
}

impl PlannedMethod {
    pub fn code(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveRunPlan {
    pub version: u32,
    pub run_id: String,
    pub created_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub policy_sha256: String,
    pub target_url: String,
    pub target_origin_sha256: String,
    pub selected_ip: IpAddr,
    pub resolved_ips: BTreeSet<IpAddr>,
    pub method: PlannedMethod,
    pub dns_context_id: String,
    pub dns_resolver_id: String,
    pub dns_ttl_seconds: u32,
    pub maximum_requests: u64,
    pub activation_key_id_sha256: String,
    pub plan_sha256: String,
}

impl LiveRunPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        run_id: impl Into<String>,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        policy_bytes: &[u8],
        target_url: impl Into<String>,
        selected_ip: IpAddr,
        resolved_ips: BTreeSet<IpAddr>,
        method: PlannedMethod,
        dns_context_id: impl Into<String>,
        dns_resolver_id: impl Into<String>,
        dns_ttl_seconds: u32,
        activation_public_key: &[u8],
    ) -> Result<Self> {
        let target_url = target_url.into();
        let parsed = validate_target_url(&target_url)?;
        let mut plan = Self {
            version: LIVE_PLAN_VERSION,
            run_id: run_id.into(),
            created_at_epoch_seconds: created_at.timestamp(),
            expires_at_epoch_seconds: expires_at.timestamp(),
            policy_sha256: hash_bytes(policy_bytes),
            target_url,
            target_origin_sha256: hash_bytes(normalized_origin(&parsed)?.as_bytes()),
            selected_ip,
            resolved_ips,
            method,
            dns_context_id: dns_context_id.into(),
            dns_resolver_id: dns_resolver_id.into(),
            dns_ttl_seconds,
            maximum_requests: LIVE_MVP_MAXIMUM_REQUESTS,
            activation_key_id_sha256: hash_bytes(activation_public_key),
            plan_sha256: String::new(),
        };
        plan.validate()?;
        plan.plan_sha256 = plan.calculate_sha256()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != LIVE_PLAN_VERSION {
            bail!("unsupported live-plan version");
        }
        validate_identifier(&self.run_id, "run_id")?;
        validate_identifier(&self.dns_context_id, "dns_context_id")?;
        validate_identifier(&self.dns_resolver_id, "dns_resolver_id")?;
        validate_sha256(&self.policy_sha256, "policy_sha256")?;
        validate_sha256(&self.target_origin_sha256, "target_origin_sha256")?;
        validate_sha256(&self.activation_key_id_sha256, "activation_key_id_sha256")?;
        if self.maximum_requests != LIVE_MVP_MAXIMUM_REQUESTS {
            bail!("live MVP permits exactly one request");
        }
        if self.created_at_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.created_at_epoch_seconds
            || self
                .expires_at_epoch_seconds
                .saturating_sub(self.created_at_epoch_seconds)
                > MAX_LIVE_PLAN_LIFETIME_SECONDS
        {
            bail!("live-plan validity window is invalid");
        }
        if self.dns_ttl_seconds == 0 || self.dns_ttl_seconds > 86_400 {
            bail!("DNS TTL is outside live-plan bounds");
        }
        if self.resolved_ips.is_empty()
            || !self.resolved_ips.contains(&self.selected_ip)
            || self
                .resolved_ips
                .iter()
                .any(|ip| !nxb_policy::is_public_destination(*ip))
        {
            bail!("resolved IP set is empty, non-public, or does not contain selected IP");
        }
        let target = validate_target_url(&self.target_url)?;
        if hash_bytes(normalized_origin(&target)?.as_bytes()) != self.target_origin_sha256 {
            bail!("target origin digest does not match URL");
        }
        if !self.plan_sha256.is_empty() {
            validate_sha256(&self.plan_sha256, "plan_sha256")?;
        }
        Ok(())
    }

    pub fn calculate_sha256(&self) -> Result<String> {
        let mut material = self.clone();
        material.plan_sha256.clear();
        hash_serializable(&material)
    }

    pub fn verify(&self, now: DateTime<Utc>) -> Result<()> {
        self.validate()?;
        if self.plan_sha256 != self.calculate_sha256()? {
            bail!("live-plan digest mismatch");
        }
        let now = now.timestamp();
        if now < self.created_at_epoch_seconds || now > self.expires_at_epoch_seconds {
            bail!("live-plan is outside its validity window");
        }
        Ok(())
    }

    pub fn parsed_url(&self) -> Result<Url> {
        validate_target_url(&self.target_url)
    }

    pub fn request_target(&self) -> Result<String> {
        let url = self.parsed_url()?;
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };
        validate_request_target(path)?;
        Ok(path.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveActivationPayload {
    pub version: u32,
    pub activation_id: String,
    pub plan_sha256: String,
    pub policy_sha256: String,
    pub target_origin_sha256: String,
    pub method: PlannedMethod,
    pub maximum_requests: u64,
    pub not_before_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
    pub signer_key_id_sha256: String,
}

impl LiveActivationPayload {
    pub fn template(
        activation_id: impl Into<String>,
        plan: &LiveRunPlan,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        plan.validate()?;
        let payload = Self {
            version: LIVE_ACTIVATION_VERSION,
            activation_id: activation_id.into(),
            plan_sha256: plan.plan_sha256.clone(),
            policy_sha256: plan.policy_sha256.clone(),
            target_origin_sha256: plan.target_origin_sha256.clone(),
            method: plan.method,
            maximum_requests: plan.maximum_requests,
            not_before_epoch_seconds: not_before.timestamp(),
            expires_at_epoch_seconds: expires_at.timestamp(),
            signer_key_id_sha256: plan.activation_key_id_sha256.clone(),
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != LIVE_ACTIVATION_VERSION {
            bail!("unsupported activation version");
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
        if self.maximum_requests != LIVE_MVP_MAXIMUM_REQUESTS {
            bail!("activation permits an unsupported request count");
        }
        if self.not_before_epoch_seconds <= 0
            || self.expires_at_epoch_seconds <= self.not_before_epoch_seconds
            || self
                .expires_at_epoch_seconds
                .saturating_sub(self.not_before_epoch_seconds)
                > MAX_ACTIVATION_LIFETIME_SECONDS
        {
            bail!("activation validity window is invalid");
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).context("could not serialize activation payload")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveActivationCertificate {
    pub payload: LiveActivationPayload,
    pub signature_hex: String,
}

impl LiveActivationCertificate {
    pub fn verify(&self, plan: &LiveRunPlan, public_key: &[u8], now: DateTime<Utc>) -> Result<()> {
        plan.verify(now)?;
        self.payload.validate()?;
        if public_key.len() != 32 {
            bail!("Ed25519 activation public key must contain 32 bytes");
        }
        if hash_bytes(public_key) != self.payload.signer_key_id_sha256
            || self.payload.signer_key_id_sha256 != plan.activation_key_id_sha256
        {
            bail!("activation signer key does not match live-plan");
        }
        if self.payload.plan_sha256 != plan.plan_sha256
            || self.payload.policy_sha256 != plan.policy_sha256
            || self.payload.target_origin_sha256 != plan.target_origin_sha256
            || self.payload.method != plan.method
            || self.payload.maximum_requests != plan.maximum_requests
        {
            bail!("activation payload does not match live-plan");
        }
        let now = now.timestamp();
        if now < self.payload.not_before_epoch_seconds
            || now > self.payload.expires_at_epoch_seconds
            || self.payload.expires_at_epoch_seconds > plan.expires_at_epoch_seconds
        {
            bail!("activation is outside its validity window");
        }
        let signature = decode_lower_hex(&self.signature_hex, "signature_hex")?;
        if signature.len() != 64 {
            bail!("Ed25519 activation signature must contain 64 bytes");
        }
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&self.payload.signing_bytes()?, &signature)
            .map_err(|_| anyhow::anyhow!("activation signature verification failed"))
    }

    pub fn certificate_sha256(&self) -> Result<String> {
        hash_serializable(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveOrchestratorReceipt {
    pub version: u32,
    pub run_id: String,
    pub plan_sha256: String,
    pub activation_id: String,
    pub activation_certificate_sha256: String,
    pub policy_sha256: String,
    pub target_origin_sha256: String,
    pub selected_ip: String,
    pub method: String,
    pub live_receipt_sha256: String,
    pub finding_count: u64,
    pub finding_ids: Vec<String>,
    pub redirect_observed: bool,
    pub completed_at_epoch_seconds: i64,
    pub receipt_sha256: String,
}

impl LiveOrchestratorReceipt {
    pub fn verify(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported orchestrator receipt version");
        }
        for (value, field) in [
            (&self.plan_sha256, "plan_sha256"),
            (
                &self.activation_certificate_sha256,
                "activation_certificate_sha256",
            ),
            (&self.policy_sha256, "policy_sha256"),
            (&self.target_origin_sha256, "target_origin_sha256"),
            (&self.live_receipt_sha256, "live_receipt_sha256"),
            (&self.receipt_sha256, "receipt_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        if self.finding_count != self.finding_ids.len() as u64 {
            bail!("finding count does not match finding IDs");
        }
        for finding_id in &self.finding_ids {
            validate_sha256(finding_id, "finding_id")?;
        }
        let mut material = self.clone();
        material.receipt_sha256.clear();
        if hash_serializable(&material)? != self.receipt_sha256 {
            bail!("orchestrator receipt digest mismatch");
        }
        Ok(())
    }
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).context("could not serialize JSON")?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)
        .with_context(|| format!("could not write {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("could not commit {}", path.display()))?;
    Ok(())
}

pub fn read_hex_file(path: &Path, field: &str) -> Result<Vec<u8>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("could not read {}", path.display()))?;
    decode_lower_hex(text.trim(), field)
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).context("could not serialize digest material")?;
    Ok(hash_bytes(&bytes))
}

fn normalized_origin(url: &Url) -> Result<String> {
    let host = url
        .host_str()
        .context("target URL does not contain a host")?
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .context("target URL does not contain a usable port")?;
    Ok(format!("{}://{}:{}", url.scheme(), host, port))
}

fn validate_target_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("target URL is invalid")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("live target must be an absolute credential-free HTTPS/443 URL without query or fragment");
    }
    let host = url.host_str().expect("validated host");
    if host.parse::<IpAddr>().is_ok()
        || host.ends_with('.')
        || !host.is_ascii()
        || host
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        bail!("live target must use a normalized DNS hostname");
    }
    validate_request_target(if url.path().is_empty() {
        "/"
    } else {
        url.path()
    })?;
    Ok(url)
}

fn validate_request_target(target: &str) -> Result<()> {
    if target.is_empty()
        || target.len() > 4 * 1024
        || !target.starts_with('/')
        || target.starts_with("//")
        || target.contains('?')
        || target.contains('#')
        || target.contains('%')
        || target.contains('\\')
        || target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        bail!("live request target is outside passive MVP policy");
    }
    if target.split('/').any(|segment| {
        DENIED_PATH_SEGMENTS
            .iter()
            .any(|denied| segment.eq_ignore_ascii_case(denied))
    }) {
        bail!("live request target contains a denied action segment");
    }
    Ok(())
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

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(feature = "live-network")]
include!("live_orchestrator_live.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn test_plan(public_key: &[u8]) -> LiveRunPlan {
        LiveRunPlan::build(
            "run-test-1",
            DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            DateTime::from_timestamp(1_800_000_600, 0).unwrap(),
            b"policy-fixture",
            "https://example.com/",
            "93.184.216.34".parse().unwrap(),
            BTreeSet::from(["93.184.216.34".parse().unwrap()]),
            PlannedMethod::Get,
            "dns-context-1",
            "operator-supplied-signed-observation",
            60,
            public_key,
        )
        .unwrap()
    }

    #[test]
    fn plan_is_deterministic_and_tamper_evident() {
        let public_key = [7_u8; 32];
        let plan = test_plan(&public_key);
        plan.verify(DateTime::from_timestamp(1_800_000_100, 0).unwrap())
            .unwrap();
        let mut tampered = plan.clone();
        tampered.selected_ip = "1.1.1.1".parse().unwrap();
        assert!(tampered
            .verify(DateTime::from_timestamp(1_800_000_100, 0).unwrap())
            .is_err());
    }

    #[test]
    fn ed25519_activation_binds_exact_plan() {
        let seed = [9_u8; 32];
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let plan = test_plan(key_pair.public_key().as_ref());
        let payload = LiveActivationPayload::template(
            "activation-test-1",
            &plan,
            DateTime::from_timestamp(1_800_000_050, 0).unwrap(),
            DateTime::from_timestamp(1_800_000_300, 0).unwrap(),
        )
        .unwrap();
        let signature = key_pair.sign(&payload.signing_bytes().unwrap());
        let certificate = LiveActivationCertificate {
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

        let mut wrong_plan = plan.clone();
        wrong_plan.method = PlannedMethod::Head;
        wrong_plan.plan_sha256 = wrong_plan.calculate_sha256().unwrap();
        assert!(certificate
            .verify(
                &wrong_plan,
                key_pair.public_key().as_ref(),
                DateTime::from_timestamp(1_800_000_100, 0).unwrap(),
            )
            .is_err());
    }
}
