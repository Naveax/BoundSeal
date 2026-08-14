use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use nxb_policy::{
    AuthorizationPolicy, AutomationPolicy, CompiledPolicy, ProgramPolicy, ScopePolicy, TargetPolicy,
};
use serde::Serialize;
use url::Url;

use super::{validate_policy_binding, workspace, READ_ONLY_METHODS};

#[derive(Serialize)]
struct GuidedPolicySnapshot<'a> {
    schema_version: u32,
    program_name: &'a str,
    program_platform: &'a str,
    program_reference: Option<&'a str>,
    include_host: &'a str,
    allowed_schemes: &'static [&'static str],
    allowed_methods: &'static [&'static str],
    allow_subdomains: bool,
    active_testing: bool,
    oob_callbacks: bool,
    credential_bruteforce: bool,
    destructive_testing: bool,
    max_requests_per_second: f64,
    max_concurrency: u16,
    max_total_requests: u64,
    authorization_confirmed: bool,
    authorization_researcher: &'a str,
    authorization_expires_at: &'a str,
}

pub(super) struct GuidedPolicyArtifact {
    pub(super) snapshot_sha256: String,
    pub(super) document_sha256: String,
    pub(super) document: String,
    pub(super) allowed_methods: Vec<String>,
    pub(super) compiled: CompiledPolicy,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compile_guided_policy(
    origin: &str,
    program_name: &str,
    program_platform: &str,
    program_reference: Option<&str>,
    researcher: &str,
    expires_at: &str,
    allow_subdomains: bool,
    max_requests_per_second: f64,
    max_concurrency: u16,
    max_total_requests: u64,
) -> Result<GuidedPolicyArtifact> {
    let origin_url =
        Url::parse(origin).context("canonical guided target origin could not be parsed")?;
    let host = origin_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("canonical guided target origin is missing its host"))?;

    let snapshot = GuidedPolicySnapshot {
        schema_version: 1,
        program_name,
        program_platform,
        program_reference,
        include_host: host,
        allowed_schemes: &["https"],
        allowed_methods: READ_ONLY_METHODS,
        allow_subdomains,
        active_testing: false,
        oob_callbacks: false,
        credential_bruteforce: false,
        destructive_testing: false,
        max_requests_per_second,
        max_concurrency,
        max_total_requests,
        authorization_confirmed: true,
        authorization_researcher: researcher,
        authorization_expires_at: expires_at,
    };
    let snapshot_sha256 = workspace::sha256(
        &serde_json::to_vec(&snapshot)
            .context("could not serialize guided policy snapshot material")?,
    );

    let expires_at = DateTime::parse_from_rfc3339(expires_at)
        .context("canonical guided authorization expiry could not be parsed")?
        .with_timezone(&Utc);

    let policy = TargetPolicy {
        schema_version: 1,
        program: ProgramPolicy {
            name: program_name.to_owned(),
            platform: program_platform.to_owned(),
            policy_url: program_reference.map(str::to_owned),
        },
        scope: ScopePolicy {
            include_hosts: BTreeSet::from([host.to_owned()]),
            exclude_hosts: BTreeSet::new(),
            allowed_schemes: BTreeSet::from(["https".to_owned()]),
            allowed_methods: READ_ONLY_METHODS
                .iter()
                .map(|method| (*method).to_owned())
                .collect(),
            allow_subdomains,
        },
        automation: AutomationPolicy {
            active_testing: false,
            credential_bruteforce: false,
            destructive_testing: false,
            oob_callbacks: false,
            max_requests_per_second,
            max_concurrency,
            max_total_requests,
        },
        authorization: AuthorizationPolicy {
            confirmed: true,
            researcher: researcher.to_owned(),
            policy_snapshot_sha256: snapshot_sha256.clone(),
            expires_at,
        },
    };

    let document = policy
        .to_canonical_toml()
        .context("could not serialize guided policy through the canonical policy schema")?;
    let reparsed = TargetPolicy::from_toml(&document)
        .context("canonical guided policy document did not parse through TargetPolicy")?;
    if reparsed
        .to_canonical_toml()
        .context("could not reserialize canonical guided policy")?
        != document
    {
        bail!("guided policy serialization is not deterministic");
    }
    if reparsed.authorization.policy_snapshot_sha256 != snapshot_sha256 {
        bail!("guided policy snapshot binding drifted during canonical round-trip");
    }

    let compiled = reparsed
        .compile(Utc::now())
        .context("canonical policy engine rejected the guided policy")?;
    if compiled.program_name() != program_name {
        bail!("compiled guided policy program identity drifted");
    }
    if compiled.included_host_count() != 1 || !compiled.allows_host(host) {
        bail!("compiled guided policy host boundary drifted");
    }
    if compiled.policy_snapshot_sha256() != snapshot_sha256 {
        bail!("compiled guided policy snapshot digest drifted");
    }
    if compiled
        .authorization_expires_at()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        != expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    {
        bail!("compiled guided policy authorization expiry drifted");
    }
    if compiled.maximum_requests_per_second() != max_requests_per_second
        || compiled.maximum_concurrency() != max_concurrency
        || compiled.maximum_total_requests() != max_total_requests
    {
        bail!("compiled guided policy automation budget drifted");
    }
    if compiled.active_testing_enabled() || compiled.oob_callbacks_enabled() {
        bail!("compiled guided policy unexpectedly enabled active behavior");
    }

    let allowed_methods = validate_policy_binding(&compiled, origin)?;
    let expected_methods = READ_ONLY_METHODS
        .iter()
        .map(|method| (*method).to_owned())
        .collect::<Vec<_>>();
    if allowed_methods != expected_methods {
        bail!("compiled guided policy exceeded the read-only product boundary");
    }

    let document_sha256 = workspace::sha256(document.as_bytes());

    Ok(GuidedPolicyArtifact {
        snapshot_sha256,
        document_sha256,
        document,
        allowed_methods,
        compiled,
    })
}
