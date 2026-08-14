use std::path::Path;

use anyhow::{bail, Result};
use serde_json::Value;

use super::{
    build_guided_setup, create_value_from_bytes, workspace, AuthorizationBasis,
};

pub(super) const ACTIVATION_ACKNOWLEDGEMENT: &str = "I_CONFIRM_THIS_EXACT_PREVIEW";

#[allow(clippy::too_many_arguments)]
pub(super) fn activate_value(
    workspace_path: &Path,
    id: &str,
    name: &str,
    origin: &str,
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
    program_name: &str,
    program_platform: &str,
    program_reference: Option<&str>,
    authorization_reference: &str,
    authorization_document: &Path,
    researcher: &str,
    authorization_basis: AuthorizationBasis,
    authorization_expires_at: &str,
    acknowledge_authorization: &str,
    allow_subdomains: bool,
    max_requests_per_second: f64,
    max_concurrency: u16,
    max_total_requests: u64,
    confirm_preview_sha256: &str,
    acknowledge_activation: &str,
) -> Result<Value> {
    workspace::validate_sha(
        confirm_preview_sha256,
        "guided preview confirmation SHA-256",
    )?;

    if acknowledge_activation != ACTIVATION_ACKNOWLEDGEMENT {
        bail!("guided target activation requires the exact preview acknowledgement");
    }

    let build = build_guided_setup(
        workspace_path,
        id,
        name,
        origin,
        include_paths,
        exclude_paths,
        program_name,
        program_platform,
        program_reference,
        authorization_reference,
        authorization_document,
        researcher,
        authorization_basis,
        authorization_expires_at,
        acknowledge_authorization,
        allow_subdomains,
        max_requests_per_second,
        max_concurrency,
        max_total_requests,
    )?;

    if build.preview.preview_sha256 != confirm_preview_sha256 {
        bail!("guided target activation preview confirmation does not match current normalized input");
    }

    let identity = &build.preview.identity;
    let expected_policy_sha256 = build.policy.document_sha256.clone();
    let policy_snapshot_sha256 = build.policy.snapshot_sha256.clone();

    let mut value = create_value_from_bytes(
        workspace_path,
        &identity.target_id,
        &identity.name,
        &identity.origin,
        identity.include_paths.clone(),
        identity.exclude_paths.clone(),
        &identity.authorization.reference,
        &build.authorization_bytes,
        build.policy.document.as_bytes(),
    )?;

    if value.get("policy_sha256").and_then(Value::as_str)
        != Some(expected_policy_sha256.as_str())
    {
        bail!("activated target policy digest does not match the confirmed preview policy");
    }

    value["activation"] = serde_json::json!({
        "confirmation": "exact_preview",
        "preview_sha256": confirm_preview_sha256,
        "policy_snapshot_sha256": policy_snapshot_sha256,
        "policy_document_sha256": expected_policy_sha256,
        "network_activity": "none",
    });

    Ok(value)
}
