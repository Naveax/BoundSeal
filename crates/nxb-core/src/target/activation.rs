use std::path::Path;

use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::Value;

use super::{
    build_guided_setup, canonical_json, create_value_from_bytes, workspace, AuthorizationBasis,
    SetupPreview,
};

pub(super) const ACTIVATION_ACKNOWLEDGEMENT: &str = "I_CONFIRM_THIS_EXACT_PREVIEW";
const GUIDED_ACTIVATION_ARTIFACT_VERSION: u32 = 1;

#[derive(Serialize)]
struct GuidedActivationArtifact<'a> {
    artifact_version: u32,
    target_id: &'a str,
    profile_identity_sha256: &'a str,
    preview: &'a SetupPreview,
    policy_document: &'a str,
    created_at: String,
    network_activity: &'static str,
}

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
        bail!(
            "guided target activation preview confirmation does not match current normalized input"
        );
    }

    let identity = &build.preview.identity;
    let expected_policy_sha256 = build.policy.document_sha256.clone();
    let policy_snapshot_sha256 = build.policy.snapshot_sha256.clone();
    let root = workspace::validate_workspace_root(workspace_path, true)?;
    let artifact_relative_path = format!(
        "state/target-{}.guided-activation.json",
        identity.target_id
    );
    let artifact_path = root.join(&artifact_relative_path);

    if workspace::safe_exists(&artifact_path)? {
        bail!("guided target activation metadata already exists");
    }

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
        rollback_profile(&root, &identity.target_id, None)?;
        bail!("activated target policy digest does not match the confirmed preview policy");
    }

    let artifact_sha256 = match publish_guided_artifact(
        &artifact_path,
        &identity.target_id,
        &value,
        &build.preview,
        &build.policy.document,
    ) {
        Ok(sha256) => sha256,
        Err(error) => {
            rollback_profile(&root, &identity.target_id, Some(&artifact_path))?;
            bail!("guided target activation continuity publication failed: {error:#}");
        }
    };

    value["activation"] = serde_json::json!({
        "confirmation": "exact_preview",
        "preview_sha256": confirm_preview_sha256,
        "policy_snapshot_sha256": policy_snapshot_sha256,
        "policy_document_sha256": expected_policy_sha256,
        "guided_artifact": artifact_relative_path,
        "guided_artifact_sha256": artifact_sha256,
        "network_activity": "none",
    });

    Ok(value)
}

fn publish_guided_artifact(
    artifact_path: &Path,
    target_id: &str,
    activated_profile: &Value,
    preview: &SetupPreview,
    policy_document: &str,
) -> Result<String> {
    let profile_identity_sha256 = activated_profile
        .get("identity_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("activated target profile is missing its identity digest"))?;
    workspace::validate_sha(profile_identity_sha256, "activated target identity SHA-256")?;

    let artifact = GuidedActivationArtifact {
        artifact_version: GUIDED_ACTIVATION_ARTIFACT_VERSION,
        target_id,
        profile_identity_sha256,
        preview,
        policy_document,
        created_at: workspace::now(),
        network_activity: "none",
    };
    let artifact_bytes = canonical_json(&artifact)?;
    workspace::create_document(artifact_path, &artifact_bytes)?;
    Ok(workspace::sha256(&artifact_bytes))
}

fn rollback_profile(root: &Path, target_id: &str, artifact_path: Option<&Path>) -> Result<()> {
    let profile_path = root.join("targets").join(format!("{target_id}.json"));
    let mut cleanup_errors = Vec::new();

    if let Some(path) = artifact_path {
        match workspace::safe_exists(path) {
            Ok(true) => {
                if let Err(error) = workspace::remove_regular(path) {
                    cleanup_errors.push(format!(
                        "guided activation artifact cleanup failed: {error:#}"
                    ));
                }
            }
            Ok(false) => {}
            Err(error) => cleanup_errors.push(format!(
                "guided activation artifact cleanup inspection failed: {error:#}"
            )),
        }
    }

    match workspace::safe_exists(&profile_path) {
        Ok(true) => {
            if let Err(error) = workspace::remove_regular(&profile_path) {
                cleanup_errors.push(format!("target profile rollback failed: {error:#}"));
            }
        }
        Ok(false) => {}
        Err(error) => cleanup_errors.push(format!(
            "target profile rollback inspection failed: {error:#}"
        )),
    }

    if !cleanup_errors.is_empty() {
        bail!(
            "guided activation rollback was incomplete: {}",
            cleanup_errors.join("; ")
        );
    }

    Ok(())
}
