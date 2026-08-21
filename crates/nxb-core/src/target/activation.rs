use std::{fs, path::Path};

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
    publication_nonce: String,
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
        rollback_profile(&root, &identity.target_id)?;
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
            rollback_profile(&root, &identity.target_id)?;
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
        publication_nonce: workspace::random_hex(16)?,
        created_at: workspace::now(),
        network_activity: "none",
    };
    let artifact_bytes = canonical_json(&artifact)?;

    if let Err(publication_error) = workspace::create_document(artifact_path, &artifact_bytes) {
        if let Err(cleanup_error) = cleanup_owned_artifact(artifact_path, &artifact_bytes) {
            bail!(
                "artifact publication failed ({publication_error:#}); owned-artifact cleanup also failed ({cleanup_error:#})"
            );
        }
        return Err(publication_error);
    }

    Ok(workspace::sha256(&artifact_bytes))
}

fn cleanup_owned_artifact(path: &Path, expected_bytes: &[u8]) -> Result<()> {
    if !workspace::safe_exists(path)? {
        return Ok(());
    }

    workspace::reject_path_indirections(path, "guided activation artifact rollback")?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        bail!("guided activation artifact rollback path is not a regular file");
    }
    if metadata.len() != expected_bytes.len() as u64 {
        return Ok(());
    }

    let existing = fs::read(path)?;
    if existing == expected_bytes {
        workspace::remove_regular(path)?;
    }

    Ok(())
}

fn rollback_profile(root: &Path, target_id: &str) -> Result<()> {
    let profile_path = root.join("targets").join(format!("{target_id}.json"));

    match workspace::safe_exists(&profile_path) {
        Ok(true) => workspace::remove_regular(&profile_path),
        Ok(false) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_artifact_cleanup_never_removes_foreign_same_size_bytes() {
        let root = std::env::temp_dir().join(format!(
            "nxb153-artifact-ownership-{}-{}",
            std::process::id(),
            workspace::random_hex(8).unwrap()
        ));
        fs::create_dir(&root).unwrap();
        workspace::set_private_directory_permissions(&root).unwrap();
        let path = root.join("artifact.json");

        let foreign = b"foreign\n";
        let owned = b"owned!!\n";
        assert_eq!(foreign.len(), owned.len());

        workspace::create_document(&path, foreign).unwrap();
        cleanup_owned_artifact(&path, owned).unwrap();
        assert_eq!(fs::read(&path).unwrap(), foreign);

        workspace::remove_regular(&path).unwrap();
        workspace::create_document(&path, owned).unwrap();
        cleanup_owned_artifact(&path, owned).unwrap();
        assert!(!workspace::safe_exists(&path).unwrap());

        fs::remove_dir(root).unwrap();
    }
}
