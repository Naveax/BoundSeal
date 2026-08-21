use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;

use super::{
    build_guided_setup, canonical_json, create_value_from_bytes, workspace, AuthorizationBasis,
    AuthorizationBinding, ProgramMetadata, SetupAuthorization, SetupAutomation, SetupPolicyBinding,
    SetupPreview, SetupPreviewIdentity, SetupProgram, TargetProfile, PROFILE_SCHEMA_VERSION,
};

pub(super) const ACTIVATION_ACKNOWLEDGEMENT: &str = "I_CONFIRM_THIS_EXACT_PREVIEW";
const GUIDED_ACTIVATION_ARTIFACT_VERSION: u32 = 1;
const GUIDED_PERSISTENCE_MARGIN_BYTES: u64 = 4 * 1024;
const PERSISTENCE_PREFLIGHT_TIME: &str = "2000-01-01T00:00:00Z";

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

pub(super) fn validate_persistence_envelope(
    preview: &SetupPreview,
    policy_document: &str,
) -> Result<()> {
    let identity = &preview.identity;
    let mut profile = TargetProfile {
        schema_version: PROFILE_SCHEMA_VERSION,
        target_id: identity.target_id.clone(),
        name: identity.name.clone(),
        origin: identity.origin.clone(),
        include_paths: identity.include_paths.clone(),
        exclude_paths: identity.exclude_paths.clone(),
        allowed_methods: identity.automation.allowed_methods.clone(),
        program: ProgramMetadata {
            name: identity.program.name.clone(),
            platform: identity.program.platform.clone(),
            reference: identity.program.reference.clone(),
        },
        authorization: AuthorizationBinding {
            reference: identity.authorization.reference.clone(),
            document_sha256: identity.authorization.document_sha256.clone(),
        },
        policy_sha256: identity.policy.policy_document_sha256.clone(),
        identity_sha256: String::new(),
        created_at: PERSISTENCE_PREFLIGHT_TIME.to_owned(),
    };
    profile.identity_sha256 = super::profile_identity_sha256(&profile)?;
    super::validate_profile(&profile)
        .context("guided persistence preflight could not construct a valid target profile")?;
    let profile_bytes = canonical_json(&profile)?;
    enforce_persistence_envelope("target profile", profile_bytes.len())?;

    let artifact = GuidedActivationArtifact {
        artifact_version: GUIDED_ACTIVATION_ARTIFACT_VERSION,
        target_id: &identity.target_id,
        profile_identity_sha256: &profile.identity_sha256,
        preview,
        policy_document,
        publication_nonce: "0".repeat(32),
        created_at: PERSISTENCE_PREFLIGHT_TIME.to_owned(),
        network_activity: "none",
    };
    let artifact_bytes = canonical_json(&artifact)?;
    enforce_persistence_envelope("guided activation artifact", artifact_bytes.len())?;

    Ok(())
}

fn enforce_persistence_envelope(label: &str, serialized_bytes: usize) -> Result<()> {
    let usable_bytes = workspace::MAX_DOCUMENT_BYTES
        .checked_sub(GUIDED_PERSISTENCE_MARGIN_BYTES)
        .ok_or_else(|| anyhow::anyhow!("guided persistence margin exceeds workspace document cap"))?;
    let serialized_bytes = serialized_bytes as u64;
    if serialized_bytes > usable_bytes {
        bail!(
            "guided {label} exceeds the persistence envelope: serialized={serialized_bytes} usable={usable_bytes} writer_cap={} margin={GUIDED_PERSISTENCE_MARGIN_BYTES}",
            workspace::MAX_DOCUMENT_BYTES
        );
    }
    Ok(())
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

    validate_persistence_envelope(&build.preview, &build.policy.document)?;

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

    let expected_profile_bytes = expected_profile_bytes_from_value(&value)?;

    if let Err(verification_error) = verify_owned_profile_bytes(
        &root,
        &identity.target_id,
        &expected_profile_bytes,
    ) {
        if let Err(rollback_error) =
            rollback_profile(&root, &identity.target_id, &expected_profile_bytes)
        {
            bail!(
                "guided target profile readback verification failed ({verification_error:#}); ownership-safe rollback also failed ({rollback_error:#})"
            );
        }
        bail!("guided target profile readback verification failed: {verification_error:#}");
    }

    if value.get("policy_sha256").and_then(Value::as_str)
        != Some(expected_policy_sha256.as_str())
    {
        rollback_profile(&root, &identity.target_id, &expected_profile_bytes)?;
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
            if let Err(rollback_error) =
                rollback_profile(&root, &identity.target_id, &expected_profile_bytes)
            {
                bail!(
                    "guided target activation continuity publication failed ({error:#}); target-profile rollback also failed ({rollback_error:#})"
                );
            }
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

fn required_string(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("activated target result is missing {field}"))
}

fn required_array<T>(value: &Value, field: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let item = value
        .get(field)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("activated target result is missing {field}"))?;
    serde_json::from_value(item)
        .with_context(|| format!("activated target result field {field} is invalid"))
}

fn expected_profile_bytes_from_value(activated_profile: &Value) -> Result<Vec<u8>> {
    let program: ProgramMetadata = required_array(activated_profile, "program")?;
    let profile = TargetProfile {
        schema_version: PROFILE_SCHEMA_VERSION,
        target_id: required_string(activated_profile, "target_id")?,
        name: required_string(activated_profile, "name")?,
        origin: required_string(activated_profile, "origin")?,
        include_paths: required_array(activated_profile, "include_paths")?,
        exclude_paths: required_array(activated_profile, "exclude_paths")?,
        allowed_methods: required_array(activated_profile, "allowed_methods")?,
        program,
        authorization: AuthorizationBinding {
            reference: required_string(activated_profile, "authorization_reference")?,
            document_sha256: required_string(activated_profile, "authorization_sha256")?,
        },
        policy_sha256: required_string(activated_profile, "policy_sha256")?,
        identity_sha256: required_string(activated_profile, "identity_sha256")?,
        created_at: required_string(activated_profile, "created_at")?,
    };

    super::validate_profile(&profile)
        .context("activated target result could not reconstruct a valid immutable profile")?;
    canonical_json(&profile).context("could not reconstruct canonical activated target profile")
}

fn verify_owned_profile_bytes(root: &Path, target_id: &str, expected_bytes: &[u8]) -> Result<()> {
    let profile_path = root.join("targets").join(format!("{target_id}.json"));
    let actual = workspace::read_document(&profile_path, "guided activation target profile")?;
    if actual != expected_bytes {
        bail!("guided activation target profile ownership changed during activation");
    }
    Ok(())
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
        if let Err(cleanup_error) = cleanup_owned_document(
            artifact_path,
            &artifact_bytes,
            "guided activation artifact rollback",
        ) {
            bail!(
                "artifact publication failed ({publication_error:#}); owned-artifact cleanup also failed ({cleanup_error:#})"
            );
        }
        return Err(publication_error);
    }

    Ok(workspace::sha256(&artifact_bytes))
}

fn cleanup_owned_document(path: &Path, expected_bytes: &[u8], label: &str) -> Result<()> {
    if !workspace::safe_exists(path)? {
        return Ok(());
    }

    workspace::reject_path_indirections(path, label)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        bail!("{label} path is not a regular file");
    }
    if metadata.len() != expected_bytes.len() as u64 {
        return Ok(());
    }

    let existing = workspace::read_document(path, label)?;
    if existing == expected_bytes {
        workspace::remove_regular(path)?;
    }

    Ok(())
}

fn rollback_profile(root: &Path, target_id: &str, expected_bytes: &[u8]) -> Result<()> {
    let profile_path = root.join("targets").join(format!("{target_id}.json"));
    cleanup_owned_document(
        &profile_path,
        expected_bytes,
        "guided activation target-profile rollback",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview_with_paths(include_paths: Vec<String>, exclude_paths: Vec<String>) -> SetupPreview {
        SetupPreview {
            identity: SetupPreviewIdentity {
                schema_version: 1,
                status: "preview",
                target_id: "example-app".to_owned(),
                name: "Example App".to_owned(),
                origin: "https://example.org".to_owned(),
                include_paths,
                exclude_paths,
                program: SetupProgram {
                    name: "Example Program".to_owned(),
                    platform: "hackerone".to_owned(),
                    reference: None,
                },
                authorization: SetupAuthorization {
                    reference: "hackerone/program/example#scope-2026".to_owned(),
                    document_sha256: "a".repeat(64),
                    researcher: "test-researcher".to_owned(),
                    basis: AuthorizationBasis::ProgramPolicy,
                    expires_at: "2099-01-01T00:00:00Z".to_owned(),
                    acknowledged: true,
                },
                automation: SetupAutomation {
                    allowed_methods: vec!["GET".to_owned(), "HEAD".to_owned(), "OPTIONS".to_owned()],
                    allow_subdomains: false,
                    active_testing: false,
                    oob_callbacks: false,
                    credential_bruteforce: false,
                    destructive_testing: false,
                    max_requests_per_second: 1.0,
                    max_concurrency: 1,
                    max_total_requests: 10,
                },
                policy: SetupPolicyBinding {
                    schema_version: 1,
                    policy_snapshot_sha256: "b".repeat(64),
                    policy_document_sha256: "c".repeat(64),
                    compiled: true,
                },
                hard_denied_actions: vec![
                    "credential_bruteforce".to_owned(),
                    "destructive_testing".to_owned(),
                    "state_changing_http_methods".to_owned(),
                ],
                network_activity: "none",
            },
            preview_sha256: "d".repeat(64),
        }
    }

    #[test]
    fn persistence_envelope_accounts_for_json_escaping_and_schema_margin() {
        let small = preview_with_paths(vec!["/api".to_owned()], vec!["/api/logout".to_owned()]);
        validate_persistence_envelope(&small, "schema_version = 1\n").unwrap();

        let include_paths = (0..64)
            .map(|index| format!("/p{index:02}{}", "\"".repeat(450)))
            .collect::<Vec<_>>();
        let exclude_paths = include_paths
            .iter()
            .map(|path| format!("{path}/x"))
            .collect::<Vec<_>>();
        let oversized = preview_with_paths(include_paths, exclude_paths);
        let error = validate_persistence_envelope(&oversized, "schema_version = 1\n")
            .expect_err("escaping-heavy persistence representation must be rejected");
        assert!(error.to_string().contains("persistence envelope"));
    }

    #[test]
    fn owned_document_cleanup_never_removes_foreign_same_size_bytes() {
        let root = std::env::temp_dir().join(format!(
            "nxb153-document-ownership-{}-{}",
            std::process::id(),
            workspace::random_hex(8).unwrap()
        ));
        fs::create_dir(&root).unwrap();
        workspace::set_private_directory_permissions(&root).unwrap();
        let path = root.join("record.json");

        let foreign = b"foreign\n";
        let owned = b"owned!!\n";
        assert_eq!(foreign.len(), owned.len());

        workspace::create_document(&path, foreign).unwrap();
        cleanup_owned_document(&path, owned, "test rollback").unwrap();
        assert_eq!(fs::read(&path).unwrap(), foreign);

        workspace::remove_regular(&path).unwrap();
        workspace::create_document(&path, owned).unwrap();
        cleanup_owned_document(&path, owned, "test rollback").unwrap();
        assert!(!workspace::safe_exists(&path).unwrap());

        fs::remove_dir(root).unwrap();
    }
}
