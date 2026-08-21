#[cfg(unix)]
use std::fs::File;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;

use super::{
    build_guided_setup, canonical_json, workspace, AuthorizationBasis, AuthorizationBinding,
    ProgramMetadata, SetupAuthorization, SetupAutomation, SetupPolicyBinding, SetupPreview,
    SetupPreviewIdentity, SetupProgram, TargetProfile, PROFILE_SCHEMA_VERSION,
};

pub(super) const ACTIVATION_ACKNOWLEDGEMENT: &str = "I_CONFIRM_THIS_EXACT_PREVIEW";
const GUIDED_ACTIVATION_ARTIFACT_VERSION: u32 = 1;
const GUIDED_PERSISTENCE_MARGIN_BYTES: u64 = 4 * 1024;
const PERSISTENCE_PREFLIGHT_TIME: &str = "2000-01-01T00:00:00Z";
const GUIDED_ARTIFACT_FIELDS: &[&str] = &[
    "artifact_version",
    "target_id",
    "profile_identity_sha256",
    "preview",
    "policy_document",
    "publication_nonce",
    "created_at",
    "network_activity",
];

#[derive(Serialize)]
struct GuidedActivationArtifact<'a> {
    artifact_version: u32,
    target_id: &'a str,
    profile_identity_sha256: &'a str,
    preview: &'a SetupPreview,
    policy_document: &'a str,
    publication_nonce: String,
    created_at: &'a str,
    network_activity: &'static str,
}

pub(super) fn validate_persistence_envelope(
    preview: &SetupPreview,
    policy_document: &str,
) -> Result<()> {
    let profile = prospective_profile(&preview.identity, PERSISTENCE_PREFLIGHT_TIME)?;
    let profile_bytes = canonical_json(&profile)?;
    enforce_persistence_envelope("target profile", profile_bytes.len())?;

    let artifact = GuidedActivationArtifact {
        artifact_version: GUIDED_ACTIVATION_ARTIFACT_VERSION,
        target_id: &preview.identity.target_id,
        profile_identity_sha256: &profile.identity_sha256,
        preview,
        policy_document,
        publication_nonce: "0".repeat(32),
        created_at: PERSISTENCE_PREFLIGHT_TIME,
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
    if workspace::sha256(&build.authorization_bytes) != identity.authorization.document_sha256 {
        bail!("authorization evidence digest drifted after guided preview construction");
    }
    let expected_policy_sha256 = build.policy.document_sha256.clone();
    let policy_snapshot_sha256 = build.policy.snapshot_sha256.clone();
    let root = workspace::validate_workspace_root(workspace_path, true)?;
    let targets = super::targets_directory(&root)?;
    let profile_path = targets.join(format!("{}.json", identity.target_id));
    let disable_path = targets.join(format!("{}.disabled.json", identity.target_id));
    let artifact_relative_path = format!(
        "state/target-{}.guided-activation.json",
        identity.target_id
    );
    let artifact_path = root.join(&artifact_relative_path);

    if workspace::safe_exists(&disable_path)? {
        bail!("target disable receipt already exists without a creatable profile");
    }
    if workspace::safe_exists(&profile_path)? {
        bail!("guided target profile already exists");
    }

    let (profile, artifact_sha256) = if workspace::safe_exists(&artifact_path)? {
        recover_inert_continuity(
            &artifact_path,
            &identity.target_id,
            &build.preview,
            &build.policy.document,
        )?
    } else {
        let created_at = workspace::now();
        let profile = prospective_profile(identity, &created_at)?;
        let artifact_sha256 = publish_guided_artifact(
            &artifact_path,
            &identity.target_id,
            &profile.identity_sha256,
            &build.preview,
            &build.policy.document,
            &created_at,
        )?;
        (profile, artifact_sha256)
    };

    if profile.policy_sha256 != expected_policy_sha256 {
        bail!("prospective target policy digest does not match the confirmed preview policy");
    }
    let profile_bytes = canonical_json(&profile)?;

    if let Err(error) = workspace::create_document(&profile_path, &profile_bytes) {
        if workspace::create_document_error_published(&error) {
            bail!(
                "guided target profile became visible but create-only publication finalization failed after continuity metadata publication; no rollback deletion was attempted: {error:#}"
            );
        }
        bail!(
            "guided target profile was not published after continuity metadata publication; continuity remains inert and can be retried only with the same exact confirmed preview: {error:#}"
        );
    }
    verify_published_bytes(
        &profile_path,
        &profile_bytes,
        "guided activation target profile",
    )?;

    activation_value(
        profile,
        confirm_preview_sha256,
        &policy_snapshot_sha256,
        &expected_policy_sha256,
        &artifact_relative_path,
        &artifact_sha256,
    )
}

fn activation_value(
    profile: TargetProfile,
    confirm_preview_sha256: &str,
    policy_snapshot_sha256: &str,
    expected_policy_sha256: &str,
    artifact_relative_path: &str,
    artifact_sha256: &str,
) -> Result<Value> {
    let mut value = serde_json::to_value(super::effective_target(profile, None))
        .context("could not serialize guided activated target profile")?;
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

fn prospective_profile(identity: &SetupPreviewIdentity, created_at: &str) -> Result<TargetProfile> {
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
        created_at: created_at.to_owned(),
    };
    profile.identity_sha256 = super::profile_identity_sha256(&profile)?;
    super::validate_profile(&profile)
        .context("guided activation could not construct a valid immutable target profile")?;
    Ok(profile)
}

fn publish_guided_artifact(
    artifact_path: &Path,
    target_id: &str,
    profile_identity_sha256: &str,
    preview: &SetupPreview,
    policy_document: &str,
    created_at: &str,
) -> Result<String> {
    workspace::validate_sha(profile_identity_sha256, "activated target identity SHA-256")?;

    let artifact = GuidedActivationArtifact {
        artifact_version: GUIDED_ACTIVATION_ARTIFACT_VERSION,
        target_id,
        profile_identity_sha256,
        preview,
        policy_document,
        publication_nonce: workspace::random_hex(16)?,
        created_at,
        network_activity: "none",
    };
    let artifact_bytes = canonical_json(&artifact)?;

    if let Err(publication_error) = workspace::create_document(artifact_path, &artifact_bytes) {
        if workspace::create_document_error_published(&publication_error) {
            bail!(
                "guided activation artifact became visible but create-only publication finalization failed; target profile publication was not attempted and no rollback deletion was attempted: {publication_error:#}"
            );
        }
        return Err(publication_error);
    }

    verify_published_bytes(
        artifact_path,
        &artifact_bytes,
        "guided activation continuity artifact",
    )?;
    Ok(workspace::sha256(&artifact_bytes))
}

fn recover_inert_continuity(
    artifact_path: &Path,
    target_id: &str,
    preview: &SetupPreview,
    policy_document: &str,
) -> Result<(TargetProfile, String)> {
    let artifact_bytes = workspace::read_document(
        artifact_path,
        "guided activation inert continuity artifact",
    )?;
    let artifact: Value = serde_json::from_slice(&artifact_bytes)
        .context("guided activation inert continuity artifact is invalid JSON")?;
    let object = artifact
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("guided activation continuity artifact must be a JSON object"))?;

    if object.len() != GUIDED_ARTIFACT_FIELDS.len()
        || GUIDED_ARTIFACT_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        bail!("guided activation continuity artifact schema is not canonical");
    }
    if object.get("artifact_version").and_then(Value::as_u64)
        != Some(u64::from(GUIDED_ACTIVATION_ARTIFACT_VERSION))
        || object.get("target_id").and_then(Value::as_str) != Some(target_id)
        || object.get("network_activity").and_then(Value::as_str) != Some("none")
    {
        bail!("guided activation continuity artifact header does not match this activation");
    }

    let expected_preview = serde_json::to_value(preview)
        .context("could not serialize current guided preview for continuity recovery")?;
    if object.get("preview") != Some(&expected_preview) {
        bail!("existing guided activation continuity does not match the exact confirmed preview");
    }
    if object.get("policy_document").and_then(Value::as_str) != Some(policy_document) {
        bail!("existing guided activation continuity policy does not match the confirmed preview");
    }
    if workspace::sha256(policy_document.as_bytes())
        != preview.identity.policy.policy_document_sha256
    {
        bail!("guided activation continuity policy digest does not match the preview binding");
    }

    let profile_identity_sha256 = object
        .get("profile_identity_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("guided activation continuity profile identity is missing"))?;
    workspace::validate_sha(
        profile_identity_sha256,
        "guided activation continuity profile identity SHA-256",
    )?;

    let publication_nonce = object
        .get("publication_nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("guided activation continuity publication nonce is missing"))?;
    if !is_lower_hex(publication_nonce, 32) {
        bail!("guided activation continuity publication nonce is invalid");
    }

    let created_at = object
        .get("created_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("guided activation continuity created_at is missing"))?;
    super::validate_time(created_at, "guided activation continuity created_at")?;

    let profile = prospective_profile(&preview.identity, created_at)?;
    if profile.identity_sha256 != profile_identity_sha256 {
        bail!("existing guided activation continuity does not bind the prospective target profile");
    }

    ensure_recovered_publication_durable(artifact_path)?;
    Ok((profile, workspace::sha256(&artifact_bytes)))
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn ensure_recovered_publication_durable(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("recovered publication path has no parent"))?;
    File::open(parent)
        .with_context(|| format!("could not open recovered publication parent {}", parent.display()))?
        .sync_all()
        .with_context(|| {
            format!(
                "could not synchronize recovered publication parent {}",
                parent.display()
            )
        })
}

#[cfg(not(unix))]
fn ensure_recovered_publication_durable(_path: &Path) -> Result<()> {
    Ok(())
}

fn verify_published_bytes(path: &Path, expected_bytes: &[u8], label: &str) -> Result<()> {
    let actual = workspace::read_document(path, label)?;
    if actual != expected_bytes {
        bail!("{label} bytes changed after create-only publication");
    }
    Ok(())
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
    fn prospective_profile_identity_is_stable_for_fixed_timestamp() {
        let preview = preview_with_paths(vec!["/api".to_owned()], vec!["/api/logout".to_owned()]);
        let first = prospective_profile(&preview.identity, PERSISTENCE_PREFLIGHT_TIME).unwrap();
        let second = prospective_profile(&preview.identity, PERSISTENCE_PREFLIGHT_TIME).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.policy_sha256, "c".repeat(64));
        assert_eq!(first.authorization.document_sha256, "a".repeat(64));
    }

    #[test]
    fn inert_continuity_recovery_requires_exact_preview_and_profile_binding() {
        let root = std::env::temp_dir().join(format!(
            "nxb153-inert-continuity-{}-{}",
            std::process::id(),
            workspace::random_hex(8).unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        workspace::set_private_directory_permissions(&root).unwrap();
        let artifact_path = root.join("target-example-app.guided-activation.json");
        let policy_document = "schema_version = 1\n";
        let mut preview =
            preview_with_paths(vec!["/api".to_owned()], vec!["/api/logout".to_owned()]);
        preview.identity.policy.policy_document_sha256 =
            workspace::sha256(policy_document.as_bytes());
        let created_at = "2026-08-21T11:00:00Z";
        let profile = prospective_profile(&preview.identity, created_at).unwrap();
        let artifact = GuidedActivationArtifact {
            artifact_version: GUIDED_ACTIVATION_ARTIFACT_VERSION,
            target_id: &preview.identity.target_id,
            profile_identity_sha256: &profile.identity_sha256,
            preview: &preview,
            policy_document,
            publication_nonce: "ab".repeat(16),
            created_at,
            network_activity: "none",
        };
        let artifact_bytes = canonical_json(&artifact).unwrap();
        workspace::create_document(&artifact_path, &artifact_bytes).unwrap();

        let (recovered, artifact_sha256) = recover_inert_continuity(
            &artifact_path,
            &preview.identity.target_id,
            &preview,
            policy_document,
        )
        .unwrap();
        assert_eq!(recovered, profile);
        assert_eq!(artifact_sha256, workspace::sha256(&artifact_bytes));

        let different_preview =
            preview_with_paths(vec!["/admin".to_owned()], vec!["/admin/logout".to_owned()]);
        assert!(recover_inert_continuity(
            &artifact_path,
            &preview.identity.target_id,
            &different_preview,
            policy_document,
        )
        .is_err());

        std::fs::remove_dir_all(root).unwrap();
    }
}
