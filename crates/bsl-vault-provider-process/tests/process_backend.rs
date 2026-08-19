#![cfg(feature = "fixture")]
#![forbid(unsafe_code)]

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use nxb_session::SessionBroker;
use nxb_vault::{InMemorySecretVault, SecretKind};
use nxb_vault_provider::{
    bootstrap_external_session, consume_activation_once, deprovision_external_session,
    ExternalVaultActivationCertificate, ExternalVaultActivationPayload,
    ExternalVaultPlanParameters, ExternalVaultProvider, ExternalVaultSessionPlan,
    ProviderDeliverySpec, ProviderIdentity, ProviderSecretRequest, ProviderSecretSpec,
    ProviderSessionOutcome, ProviderSessionRequest,
};
use nxb_vault_provider_process::{
    fixture, sha256_file, sha256_hex, ProcessVaultProvider, ProcessVaultProviderConfig,
    ProcessVaultProviderError,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

const NOW: i64 = 1_900_000_000;

fn fixture_executable() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nxb-vault-provider-fixture"))
}

fn fixture_identity(executable_sha256: &str) -> ProviderIdentity {
    ProviderIdentity {
        provider_id: "fixture-provider".into(),
        provider_instance_sha256: executable_sha256.into(),
        capability_sha256: fixture::expected_capability_sha256(),
    }
}

fn provider_config(timeout: Duration) -> ProcessVaultProviderConfig {
    let executable = fixture_executable();
    let executable_sha256 = sha256_file(&executable).unwrap();
    ProcessVaultProviderConfig {
        executable,
        expected_identity: fixture_identity(&executable_sha256),
        executable_sha256,
        operation_timeout: timeout,
    }
}

fn plan(public_key: &[u8], identity: ProviderIdentity) -> ExternalVaultSessionPlan {
    ExternalVaultSessionPlan::build(ExternalVaultPlanParameters {
        bootstrap_id: "bootstrap-process-1".into(),
        discovery_plan_sha256: sha256_hex(b"nxb140-discovery-plan"),
        target_origin_sha256: sha256_hex(b"https://app.example.com:443"),
        authority: "app.example.com".into(),
        run_id: "run-process-1".into(),
        worker_id: "worker-process-1".into(),
        account_id: "account-process-1".into(),
        tenant_id: "tenant-process-1".into(),
        role_id: "role-process-1".into(),
        provider: identity,
        secrets: vec![ProviderSecretSpec {
            logical_id: "authorization".into(),
            provider_handle: "fixture/bearer".into(),
            kind: SecretKind::BearerToken,
            delivery: ProviderDeliverySpec::Header {
                name: "authorization".into(),
                prefix_hex: "42656172657220".into(),
            },
            maximum_value_bytes: 4096,
            required_version_sha256: Some(sha256_hex(b"fixture-version-1")),
        }],
        created_at_epoch_seconds: NOW,
        expires_at_epoch_seconds: NOW + 300,
        session_expires_at_epoch_seconds: NOW + 1_800,
        activation_public_key: public_key.to_vec(),
    })
    .unwrap()
}

fn certificate(
    plan: &ExternalVaultSessionPlan,
    key_pair: &Ed25519KeyPair,
) -> ExternalVaultActivationCertificate {
    let payload =
        ExternalVaultActivationPayload::template("activation-process-1", plan, NOW, NOW + 240)
            .unwrap();
    let signature = key_pair.sign(&payload.signing_bytes().unwrap());
    ExternalVaultActivationCertificate {
        payload,
        signature_hex: lower_hex(signature.as_ref()),
    }
}

fn unique_state_directory(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    std::env::temp_dir().join(format!(
        "nxb140-process-provider-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn session_request() -> ProviderSessionRequest {
    ProviderSessionRequest {
        bootstrap_id_sha256: sha256_hex(b"bootstrap"),
        plan_sha256: sha256_hex(b"plan"),
        discovery_plan_sha256: sha256_hex(b"discovery"),
        target_origin_sha256: sha256_hex(b"origin"),
        authority: "app.example.com".into(),
        scheme: "https".into(),
        run_id: "run-process-1".into(),
        worker_id: "worker-process-1".into(),
        account_id: "account-process-1".into(),
        tenant_id: "tenant-process-1".into(),
        role_id: "role-process-1".into(),
        requested_secret_count: 1,
        session_expires_at_epoch_seconds: NOW + 1_800,
    }
}

#[test]
fn pinned_process_provider_bootstraps_and_tears_down() {
    let config = provider_config(Duration::from_secs(5));
    let identity = config.expected_identity.clone();
    let executable_display = config.executable.display().to_string();
    let mut provider = ProcessVaultProvider::connect(config).unwrap();
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[20_u8; 32]).unwrap();
    let plan = plan(key_pair.public_key().as_ref(), identity);
    let certificate = certificate(&plan, &key_pair);
    let state_directory = unique_state_directory("bootstrap");
    let consumed = consume_activation_once(
        &state_directory,
        &plan,
        &certificate,
        key_pair.public_key().as_ref(),
        NOW + 1,
    )
    .unwrap();
    fs::remove_dir_all(&state_directory).unwrap();

    let mut vault = InMemorySecretVault::new("process-vault").unwrap();
    let mut broker = SessionBroker::new("process-broker").unwrap();
    let provisioned = bootstrap_external_session(
        &plan,
        consumed,
        &mut provider,
        &mut broker,
        &mut vault,
        NOW + 1,
    )
    .unwrap();

    provisioned.receipt().verify().unwrap();
    assert_eq!(vault.secret_count(), 1);
    assert_eq!(provisioned.session().profile.secret_handles.len(), 1);
    let debug = format!("{provider:?}");
    assert!(!debug.contains("nxb140-test-secret"));
    assert!(!debug.contains(&executable_display));

    let teardown =
        deprovision_external_session(provisioned, &mut broker, &mut vault, NOW + 2).unwrap();
    teardown.verify().unwrap();
    assert_eq!(vault.secret_count(), 0);
}

#[test]
fn executable_digest_mismatch_is_rejected_before_spawn() {
    let executable = fixture_executable();
    let wrong_digest = "00".repeat(32);
    let error = ProcessVaultProvider::connect(ProcessVaultProviderConfig {
        executable,
        executable_sha256: wrong_digest.clone(),
        expected_identity: fixture_identity(&wrong_digest),
        operation_timeout: Duration::from_secs(5),
    })
    .unwrap_err();
    assert_eq!(error, ProcessVaultProviderError::ExecutableDigestMismatch);
}

#[test]
fn handshake_identity_mismatch_is_fail_closed() {
    let mut config = provider_config(Duration::from_secs(5));
    config.expected_identity.capability_sha256 = sha256_hex(b"wrong-capability");
    let error = ProcessVaultProvider::connect(config).unwrap_err();
    assert_eq!(error, ProcessVaultProviderError::ProviderIdentityMismatch);
}

#[test]
fn timeout_kills_child_but_allows_upstream_abort_completion() {
    let mut provider =
        ProcessVaultProvider::connect(provider_config(Duration::from_secs(5))).unwrap();
    let mut session = provider.begin(&session_request()).unwrap();
    let failure = provider
        .fetch(
            &mut session,
            &ProviderSecretRequest {
                logical_id: "stall".into(),
                provider_handle: "fixture/stall".into(),
                kind: SecretKind::BearerToken,
                maximum_value_bytes: 4096,
                required_version_sha256: None,
            },
        )
        .unwrap_err();
    assert_eq!(failure.code(), "process_timeout");
    provider
        .finish(session, ProviderSessionOutcome::Aborted)
        .unwrap();
}

#[test]
fn logical_provider_failure_remains_abortable() {
    let mut provider =
        ProcessVaultProvider::connect(provider_config(Duration::from_secs(5))).unwrap();
    let mut session = provider.begin(&session_request()).unwrap();
    let failure = provider
        .fetch(
            &mut session,
            &ProviderSecretRequest {
                logical_id: "denied".into(),
                provider_handle: "fixture/failure".into(),
                kind: SecretKind::BearerToken,
                maximum_value_bytes: 4096,
                required_version_sha256: None,
            },
        )
        .unwrap_err();
    assert_eq!(failure.code(), "fixture_fetch_denied");
    provider
        .finish(session, ProviderSessionOutcome::Aborted)
        .unwrap();
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
