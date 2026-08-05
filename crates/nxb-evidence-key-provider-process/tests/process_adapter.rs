#![cfg(feature = "fixture")]
#![forbid(unsafe_code)]

use std::{path::PathBuf, time::Duration};

use nxb_evidence_key_provider::{
    acquire_evidence_sealer, EvidenceKeyActivation, EvidenceKeyPlan, EvidenceKeyPlanInput,
    EvidenceKeyProvider, EvidenceKeyProviderError, ProviderKeyRequest, ProviderSessionDisposition,
    ProviderSessionOutcome, ProviderSessionRequest,
};
use nxb_evidence_key_provider_process::{
    ProcessEvidenceKeyProvider, ProcessEvidenceKeyProviderConfig,
};
use nxb_vault_provider::ProviderIdentity;
use nxb_vault_provider_process::{sha256_file, sha256_hex, ProcessVaultProviderConfig};
use ring::signature::{Ed25519KeyPair, KeyPair};

const NOW: i64 = 2_000_000_000;
const FIXTURE_PROVIDER_ID: &str = "fixture-evidence-key-provider";
const FIXTURE_CAPABILITY: &[u8] = b"nxb150-pinned-process-evidence-key-fixture";
const FIXTURE_VERSION_ID: &str = "fixture-evidence-key-version-1";
const STORE_ID: &str = "evidence-store-1";
const KEY_ID: &str = "evidence-key-1";

fn fixture_executable() -> PathBuf {
    PathBuf::from(env!(
        "CARGO_BIN_EXE_nxb-evidence-key-provider-process-fixture"
    ))
}

fn process_identity(executable_sha256: &str) -> ProviderIdentity {
    ProviderIdentity {
        provider_id: FIXTURE_PROVIDER_ID.into(),
        provider_instance_sha256: executable_sha256.into(),
        capability_sha256: sha256_hex(FIXTURE_CAPABILITY),
    }
}

fn config(
    provider_handle: &str,
    required_version_sha256: Option<String>,
    timeout: Duration,
) -> ProcessEvidenceKeyProviderConfig {
    let executable = fixture_executable();
    let executable_sha256 = sha256_file(&executable).unwrap();
    ProcessEvidenceKeyProviderConfig {
        process: ProcessVaultProviderConfig {
            executable,
            expected_identity: process_identity(&executable_sha256),
            executable_sha256,
            operation_timeout: timeout,
        },
        store_id: STORE_ID.into(),
        key_id: KEY_ID.into(),
        provider_handle: provider_handle.into(),
        required_version_sha256,
        session_expires_at_epoch_seconds: NOW + 300,
    }
}

fn signed_plan(
    identity: nxb_evidence_key_provider::EvidenceKeyProviderIdentity,
    store_id: &str,
) -> (EvidenceKeyPlan, EvidenceKeyActivation) {
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[50_u8; 32]).unwrap();
    let plan = EvidenceKeyPlan::create(EvidenceKeyPlanInput {
        provider_identity: identity,
        key_id: KEY_ID.into(),
        store_id: store_id.into(),
        policy_snapshot_sha256: sha256_hex(b"nxb150-policy-snapshot"),
        activation_public_key_hex: lower_hex(key_pair.public_key().as_ref()),
        issued_at_epoch_seconds: NOW - 5,
        expires_at_epoch_seconds: NOW + 120,
    })
    .unwrap();
    let message = EvidenceKeyActivation::signing_message(&plan.plan_sha256).unwrap();
    let activation = EvidenceKeyActivation::from_signature(
        plan.plan_sha256.clone(),
        key_pair.sign(&message).as_ref(),
    )
    .unwrap();
    (plan, activation)
}

fn direct_requests(plan: &EvidenceKeyPlan) -> (ProviderSessionRequest, ProviderKeyRequest) {
    (
        ProviderSessionRequest {
            plan_id: plan.plan_id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            store_id: plan.store_id.clone(),
            policy_snapshot_sha256: plan.policy_snapshot_sha256.clone(),
        },
        ProviderKeyRequest {
            plan_id: plan.plan_id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            key_id: plan.key_id.clone(),
            store_id: plan.store_id.clone(),
            policy_snapshot_sha256: plan.policy_snapshot_sha256.clone(),
        },
    )
}

fn aborted_outcome(plan: &EvidenceKeyPlan, failure_code: &str) -> ProviderSessionOutcome {
    ProviderSessionOutcome {
        disposition: ProviderSessionDisposition::Aborted,
        plan_sha256: plan.plan_sha256.clone(),
        receipt_sha256: None,
        failure_code: Some(failure_code.into()),
    }
}

#[test]
fn pinned_process_adapter_acquires_key_and_tears_down() {
    let config = config(
        "fixture/evidence-key",
        Some(sha256_hex(FIXTURE_VERSION_ID.as_bytes())),
        Duration::from_secs(5),
    );
    let identity = config.evidence_identity().unwrap();
    let executable_display = config.process.executable.display().to_string();
    let (plan, activation) = signed_plan(identity, STORE_ID);
    let mut provider = ProcessEvidenceKeyProvider::new(config).unwrap();

    let (sealer, receipt) =
        acquire_evidence_sealer(plan, activation, &mut provider, NOW).unwrap();

    assert_eq!(sealer.key_id(), KEY_ID);
    assert_eq!(receipt.key_version_id, FIXTURE_VERSION_ID);
    let debug = format!("{provider:?}");
    assert!(!debug.contains("fixture/evidence-key"));
    assert!(!debug.contains(&executable_display));
    assert!(!debug.contains("90, 90"));
}

#[test]
fn invalid_activation_is_rejected_before_process_spawn() {
    let mut config = config("fixture/evidence-key", None, Duration::from_secs(5));
    let wrong_digest = "00".repeat(32);
    config.process.executable_sha256 = wrong_digest.clone();
    config.process.expected_identity.provider_instance_sha256 = wrong_digest;
    let identity = config.evidence_identity().unwrap();
    let (plan, _) = signed_plan(identity, STORE_ID);
    let activation =
        EvidenceKeyActivation::from_signature(plan.plan_sha256.clone(), &[0_u8; 64]).unwrap();
    let mut provider = ProcessEvidenceKeyProvider::new(config).unwrap();

    assert!(matches!(
        acquire_evidence_sealer(plan, activation, &mut provider, NOW),
        Err(EvidenceKeyProviderError::ActivationSignatureInvalid)
    ));
}

#[test]
fn executable_digest_mismatch_is_rejected_during_signed_begin() {
    let mut config = config("fixture/evidence-key", None, Duration::from_secs(5));
    let wrong_digest = "00".repeat(32);
    config.process.executable_sha256 = wrong_digest.clone();
    config.process.expected_identity.provider_instance_sha256 = wrong_digest;
    let identity = config.evidence_identity().unwrap();
    let (plan, activation) = signed_plan(identity, STORE_ID);
    let mut provider = ProcessEvidenceKeyProvider::new(config).unwrap();

    assert!(matches!(
        acquire_evidence_sealer(plan, activation, &mut provider, NOW),
        Err(EvidenceKeyProviderError::ProviderBeginFailure(code))
            if code == "process_executable_digest_mismatch"
    ));
}

#[test]
fn store_mismatch_is_rejected_before_provider_session_begin() {
    let config = config("fixture/evidence-key", None, Duration::from_secs(5));
    let identity = config.evidence_identity().unwrap();
    let (plan, activation) = signed_plan(identity, "different-store");
    let mut provider = ProcessEvidenceKeyProvider::new(config).unwrap();

    assert!(matches!(
        acquire_evidence_sealer(plan, activation, &mut provider, NOW),
        Err(EvidenceKeyProviderError::ProviderBeginFailure(code))
            if code == "process_store_mismatch"
    ));
}

#[test]
fn provider_version_mismatch_aborts_cleanly() {
    let config = config(
        "fixture/evidence-key",
        Some(sha256_hex(b"unexpected-version")),
        Duration::from_secs(5),
    );
    let identity = config.evidence_identity().unwrap();
    let (plan, activation) = signed_plan(identity, STORE_ID);
    let mut provider = ProcessEvidenceKeyProvider::new(config).unwrap();

    assert!(matches!(
        acquire_evidence_sealer(plan, activation, &mut provider, NOW),
        Err(EvidenceKeyProviderError::ProviderFetchFailure(code))
            if code == "process_version_mismatch"
    ));
}

#[test]
fn short_key_material_is_rejected_and_aborted() {
    let config = config("fixture/short-key", None, Duration::from_secs(5));
    let identity = config.evidence_identity().unwrap();
    let (plan, activation) = signed_plan(identity, STORE_ID);
    let mut provider = ProcessEvidenceKeyProvider::new(config).unwrap();

    assert!(matches!(
        acquire_evidence_sealer(plan, activation, &mut provider, NOW),
        Err(EvidenceKeyProviderError::ProviderFetchFailure(code))
            if code == "process_key_material_invalid"
    ));
}

#[test]
fn logical_child_failure_remains_abortable() {
    let config = config("fixture/failure", None, Duration::from_secs(5));
    let identity = config.evidence_identity().unwrap();
    let (plan, activation) = signed_plan(identity, STORE_ID);
    let mut provider = ProcessEvidenceKeyProvider::new(config).unwrap();

    assert!(matches!(
        acquire_evidence_sealer(plan, activation, &mut provider, NOW),
        Err(EvidenceKeyProviderError::ProviderFetchFailure(code))
            if code == "fixture_fetch_denied"
    ));
}

#[test]
fn timeout_kills_child_and_allows_abort_completion() {
    let config = config("fixture/stall", None, Duration::from_millis(100));
    let identity = config.evidence_identity().unwrap();
    let (plan, activation) = signed_plan(identity, STORE_ID);
    let mut provider = ProcessEvidenceKeyProvider::new(config).unwrap();

    assert!(matches!(
        acquire_evidence_sealer(plan, activation, &mut provider, NOW),
        Err(EvidenceKeyProviderError::ProviderFetchFailure(code))
            if code == "process_timeout"
    ));
}

#[test]
fn mismatched_fetch_request_is_rejected_before_child_fetch() {
    let config = config("fixture/evidence-key", None, Duration::from_secs(5));
    let identity = config.evidence_identity().unwrap();
    let (plan, _) = signed_plan(identity, STORE_ID);
    let (session_request, mut key_request) = direct_requests(&plan);
    key_request.key_id = "other-key".into();
    let mut provider = ProcessEvidenceKeyProvider::new(config).unwrap();

    provider.begin(&session_request).unwrap();
    let error = provider.fetch_key(&key_request).unwrap_err();
    assert_eq!(error.code, "process_request_mismatch");
    provider
        .finish(&aborted_outcome(&plan, "process_request_mismatch"))
        .unwrap();
}

#[test]
fn second_fetch_is_rejected_and_session_remains_abortable() {
    let config = config("fixture/evidence-key", None, Duration::from_secs(5));
    let identity = config.evidence_identity().unwrap();
    let (plan, _) = signed_plan(identity, STORE_ID);
    let (session_request, key_request) = direct_requests(&plan);
    let mut provider = ProcessEvidenceKeyProvider::new(config).unwrap();

    provider.begin(&session_request).unwrap();
    let material = provider.fetch_key(&key_request).unwrap();
    drop(material);
    let error = provider.fetch_key(&key_request).unwrap_err();
    assert_eq!(error.code, "process_adapter_invalid_state");
    provider
        .finish(&aborted_outcome(&plan, "process_adapter_invalid_state"))
        .unwrap();
}

#[test]
fn capability_identity_changes_with_provider_mapping() {
    let first = config("fixture/evidence-key", None, Duration::from_secs(5))
        .evidence_identity()
        .unwrap();
    let second = config("fixture/short-key", None, Duration::from_secs(5))
        .evidence_identity()
        .unwrap();
    assert_ne!(first.capability_sha256, second.capability_sha256);
}

#[test]
fn capability_identity_binds_exact_submillisecond_timeout() {
    let one_nanosecond = config("fixture/evidence-key", None, Duration::from_nanos(1))
        .evidence_identity()
        .unwrap();
    let nine_hundred_ninety_nine_microseconds = config(
        "fixture/evidence-key",
        None,
        Duration::from_micros(999),
    )
    .evidence_identity()
    .unwrap();

    assert_ne!(
        one_nanosecond.capability_sha256,
        nine_hundred_ninety_nine_microseconds.capability_sha256
    );
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
