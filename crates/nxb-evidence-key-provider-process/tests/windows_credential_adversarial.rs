#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    ffi::c_void,
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use nxb_evidence_key_provider::{
    acquire_evidence_sealer, EvidenceKeyActivation, EvidenceKeyPlan, EvidenceKeyPlanInput,
    EvidenceKeyProviderError,
};
use nxb_evidence_key_provider_process::{
    bundled_windows_credential_config, ProcessEvidenceKeyProvider,
    WINDOWS_CREDENTIAL_TARGET_PREFIX,
};
use nxb_vault_provider_process::{sha256_file, sha256_hex};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

const NOW: i64 = 2_000_000_000;
const CRED_TYPE_GENERIC: u32 = 1;
const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;

fn helper_executable() -> PathBuf {
    PathBuf::from(env!(
        "CARGO_BIN_EXE_nxb-windows-credential-evidence-key-helper"
    ))
}

fn install_root() -> PathBuf {
    helper_executable()
        .parent()
        .expect("helper parent")
        .to_path_buf()
}

fn helper_sha256() -> String {
    sha256_file(&helper_executable()).expect("helper sha256")
}

fn unique_ids(label: &str) -> (String, String) {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    (
        format!("nxb152-e-{label}-{}-{sequence}", std::process::id()),
        "temporary-key".into(),
    )
}

fn target_name(store_id: &str, key_id: &str) -> String {
    format!("{WINDOWS_CREDENTIAL_TARGET_PREFIX}{store_id}::{key_id}")
}

fn helper_output(arguments: &[String]) -> Output {
    Command::new(helper_executable())
        .args(arguments)
        .output()
        .expect("helper invocation")
}

fn lifecycle_arguments(operation: &str, store_id: &str, key_id: &str) -> Vec<String> {
    vec![
        operation.into(),
        "--store-id".into(),
        store_id.into(),
        "--key-id".into(),
        key_id.into(),
    ]
}

fn lifecycle_mutation_arguments(operation: &str, store_id: &str, key_id: &str) -> Vec<String> {
    let mut arguments = lifecycle_arguments(operation, store_id, key_id);
    arguments.push("--confirm-target".into());
    arguments.push(target_name(store_id, key_id));
    arguments
}

fn lifecycle_json(arguments: &[String]) -> Value {
    let output = helper_output(arguments);
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).expect("lifecycle json")
}

fn assert_metadata_only(value: &Value) {
    let object = value.as_object().expect("metadata object");
    let mut actual: Vec<_> = object.keys().map(String::as_str).collect();
    actual.sort_unstable();
    let mut expected = vec![
        "key_bytes",
        "operation",
        "persistence",
        "present",
        "target",
        "version_id",
    ];
    expected.sort_unstable();
    assert_eq!(actual, expected);
    assert!(!object.contains_key("key"));
    assert!(!object.contains_key("secret"));
    assert!(!object.contains_key("credential_blob"));
    assert!(!object.contains_key("key_material"));
}

fn create_valid_credential(store_id: &str, key_id: &str) -> String {
    delete_raw_credential(&target_name(store_id, key_id));
    let value = lifecycle_json(&lifecycle_mutation_arguments("create", store_id, key_id));
    assert_metadata_only(&value);
    assert_eq!(value["operation"], "create");
    assert_eq!(value["present"], true);
    assert_eq!(value["key_bytes"], 32);
    assert_eq!(value["persistence"], "local_machine");
    let version = value["version_id"]
        .as_str()
        .expect("version id")
        .to_owned();
    assert!(version.starts_with("v1-"));
    assert_eq!(version.len(), 35);
    version
}

struct CredentialCleanup {
    target: String,
}

impl CredentialCleanup {
    fn new(store_id: &str, key_id: &str) -> Self {
        Self {
            target: target_name(store_id, key_id),
        }
    }
}

impl Drop for CredentialCleanup {
    fn drop(&mut self) {
        delete_raw_credential(&self.target);
    }
}

fn signed_plan(
    identity: nxb_evidence_key_provider::EvidenceKeyProviderIdentity,
    store_id: &str,
    key_id: &str,
) -> (EvidenceKeyPlan, EvidenceKeyActivation) {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[77_u8; 32]).expect("key pair");
    let plan = EvidenceKeyPlan::create(EvidenceKeyPlanInput {
        provider_identity: identity,
        key_id: key_id.into(),
        store_id: store_id.into(),
        policy_snapshot_sha256: "b".repeat(64),
        activation_public_key_hex: lower_hex(pair.public_key().as_ref()),
        issued_at_epoch_seconds: NOW - 5,
        expires_at_epoch_seconds: NOW + 120,
    })
    .expect("plan");
    let message = EvidenceKeyActivation::signing_message(&plan.plan_sha256).expect("message");
    let activation = EvidenceKeyActivation::from_signature(
        plan.plan_sha256.clone(),
        pair.sign(&message).as_ref(),
    )
    .expect("activation");
    (plan, activation)
}

fn acquire_error(
    config: nxb_evidence_key_provider_process::ProcessEvidenceKeyProviderConfig,
) -> EvidenceKeyProviderError {
    let identity = config.evidence_identity().expect("evidence identity");
    let store_id = config.store_id.clone();
    let key_id = config.key_id.clone();
    let (plan, activation) = signed_plan(identity, &store_id, &key_id);
    let mut provider = ProcessEvidenceKeyProvider::new(config).expect("provider");
    acquire_evidence_sealer(plan, activation, &mut provider, NOW)
        .expect_err("adversarial acquisition must fail")
}

fn base_config(
    store_id: &str,
    key_id: &str,
    required_version_sha256: Option<String>,
) -> nxb_evidence_key_provider_process::ProcessEvidenceKeyProviderConfig {
    bundled_windows_credential_config(
        &install_root(),
        &helper_sha256(),
        store_id,
        key_id,
        required_version_sha256,
        NOW + 300,
        Duration::from_secs(5),
    )
    .expect("bundled config")
}

#[test]
fn wrong_executable_digest_is_fail_closed_with_real_helper() {
    let (store_id, key_id) = unique_ids("wrong-digest");
    let mut config = base_config(&store_id, &key_id, None);
    let wrong = "00".repeat(32);
    config.process.executable_sha256 = wrong.clone();
    config.process.expected_identity.provider_instance_sha256 = wrong;
    assert!(matches!(
        acquire_error(config),
        EvidenceKeyProviderError::ProviderBeginFailure(code)
            if code == "process_executable_digest_mismatch"
    ));
}

#[test]
fn wrong_provider_capability_is_fail_closed_with_real_helper() {
    let (store_id, key_id) = unique_ids("wrong-identity");
    let mut config = base_config(&store_id, &key_id, None);
    config.process.expected_identity.capability_sha256 = "00".repeat(32);
    assert!(matches!(
        acquire_error(config),
        EvidenceKeyProviderError::ProviderBeginFailure(code)
            if code == "process_identity_mismatch"
    ));
}

#[test]
fn wrong_provider_handle_is_rejected_by_real_helper() {
    let (store_id, key_id) = unique_ids("wrong-handle");
    let _cleanup = CredentialCleanup::new(&store_id, &key_id);
    create_valid_credential(&store_id, &key_id);
    let mut config = base_config(&store_id, &key_id, None);
    config.provider_handle.push_str("::wrong");
    assert!(matches!(
        acquire_error(config),
        EvidenceKeyProviderError::ProviderFetchFailure(code)
            if code == "windows_credential_handle_mismatch"
    ));
}

#[test]
fn missing_credential_is_rejected_by_real_helper() {
    let (store_id, key_id) = unique_ids("missing");
    delete_raw_credential(&target_name(&store_id, &key_id));
    assert!(matches!(
        acquire_error(base_config(&store_id, &key_id, None)),
        EvidenceKeyProviderError::ProviderFetchFailure(code)
            if code == "windows_credential_missing"
    ));
}

#[test]
fn stale_required_version_is_rejected_by_real_helper() {
    let (store_id, key_id) = unique_ids("stale-version");
    let _cleanup = CredentialCleanup::new(&store_id, &key_id);
    let actual_version = create_valid_credential(&store_id, &key_id);
    let stale = sha256_hex(b"definitely-not-the-current-version");
    assert_ne!(stale, sha256_hex(actual_version.as_bytes()));
    assert!(matches!(
        acquire_error(base_config(&store_id, &key_id, Some(stale))),
        EvidenceKeyProviderError::ProviderFetchFailure(code)
            if code == "windows_credential_version_mismatch"
    ));
}

#[test]
fn corrupt_credential_record_is_rejected_by_real_helper() {
    let (store_id, key_id) = unique_ids("corrupt");
    let target = target_name(&store_id, &key_id);
    let _cleanup = CredentialCleanup::new(&store_id, &key_id);
    delete_raw_credential(&target);
    write_corrupt_credential(&target);
    assert!(matches!(
        acquire_error(base_config(&store_id, &key_id, None)),
        EvidenceKeyProviderError::ProviderFetchFailure(code)
            if code == "windows_credential_metadata_invalid"
    ));
}

#[test]
fn lifecycle_failures_are_exact_and_metadata_remains_non_secret() {
    let (store_id, key_id) = unique_ids("lifecycle");
    let _cleanup = CredentialCleanup::new(&store_id, &key_id);
    delete_raw_credential(&target_name(&store_id, &key_id));

    let rotate_missing = helper_output(&lifecycle_mutation_arguments("rotate", &store_id, &key_id));
    assert!(!rotate_missing.status.success());
    assert!(rotate_missing.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&rotate_missing.stderr).trim(),
        "NXB_ERROR=windows_credential_missing"
    );

    let delete_missing = helper_output(&lifecycle_mutation_arguments("delete", &store_id, &key_id));
    assert!(!delete_missing.status.success());
    assert!(delete_missing.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&delete_missing.stderr).trim(),
        "NXB_ERROR=windows_credential_missing"
    );

    let mut wrong_confirmation = lifecycle_arguments("create", &store_id, &key_id);
    wrong_confirmation.push("--confirm-target".into());
    wrong_confirmation.push("yes".into());
    let confirmation = helper_output(&wrong_confirmation);
    assert!(!confirmation.status.success());
    assert!(confirmation.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&confirmation.stderr).trim(),
        "NXB_ERROR=windows_credential_confirmation_required"
    );

    create_valid_credential(&store_id, &key_id);
    let duplicate = helper_output(&lifecycle_mutation_arguments("create", &store_id, &key_id));
    assert!(!duplicate.status.success());
    assert!(duplicate.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&duplicate.stderr).trim(),
        "NXB_ERROR=windows_credential_already_exists"
    );

    let status = lifecycle_json(&lifecycle_arguments("status", &store_id, &key_id));
    assert_metadata_only(&status);
    assert_eq!(status["present"], true);
    assert_eq!(status["key_bytes"], 32);
}

#[test]
fn malformed_and_truncated_protocol_inputs_fail_without_output() {
    for bytes in [b"NXB1".as_slice(), b"BAD!\0\0\0\0\0\0\0\0".as_slice()] {
        let mut child = Command::new(helper_executable())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("protocol helper spawn");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(bytes)
            .expect("protocol bytes");
        drop(child.stdin.take());
        let output = child.wait_with_output().expect("protocol helper output");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[repr(C)]
struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

#[repr(C)]
struct CredentialW {
    flags: u32,
    credential_type: u32,
    target_name: *mut u16,
    comment: *mut u16,
    last_written: FileTime,
    credential_blob_size: u32,
    credential_blob: *mut u8,
    persist: u32,
    attribute_count: u32,
    attributes: *mut c_void,
    target_alias: *mut u16,
    user_name: *mut u16,
}

#[link(name = "Advapi32")]
unsafe extern "system" {
    #[link_name = "CredWriteW"]
    fn cred_write_w(credential: *const CredentialW, flags: u32) -> i32;

    #[link_name = "CredDeleteW"]
    fn cred_delete_w(target_name: *const u16, credential_type: u32, flags: u32) -> i32;
}

fn write_corrupt_credential(target: &str) {
    let mut wide_target = wide_nul(target);
    let mut wide_comment = wide_nul("NXB_EVIDENCE_KEY_VERSION:v1-00000000000000000000000000000000");
    let mut non_secret_corrupt_sentinel = [0xa5_u8; 31];
    let credential = CredentialW {
        flags: 0,
        credential_type: CRED_TYPE_GENERIC,
        target_name: wide_target.as_mut_ptr(),
        comment: wide_comment.as_mut_ptr(),
        last_written: FileTime {
            low_date_time: 0,
            high_date_time: 0,
        },
        credential_blob_size: non_secret_corrupt_sentinel.len() as u32,
        credential_blob: non_secret_corrupt_sentinel.as_mut_ptr(),
        persist: CRED_PERSIST_LOCAL_MACHINE,
        attribute_count: 0,
        attributes: ptr::null_mut(),
        target_alias: ptr::null_mut(),
        user_name: ptr::null_mut(),
    };
    // SAFETY: every pointer references a live buffer for the duration of this synchronous
    // test-only CredWriteW call. The 31-byte blob is an explicit non-secret corrupt sentinel,
    // not evidence-key material. It exists only to prove the production helper rejects a
    // malformed credential record.
    let success = unsafe { cred_write_w(&credential, 0) };
    non_secret_corrupt_sentinel.fill(0);
    assert_ne!(success, 0, "CredWriteW corrupt fixture failed");
}

fn delete_raw_credential(target: &str) {
    let wide_target = wide_nul(target);
    // SAFETY: wide_target is NUL-terminated and live for the synchronous CredDeleteW call.
    // Missing credentials are intentionally ignored by this test cleanup primitive.
    let _ = unsafe { cred_delete_w(wide_target.as_ptr(), CRED_TYPE_GENERIC, 0) };
}

fn wide_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
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
