use std::time::Duration;

use nxb_evidence_key_provider_process::{
    bundled_windows_credential_config, ProcessEvidenceKeyProviderError,
    WINDOWS_CREDENTIAL_CAPABILITY_V1, WINDOWS_CREDENTIAL_HELPER_FILE_NAME,
    WINDOWS_CREDENTIAL_PROVIDER_ID, WINDOWS_CREDENTIAL_TARGET_PREFIX,
};
use nxb_vault_provider_process::sha256_hex;

fn absolute_install_root() -> std::path::PathBuf {
    std::env::current_dir()
        .expect("current directory")
        .join("nxb-pass-d-bundled-install-root")
}

#[test]
fn bundled_config_binds_exact_sibling_helper_identity_and_handle() {
    let install_root = absolute_install_root();
    let helper_sha256 = "11".repeat(32);
    let required_version_sha256 = Some("22".repeat(32));

    let config = bundled_windows_credential_config(
        &install_root,
        &helper_sha256,
        "store-a",
        "key-a",
        required_version_sha256.clone(),
        1_900_000_000,
        Duration::from_millis(250),
    )
    .expect("bundled config should be valid");

    assert_eq!(
        config.process.executable,
        install_root.join(WINDOWS_CREDENTIAL_HELPER_FILE_NAME)
    );
    assert_eq!(config.process.executable_sha256, helper_sha256);
    assert_eq!(
        config.process.expected_identity.provider_id,
        WINDOWS_CREDENTIAL_PROVIDER_ID
    );
    assert_eq!(
        config.process.expected_identity.provider_instance_sha256,
        helper_sha256
    );
    assert_eq!(
        config.process.expected_identity.capability_sha256,
        sha256_hex(WINDOWS_CREDENTIAL_CAPABILITY_V1)
    );
    assert_eq!(config.store_id, "store-a");
    assert_eq!(config.key_id, "key-a");
    assert_eq!(
        config.provider_handle,
        format!("{WINDOWS_CREDENTIAL_TARGET_PREFIX}store-a::key-a")
    );
    assert_eq!(config.required_version_sha256, required_version_sha256);
    assert_eq!(config.process.operation_timeout, Duration::from_millis(250));

    config
        .evidence_identity()
        .expect("factory output must satisfy adapter validation");
}

#[test]
fn bundled_config_rejects_relative_install_root() {
    let error = bundled_windows_credential_config(
        std::path::Path::new("relative-install-root"),
        &"11".repeat(32),
        "store-a",
        "key-a",
        None,
        1_900_000_000,
        Duration::from_millis(250),
    )
    .expect_err("relative install root must fail");

    assert_eq!(
        error,
        ProcessEvidenceKeyProviderError::InvalidConfiguration("install_root")
    );
}

#[test]
fn bundled_config_rejects_unpinned_helper_digest() {
    let error = bundled_windows_credential_config(
        &absolute_install_root(),
        "not-a-sha256",
        "store-a",
        "key-a",
        None,
        1_900_000_000,
        Duration::from_millis(250),
    )
    .expect_err("invalid helper digest must fail");

    assert_eq!(
        error,
        ProcessEvidenceKeyProviderError::InvalidConfiguration("helper_sha256")
    );
}
