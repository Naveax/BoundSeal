use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

fn nxb() -> &'static str {
    env!("CARGO_BIN_EXE_nxb")
}

fn temporary_workspace() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nxb153-guided-artifact-{}-{nonce}",
        std::process::id()
    ))
}

fn run(arguments: &[String]) -> Output {
    Command::new(nxb())
        .args(arguments)
        .output()
        .expect("could not execute nxb")
}

fn run_json(arguments: &[String]) -> Value {
    let output = run(arguments);
    assert!(
        output.status.success(),
        "command failed: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command returned invalid JSON")
}

fn initialize(root: &Path) {
    let value = run_json(&[
        "workspace".into(),
        "init".into(),
        "--workspace".into(),
        root.to_string_lossy().into_owned(),
        "--name".into(),
        "NXB-153 Guided Artifact Test".into(),
        "--json".into(),
    ]);
    assert_eq!(
        value.get("status").and_then(Value::as_str),
        Some("initialized")
    );
}

fn authorization_document(root: &Path) -> PathBuf {
    let path = root.join("tmp").join("authorization-evidence.txt");
    fs::write(
        &path,
        b"GUIDED-RAW-AUTHORIZATION-SENTINEL must never persist\n",
    )
    .unwrap();
    path
}

fn guided_arguments(command: &str, root: &Path, authorization: &Path) -> Vec<String> {
    vec![
        "target".into(),
        command.into(),
        "--workspace".into(),
        root.to_string_lossy().into_owned(),
        "--id".into(),
        "example-app".into(),
        "--name".into(),
        "Example App".into(),
        "--origin".into(),
        "https://example.org".into(),
        "--include-path".into(),
        "/api".into(),
        "--exclude-path".into(),
        "/api/logout".into(),
        "--program-name".into(),
        "Example Program".into(),
        "--program-platform".into(),
        "hackerone".into(),
        "--program-reference".into(),
        "https://hackerone.com/example".into(),
        "--authorization-reference".into(),
        "hackerone/program/example#scope-2026".into(),
        "--authorization-document".into(),
        authorization.to_string_lossy().into_owned(),
        "--researcher".into(),
        "test-researcher".into(),
        "--authorization-basis".into(),
        "program-policy".into(),
        "--authorization-expires-at".into(),
        "2099-01-01T00:00:00Z".into(),
        "--acknowledge-authorization".into(),
        "I_HAVE_EXPLICIT_AUTHORIZATION".into(),
        "--max-requests-per-second".into(),
        "1".into(),
        "--max-concurrency".into(),
        "1".into(),
        "--max-total-requests".into(),
        "10".into(),
        "--json".into(),
    ]
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

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    lower_hex(digest.as_ref())
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[test]
fn guided_activation_persists_verified_non_secret_continuity_artifact() {
    let root = temporary_workspace();
    initialize(&root);
    let authorization = authorization_document(&root);

    let preview = run_json(&guided_arguments("setup", &root, &authorization));
    let preview_sha256 = preview
        .get("preview_sha256")
        .and_then(Value::as_str)
        .expect("preview SHA-256 missing")
        .to_owned();

    let mut activation_arguments = guided_arguments("activate", &root, &authorization);
    let json_index = activation_arguments
        .iter()
        .position(|value| value == "--json")
        .expect("--json missing");
    activation_arguments.splice(
        json_index..json_index,
        [
            "--confirm-preview-sha".to_owned(),
            preview_sha256.clone(),
            "--acknowledge-activation".to_owned(),
            "I_CONFIRM_THIS_EXACT_PREVIEW".to_owned(),
        ],
    );

    let activated = run_json(&activation_arguments);
    assert_eq!(
        activated.get("status").and_then(Value::as_str),
        Some("active")
    );

    let artifact_relative = activated
        .pointer("/activation/guided_artifact")
        .and_then(Value::as_str)
        .expect("guided artifact path missing");
    assert_eq!(
        artifact_relative,
        "state/target-example-app.guided-activation.json"
    );

    let artifact_path = root.join(artifact_relative);
    let artifact_bytes = fs::read(&artifact_path).expect("guided artifact is missing");
    let artifact_text =
        std::str::from_utf8(&artifact_bytes).expect("guided artifact is not UTF-8");

    assert!(!artifact_text.contains("GUIDED-RAW-AUTHORIZATION-SENTINEL"));
    assert!(!artifact_text.contains(authorization.to_string_lossy().as_ref()));

    let artifact: Value =
        serde_json::from_slice(&artifact_bytes).expect("guided artifact JSON is invalid");
    assert_eq!(
        artifact.get("artifact_version").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        artifact.get("target_id").and_then(Value::as_str),
        Some("example-app")
    );
    assert_eq!(
        artifact
            .get("profile_identity_sha256")
            .and_then(Value::as_str),
        activated.get("identity_sha256").and_then(Value::as_str)
    );
    assert_eq!(
        artifact
            .pointer("/preview/preview_sha256")
            .and_then(Value::as_str),
        Some(preview_sha256.as_str())
    );
    assert_eq!(
        artifact
            .pointer("/preview/automation/allow_subdomains")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        artifact
            .pointer("/preview/authorization/basis")
            .and_then(Value::as_str),
        Some("program-policy")
    );
    assert_eq!(
        artifact
            .pointer("/preview/authorization/researcher")
            .and_then(Value::as_str),
        Some("test-researcher")
    );
    assert_eq!(
        artifact
            .pointer("/preview/authorization/expires_at")
            .and_then(Value::as_str),
        Some("2099-01-01T00:00:00Z")
    );
    assert_eq!(
        artifact.get("network_activity").and_then(Value::as_str),
        Some("none")
    );

    let publication_nonce = artifact
        .get("publication_nonce")
        .and_then(Value::as_str)
        .expect("publication nonce missing");
    assert_eq!(publication_nonce.len(), 32);
    assert!(is_lower_hex(publication_nonce));

    let policy_document = artifact
        .get("policy_document")
        .and_then(Value::as_str)
        .expect("canonical policy document missing");
    assert!(policy_document.contains("allow_subdomains = false"));
    assert!(policy_document.contains("credential_bruteforce = false"));
    assert!(policy_document.contains("destructive_testing = false"));

    let policy_document_sha256 = sha256(policy_document.as_bytes());
    assert_eq!(
        artifact
            .pointer("/preview/policy/policy_document_sha256")
            .and_then(Value::as_str),
        Some(policy_document_sha256.as_str())
    );
    assert_eq!(
        activated.get("policy_sha256").and_then(Value::as_str),
        Some(policy_document_sha256.as_str())
    );
    assert_eq!(
        activated
            .pointer("/activation/policy_document_sha256")
            .and_then(Value::as_str),
        Some(policy_document_sha256.as_str())
    );

    let artifact_sha256 = sha256(artifact_bytes.as_slice());
    assert_eq!(
        activated
            .pointer("/activation/guided_artifact_sha256")
            .and_then(Value::as_str),
        Some(artifact_sha256.as_str())
    );

    assert_eq!(fs::read_dir(root.join("config")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 1);

    let shown = run_json(&[
        "target".into(),
        "show".into(),
        "--workspace".into(),
        root.to_string_lossy().into_owned(),
        "--id".into(),
        "example-app".into(),
        "--json".into(),
    ]);
    assert_eq!(
        shown.get("status").and_then(Value::as_str),
        Some("active")
    );
    assert_eq!(
        shown.get("identity_sha256").and_then(Value::as_str),
        activated.get("identity_sha256").and_then(Value::as_str)
    );

    fs::remove_dir_all(root).unwrap();
}
