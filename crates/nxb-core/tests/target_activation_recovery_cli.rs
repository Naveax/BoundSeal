use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

const ACTIVATE_EXIT_CODE: i32 = 56;

fn nxb() -> &'static str {
    env!("CARGO_BIN_EXE_nxb")
}

fn temporary_workspace(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nxb153-target-activation-recovery-{name}-{}-{nonce}",
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

fn assert_activation_rejection(output: &Output) {
    assert_eq!(output.status.code(), Some(ACTIVATE_EXIT_CODE));
    assert!(output.stdout.is_empty());
    let value: Value =
        serde_json::from_slice(&output.stderr).expect("failure stderr is not diagnostic JSON");
    assert_eq!(
        value.get("code").and_then(Value::as_str),
        Some("NXB153-TARGET-ACTIVATE-REJECTED")
    );
}

fn initialize(root: &Path) {
    let value = run_json(&[
        "workspace".into(),
        "init".into(),
        "--workspace".into(),
        root.to_string_lossy().into_owned(),
        "--name".into(),
        "NXB-153 Activation Recovery Test".into(),
        "--json".into(),
    ]);
    assert_eq!(
        value.get("status").and_then(Value::as_str),
        Some("initialized")
    );
}

fn authorization_document(root: &Path) -> PathBuf {
    let path = root.join("tmp").join("authorization-evidence.txt");
    fs::write(&path, b"authorized recovery fixture\n").unwrap();
    path
}

fn guided_arguments(
    command: &str,
    root: &Path,
    authorization: &Path,
    include_path: &str,
    exclude_path: &str,
) -> Vec<String> {
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
        include_path.into(),
        "--exclude-path".into(),
        exclude_path.into(),
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

fn preview(
    root: &Path,
    authorization: &Path,
    include_path: &str,
    exclude_path: &str,
) -> Value {
    run_json(&guided_arguments(
        "setup",
        root,
        authorization,
        include_path,
        exclude_path,
    ))
}

fn activation_arguments(
    root: &Path,
    authorization: &Path,
    include_path: &str,
    exclude_path: &str,
    preview_sha256: &str,
) -> Vec<String> {
    let mut arguments = guided_arguments(
        "activate",
        root,
        authorization,
        include_path,
        exclude_path,
    );
    let json_index = arguments
        .iter()
        .position(|value| value == "--json")
        .unwrap();
    arguments.splice(
        json_index..json_index,
        [
            "--confirm-preview-sha".to_owned(),
            preview_sha256.to_owned(),
            "--acknowledge-activation".to_owned(),
            "I_CONFIRM_THIS_EXACT_PREVIEW".to_owned(),
        ],
    );
    arguments
}

fn artifact_path(root: &Path) -> PathBuf {
    root.join("state")
        .join("target-example-app.guided-activation.json")
}

fn profile_path(root: &Path) -> PathBuf {
    root.join("targets").join("example-app.json")
}

#[test]
fn exact_inert_continuity_is_reused_without_rewriting_artifact() {
    let root = temporary_workspace("exact");
    initialize(&root);
    let authorization = authorization_document(&root);

    let setup = preview(&root, &authorization, "/api", "/api/logout");
    let preview_sha256 = setup
        .get("preview_sha256")
        .and_then(Value::as_str)
        .unwrap();
    let arguments = activation_arguments(
        &root,
        &authorization,
        "/api",
        "/api/logout",
        preview_sha256,
    );
    let first = run_json(&arguments);
    let first_identity = first
        .get("identity_sha256")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();

    let artifact = artifact_path(&root);
    let profile = profile_path(&root);
    let artifact_before = fs::read(&artifact).unwrap();
    let artifact_value: Value = serde_json::from_slice(&artifact_before).unwrap();
    assert_eq!(
        artifact_value
            .get("profile_identity_sha256")
            .and_then(Value::as_str),
        Some(first_identity.as_str())
    );

    fs::remove_file(&profile).unwrap();
    assert!(!profile.exists());
    assert!(artifact.exists());

    let recovered = run_json(&arguments);
    assert_eq!(
        recovered.get("identity_sha256").and_then(Value::as_str),
        Some(first_identity.as_str())
    );
    assert_eq!(
        recovered
            .pointer("/activation/preview_sha256")
            .and_then(Value::as_str),
        Some(preview_sha256)
    );
    assert_eq!(fs::read(&artifact).unwrap(), artifact_before);
    assert!(profile.exists());

    let persisted_profile: Value =
        serde_json::from_slice(&fs::read(&profile).unwrap()).expect("profile is invalid JSON");
    assert_eq!(
        persisted_profile
            .get("identity_sha256")
            .and_then(Value::as_str),
        Some(first_identity.as_str())
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn inert_continuity_rejects_changed_preview_without_mutation() {
    let root = temporary_workspace("mismatch");
    initialize(&root);
    let authorization = authorization_document(&root);

    let original_setup = preview(&root, &authorization, "/api", "/api/logout");
    let original_sha = original_setup
        .get("preview_sha256")
        .and_then(Value::as_str)
        .unwrap();
    let original_arguments = activation_arguments(
        &root,
        &authorization,
        "/api",
        "/api/logout",
        original_sha,
    );
    run_json(&original_arguments);

    let artifact = artifact_path(&root);
    let profile = profile_path(&root);
    let artifact_before = fs::read(&artifact).unwrap();
    fs::remove_file(&profile).unwrap();

    let changed_setup = preview(&root, &authorization, "/admin", "/admin/logout");
    let changed_sha = changed_setup
        .get("preview_sha256")
        .and_then(Value::as_str)
        .unwrap();
    assert_ne!(original_sha, changed_sha);

    let changed_arguments = activation_arguments(
        &root,
        &authorization,
        "/admin",
        "/admin/logout",
        changed_sha,
    );
    assert_activation_rejection(&run(&changed_arguments));

    assert_eq!(fs::read(&artifact).unwrap(), artifact_before);
    assert!(!profile.exists());

    fs::remove_dir_all(root).unwrap();
}
