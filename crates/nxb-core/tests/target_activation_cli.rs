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
        "nxb153-target-activation-{name}-{}-{nonce}",
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
    assert!(output.stdout.is_empty(), "failed JSON activation wrote stdout");

    let value: Value =
        serde_json::from_slice(&output.stderr).expect("failure stderr is not diagnostic JSON");

    assert_eq!(
        value.get("code").and_then(Value::as_str),
        Some("NXB153-TARGET-ACTIVATE-REJECTED")
    );
    assert_eq!(value.get("domain").and_then(Value::as_str), Some("target"));
    assert_eq!(
        value.get("operation").and_then(Value::as_str),
        Some("activate")
    );
    assert_eq!(
        value.get("exit_code").and_then(Value::as_i64),
        Some(i64::from(ACTIVATE_EXIT_CODE))
    );
}

fn initialize(root: &Path) {
    let value = run_json(&[
        "workspace".into(),
        "init".into(),
        "--workspace".into(),
        root.to_string_lossy().into_owned(),
        "--name".into(),
        "NXB-153 Activation Test".into(),
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
        b"PASS-C-RAW-AUTHORIZATION-SENTINEL must never persist\n",
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

fn preview(root: &Path, authorization: &Path) -> Value {
    run_json(&guided_arguments("setup", root, authorization))
}

fn activation_arguments(
    root: &Path,
    authorization: &Path,
    preview_sha256: &str,
) -> Vec<String> {
    let mut arguments = guided_arguments("activate", root, authorization);
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

#[test]
fn exact_preview_activation_creates_existing_profile_model_without_secret_persistence() {
    let root = temporary_workspace("success");
    initialize(&root);
    let authorization = authorization_document(&root);

    let preview = preview(&root, &authorization);
    let preview_sha256 = preview
        .get("preview_sha256")
        .and_then(Value::as_str)
        .unwrap();
    let preview_policy_sha256 = preview
        .pointer("/policy/policy_document_sha256")
        .and_then(Value::as_str)
        .unwrap();

    let activated = run_json(&activation_arguments(
        &root,
        &authorization,
        preview_sha256,
    ));

    assert_eq!(
        activated.get("status").and_then(Value::as_str),
        Some("active")
    );
    assert_eq!(
        activated.get("target_id").and_then(Value::as_str),
        Some("example-app")
    );
    assert_eq!(
        activated.get("origin").and_then(Value::as_str),
        Some("https://example.org")
    );
    assert_eq!(
        activated.get("policy_sha256").and_then(Value::as_str),
        Some(preview_policy_sha256)
    );
    assert_eq!(
        activated
            .pointer("/activation/preview_sha256")
            .and_then(Value::as_str),
        Some(preview_sha256)
    );
    assert_eq!(
        activated
            .pointer("/activation/confirmation")
            .and_then(Value::as_str),
        Some("exact_preview")
    );
    assert_eq!(
        activated
            .pointer("/activation/network_activity")
            .and_then(Value::as_str),
        Some("none")
    );

    let profile_path = root.join("targets").join("example-app.json");
    let profile_text = fs::read_to_string(&profile_path).unwrap();
    assert!(!profile_text.contains("PASS-C-RAW-AUTHORIZATION-SENTINEL"));
    assert!(!profile_text.contains(authorization.to_string_lossy().as_ref()));
    assert!(profile_text.contains(preview_policy_sha256));

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
    assert_eq!(shown.get("policy_sha256"), activated.get("policy_sha256"));
    assert_eq!(shown.get("identity_sha256"), activated.get("identity_sha256"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stale_preview_digest_rejects_changed_budget_before_persistence() {
    let root = temporary_workspace("stale-preview");
    initialize(&root);
    let authorization = authorization_document(&root);

    let preview = preview(&root, &authorization);
    let preview_sha256 = preview
        .get("preview_sha256")
        .and_then(Value::as_str)
        .unwrap();

    let mut arguments = activation_arguments(&root, &authorization, preview_sha256);
    let index = arguments
        .iter()
        .position(|value| value == "--max-total-requests")
        .unwrap();
    arguments[index + 1] = "11".into();

    let output = run(&arguments);
    assert_activation_rejection(&output);

    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(root.join("config")).unwrap().count(), 0);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn wrong_activation_acknowledgement_and_duplicate_activation_fail_closed() {
    let root = temporary_workspace("acknowledgement");
    initialize(&root);
    let authorization = authorization_document(&root);

    let preview = preview(&root, &authorization);
    let preview_sha256 = preview
        .get("preview_sha256")
        .and_then(Value::as_str)
        .unwrap();

    let mut wrong = activation_arguments(&root, &authorization, preview_sha256);
    let ack_index = wrong
        .iter()
        .position(|value| value == "--acknowledge-activation")
        .unwrap();
    wrong[ack_index + 1] = "yes".into();

    assert_activation_rejection(&run(&wrong));
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);

    let valid = activation_arguments(&root, &authorization, preview_sha256);
    let first = run(&valid);
    assert!(
        first.status.success(),
        "first activation failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    assert_activation_rejection(&run(&valid));
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 1);

    fs::remove_dir_all(root).unwrap();
}
