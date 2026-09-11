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
        "nxb153-target-completed-recovery-{name}-{}-{nonce}",
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
        "NXB-153 Completed Recovery Test".into(),
        "--json".into(),
    ]);
    assert_eq!(
        value.get("status").and_then(Value::as_str),
        Some("initialized")
    );
}

fn authorization_document(root: &Path) -> PathBuf {
    let path = root.join("tmp").join("authorization-evidence.txt");
    fs::write(&path, b"authorized completed recovery fixture\n").unwrap();
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

fn profile_path(root: &Path) -> PathBuf {
    root.join("targets").join("example-app.json")
}

fn artifact_path(root: &Path) -> PathBuf {
    root.join("state")
        .join("target-example-app.guided-activation.json")
}

fn disable_path(root: &Path) -> PathBuf {
    root.join("targets").join("example-app.disabled.json")
}

struct CompletedFixture {
    root: PathBuf,
    authorization: PathBuf,
    arguments: Vec<String>,
    profile_bytes: Vec<u8>,
    artifact_bytes: Vec<u8>,
}

fn completed_fixture(name: &str) -> CompletedFixture {
    let root = temporary_workspace(name);
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
    run_json(&arguments);
    let profile_bytes = fs::read(profile_path(&root)).unwrap();
    let artifact_bytes = fs::read(artifact_path(&root)).unwrap();
    CompletedFixture {
        root,
        authorization,
        arguments,
        profile_bytes,
        artifact_bytes,
    }
}

#[test]
fn existing_profile_without_guided_artifact_is_rejected_without_mutation() {
    let fixture = completed_fixture("missing-artifact");
    let artifact = artifact_path(&fixture.root);
    fs::remove_file(&artifact).unwrap();

    assert_activation_rejection(&run(&fixture.arguments));
    assert_eq!(fs::read(profile_path(&fixture.root)).unwrap(), fixture.profile_bytes);
    assert!(!artifact.exists());

    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn existing_profile_bytes_must_match_exact_prospective_profile() {
    let fixture = completed_fixture("profile-mismatch");
    let profile = profile_path(&fixture.root);
    let original = String::from_utf8(fixture.profile_bytes.clone()).unwrap();
    let mutated = original.replacen("Example App", "Example Apx", 1);
    assert_ne!(mutated.as_bytes(), fixture.profile_bytes.as_slice());
    fs::write(&profile, mutated.as_bytes()).unwrap();

    let artifact_before = fs::read(artifact_path(&fixture.root)).unwrap();
    assert_activation_rejection(&run(&fixture.arguments));
    assert_eq!(fs::read(&profile).unwrap(), mutated.as_bytes());
    assert_eq!(
        fs::read(artifact_path(&fixture.root)).unwrap(),
        artifact_before
    );

    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn completed_activation_rejects_changed_confirmed_preview_without_mutation() {
    let fixture = completed_fixture("changed-preview");
    let changed_setup = preview(&fixture.root, &fixture.authorization, "/admin", "/admin/logout");
    let changed_sha = changed_setup
        .get("preview_sha256")
        .and_then(Value::as_str)
        .unwrap();
    let changed_arguments = activation_arguments(
        &fixture.root,
        &fixture.authorization,
        "/admin",
        "/admin/logout",
        changed_sha,
    );

    assert_activation_rejection(&run(&changed_arguments));
    assert_eq!(
        fs::read(profile_path(&fixture.root)).unwrap(),
        fixture.profile_bytes
    );
    assert_eq!(
        fs::read(artifact_path(&fixture.root)).unwrap(),
        fixture.artifact_bytes
    );

    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn disable_receipt_blocks_completed_activation_recovery_without_mutation() {
    let fixture = completed_fixture("disable-receipt");
    let disable = disable_path(&fixture.root);
    fs::write(&disable, b"disable-receipt-sentinel\n").unwrap();

    assert_activation_rejection(&run(&fixture.arguments));
    assert_eq!(
        fs::read(profile_path(&fixture.root)).unwrap(),
        fixture.profile_bytes
    );
    assert_eq!(
        fs::read(artifact_path(&fixture.root)).unwrap(),
        fixture.artifact_bytes
    );
    assert_eq!(fs::read(&disable).unwrap(), b"disable-receipt-sentinel\n");

    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn visible_profile_with_leftover_publication_link_recovers_without_rollback_mutation() {
    let fixture = completed_fixture("leftover-publication-link");
    let profile = profile_path(&fixture.root);
    let leftover = fixture
        .root
        .join("targets")
        .join(".example-app.json.0123456789abcdef01234567.tmp");
    fs::hard_link(&profile, &leftover).unwrap();
    let leftover_before = fs::read(&leftover).unwrap();

    let recovered = run_json(&fixture.arguments);
    let recovered_identity = recovered
        .get("identity_sha256")
        .and_then(Value::as_str)
        .unwrap();
    let persisted: Value = serde_json::from_slice(&fixture.profile_bytes).unwrap();
    assert_eq!(
        Some(recovered_identity),
        persisted.get("identity_sha256").and_then(Value::as_str)
    );
    assert_eq!(fs::read(&profile).unwrap(), fixture.profile_bytes);
    assert_eq!(
        fs::read(artifact_path(&fixture.root)).unwrap(),
        fixture.artifact_bytes
    );
    assert_eq!(fs::read(&leftover).unwrap(), leftover_before);

    let listed = run_json(&[
        "target".into(),
        "list".into(),
        "--workspace".into(),
        fixture.root.to_string_lossy().into_owned(),
        "--json".into(),
    ]);
    assert_eq!(listed.get("count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        listed.pointer("/targets/0/target_id").and_then(Value::as_str),
        Some("example-app")
    );

    let status = run_json(&[
        "workspace".into(),
        "status".into(),
        "--workspace".into(),
        fixture.root.to_string_lossy().into_owned(),
        "--json".into(),
    ]);
    assert_eq!(
        status.pointer("/records/targets").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(fs::read(&leftover).unwrap(), leftover_before);

    fs::remove_dir_all(fixture.root).unwrap();
}
