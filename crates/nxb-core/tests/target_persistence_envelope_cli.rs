use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

const SETUP_EXIT_CODE: i32 = 55;
const PERSISTENCE_USABLE_BYTES: u64 = 60 * 1024;

fn nxb() -> &'static str {
    env!("CARGO_BIN_EXE_nxb")
}

fn temporary_workspace(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nxb153-persistence-envelope-{name}-{}-{nonce}",
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
        "NXB-153 Persistence Envelope Test".into(),
        "--json".into(),
    ]);
    assert_eq!(
        value.get("status").and_then(Value::as_str),
        Some("initialized")
    );
}

fn authorization_document(root: &Path) -> PathBuf {
    let path = root.join("tmp").join("authorization-evidence.txt");
    fs::write(&path, b"explicit authorization fixture\n").unwrap();
    path
}

fn scope_import(root: &Path, name: &str, value: &Value) -> PathBuf {
    let path = root.join("tmp").join(name);
    fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    path
}

fn import_arguments(
    command: &str,
    root: &Path,
    authorization: &Path,
    scope: &Path,
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
        "--scope-import".into(),
        scope.to_string_lossy().into_owned(),
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

fn assert_setup_rejected_for_envelope(output: &Output) {
    assert_eq!(output.status.code(), Some(SETUP_EXIT_CODE));
    assert!(output.stdout.is_empty());
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(
        diagnostic.get("code").and_then(Value::as_str),
        Some("NXB153-TARGET-SETUP-REJECTED")
    );
    assert!(diagnostic
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| message.contains("persistence envelope")));
}

#[test]
fn setup_import_rejects_scope_that_parses_but_cannot_fit_persistence_envelope() {
    let root = temporary_workspace("oversized");
    initialize(&root);
    let authorization = authorization_document(&root);

    // Quotes are valid scope-path bytes but are escaped in JSON. Thirty-eight
    // include/exclude pairs keep the import itself below its 64 KiB parser cap
    // while pushing the richer persisted continuity representation above the
    // 60 KiB NXB-153 admission envelope.
    let include_paths = (0..38)
        .map(|index| format!("/p{index:02}{}", "\"".repeat(400)))
        .collect::<Vec<_>>();
    let exclude_paths = include_paths
        .iter()
        .map(|path| format!("{path}/x"))
        .collect::<Vec<_>>();

    let scope = scope_import(
        &root,
        "oversized-scope.json",
        &serde_json::json!({
            "schema_version": 1,
            "origin": "https://example.org",
            "include_paths": include_paths,
            "exclude_paths": exclude_paths,
            "allow_subdomains": false
        }),
    );
    let import_size = fs::metadata(&scope).unwrap().len();
    assert!(import_size < 64 * 1024, "fixture must reach persistence preflight");

    let output = run(&import_arguments(
        "setup-import",
        &root,
        &authorization,
        &scope,
    ));
    assert_setup_rejected_for_envelope(&output);
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(root.join("state")).unwrap().count(), 0);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn admitted_scope_activates_with_profile_and_artifact_inside_envelope() {
    let root = temporary_workspace("admitted");
    initialize(&root);
    let authorization = authorization_document(&root);
    let scope = scope_import(
        &root,
        "scope.json",
        &serde_json::json!({
            "schema_version": 1,
            "origin": "https://example.org",
            "include_paths": ["/api", "/assets"],
            "exclude_paths": ["/api/logout"],
            "allow_subdomains": false
        }),
    );

    let preview = run_json(&import_arguments(
        "setup-import",
        &root,
        &authorization,
        &scope,
    ));
    let preview_sha = preview
        .get("preview_sha256")
        .and_then(Value::as_str)
        .expect("preview SHA missing")
        .to_owned();

    let mut activation = import_arguments("activate-import", &root, &authorization, &scope);
    let json_index = activation
        .iter()
        .position(|value| value == "--json")
        .unwrap();
    activation.splice(
        json_index..json_index,
        [
            "--confirm-preview-sha".to_owned(),
            preview_sha,
            "--acknowledge-activation".to_owned(),
            "I_CONFIRM_THIS_EXACT_PREVIEW".to_owned(),
        ],
    );
    let activated = run_json(&activation);
    assert_eq!(
        activated.get("status").and_then(Value::as_str),
        Some("active")
    );

    let profile = root.join("targets").join("example-app.json");
    let artifact = root
        .join("state")
        .join("target-example-app.guided-activation.json");
    assert!(fs::metadata(profile).unwrap().len() <= PERSISTENCE_USABLE_BYTES);
    assert!(fs::metadata(artifact).unwrap().len() <= PERSISTENCE_USABLE_BYTES);

    fs::remove_dir_all(root).unwrap();
}
