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
        "nxb153-path-binding-{name}-{}-{nonce}",
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
        "NXB-153 Path Binding Test".into(),
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

fn guided_arguments(
    command: &str,
    root: &Path,
    authorization: &Path,
    include_path: &str,
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
        "--program-name".into(),
        "Example Program".into(),
        "--program-platform".into(),
        "hackerone".into(),
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

fn activation_arguments(
    root: &Path,
    authorization: &Path,
    include_path: &str,
    preview_sha256: &str,
) -> Vec<String> {
    let mut arguments = guided_arguments("activate", root, authorization, include_path);
    let json_index = arguments
        .iter()
        .position(|value| value == "--json")
        .expect("--json missing");
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
fn path_scope_change_invalidates_preview_and_binds_active_identity() {
    let root = temporary_workspace("scope");
    initialize(&root);
    let authorization = authorization_document(&root);

    let api_preview = run_json(&guided_arguments("setup", &root, &authorization, "/api"));
    let admin_preview = run_json(&guided_arguments(
        "setup",
        &root,
        &authorization,
        "/admin",
    ));

    let api_sha = api_preview
        .get("preview_sha256")
        .and_then(Value::as_str)
        .expect("api preview SHA missing");
    let admin_sha = admin_preview
        .get("preview_sha256")
        .and_then(Value::as_str)
        .expect("admin preview SHA missing");
    assert_ne!(api_sha, admin_sha);

    let stale = run(&activation_arguments(
        &root,
        &authorization,
        "/admin",
        api_sha,
    ));
    assert_eq!(stale.status.code(), Some(ACTIVATE_EXIT_CODE));
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);

    let activated = run_json(&activation_arguments(
        &root,
        &authorization,
        "/admin",
        admin_sha,
    ));
    assert_eq!(
        activated.get("include_paths"),
        Some(&serde_json::json!(["/admin"]))
    );
    assert_eq!(
        activated.get("status").and_then(Value::as_str),
        Some("active")
    );

    let profile_path = root.join("targets").join("example-app.json");
    let profile: Value = serde_json::from_slice(&fs::read(profile_path).unwrap()).unwrap();
    assert_eq!(
        profile.get("include_paths"),
        Some(&serde_json::json!(["/admin"]))
    );
    assert_eq!(
        profile.get("identity_sha256"),
        activated.get("identity_sha256")
    );

    fs::remove_dir_all(root).unwrap();
}
