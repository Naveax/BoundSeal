use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

const SETUP_EXIT_CODE: i32 = 55;

fn nxb() -> &'static str {
    env!("CARGO_BIN_EXE_nxb")
}

fn temporary_workspace() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nxb153-subdomain-failclosed-{}-{nonce}",
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
        "NXB-153 Subdomain Fail-Closed Test".into(),
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

fn common_tail(authorization: &Path) -> Vec<String> {
    vec![
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
        "--json".into(),
    ]
}

fn assert_subdomain_rejection(output: &Output) {
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
        .is_some_and(|message| message.contains("registrable-domain boundary")));
}

#[test]
fn manual_and_imported_subdomain_expansion_fail_closed_without_psl_boundary() {
    let root = temporary_workspace();
    initialize(&root);
    let authorization = authorization_document(&root);

    let mut manual = vec![
        "target".into(),
        "setup".into(),
        "--workspace".into(),
        root.to_string_lossy().into_owned(),
        "--id".into(),
        "example-app".into(),
        "--name".into(),
        "Example App".into(),
        "--origin".into(),
        "https://example.co.uk".into(),
        "--include-path".into(),
        "/api".into(),
        "--allow-subdomains".into(),
    ];
    manual.extend(common_tail(&authorization));
    assert_subdomain_rejection(&run(&manual));

    let scope = root.join("tmp").join("scope.json");
    fs::write(
        &scope,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "origin": "https://example.co.uk",
            "include_paths": ["/api"],
            "exclude_paths": [],
            "allow_subdomains": true
        }))
        .unwrap(),
    )
    .unwrap();

    let mut imported = vec![
        "target".into(),
        "setup-import".into(),
        "--workspace".into(),
        root.to_string_lossy().into_owned(),
        "--id".into(),
        "example-app".into(),
        "--name".into(),
        "Example App".into(),
        "--scope-import".into(),
        scope.to_string_lossy().into_owned(),
    ];
    imported.extend(common_tail(&authorization));
    assert_subdomain_rejection(&run(&imported));

    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(root.join("state")).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
}
