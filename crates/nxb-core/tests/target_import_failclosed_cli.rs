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

fn temporary_workspace(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nxb153-import-failclosed-{name}-{}-{nonce}",
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
        "NXB-153 Import Fail-Closed Test".into(),
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

fn setup_import_arguments(root: &Path, authorization: &Path, scope: &Path) -> Vec<String> {
    vec![
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

fn assert_setup_rejected(output: &Output) {
    assert_eq!(output.status.code(), Some(SETUP_EXIT_CODE));
    assert!(output.stdout.is_empty());
    let diagnostic: Value =
        serde_json::from_slice(&output.stderr).expect("failure stderr is not diagnostic JSON");
    assert_eq!(
        diagnostic.get("code").and_then(Value::as_str),
        Some("NXB153-TARGET-SETUP-REJECTED")
    );
}

#[test]
fn import_requires_explicit_non_empty_include_paths() {
    let root = temporary_workspace("paths");
    initialize(&root);
    let authorization = authorization_document(&root);

    let cases = [
        serde_json::json!({
            "schema_version": 1,
            "origin": "https://example.org",
            "exclude_paths": [],
            "allow_subdomains": false
        }),
        serde_json::json!({
            "schema_version": 1,
            "origin": "https://example.org",
            "include_paths": [],
            "exclude_paths": [],
            "allow_subdomains": false
        }),
    ];

    for (index, value) in cases.iter().enumerate() {
        let scope = root.join("tmp").join(format!("scope-{index}.json"));
        fs::write(&scope, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        let output = run(&setup_import_arguments(&root, &authorization, &scope));
        assert_setup_rejected(&output);
        assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);
    }

    fs::remove_dir_all(root).unwrap();
}
