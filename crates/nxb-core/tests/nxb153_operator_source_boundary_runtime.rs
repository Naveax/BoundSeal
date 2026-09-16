use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

const SCOPE_LIMIT: usize = 64 * 1024;
const POLICY_LIMIT: usize = 1024 * 1024;
const AUTHORIZATION_LIMIT: usize = 8 * 1024 * 1024;

const POLICY_BASE: &str = r#"schema_version = 1

[program]
name = "Example Program"
platform = "hackerone"
policy_url = "https://hackerone.com/example"

[scope]
include_hosts = ["example.org"]
exclude_hosts = []
allowed_schemes = ["https"]
allowed_methods = ["GET", "HEAD", "OPTIONS"]
allow_subdomains = false

[automation]
active_testing = false
credential_bruteforce = false
destructive_testing = false
oob_callbacks = false
max_requests_per_second = 1.0
max_concurrency = 1
max_total_requests = 10

[authorization]
confirmed = true
researcher = "test-researcher"
policy_snapshot_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
expires_at = 2099-01-01T00:00:00Z
"#;

fn nxb() -> &'static str {
    env!("CARGO_BIN_EXE_nxb")
}

fn temporary_workspace(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nxb153-operator-boundary-{name}-{}-{nonce}",
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
        "NXB-153 Operator Boundary Test".into(),
        "--json".into(),
    ]);
    assert_eq!(
        value.get("status").and_then(Value::as_str),
        Some("initialized")
    );
}

fn write_policy(path: &Path, length: usize) {
    let mut bytes = POLICY_BASE.as_bytes().to_vec();
    assert!(bytes.len() + 2 <= length);
    bytes.extend_from_slice(b"\n#");
    bytes.resize(length, b'x');
    fs::write(path, bytes).unwrap();
}

fn write_authorization(path: &Path, length: usize) {
    fs::write(path, vec![b'a'; length]).unwrap();
}

fn create_arguments(root: &Path, policy: &Path, authorization: &Path) -> Vec<String> {
    vec![
        "target".into(),
        "create".into(),
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
        "--authorization-reference".into(),
        "hackerone/program/example#scope-2026".into(),
        "--authorization-document".into(),
        authorization.to_string_lossy().into_owned(),
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--json".into(),
    ]
}

fn assert_create_rejected(output: &Output) {
    assert_eq!(output.status.code(), Some(50));
    assert!(output.stdout.is_empty());
    let diagnostic: Value =
        serde_json::from_slice(&output.stderr).expect("failure stderr is not diagnostic JSON");
    assert_eq!(
        diagnostic.get("code").and_then(Value::as_str),
        Some("NXB151-TARGET-CREATE-REJECTED")
    );
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

fn write_scope(path: &Path, length: usize) {
    let mut bytes = br#"{"schema_version":1,"origin":"https://example.org","include_paths":["/api"],"exclude_paths":[],"allow_subdomains":false}"#.to_vec();
    assert!(bytes.len() <= length);
    bytes.resize(length, b' ');
    fs::write(path, bytes).unwrap();
}

#[test]
fn scope_import_accepts_exact_64_kib_and_rejects_one_byte_oversize() {
    let root = temporary_workspace("scope");
    initialize(&root);
    let authorization = root.join("tmp").join("authorization.txt");
    let scope = root.join("tmp").join("scope.json");
    write_authorization(&authorization, 32);

    write_scope(&scope, SCOPE_LIMIT);
    let preview = run_json(&setup_import_arguments(&root, &authorization, &scope));
    assert_eq!(
        preview.get("status").and_then(Value::as_str),
        Some("preview")
    );

    write_scope(&scope, SCOPE_LIMIT + 1);
    let output = run(&setup_import_arguments(&root, &authorization, &scope));
    assert_eq!(output.status.code(), Some(55));
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn policy_and_authorization_accept_exact_product_limits() {
    let root = temporary_workspace("exact");
    initialize(&root);
    let policy = root.join("tmp").join("policy.toml");
    let authorization = root.join("tmp").join("authorization.bin");
    write_policy(&policy, POLICY_LIMIT);
    write_authorization(&authorization, AUTHORIZATION_LIMIT);

    let created = run_json(&create_arguments(&root, &policy, &authorization));
    assert_eq!(
        created.get("status").and_then(Value::as_str),
        Some("active")
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn policy_rejects_one_byte_over_1_mib_without_mutation() {
    let root = temporary_workspace("policy-oversize");
    initialize(&root);
    let policy = root.join("tmp").join("policy.toml");
    let authorization = root.join("tmp").join("authorization.bin");
    write_policy(&policy, POLICY_LIMIT + 1);
    write_authorization(&authorization, 32);

    let output = run(&create_arguments(&root, &policy, &authorization));
    assert_create_rejected(&output);
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn authorization_rejects_one_byte_over_8_mib_without_mutation() {
    let root = temporary_workspace("authorization-oversize");
    initialize(&root);
    let policy = root.join("tmp").join("policy.toml");
    let authorization = root.join("tmp").join("authorization.bin");
    write_policy(&policy, POLICY_BASE.len() + 2);
    write_authorization(&authorization, AUTHORIZATION_LIMIT + 1);

    let output = run(&create_arguments(&root, &policy, &authorization));
    assert_create_rejected(&output);
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);

    fs::remove_dir_all(root).unwrap();
}
