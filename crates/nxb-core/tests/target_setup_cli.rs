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
        "nxb153-target-setup-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn run(arguments: &[&str]) -> Output {
    Command::new(nxb())
        .args(arguments)
        .output()
        .expect("could not execute nxb")
}

fn run_json(arguments: &[&str]) -> Value {
    let output = run(arguments);

    assert!(
        output.status.success(),
        "command failed: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).expect("command returned invalid JSON")
}

fn assert_setup_rejection(output: &Output) {
    assert_eq!(output.status.code(), Some(SETUP_EXIT_CODE));

    assert!(output.stdout.is_empty(), "failed JSON command wrote stdout");

    let value: Value =
        serde_json::from_slice(&output.stderr).expect("failure stderr is not diagnostic JSON");

    assert_eq!(
        value.get("code").and_then(Value::as_str),
        Some("NXB153-TARGET-SETUP-REJECTED")
    );

    assert_eq!(value.get("domain").and_then(Value::as_str), Some("target"));

    assert_eq!(
        value.get("operation").and_then(Value::as_str),
        Some("setup")
    );

    assert_eq!(
        value.get("exit_code").and_then(Value::as_i64),
        Some(i64::from(SETUP_EXIT_CODE))
    );
}

fn initialize(root: &Path) {
    let root_text = root.to_str().unwrap();

    let value = run_json(&[
        "workspace",
        "init",
        "--workspace",
        root_text,
        "--name",
        "NXB-153 Target Setup Test",
        "--json",
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
        b"authorization evidence fixture; no credential material\n",
    )
    .unwrap();

    path
}

fn setup_arguments<'a>(root: &'a str, authorization: &'a str) -> Vec<&'a str> {
    vec![
        "target",
        "setup",
        "--workspace",
        root,
        "--id",
        "example-app",
        "--name",
        "Example App",
        "--origin",
        "https://example.org",
        "--include-path",
        "/api",
        "--exclude-path",
        "/api/logout",
        "--program-name",
        "Example Program",
        "--program-platform",
        "hackerone",
        "--program-reference",
        "https://hackerone.com/example",
        "--authorization-reference",
        "hackerone/program/example#scope-2026",
        "--authorization-document",
        authorization,
        "--researcher",
        "test-researcher",
        "--authorization-basis",
        "program-policy",
        "--authorization-expires-at",
        "2099-01-01T00:00:00Z",
        "--acknowledge-authorization",
        "I_HAVE_EXPLICIT_AUTHORIZATION",
        "--max-requests-per-second",
        "1",
        "--max-concurrency",
        "1",
        "--max-total-requests",
        "10",
        "--json",
    ]
}

#[test]
fn preview_is_deterministic_networkless_and_non_persistent() {
    let root = temporary_workspace("preview");

    initialize(&root);

    let authorization = authorization_document(&root);

    let root_text = root.to_str().unwrap();
    let authorization_text = authorization.to_str().unwrap();

    let targets = root.join("targets");

    let arguments = setup_arguments(root_text, authorization_text);

    let first = run_json(&arguments);
    let second = run_json(&arguments);

    assert_eq!(first, second, "preview must be deterministic");

    assert_eq!(first.get("status").and_then(Value::as_str), Some("preview"));

    assert_eq!(
        first.get("origin").and_then(Value::as_str),
        Some("https://example.org")
    );

    assert_eq!(
        first.get("network_activity").and_then(Value::as_str),
        Some("none")
    );

    assert_eq!(
        first
            .get("preview_sha256")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );

    assert_eq!(
        first
            .pointer("/authorization/basis")
            .and_then(Value::as_str),
        Some("program-policy")
    );

    assert_eq!(
        first
            .pointer("/policy/schema_version")
            .and_then(Value::as_u64),
        Some(1)
    );

    assert_eq!(
        first.pointer("/policy/compiled").and_then(Value::as_bool),
        Some(true)
    );

    assert_eq!(
        first
            .pointer("/policy/policy_snapshot_sha256")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );

    assert_eq!(
        first
            .pointer("/policy/policy_document_sha256")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );

    assert_ne!(
        first
            .pointer("/policy/policy_snapshot_sha256")
            .and_then(Value::as_str),
        first
            .pointer("/policy/policy_document_sha256")
            .and_then(Value::as_str)
    );

    assert_eq!(
        first
            .pointer("/automation/credential_bruteforce")
            .and_then(Value::as_bool),
        Some(false)
    );

    assert_eq!(
        first
            .pointer("/automation/destructive_testing")
            .and_then(Value::as_bool),
        Some(false)
    );

    assert_eq!(
        first
            .pointer("/automation/allow_subdomains")
            .and_then(Value::as_bool),
        Some(false)
    );

    assert_eq!(fs::read_dir(&targets).unwrap().count(), 0);

    let serialized = serde_json::to_string(&first).unwrap();

    assert!(!serialized.contains("authorization evidence fixture"));

    assert!(!serialized.contains(authorization_text));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn preview_rejects_unsafe_or_unauthorized_input_without_mutation() {
    let root = temporary_workspace("reject");

    initialize(&root);

    let authorization = authorization_document(&root);

    let root_text = root.to_str().unwrap();
    let authorization_text = authorization.to_str().unwrap();

    let targets = root.join("targets");

    let cases = [
        ("--origin", "https://*.example.org"),
        ("--origin", "https://example.org:8443"),
        ("--origin", "http://example.org"),
        ("--authorization-expires-at", "2000-01-01T00:00:00Z"),
        ("--acknowledge-authorization", "yes"),
        ("--program-platform", "HackerOne"),
        ("--max-requests-per-second", "6"),
        ("--max-concurrency", "9"),
        ("--max-total-requests", "100001"),
        ("--exclude-path", "/api"),
    ];

    for (field, replacement) in cases {
        let mut arguments = setup_arguments(root_text, authorization_text);

        let index = arguments
            .iter()
            .position(|value| *value == field)
            .expect("test field missing");

        arguments[index + 1] = replacement;

        let output = run(&arguments);

        assert_setup_rejection(&output);

        assert_eq!(fs::read_dir(&targets).unwrap().count(), 0);
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn preview_rejects_subdomain_expansion_until_registrable_boundary_is_verified() {
    let root = temporary_workspace("subdomain-reject");
    initialize(&root);
    let authorization = authorization_document(&root);
    let root_text = root.to_str().unwrap();
    let authorization_text = authorization.to_str().unwrap();

    let mut arguments = setup_arguments(root_text, authorization_text);
    let json_index = arguments
        .iter()
        .position(|value| *value == "--json")
        .unwrap();
    arguments.insert(json_index, "--allow-subdomains");

    let output = run(&arguments);
    assert_setup_rejection(&output);
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(diagnostic
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| message.contains("registrable-domain boundary")));
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(root.join("state")).unwrap().count(), 0);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn preview_policy_compiler_binds_budget_changes() {
    let root = temporary_workspace("policy-compiler");

    initialize(&root);

    let authorization = authorization_document(&root);
    let root_text = root.to_str().unwrap();
    let authorization_text = authorization.to_str().unwrap();

    let baseline_arguments = setup_arguments(root_text, authorization_text);

    let baseline = run_json(&baseline_arguments);

    let mut changed_arguments = setup_arguments(root_text, authorization_text);

    let index = changed_arguments
        .iter()
        .position(|value| *value == "--max-total-requests")
        .unwrap();

    changed_arguments[index + 1] = "11";

    let changed = run_json(&changed_arguments);

    assert_ne!(
        baseline.get("preview_sha256").and_then(Value::as_str),
        changed.get("preview_sha256").and_then(Value::as_str)
    );

    assert_ne!(
        baseline
            .pointer("/policy/policy_snapshot_sha256")
            .and_then(Value::as_str),
        changed
            .pointer("/policy/policy_snapshot_sha256")
            .and_then(Value::as_str)
    );

    assert_ne!(
        baseline
            .pointer("/policy/policy_document_sha256")
            .and_then(Value::as_str),
        changed
            .pointer("/policy/policy_document_sha256")
            .and_then(Value::as_str)
    );

    assert_eq!(
        baseline
            .pointer("/authorization/document_sha256")
            .and_then(Value::as_str),
        changed
            .pointer("/authorization/document_sha256")
            .and_then(Value::as_str)
    );

    assert_eq!(
        changed
            .pointer("/automation/max_total_requests")
            .and_then(Value::as_u64),
        Some(11)
    );

    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn preview_normalizes_explicit_https_443() {
    let root = temporary_workspace("canonical");

    initialize(&root);

    let authorization = authorization_document(&root);

    let root_text = root.to_str().unwrap();
    let authorization_text = authorization.to_str().unwrap();

    let mut arguments = setup_arguments(root_text, authorization_text);

    let origin_index = arguments
        .iter()
        .position(|value| *value == "--origin")
        .unwrap();

    arguments[origin_index + 1] = "https://EXAMPLE.ORG:443";

    let preview = run_json(&arguments);

    assert_eq!(
        preview.get("origin").and_then(Value::as_str),
        Some("https://example.org")
    );

    assert_eq!(
        preview
            .pointer("/automation/allow_subdomains")
            .and_then(Value::as_bool),
        Some(false)
    );

    assert_eq!(fs::read_dir(root.join("targets"),).unwrap().count(), 0);

    fs::remove_dir_all(root).unwrap();
}
