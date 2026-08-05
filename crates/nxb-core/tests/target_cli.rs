use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

const CREATE_EXIT_CODE: i32 = 50;
const LIST_EXIT_CODE: i32 = 51;
const SHOW_EXIT_CODE: i32 = 52;

fn nxb() -> &'static str {
    env!("CARGO_BIN_EXE_nxb")
}

fn temporary_workspace(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nxb-target-cli-{name}-{}-{nonce}",
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

fn assert_diagnostic(
    output: &Output,
    expected_exit: i32,
    expected_code: &str,
    expected_operation: &str,
) {
    assert_eq!(output.status.code(), Some(expected_exit));
    assert!(output.stdout.is_empty(), "failed JSON command wrote stdout");
    let value: Value =
        serde_json::from_slice(&output.stderr).expect("failure stderr is not diagnostic JSON");
    assert_eq!(value.get("schema_version").and_then(Value::as_u64), Some(1));
    assert_eq!(value.get("status").and_then(Value::as_str), Some("error"));
    assert_eq!(value.get("code").and_then(Value::as_str), Some(expected_code));
    assert_eq!(value.get("domain").and_then(Value::as_str), Some("target"));
    assert_eq!(
        value.get("operation").and_then(Value::as_str),
        Some(expected_operation)
    );
    assert_eq!(
        value.get("exit_code").and_then(Value::as_i64),
        Some(i64::from(expected_exit))
    );
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .expect("diagnostic message is missing");
    assert!(!message.is_empty());
    assert!(!message
        .chars()
        .any(|value| matches!(value, '\n' | '\r' | '\0')));
}

fn initialize(root: &Path) {
    let root = root.to_str().expect("temporary path is not UTF-8");
    let value = run_json(&[
        "workspace",
        "init",
        "--workspace",
        root,
        "--name",
        "Target CLI Test",
        "--json",
    ]);
    assert_eq!(value.get("status").and_then(Value::as_str), Some("initialized"));
}

fn create_target(root: &Path) -> Value {
    let root = root.to_str().expect("temporary path is not UTF-8");
    run_json(&[
        "target",
        "create",
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
        "--json",
    ])
}

#[test]
fn target_cli_create_list_show_and_disable_lifecycle() {
    let root = temporary_workspace("lifecycle");
    initialize(&root);

    let created = create_target(&root);
    assert_eq!(created.get("status").and_then(Value::as_str), Some("active"));
    assert_eq!(
        created.get("network_activity").and_then(Value::as_str),
        Some("none")
    );

    let root_text = root.to_str().unwrap();
    let listed = run_json(&["target", "list", "--workspace", root_text, "--json"]);
    assert_eq!(listed.get("count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        listed.get("network_activity").and_then(Value::as_str),
        Some("none")
    );

    let shown = run_json(&[
        "target",
        "show",
        "--workspace",
        root_text,
        "--id",
        "example-app",
        "--json",
    ]);
    assert_eq!(shown.get("origin").and_then(Value::as_str), Some("https://example.org"));

    let disabled = run_json(&[
        "target",
        "disable",
        "--workspace",
        root_text,
        "--id",
        "example-app",
        "--reason",
        "operator-hold",
        "--json",
    ]);
    assert_eq!(disabled.get("status").and_then(Value::as_str), Some("disabled"));

    let active = run_json(&["target", "list", "--workspace", root_text, "--json"]);
    assert_eq!(active.get("count").and_then(Value::as_u64), Some(0));
    let all = run_json(&[
        "target",
        "list",
        "--workspace",
        root_text,
        "--include-disabled",
        "--json",
    ]);
    assert_eq!(all.get("count").and_then(Value::as_u64), Some(1));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn target_cli_rejects_unsafe_origins_and_pending_migration() {
    let root = temporary_workspace("fail-closed");
    initialize(&root);
    let root_text = root.to_str().unwrap();

    for (index, origin) in [
        "http://example.org",
        "https://user@example.org",
        "https://127.0.0.1",
        "https://service.internal",
        "https://*.example.org",
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("invalid-{index}");
        let output = run(&[
            "target",
            "create",
            "--workspace",
            root_text,
            "--id",
            &id,
            "--name",
            "Invalid Target",
            "--origin",
            origin,
            "--json",
        ]);
        assert_diagnostic(
            &output,
            CREATE_EXIT_CODE,
            "NXB151-TARGET-CREATE-REJECTED",
            "create",
        );
    }

    fs::write(root.join("state").join("migration-active.json"), b"{}\n").unwrap();
    let output = run(&["target", "list", "--workspace", root_text, "--json"]);
    assert_diagnostic(
        &output,
        LIST_EXIT_CODE,
        "NXB151-TARGET-LIST-INVALID",
        "list",
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn target_cli_rejects_profile_and_receipt_tampering() {
    let root = temporary_workspace("tamper");
    initialize(&root);
    create_target(&root);
    let root_text = root.to_str().unwrap();
    let profile_path = root.join("targets").join("example-app.json");
    let original = fs::read(&profile_path).unwrap();

    let mut profile: Value = serde_json::from_slice(&original).unwrap();
    profile["origin"] = Value::String("https://attacker.invalid".into());
    fs::write(&profile_path, serde_json::to_vec_pretty(&profile).unwrap()).unwrap();
    let output = run(&[
        "target",
        "show",
        "--workspace",
        root_text,
        "--id",
        "example-app",
        "--json",
    ]);
    assert_diagnostic(
        &output,
        SHOW_EXIT_CODE,
        "NXB151-TARGET-SHOW-INVALID",
        "show",
    );

    fs::write(&profile_path, original).unwrap();
    run_json(&[
        "target",
        "disable",
        "--workspace",
        root_text,
        "--id",
        "example-app",
        "--reason",
        "scope-removed",
        "--json",
    ]);
    let receipt_path = root.join("targets").join("example-app.disabled.json");
    let mut receipt: Value = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    receipt["profile_sha256"] = Value::String("0".repeat(64));
    fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    let output = run(&[
        "target",
        "show",
        "--workspace",
        root_text,
        "--id",
        "example-app",
        "--json",
    ]);
    assert_diagnostic(
        &output,
        SHOW_EXIT_CODE,
        "NXB151-TARGET-SHOW-INVALID",
        "show",
    );

    fs::remove_dir_all(root).unwrap();
}
