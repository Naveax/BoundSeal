use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde_json::Value;

fn nxb() -> &'static str {
    env!("CARGO_BIN_EXE_nxb")
}

fn temporary_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nxb-diagnostic-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn run(arguments: &[&str]) -> Output {
    Command::new(nxb())
        .args(arguments)
        .output()
        .expect("could not execute nxb")
}

fn assert_diagnostic(
    output: &Output,
    expected_exit: i32,
    expected_code: &str,
    expected_domain: &str,
    expected_operation: &str,
) {
    assert_eq!(output.status.code(), Some(expected_exit));
    let value: Value =
        serde_json::from_slice(&output.stderr).expect("failure stderr is not diagnostic JSON");
    assert_eq!(value.get("schema_version").and_then(Value::as_u64), Some(1));
    assert_eq!(value.get("status").and_then(Value::as_str), Some("error"));
    assert_eq!(
        value.get("code").and_then(Value::as_str),
        Some(expected_code)
    );
    assert_eq!(
        value.get("domain").and_then(Value::as_str),
        Some(expected_domain)
    );
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

#[test]
fn workspace_init_and_doctor_emit_stable_json_diagnostics() {
    let occupied = temporary_path("occupied");
    fs::create_dir(&occupied).unwrap();
    fs::write(occupied.join("unexpected.txt"), b"occupied\n").unwrap();
    let occupied_text = occupied.to_str().unwrap();
    let output = run(&[
        "workspace",
        "init",
        "--workspace",
        occupied_text,
        "--name",
        "Occupied",
        "--json",
    ]);
    assert_diagnostic(
        &output,
        10,
        "NXB151-WORKSPACE-INIT-FAILED",
        "workspace",
        "init",
    );

    let missing = temporary_path("missing");
    let missing_text = missing.to_str().unwrap();
    let output = run(&["workspace", "doctor", "--workspace", missing_text, "--json"]);
    assert_diagnostic(
        &output,
        20,
        "NXB151-WORKSPACE-DOCTOR-UNHEALTHY",
        "workspace",
        "doctor",
    );

    fs::remove_dir_all(occupied).unwrap();
}

#[test]
fn workspace_status_and_migration_status_emit_stable_json_diagnostics() {
    let root = temporary_path("pending");
    let root_text = root.to_str().unwrap();
    let initialized = run(&[
        "workspace",
        "init",
        "--workspace",
        root_text,
        "--name",
        "Pending Migration",
        "--json",
    ]);
    assert!(initialized.status.success());

    let active = root.join("state").join("migration-active.json");
    let journal = serde_json::json!({
        "journal_version": 1,
        "migration_id": "nxb-migration-diagnostic-0001",
        "from_schema": 0,
        "to_schema": 1,
        "source_sha256": "1".repeat(64),
        "target_sha256": "2".repeat(64),
        "prepared_at": "2026-08-05T00:00:00Z"
    });
    let mut journal_bytes = serde_json::to_vec_pretty(&journal).unwrap();
    journal_bytes.push(b'\n');
    fs::write(&active, journal_bytes).unwrap();
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(&active).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&active, permissions).unwrap();
    }

    let output = run(&["workspace", "status", "--workspace", root_text, "--json"]);
    assert_diagnostic(
        &output,
        30,
        "NXB151-WORKSPACE-STATUS-FAILED",
        "workspace",
        "status",
    );
    assert!(
        !output.stdout.is_empty(),
        "status must preserve its redacted state document"
    );

    let missing = temporary_path("missing-migration");
    let missing_text = missing.to_str().unwrap();
    let output = run(&[
        "workspace",
        "migrate",
        "status",
        "--workspace",
        missing_text,
        "--json",
    ]);
    assert_diagnostic(
        &output,
        42,
        "NXB151-MIGRATION-STATUS-FAILED",
        "migration",
        "status",
    );

    fs::remove_dir_all(root).unwrap();
}
