use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

fn bsl() -> &'static str {
    env!("CARGO_BIN_EXE_bsl")
}

fn temporary_directory(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bsl-target-cli-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn run(arguments: &[&str]) -> Output {
    Command::new(bsl())
        .args(arguments)
        .output()
        .expect("could not execute bsl")
}

fn init_workspace(path: &Path) {
    let output = run(&[
        "workspace",
        "init",
        "--workspace",
        path.to_str().unwrap(),
        "--name",
        "Target CLI Test",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "workspace init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn policy_text(host: &str) -> String {
    format!(
        r#"schema_version = 1

[program]
name = "Example Program"
platform = "hackerone"
policy_url = "https://hackerone.com/example"

[scope]
include_hosts = ["{host}"]
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
"#
    )
}

fn create_target(root: &Path, policy: &Path, authorization: &Path) -> Output {
    run(&[
        "target",
        "create",
        "--workspace",
        root.to_str().unwrap(),
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
        "--authorization-reference",
        "hackerone/program/example#scope-2026",
        "--authorization-document",
        authorization.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--json",
    ])
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn assert_json_error(output: &Output, exit_code: i32, code: &str) {
    assert_eq!(output.status.code(), Some(exit_code));
    let value: Value = serde_json::from_slice(&output.stderr).expect("stderr is not JSON");
    assert_eq!(value.get("schema_version").and_then(Value::as_u64), Some(1));
    assert_eq!(value.get("status").and_then(Value::as_str), Some("error"));
    assert_eq!(value.get("code").and_then(Value::as_str), Some(code));
    assert_eq!(
        value.get("exit_code").and_then(Value::as_i64),
        Some(i64::from(exit_code))
    );
}

#[test]
fn target_lifecycle_is_networkless_and_redacted() {
    let root = temporary_directory("lifecycle");
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::remove_dir(&root).unwrap();
    init_workspace(&root);
    let policy = root.join("tmp").join("policy.toml");
    let authorization = root.join("tmp").join("authorization.txt");
    fs::write(&policy, policy_text("example.org")).unwrap();
    fs::write(&authorization, b"Bearer cli-secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&authorization, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let create = create_target(&root, &policy, &authorization);
    assert!(
        create.status.success(),
        "target create failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );
    let created: Value = serde_json::from_slice(&create.stdout).unwrap();
    assert_eq!(
        created.get("network_activity").and_then(Value::as_str),
        Some("none")
    );
    assert_eq!(
        created.get("status").and_then(Value::as_str),
        Some("active")
    );
    let profile = fs::read_to_string(root.join("targets").join("example-app.json")).unwrap();
    assert!(!profile.contains("cli-secret"));
    assert!(!profile.contains(policy.to_string_lossy().as_ref()));
    assert!(!profile.contains(authorization.to_string_lossy().as_ref()));

    let validate = run(&[
        "target",
        "validate",
        "--workspace",
        root.to_str().unwrap(),
        "--id",
        "example-app",
        "--authorization-document",
        authorization.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--json",
    ]);
    assert!(
        validate.status.success(),
        "target validate failed: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let validated: Value = serde_json::from_slice(&validate.stdout).unwrap();
    assert_eq!(
        validated
            .pointer("/validation/status")
            .and_then(Value::as_str),
        Some("valid")
    );

    let list = run(&[
        "target",
        "list",
        "--workspace",
        root.to_str().unwrap(),
        "--json",
    ]);
    assert!(list.status.success());
    let listed: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(listed.get("count").and_then(Value::as_u64), Some(1));

    let show = run(&[
        "target",
        "show",
        "--workspace",
        root.to_str().unwrap(),
        "--id",
        "example-app",
        "--json",
    ]);
    assert!(show.status.success());
    let shown: Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(
        shown.get("policy_sha256").and_then(Value::as_str),
        Some(sha256(&fs::read(&policy).unwrap()).as_str())
    );

    let disable = run(&[
        "target",
        "disable",
        "--workspace",
        root.to_str().unwrap(),
        "--id",
        "example-app",
        "--reason",
        "operator-hold",
        "--json",
    ]);
    assert!(disable.status.success());
    let disabled: Value = serde_json::from_slice(&disable.stdout).unwrap();
    assert_eq!(
        disabled.get("status").and_then(Value::as_str),
        Some("disabled")
    );

    let list = run(&[
        "target",
        "list",
        "--workspace",
        root.to_str().unwrap(),
        "--json",
    ]);
    let listed: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(listed.get("count").and_then(Value::as_u64), Some(0));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn target_failures_use_stable_exit_codes_and_json_diagnostics() {
    let root = temporary_directory("diagnostics");
    init_workspace(&root);
    let policy = root.join("tmp").join("policy.toml");
    let authorization = root.join("tmp").join("authorization.txt");
    fs::write(&policy, policy_text("example.org")).unwrap();
    fs::write(&authorization, b"authorization\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&authorization, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let unsafe_origin = run(&[
        "target",
        "create",
        "--workspace",
        root.to_str().unwrap(),
        "--id",
        "unsafe-origin",
        "--name",
        "Unsafe",
        "--origin",
        "https://user@example.org",
        "--authorization-reference",
        "hackerone/program/example#scope-2026",
        "--authorization-document",
        authorization.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--json",
    ]);
    assert_json_error(&unsafe_origin, 50, "BSL151-TARGET-CREATE-REJECTED");
    let missing = run(&[
        "target",
        "show",
        "--workspace",
        root.to_str().unwrap(),
        "--id",
        "missing-target",
        "--json",
    ]);
    assert_json_error(&missing, 52, "BSL151-TARGET-SHOW-INVALID");
    fs::remove_dir_all(root).unwrap();
}
