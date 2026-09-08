use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

const LIST_EXIT_CODE: i32 = 51;

fn nxb() -> &'static str {
    env!("CARGO_BIN_EXE_nxb")
}

fn temporary_workspace(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nxb153-target-transient-{name}-{}-{nonce}",
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

fn assert_list_rejection(output: &Output) {
    assert_eq!(output.status.code(), Some(LIST_EXIT_CODE));
    assert!(output.stdout.is_empty());
    let diagnostic: Value =
        serde_json::from_slice(&output.stderr).expect("list failure stderr is not JSON");
    assert_eq!(
        diagnostic.get("code").and_then(Value::as_str),
        Some("NXB151-TARGET-LIST-INVALID")
    );
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = temporary_workspace(name);
        run_json(&[
            "workspace".into(),
            "init".into(),
            "--workspace".into(),
            root.to_string_lossy().into_owned(),
            "--name".into(),
            "NXB-153 Transient Enumeration Test".into(),
            "--json".into(),
        ]);

        let policy = root.join("tmp").join("policy.toml");
        let authorization = root.join("tmp").join("authorization.txt");
        fs::write(
            &policy,
            r#"schema_version = 1

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
"#,
        )
        .unwrap();
        fs::write(&authorization, b"authorized transient enumeration fixture\n").unwrap();

        run_json(&[
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
        ]);

        Self { root }
    }

    fn profile(&self) -> PathBuf {
        self.root.join("targets").join("example-app.json")
    }

    fn disable_receipt(&self) -> PathBuf {
        self.root
            .join("targets")
            .join("example-app.disabled.json")
    }

    fn target_list(&self, include_disabled: bool) -> Output {
        let mut arguments = vec![
            "target".into(),
            "list".into(),
            "--workspace".into(),
            self.root.to_string_lossy().into_owned(),
        ];
        if include_disabled {
            arguments.push("--include-disabled".into());
        }
        arguments.push("--json".into());
        run(&arguments)
    }

    fn status(&self) -> Value {
        run_json(&[
            "workspace".into(),
            "status".into(),
            "--workspace".into(),
            self.root.to_string_lossy().into_owned(),
            "--json".into(),
        ])
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn parse_success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "command failed: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command returned invalid JSON")
}

fn hard_link_fixture(source: &Path, destination: &Path) -> Vec<u8> {
    fs::hard_link(source, destination).unwrap();
    fs::read(destination).unwrap()
}

#[test]
fn exact_profile_and_disable_transients_are_quarantined_without_mutation_or_counting() {
    let fixture = Fixture::new("exact");
    let profile_transient = fixture
        .root
        .join("targets")
        .join(".example-app.json.0123456789abcdef01234567.tmp");
    let profile_transient_before = hard_link_fixture(&fixture.profile(), &profile_transient);

    let listed = parse_success(fixture.target_list(false));
    assert_eq!(listed.get("count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        listed.pointer("/targets/0/status").and_then(Value::as_str),
        Some("active")
    );
    assert_eq!(
        fixture
            .status()
            .pointer("/records/targets")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(fs::read(&profile_transient).unwrap(), profile_transient_before);

    run_json(&[
        "target".into(),
        "disable".into(),
        "--workspace".into(),
        fixture.root.to_string_lossy().into_owned(),
        "--id".into(),
        "example-app".into(),
        "--reason".into(),
        "operator-hold".into(),
        "--json".into(),
    ]);

    let disable_transient = fixture
        .root
        .join("targets")
        .join(".example-app.disabled.json.fedcba987654321001234567.tmp");
    let disable_transient_before =
        hard_link_fixture(&fixture.disable_receipt(), &disable_transient);

    let listed = parse_success(fixture.target_list(true));
    assert_eq!(listed.get("count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        listed.pointer("/targets/0/status").and_then(Value::as_str),
        Some("disabled")
    );
    assert_eq!(
        fixture
            .status()
            .pointer("/records/targets")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(fs::read(&profile_transient).unwrap(), profile_transient_before);
    assert_eq!(fs::read(&disable_transient).unwrap(), disable_transient_before);
}

#[test]
fn malformed_or_foreign_transient_lookalikes_remain_fail_closed() {
    let fixture = Fixture::new("malformed");
    let targets = fixture.root.join("targets");
    let profile = fixture.profile();
    let names = [
        ".example-app.json.0123456789abcdef0123456.tmp",
        ".example-app.json.0123456789abcdef012345678.tmp",
        ".example-app.json.0123456789abcdeF01234567.tmp",
        ".example-app.json.0123456789abcdeg01234567.tmp",
        ".example-app.json.0123456789abcdef01234567.tmp.extra",
        ".foreign.txt.0123456789abcdef01234567.tmp",
        "foreign.txt",
    ];

    for name in names {
        let lookalike = targets.join(name);
        hard_link_fixture(&profile, &lookalike);
        assert_list_rejection(&fixture.target_list(false));
        assert!(lookalike.exists(), "rejected lookalike must not be deleted");
        fs::remove_file(lookalike).unwrap();
    }
}

#[test]
fn non_file_target_entry_remains_fail_closed() {
    let fixture = Fixture::new("non-file");
    let directory = fixture.root.join("targets").join("unexpected-directory");
    fs::create_dir(&directory).unwrap();

    assert_list_rejection(&fixture.target_list(false));
    assert!(directory.is_dir());
}
