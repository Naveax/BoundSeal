use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

fn nxb() -> &'static str {
    env!("CARGO_BIN_EXE_nxb")
}

fn temporary_workspace(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();

    std::env::temp_dir().join(format!(
        "nxb153-target-import-{name}-{}-{nonce}",
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
        "NXB-153 Import Test".into(),
        "--json".into(),
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
        b"PASS-D-RAW-AUTHORIZATION-SENTINEL must never persist\n",
    )
    .unwrap();
    path
}

fn scope_import(root: &Path, name: &str, value: &Value) -> PathBuf {
    let path = root.join("tmp").join(name);
    fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    path
}

fn common_guided_arguments(command: &str, root: &Path, authorization: &Path) -> Vec<String> {
    vec![
        "target".into(),
        command.into(),
        "--workspace".into(),
        root.to_string_lossy().into_owned(),
        "--id".into(),
        "example-app".into(),
        "--name".into(),
        "Example App".into(),
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
    ]
}

fn import_arguments(
    command: &str,
    root: &Path,
    authorization: &Path,
    import: &Path,
    json: bool,
) -> Vec<String> {
    let mut arguments = common_guided_arguments(command, root, authorization);
    arguments.push("--scope-import".into());
    arguments.push(import.to_string_lossy().into_owned());
    if json {
        arguments.push("--json".into());
    }
    arguments
}

fn manual_setup_arguments(root: &Path, authorization: &Path) -> Vec<String> {
    let mut arguments = common_guided_arguments("setup", root, authorization);
    arguments.extend([
        "--origin".into(),
        "https://EXAMPLE.org:443".into(),
        "--include-path".into(),
        "/api/v2".into(),
        "--include-path".into(),
        "/api".into(),
        "--exclude-path".into(),
        "/api/logout".into(),
        "--json".into(),
    ]);
    arguments
}

fn assert_setup_rejected(output: &Output) {
    assert_eq!(output.status.code(), Some(55));
    assert!(output.stdout.is_empty());

    let value: Value =
        serde_json::from_slice(&output.stderr).expect("failure stderr is not diagnostic JSON");
    assert_eq!(
        value.get("code").and_then(Value::as_str),
        Some("NXB153-TARGET-SETUP-REJECTED")
    );
}

#[test]
fn imported_scope_normalizes_to_the_exact_manual_preview_and_readable_text() {
    let root = temporary_workspace("equivalence");
    initialize(&root);
    let authorization = authorization_document(&root);

    let import = scope_import(
        &root,
        "scope.json",
        &serde_json::json!({
            "schema_version": 1,
            "origin": "https://EXAMPLE.org:443",
            "include_paths": ["/api/v2", "/api"],
            "exclude_paths": ["/api/logout"],
            "allow_subdomains": false
        }),
    );

    let imported = run_json(&import_arguments(
        "setup-import",
        &root,
        &authorization,
        &import,
        true,
    ));
    let manual = run_json(&manual_setup_arguments(&root, &authorization));

    assert_eq!(
        imported, manual,
        "import must disappear after normalization"
    );
    assert_eq!(
        imported.get("origin").and_then(Value::as_str),
        Some("https://example.org")
    );
    assert_eq!(
        imported.get("include_paths"),
        Some(&serde_json::json!(["/api", "/api/v2"]))
    );
    assert_eq!(
        imported.get("exclude_paths"),
        Some(&serde_json::json!(["/api/logout"]))
    );

    let text_arguments = import_arguments("setup-import", &root, &authorization, &import, false);
    let first_text = run(&text_arguments);
    let second_text = run(&text_arguments);

    assert!(first_text.status.success());
    assert!(second_text.status.success());
    assert_eq!(first_text.stdout, second_text.stdout);
    assert!(first_text.stderr.is_empty());

    let text = String::from_utf8(first_text.stdout).unwrap();
    assert!(text.contains("status: preview\n"));
    assert!(text.contains("origin: https://example.org\n"));
    assert!(text.contains("include_paths:\n  - /api\n  - /api/v2\n"));
    assert!(text.contains("exclude_paths:\n  - /api/logout\n"));
    assert!(text.contains("allowed_methods: GET, HEAD, OPTIONS\n"));
    assert!(text.contains("credential_bruteforce: false\n"));
    assert!(text.contains("destructive_testing: false\n"));
    assert!(text.contains("network_activity: none\n"));
    assert!(text.contains("preview_sha256: "));
    assert!(!text.contains(import.to_string_lossy().as_ref()));
    assert!(!text.contains("PASS-D-RAW-AUTHORIZATION-SENTINEL"));

    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn imported_scope_activates_end_to_end_without_hand_authored_policy_or_profile() {
    let root = temporary_workspace("activate");
    initialize(&root);
    let authorization = authorization_document(&root);
    let import = scope_import(
        &root,
        "scope.json",
        &serde_json::json!({
            "schema_version": 1,
            "origin": "https://example.org",
            "include_paths": ["/api"],
            "exclude_paths": ["/api/logout"],
            "allow_subdomains": false
        }),
    );

    let preview = run_json(&import_arguments(
        "setup-import",
        &root,
        &authorization,
        &import,
        true,
    ));
    let preview_sha = preview
        .get("preview_sha256")
        .and_then(Value::as_str)
        .unwrap();

    let mut activation = import_arguments("activate-import", &root, &authorization, &import, true);
    let json_index = activation
        .iter()
        .position(|value| value == "--json")
        .unwrap();
    activation.splice(
        json_index..json_index,
        [
            "--confirm-preview-sha".to_owned(),
            preview_sha.to_owned(),
            "--acknowledge-activation".to_owned(),
            "I_CONFIRM_THIS_EXACT_PREVIEW".to_owned(),
        ],
    );

    let active = run_json(&activation);
    assert_eq!(active.get("status").and_then(Value::as_str), Some("active"));
    assert_eq!(
        active
            .pointer("/activation/preview_sha256")
            .and_then(Value::as_str),
        Some(preview_sha)
    );

    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 1);
    assert_eq!(fs::read_dir(root.join("config")).unwrap().count(), 0);

    let profile = fs::read_to_string(root.join("targets").join("example-app.json")).unwrap();
    assert!(!profile.contains("PASS-D-RAW-AUTHORIZATION-SENTINEL"));
    assert!(!profile.contains(import.to_string_lossy().as_ref()));
    assert!(!profile.contains(authorization.to_string_lossy().as_ref()));

    let shown = run_json(&[
        "target".into(),
        "show".into(),
        "--workspace".into(),
        root.to_string_lossy().into_owned(),
        "--id".into(),
        "example-app".into(),
        "--json".into(),
    ]);
    assert_eq!(shown.get("status").and_then(Value::as_str), Some("active"));
    assert_eq!(
        shown.get("origin").and_then(Value::as_str),
        Some("https://example.org")
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unsafe_or_ambiguous_scope_imports_fail_closed_without_persistence() {
    let root = temporary_workspace("reject");
    initialize(&root);
    let authorization = authorization_document(&root);

    let cases = [
        serde_json::json!({
            "schema_version": 2,
            "origin": "https://example.org",
            "include_paths": ["/api"],
            "exclude_paths": [],
            "allow_subdomains": false
        }),
        serde_json::json!({
            "schema_version": 1,
            "origin": "https://*.example.org",
            "include_paths": ["/api"],
            "exclude_paths": [],
            "allow_subdomains": false
        }),
        serde_json::json!({
            "schema_version": 1,
            "origin": "https://example.org",
            "include_paths": ["/api", "/api"],
            "exclude_paths": [],
            "allow_subdomains": false
        }),
        serde_json::json!({
            "schema_version": 1,
            "origin": "https://example.org",
            "include_paths": ["/api"],
            "exclude_paths": ["/admin"],
            "allow_subdomains": false
        }),
        serde_json::json!({
            "schema_version": 1,
            "origin": "https://example.org",
            "include_paths": ["/api"],
            "exclude_paths": [],
            "allow_subdomains": false,
            "unexpected": true
        }),
    ];

    for (index, value) in cases.iter().enumerate() {
        let import = scope_import(&root, &format!("reject-{index}.json"), value);
        let output = run(&import_arguments(
            "setup-import",
            &root,
            &authorization,
            &import,
            true,
        ));
        assert_setup_rejected(&output);
    }

    let oversized = root.join("tmp").join("oversized.json");
    fs::write(&oversized, vec![b'x'; 64 * 1024 + 1]).unwrap();
    let output = run(&import_arguments(
        "setup-import",
        &root,
        &authorization,
        &oversized,
        true,
    ));
    assert_setup_rejected(&output);

    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(root.join("config")).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
}
