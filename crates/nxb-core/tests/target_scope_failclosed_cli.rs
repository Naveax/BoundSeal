use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

const SETUP_EXIT_CODE: i32 = 55;
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
        "nxb153-scope-failclosed-{name}-{}-{nonce}",
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
        "NXB-153 Scope Fail-Closed Test".into(),
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

fn guided_arguments(command: &str, root: &Path, authorization: &Path) -> Vec<String> {
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
        "/api".into(),
        "--exclude-path".into(),
        "/api/logout".into(),
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

fn remove_flag_and_value(arguments: &mut Vec<String>, flag: &str) {
    let index = arguments
        .iter()
        .position(|value| value == flag)
        .expect("test flag missing");
    arguments.drain(index..=index + 1);
}

fn replace_flag_value(arguments: &mut [String], flag: &str, replacement: &str) {
    let index = arguments
        .iter()
        .position(|value| value == flag)
        .expect("test flag missing");
    arguments[index + 1] = replacement.to_owned();
}

fn assert_rejected(output: &Output, expected_exit: i32, expected_code: &str, detail: &str) {
    assert_eq!(output.status.code(), Some(expected_exit));
    assert!(output.stdout.is_empty(), "failed JSON command wrote stdout");
    let diagnostic: Value =
        serde_json::from_slice(&output.stderr).expect("failure stderr is not diagnostic JSON");
    assert_eq!(
        diagnostic.get("code").and_then(Value::as_str),
        Some(expected_code)
    );
    let message = diagnostic
        .get("message")
        .and_then(Value::as_str)
        .expect("diagnostic message missing");
    assert!(
        message.contains(detail),
        "diagnostic did not contain {detail:?}: {message}"
    );
}

#[test]
fn manual_guided_scope_requires_explicit_include_but_explicit_root_remains_valid() {
    let root = temporary_workspace("manual-include");
    initialize(&root);
    let authorization = authorization_document(&root);

    let mut omitted = guided_arguments("setup", &root, &authorization);
    remove_flag_and_value(&mut omitted, "--include-path");
    let output = run(&omitted);
    assert_rejected(
        &output,
        SETUP_EXIT_CODE,
        "NXB153-TARGET-SETUP-REJECTED",
        "explicit include path",
    );
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);

    let mut activation = guided_arguments("activate", &root, &authorization);
    remove_flag_and_value(&mut activation, "--include-path");
    let json_index = activation
        .iter()
        .position(|value| value == "--json")
        .unwrap();
    activation.splice(
        json_index..json_index,
        [
            "--confirm-preview-sha".to_owned(),
            "a".repeat(64),
            "--acknowledge-activation".to_owned(),
            "I_CONFIRM_THIS_EXACT_PREVIEW".to_owned(),
        ],
    );
    let output = run(&activation);
    assert_rejected(
        &output,
        ACTIVATE_EXIT_CODE,
        "NXB153-TARGET-ACTIVATE-REJECTED",
        "explicit include path",
    );
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(root.join("state")).unwrap().count(), 0);

    let mut explicit_root = guided_arguments("setup", &root, &authorization);
    replace_flag_value(&mut explicit_root, "--include-path", "/");
    let preview = run_json(&explicit_root);
    assert_eq!(
        preview
            .get("include_paths")
            .and_then(Value::as_array)
            .and_then(|paths| paths.first())
            .and_then(Value::as_str),
        Some("/")
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn exclude_prefix_cannot_shadow_another_explicit_include() {
    let root = temporary_workspace("shadow");
    initialize(&root);
    let authorization = authorization_document(&root);

    let mut arguments = guided_arguments("setup", &root, &authorization);
    replace_flag_value(&mut arguments, "--exclude-path", "/api/admin");
    let insert_at = arguments
        .iter()
        .position(|value| value == "--exclude-path")
        .unwrap();
    arguments.splice(
        insert_at..insert_at,
        [
            "--include-path".to_owned(),
            "/api/admin/settings".to_owned(),
        ],
    );

    let output = run(&arguments);
    assert_rejected(
        &output,
        SETUP_EXIT_CODE,
        "NXB153-TARGET-SETUP-REJECTED",
        "shadow",
    );
    assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interior_empty_path_segments_are_rejected() {
    let root = temporary_workspace("empty-segment");
    initialize(&root);
    let authorization = authorization_document(&root);

    let mut arguments = guided_arguments("setup", &root, &authorization);
    replace_flag_value(&mut arguments, "--include-path", "/api//admin");
    replace_flag_value(
        &mut arguments,
        "--exclude-path",
        "/api//admin/logout",
    );
    let output = run(&arguments);
    assert_rejected(
        &output,
        SETUP_EXIT_CODE,
        "NXB153-TARGET-SETUP-REJECTED",
        "not canonical",
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn imported_scope_rejects_shadowing_and_interior_empty_segments() {
    let root = temporary_workspace("import");
    initialize(&root);
    let authorization = authorization_document(&root);

    let cases = [
        serde_json::json!({
            "schema_version": 1,
            "origin": "https://example.org",
            "include_paths": ["/api", "/api/admin/settings"],
            "exclude_paths": ["/api/admin"],
            "allow_subdomains": false
        }),
        serde_json::json!({
            "schema_version": 1,
            "origin": "https://example.org",
            "include_paths": ["/api//admin"],
            "exclude_paths": ["/api//admin/logout"],
            "allow_subdomains": false
        }),
    ];

    for (index, value) in cases.iter().enumerate() {
        let scope = root.join("tmp").join(format!("scope-{index}.json"));
        fs::write(&scope, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        let output = run(&setup_import_arguments(&root, &authorization, &scope));
        assert_rejected(
            &output,
            SETUP_EXIT_CODE,
            "NXB153-TARGET-SETUP-REJECTED",
            if index == 0 { "shadow" } else { "not canonical" },
        );
        assert_eq!(fs::read_dir(root.join("targets")).unwrap().count(), 0);
    }

    fs::remove_dir_all(root).unwrap();
}
