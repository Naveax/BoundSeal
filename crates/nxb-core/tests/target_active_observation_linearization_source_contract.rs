use std::{
    fs,
    path::{Path, PathBuf},
};

const TARGET_PATH: &str = "crates/nxb-core/src/target.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source() -> String {
    let path = repository_root().join(TARGET_PATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn section<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let start_index = text
        .find(start)
        .unwrap_or_else(|| panic!("{TARGET_PATH}: missing section start: {start}"));
    let tail = &text[start_index..];
    let end_relative = tail
        .find(end)
        .unwrap_or_else(|| panic!("{TARGET_PATH}: missing section end: {end}"));
    &tail[..end_relative]
}

fn required_index(text: &str, needle: &str, section_name: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("{TARGET_PATH} {section_name}: missing marker: {needle}"))
}

#[test]
fn every_active_observation_reconciles_disable_receipt_at_its_final_result_gate() {
    let text = source();

    let helper = section(
        &text,
        "fn reconcile_effective_target(",
        "\nfn read_receipt(",
    );
    for marker in [
        "known_receipt: Option<DisableReceipt>",
        "read_optional_receipt(&disable_path(targets, &profile.target_id), &profile)?",
        "Ok(effective_target(profile, receipt))",
    ] {
        assert!(
            helper.contains(marker),
            "{TARGET_PATH}: final observation helper is missing authority marker: {marker}"
        );
    }

    let create = section(&text, "fn create_value_from_bytes(", "\nfn list_value(");
    let create_publish = required_index(
        create,
        "workspace::create_document(&path, &bytes)?;",
        "create",
    );
    let create_reconcile = required_index(
        create,
        "reconcile_effective_target(&targets, profile, None)?",
        "create",
    );
    let create_serialize = required_index(create, "serde_json::to_value(effective)", "create");
    assert!(
        create_publish < create_reconcile && create_reconcile < create_serialize,
        "{TARGET_PATH}: create must reconcile disable state after profile publication and before result serialization"
    );
    assert!(
        !create.contains("effective_target(profile, None)"),
        "{TARGET_PATH}: create must not bypass final disable reconciliation"
    );

    let list = section(&text, "fn list_value(", "\nfn show_value(");
    let list_load = required_index(list, "load_profiles(&targets_directory)?", "list");
    let list_reconcile = required_index(
        list,
        "reconcile_effective_target(&targets_directory, profile, receipt)?",
        "list",
    );
    let list_filter = required_index(
        list,
        "effective.status == \"disabled\" && !include_disabled",
        "list",
    );
    let list_push = required_index(list, "targets.push(effective);", "list");
    assert!(
        list_load < list_reconcile && list_reconcile < list_filter && list_filter < list_push,
        "{TARGET_PATH}: list must reconcile every provisionally active profile before filtering or serialization"
    );

    let show = section(&text, "fn show_value(", "\nfn disable_value(");
    let show_read = required_index(show, "read_profile(&profile_path(&targets, id))?", "show");
    let show_reconcile = required_index(
        show,
        "reconcile_effective_target(&targets, profile, None)?",
        "show",
    );
    let show_serialize = required_index(show, "serde_json::to_value(effective)", "show");
    assert!(
        show_read < show_reconcile && show_reconcile < show_serialize,
        "{TARGET_PATH}: show must reconcile disable state immediately before result serialization"
    );

    let validate = section(&text, "fn validate_value(", "\nfn ready_workspace(");
    let validate_policy = required_index(
        validate,
        "validate_policy_binding(&compiled, &profile.origin)? != profile.allowed_methods",
        "validate",
    );
    let validate_reconcile = required_index(
        validate,
        "reconcile_effective_target(&targets, profile, None)?",
        "validate",
    );
    let validate_serialize = required_index(
        validate,
        "serde_json::to_value(effective)",
        "validate",
    );
    assert!(
        validate_policy < validate_reconcile && validate_reconcile < validate_serialize,
        "{TARGET_PATH}: validate must reconcile disable state after validation work and before result serialization"
    );

    for (name, body) in [
        ("create", create),
        ("list", list),
        ("show", show),
        ("validate", validate),
    ] {
        assert!(
            !body.contains("effective_target(profile, None)"),
            "{TARGET_PATH} {name}: active result construction must not bypass final disable reconciliation"
        );
    }
}
