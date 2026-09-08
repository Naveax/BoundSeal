use std::{
    fs,
    path::{Path, PathBuf},
};

const ACTIVATION_PATH: &str = "crates/nxb-core/src/target/activation.rs";
const DISABLE_GATE: &str = "ensure_target_not_disabled(&disable_path)?;";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn activation_source() -> String {
    let path = repository_root().join(ACTIVATION_PATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn required_index(text: &str, needle: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("{ACTIVATION_PATH}: missing source marker: {needle}"))
}

#[test]
fn guided_activation_linearizes_active_result_after_disable_receipt_checks() {
    let text = activation_source();

    let helper_start = required_index(&text, "fn ensure_target_not_disabled(disable_path: &Path)");
    let helper_end_relative = text[helper_start..]
        .find("\n}\n\n#[allow(clippy::too_many_arguments)]")
        .expect("disable helper boundary is missing");
    let helper = &text[helper_start..helper_start + helper_end_relative + 2];
    assert!(
        helper.contains("workspace::safe_exists(disable_path)?"),
        "{ACTIVATION_PATH}: disable gate must inspect the canonical disable receipt path with safe_exists"
    );
    assert!(
        helper.contains("guided activation active result was withheld"),
        "{ACTIVATION_PATH}: disable gate must fail closed rather than silently accepting a visible receipt"
    );

    let body_start = required_index(&text, "pub(super) fn activate_value(");
    assert!(
        helper_start < body_start,
        "{ACTIVATION_PATH}: disable gate helper must be defined before activate_value"
    );
    let body_end_relative = text[body_start..]
        .find("\nfn activation_value(")
        .expect("activation_value helper boundary is missing");
    let body = &text[body_start..body_start + body_end_relative];

    let gates = body
        .match_indices(DISABLE_GATE)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(
        gates.len(),
        3,
        "{ACTIVATION_PATH}: expected one early and two final disable-receipt gates"
    );

    let profile_exists = required_index(
        body,
        "let profile_exists = workspace::safe_exists(&profile_path)?;",
    );
    assert!(
        gates[0] < profile_exists,
        "{ACTIVATION_PATH}: the first disable gate must remain before profile/artifact recovery or publication"
    );

    let recovered_verify =
        required_index(body, "\"guided activation recovered target profile\"");
    let recovered_durable = required_index(
        body,
        "ensure_recovered_publication_durable(&profile_path)?;",
    );
    let recovered_return = required_index(body, "return activation_value(");
    assert!(
        recovered_verify < recovered_durable
            && recovered_durable < gates[1]
            && gates[1] < recovered_return,
        "{ACTIVATION_PATH}: completed recovery must recheck disable state after exact profile verification/durability and before returning active"
    );

    let normal_verify = required_index(body, "\"guided activation target profile\"");
    let final_activation = body
        .rfind("\n    activation_value(")
        .expect("final activation_value return is missing");
    assert!(
        normal_verify < gates[2] && gates[2] < final_activation,
        "{ACTIVATION_PATH}: normal activation must recheck disable state after profile byte verification and before returning active"
    );

    for forbidden in [
        "remove_file(",
        "remove_regular(",
        "replace_document(",
        "fs::rename(",
    ] {
        assert!(
            !body.contains(forbidden),
            "{ACTIVATION_PATH}: guided activation must not add rollback/delete/replace mutation: {forbidden}"
        );
    }
}
