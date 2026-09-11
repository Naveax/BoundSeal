use std::{
    fs,
    path::{Path, PathBuf},
};

const WORKFLOW_PATH: &str = ".github/workflows/nxb-153-admission.yml";
const LINUX_H1_PATH: &str = "scripts/nxb-153-linux-immutable-source-h1-inner.sh";
const LINUX_INNER_PATH: &str = "scripts/nxb-153-linux-immutable-source-inner.sh";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_source(relative_path: &str) -> String {
    let path = repository_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

#[test]
fn hosted_linux_root_namespace_adapter_is_exact_and_fail_closed() {
    let h1 = read_source(LINUX_H1_PATH);
    let inner = read_source(LINUX_INNER_PATH);

    for marker in [
        "if [[ \"$(id -u)\" -eq 0 ]]; then",
        "real_unshare=\"$(type -P unshare)\"",
        "[[ \"$real_unshare\" == /* && -x \"$real_unshare\" ]]",
        "\"$1\" != '--user'",
        "\"$2\" != '--map-root-user'",
        "\"$3\" != '--mount'",
        "\"$4\" != '--pid'",
        "\"$5\" != '--fork'",
        "root namespace adapter rejected unexpected unshare arguments",
        "command \"$NXB153_REAL_UNSHARE\" --mount --pid --fork \"$@\"",
        "export -n -f unshare",
        "unset NXB153_REAL_UNSHARE",
    ] {
        assert!(
            h1.contains(marker),
            "{LINUX_H1_PATH}: missing hosted-root namespace authority marker: {marker}"
        );
    }

    assert!(
        inner.contains("unshare --user --map-root-user --mount --pid --fork bash -c"),
        "{LINUX_INNER_PATH}: exact inner user-namespace request must remain source-visible for the H1 adapter"
    );
    assert_eq!(
        inner
            .matches("unshare --user --map-root-user --mount --pid --fork")
            .count(),
        2,
        "{LINUX_INNER_PATH}: H1 adapter contract expects exactly the self-test and validation namespace requests"
    );
}

#[test]
fn hosted_windows_json_timestamps_remain_strings_for_canonical_validation() {
    let workflow = read_source(WORKFLOW_PATH);

    for marker in [
        "$convertFromJsonCommand = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop",
        "$convertFromJsonCommand.Parameters.ContainsKey('DateKind')",
        "$dateKindDefaultKey = 'ConvertFrom-Json:DateKind'",
        "$PSDefaultParameterValues[$dateKindDefaultKey] = 'String'",
        "$hadDateKindDefault = $PSDefaultParameterValues.ContainsKey($dateKindDefaultKey)",
        "$PSDefaultParameterValues[$dateKindDefaultKey] = $previousDateKindDefault",
        "[void]$PSDefaultParameterValues.Remove($dateKindDefaultKey)",
    ] {
        assert!(
            workflow.contains(marker),
            "{WORKFLOW_PATH}: missing canonical JSON timestamp authority marker: {marker}"
        );
    }

    let set_index = workflow
        .find("$PSDefaultParameterValues[$dateKindDefaultKey] = 'String'")
        .expect("workflow must set DateKind=String before Windows admission");
    let prepare_index = workflow
        .find("& .\\scripts\\prepare-and-validate-nxb-153-windows.ps1 -RepoRoot .")
        .expect("workflow must invoke Windows preparation");
    let record_index = workflow
        .find("& .\\scripts\\record-nxb-153-windows-process-lifecycle-evidence.ps1 -RepoRoot .")
        .expect("workflow must invoke Windows process evidence recording");
    let review_index = workflow
        .find("& .\\scripts\\review-nxb-153-windows-admission-complete.ps1 -RepoRoot .")
        .expect("workflow must invoke Windows complete admission review");
    let cleanup_index = workflow
        .find("[void]$PSDefaultParameterValues.Remove($dateKindDefaultKey)")
        .expect("workflow must clean up the DateKind default");

    assert!(set_index < prepare_index);
    assert!(prepare_index < record_index);
    assert!(record_index < review_index);
    assert!(review_index < cleanup_index);
}
