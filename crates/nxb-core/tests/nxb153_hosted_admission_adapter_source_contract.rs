use std::{
    fs,
    path::{Path, PathBuf},
};

const WORKFLOW_PATH: &str = ".github/workflows/nxb-153-admission.yml";
const ATTRIBUTES_PATH: &str = ".gitattributes";
const LINUX_H1_PATH: &str = "scripts/nxb-153-linux-immutable-source-h1-inner.sh";
const LINUX_H2_PATH: &str = "scripts/nxb-153-linux-immutable-source-h2-copy-inner.sh";
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
        "real_mount=\"$(type -P mount)\"",
        "[[ \"$real_unshare\" == /* && -x \"$real_unshare\" ]]",
        "[[ \"$real_mount\" == /* && -x \"$real_mount\" ]]",
        "\"$1\" != '--user'",
        "\"$2\" != '--map-root-user'",
        "\"$3\" != '--mount'",
        "\"$4\" != '--pid'",
        "\"$5\" != '--fork'",
        "root namespace adapter rejected unexpected unshare arguments",
        "command \"$NXB153_REAL_UNSHARE\" --mount --pid --fork \"$@\"",
        "mount()",
        "\"$1\" == '--bind' && \"$2\" == \"$3\"",
        "NXB153_PENDING_SELF_BIND=\"$2\"",
        "\"$2\" == 'remount,bind,ro'",
        "\"$3\" == \"$NXB153_PENDING_SELF_BIND\"",
        "command \"$NXB153_REAL_MOUNT\" -o remount,ro,nosuid,nodev \"$3\"",
        "command \"$NXB153_REAL_MOUNT\" \"$@\"",
        "export -f unshare mount",
        "export -n -f unshare mount",
        "unset NXB153_REAL_UNSHARE",
        "unset NXB153_REAL_MOUNT",
    ] {
        assert!(
            h1.contains(marker),
            "{LINUX_H1_PATH}: missing hosted-root namespace/mount authority marker: {marker}"
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
    assert!(
        inner.contains("mount --bind \"$source_root\" \"$source_root\"")
            && inner.contains("mount --bind \"$vendor_root\" \"$vendor_root\"")
            && inner.contains("mount --bind \"$config_root\" \"$config_root\""),
        "{LINUX_INNER_PATH}: hosted-root adapter must remain scoped to explicit self-bind requests"
    );
    assert!(
        inner.contains("mount --bind \"$config_root/config.toml\" \"$gate_home/config.toml\""),
        "{LINUX_INNER_PATH}: non-self CARGO_HOME config binding must remain a real bind mount"
    );
}

#[test]
fn hosted_linux_h2_outer_namespace_adapts_root_without_weakening_nested_remount_probes() {
    let h2 = read_source(LINUX_H2_PATH);

    for marker in [
        "run_outer_namespace()",
        "real_unshare=\"$(type -P unshare)\"",
        "H2 outer namespace adapter could not resolve host unshare",
        "if [[ \"$(id -u)\" -eq 0 ]]; then",
        "\"$real_unshare\" --mount --pid --fork \"$@\"",
        "\"$real_unshare\" --user --map-root-user --mount --pid --fork \"$@\"",
        "if ! run_outer_namespace bash -s -- \"$host\" \"$snapshot\" \"$shim\"",
        "run_outer_namespace bash -s -- \\",
    ] {
        assert!(
            h2.contains(marker),
            "{LINUX_H2_PATH}: missing hosted H2 namespace adapter marker: {marker}"
        );
    }

    assert_eq!(
        h2.matches("if unshare --user --map-root-user --mount --pid --fork bash -c")
            .count(),
        2,
        "{LINUX_H2_PATH}: nested user-namespace remount attack probes must remain unadapted"
    );
    assert!(
        h2.contains("mount -o remount,rw \"$1\" 2>/dev/null"),
        "{LINUX_H2_PATH}: nested remount attack must continue attempting writable remount"
    );
}

#[test]
fn hosted_windows_path_normalizes_git_and_python_to_single_applications() {
    let workflow = read_source(WORKFLOW_PATH);

    for marker in [
        "$normalizedPath = [Collections.Generic.List[string]]::new()",
        "$gitDirectorySeen = $false",
        "$gitCandidate = Join-Path $pathEntry 'git.exe'",
        "hosted Windows PATH did not normalize to one Git application",
        "$pythonNormalizedPath = [Collections.Generic.List[string]]::new()",
        "$pythonDirectorySeen = $false",
        "$pythonCandidate = Join-Path $pathEntry 'python3.exe'",
        "hosted Windows PATH contains no Python 3 application directory",
        "$pythonApplications = @(Get-Command python3 -CommandType Application -ErrorAction Stop)",
        "$pythonApplications.Count -ne 1",
        "hosted Windows PATH did not normalize to one Python 3 application",
    ] {
        assert!(
            workflow.contains(marker),
            "{WORKFLOW_PATH}: missing hosted Windows PATH authority marker: {marker}"
        );
    }

    let git_normalized = workflow
        .find("$env:PATH = $normalizedPath -join [IO.Path]::PathSeparator")
        .expect("workflow must commit the single-Git PATH");
    let python_scan = workflow
        .find("$pythonNormalizedPath = [Collections.Generic.List[string]]::new()")
        .expect("workflow must begin Python PATH normalization");
    let python_normalized = workflow
        .find("$env:PATH = $pythonNormalizedPath -join [IO.Path]::PathSeparator")
        .expect("workflow must commit the single-Python PATH");
    let prepare = workflow
        .find("& .\\scripts\\prepare-and-validate-nxb-153-windows.ps1 -RepoRoot .")
        .expect("workflow must invoke Windows preparation");

    assert!(git_normalized < python_scan);
    assert!(python_scan < python_normalized);
    assert!(python_normalized < prepare);
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

#[test]
fn hosted_windows_exact_blob_checkout_pins_powershell_and_python_to_lf() {
    let attributes = read_source(ATTRIBUTES_PATH);

    for marker in [
        "/scripts/*.ps1 text eol=lf",
        "/scripts/*.py text eol=lf",
    ] {
        assert!(
            attributes.lines().any(|line| line == marker),
            "{ATTRIBUTES_PATH}: missing exact-blob checkout authority marker: {marker}"
        );
    }
}
