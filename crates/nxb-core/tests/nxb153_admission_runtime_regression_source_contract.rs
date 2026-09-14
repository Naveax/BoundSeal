use std::{
    fs,
    path::{Path, PathBuf},
};

const LINUX_INNER_PATH: &str = "scripts/nxb-153-linux-immutable-source-inner.sh";
const WINDOWS_GIT_GUARD_PATH: &str =
    "scripts/nxb-153-windows-immutable-source-git-output-inner.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_source(relative_path: &str) -> String {
    let path = repository_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

#[test]
fn linux_nested_bash_labels_remain_inside_the_outer_script_argument() {
    let source = read_source(LINUX_INNER_PATH);

    for marker in [
        r#"assert_readonly_mount "$source_root" "immutable source root""#,
        r#"assert_readonly_mount "$vendor_root" "vendored dependency snapshot""#,
        r#"assert_readonly_mount "$config_root" "gate Cargo config root""#,
    ] {
        assert!(
            source.contains(marker),
            "{LINUX_INNER_PATH}: missing double-quoted nested bash label: {marker}"
        );
    }

    for forbidden in [
        r#"assert_readonly_mount "$source_root" 'immutable source root'"#,
        r#"assert_readonly_mount "$vendor_root" 'vendored dependency snapshot'"#,
        r#"assert_readonly_mount "$config_root" 'gate Cargo config root'"#,
    ] {
        assert!(
            !source.contains(forbidden),
            "{LINUX_INNER_PATH}: raw single-quoted label would terminate the outer bash -c source argument: {forbidden}"
        );
    }
}

#[test]
fn windows_git_proxy_captures_its_authority_across_nested_script_scopes() {
    let source = read_source(WINDOWS_GIT_GUARD_PATH);

    for marker in [
        "$gitProxyApplication = [string]$script:NxbH2GitApplication",
        "$gitProxyWorkingDirectory = $RepoRoot",
        "$gitProxyLimits = $script:NxbH2GitProxyLimits",
        "$gitProxy = {",
        "}.GetNewClosure()",
        r#"Set-Item -Path Function:\git -Value $gitProxy -Force"#,
        "$startInfo.FileName = $gitProxyApplication",
        "$startInfo.WorkingDirectory = $gitProxyWorkingDirectory",
        "$readTask.Wait($gitProxyLimits.ReadTimeoutMilliseconds)",
        "$total -gt $gitProxyLimits.Byte",
        "$lineCount -gt $gitProxyLimits.Lines",
    ] {
        assert!(
            source.contains(marker),
            "{WINDOWS_GIT_GUARD_PATH}: missing closure-bound Git authority marker: {marker}"
        );
    }

    for forbidden in [
        "$startInfo.FileName = $script:NxbH2GitApplication",
        "$readTask.Wait($script:NxbH2GitReadInactivityTimeoutMilliseconds)",
        "$total -gt $script:NxbH2GitOutputByteLimit",
        "$lineCount -gt $script:NxbH2GitOutputLineLimit",
    ] {
        assert!(
            !source.contains(forbidden),
            "{WINDOWS_GIT_GUARD_PATH}: nested Git proxy still depends on caller-sensitive script scope: {forbidden}"
        );
    }
}
