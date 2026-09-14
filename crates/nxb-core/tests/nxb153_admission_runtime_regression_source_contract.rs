use std::{
    fs,
    path::{Path, PathBuf},
};

const LINUX_INNER_PATH: &str = "scripts/nxb-153-linux-immutable-source-inner.sh";
const LINUX_HOSTED_WRAPPER_PATH: &str =
    "scripts/nxb-153-linux-immutable-source-h1-inner.sh";
const REGISTRY_SOURCE_PATH: &str = "scripts/nxb-153-registry-source.py";
const WINDOWS_STRING_GUARD_PATH: &str = "scripts/nxb-153-windows-immutable-source.ps1";
const WINDOWS_GIT_GUARD_PATH: &str =
    "scripts/nxb-153-windows-immutable-source-git-output-inner.ps1";
const WINDOWS_H2_ENTRY_PATH: &str =
    "scripts/nxb-153-windows-immutable-source-h2-entry-inner.ps1";
const WINDOWS_H2_INNER_PATH: &str = "scripts/nxb-153-windows-immutable-source-h2-inner.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_source(relative_path: &str) -> String {
    let path = repository_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn required_offset(source: &str, marker: &str, path: &str) -> usize {
    source
        .find(marker)
        .unwrap_or_else(|| panic!("{path}: missing source marker: {marker}"))
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
fn linux_hosted_namespace_adapters_stop_exporting_before_deeper_children() {
    let source = read_source(LINUX_HOSTED_WRAPPER_PATH);
    let mount_start = required_offset(
        &source,
        "        mount() {",
        LINUX_HOSTED_WRAPPER_PATH,
    );
    let handoff_marker = "builtin export -n -f unshare mount 2>/dev/null || true";
    let handoff = mount_start
        + required_offset(
            &source[mount_start..],
            handoff_marker,
            LINUX_HOSTED_WRAPPER_PATH,
        );
    let wrapper_export = required_offset(
        &source,
        "        export -f unshare mount",
        LINUX_HOSTED_WRAPPER_PATH,
    );

    assert!(
        mount_start < handoff && handoff < wrapper_export,
        "{LINUX_HOSTED_WRAPPER_PATH}: adapter de-export must stay inside mount() before the outer wrapper export"
    );
}

#[test]
fn cargo_197_vendor_comment_is_bound_without_weakening_checksum_authority() {
    let source = read_source(REGISTRY_SOURCE_PATH);
    for marker in [
        "CARGO_CHECKSUM_COMMENT = (",
        r#"set(checksum_payload) != {"$comment", "files", "package"}"#,
        r#"checksum_payload.get("$comment") != CARGO_CHECKSUM_COMMENT"#,
        r#""$comment": CARGO_CHECKSUM_COMMENT"#,
    ] {
        assert!(
            source.contains(marker),
            "{REGISTRY_SOURCE_PATH}: missing Cargo 1.97 checksum-comment contract marker: {marker}"
        );
    }
}

#[test]
fn windows_out_string_proxy_captures_limits_across_nested_script_scopes() {
    let source = read_source(WINDOWS_STRING_GUARD_PATH);
    for marker in [
        "$script:NxbH2OutStringLimits = @{",
        "$outStringLimits = $script:NxbH2OutStringLimits",
        "$outStringProxy = {",
        "}.GetNewClosure()",
        r#"Set-Item -Path Function:\Out-String -Value $outStringProxy -Force"#,
        "$items.Count + 1 -gt $outStringLimits.Objects",
        "$inputBytes -gt $outStringLimits.Byte",
        "$outputBytes -gt $outStringLimits.Byte",
    ] {
        assert!(
            source.contains(marker),
            "{WINDOWS_STRING_GUARD_PATH}: missing closure-bound Out-String marker: {marker}"
        );
    }
    for forbidden in [
        "$script:NxbH2OutStringByteLimit",
        "$script:NxbH2OutStringObjectLimit",
        "function Out-String {",
    ] {
        assert!(
            !source.contains(forbidden),
            "{WINDOWS_STRING_GUARD_PATH}: caller-sensitive Out-String authority remains: {forbidden}"
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

#[test]
fn windows_h2_acl_rights_use_the_access_control_enum_namespace() {
    for path in [WINDOWS_H2_ENTRY_PATH, WINDOWS_H2_INNER_PATH] {
        let source = read_source(path);
        assert!(
            !source.contains("[IO.FileSystemRights]"),
            "{path}: IO.FileSystemRights is not a valid PowerShell/.NET type name"
        );

        for right in [
            "WriteData",
            "AppendData",
            "CreateFiles",
            "CreateDirectories",
            "Delete",
            "DeleteSubdirectoriesAndFiles",
            "WriteAttributes",
            "WriteExtendedAttributes",
        ] {
            let marker = format!("[Security.AccessControl.FileSystemRights]::{right}");
            assert!(
                source.contains(&marker),
                "{path}: missing canonical ACL right marker: {marker}"
            );
        }
    }
}
