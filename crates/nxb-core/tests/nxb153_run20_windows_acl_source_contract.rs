use std::{
    fs,
    path::{Path, PathBuf},
};

const WINDOWS_IMMUTABLE_SOURCE_PATH: &str = "scripts/nxb-153-windows-immutable-source-inner.ps1";
const WINDOWS_WORKSPACE_PATH: &str = "crates/nxb-core/src/workspace/windows.rs";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

#[test]
fn windows_source_deny_acl_is_staged_explicitly_per_retained_source_object() {
    let authority = source(WINDOWS_IMMUTABLE_SOURCE_PATH);

    for marker in [
        "$sourceDirectoryAcls = [Collections.Generic.List[object]]::new()",
        "$sourceFileAcls = [Collections.Generic.List[object]]::new()",
        "Set-NxbSourceFileWriteDeny -Path $source",
        "Set-NxbSourceFileWriteDeny -Path $actualFiles[$entry.Path]",
        "for ($index = $sourceFileAcls.Count - 1; $index -ge 0; $index--)",
        "Acl = Get-Acl -LiteralPath $sourceDirectory",
        "Set-NxbSourceWriteDeny -Path $sourceDirectory",
        "for ($index = $sourceDirectoryAcls.Count - 1; $index -ge 0; $index--)",
        "Set-Acl -LiteralPath $snapshot.Path -AclObject $snapshot.Acl -ErrorAction Stop",
    ] {
        assert!(
            authority.contains(marker),
            "{WINDOWS_IMMUTABLE_SOURCE_PATH}: missing run-20 Windows ACL marker: {marker}"
        );
    }

    assert!(
        authority
            .matches("foreach ($sourceDirectory in @($root, $nested))")
            .count()
            >= 2,
        "{WINDOWS_IMMUTABLE_SOURCE_PATH}: self-test must snapshot and explicitly deny both root and nested source directories"
    );
    assert!(
        authority
            .matches("foreach ($sourceDirectory in $sourceDirectories)")
            .count()
            >= 3,
        "{WINDOWS_IMMUTABLE_SOURCE_PATH}: production path must snapshot, explicitly deny, and probe every retained source directory"
    );
}

#[test]
fn windows_runtime_directories_are_protected_before_source_denies_are_staged() {
    let authority = source(WINDOWS_IMMUTABLE_SOURCE_PATH);
    let runtime = authority
        .find("foreach ($runtime in @($runtimeTarget, $runtimeTmp, $runtimeCargoHome))")
        .expect("runtime protection loop is missing");
    let snapshot = authority[runtime..]
        .find("Acl = Get-Acl -LiteralPath $sourceDirectory")
        .map(|offset| runtime + offset)
        .expect("source ACL snapshot loop is missing");
    let deny = authority[snapshot..]
        .find("Set-NxbSourceWriteDeny -Path $sourceDirectory")
        .map(|offset| snapshot + offset)
        .expect("source ACL deny loop is missing");

    assert!(
        runtime < snapshot && snapshot < deny,
        "{WINDOWS_IMMUTABLE_SOURCE_PATH}: runtime directories must be protected before source ACL snapshots and deny staging"
    );
}

#[test]
fn windows_workspace_acl_full_control_decoder_accepts_documented_equivalent_sddl_forms() {
    let authority = source(WINDOWS_WORKSPACE_PATH);

    for marker in [
        "const WINDOWS_FILE_ALL_ACCESS_MASK: u32 = 0x001F_01FF;",
        "const WINDOWS_GENERIC_ALL_MASK: u32 = 0x1000_0000;",
        "fn sddl_rights_include_full_control(rights: &str) -> bool",
        ".strip_prefix(\"0x\")",
        "rights.strip_prefix(\"0X\")",
        "u32::from_str_radix(hex, 16)",
        "mask & WINDOWS_FILE_ALL_ACCESS_MASK == WINDOWS_FILE_ALL_ACCESS_MASK",
        "mask & WINDOWS_GENERIC_ALL_MASK == WINDOWS_GENERIC_ALL_MASK",
        "token == b\"FA\" || token == b\"GA\"",
        "sddl_rights_include_full_control(ace.rights)",
        "fn recognizes_symbolic_and_hexadecimal_full_control_rights()",
        "D:P(A;;FA;;;S-1-5-21-100-200-300-1001)",
        "D:P(A;;GA;;;S-1-5-21-100-200-300-1001)",
        "D:P(A;;0x001f01ff;;;S-1-5-21-100-200-300-1001)",
        "D:P(A;;0x10000000;;;S-1-5-21-100-200-300-1001)",
    ] {
        assert!(
            authority.contains(marker),
            "{WINDOWS_WORKSPACE_PATH}: Windows ACL full-control decoder is missing marker: {marker}"
        );
    }

    assert!(
        !authority.contains("ace.rights.contains(\"FA\")"),
        "{WINDOWS_WORKSPACE_PATH}: full-control validation must not depend on one SDDL spelling"
    );
    for marker in [
        "let current_full_control = sddl_has_full_control(&sddl, current_sid);",
        "let current_any_ace = sddl_aces(&sddl).any(|ace| ace.principal == current_sid);",
        "let current_allow_rights = bounded_sddl_allow_rights(&sddl, current_sid);",
        "fn bounded_sddl_allow_rights(sddl: &str, principal: &str) -> String",
        ".take(4)",
        "encoded.truncate(96);",
        "let system_full_control =",
        "let administrators_full_control =",
        "current={current_full_control} current_any_ace={current_any_ace} current_allow_rights={current_allow_rights} system={system_full_control} administrators={administrators_full_control}",
    ] {
        assert!(
            authority.contains(marker),
            "{WINDOWS_WORKSPACE_PATH}: bounded ACL trustee-state diagnostic is missing marker: {marker}"
        );
    }
    assert!(
        !authority.contains("required full-control entries are missing: sddl="),
        "{WINDOWS_WORKSPACE_PATH}: ACL diagnostics must not dump the complete security descriptor"
    );
    assert!(
        !authority.contains("current_sid={current_sid}"),
        "{WINDOWS_WORKSPACE_PATH}: ACL diagnostics must not emit the current user's SID"
    );

    let harden_start = authority
        .find("fn harden_windows_acl")
        .expect("Windows ACL hardening function is missing");
    let validate_start = authority[harden_start..]
        .find("fn validate_windows_acl_with_sid")
        .map(|offset| harden_start + offset)
        .expect("Windows ACL validator is missing");
    let harden = &authority[harden_start..validate_start];
    let inheritance = harden
        .find("OsString::from(\"/inheritancelevel:r\")")
        .expect("Windows ACL hardening must remove inherited ACEs");
    let grant = harden
        .find("let grant_arguments = [")
        .expect("Windows ACL required-principal grant block is missing");
    let remove = harden
        .find("let mut remove_arguments = vec![OsString::from(\"/remove:g\")]")
        .expect("Windows ACL broad-grant removal block is missing");
    assert!(
        inheritance < grant && grant < remove,
        "{WINDOWS_WORKSPACE_PATH}: inherited ACEs must be removed before exact required grants and broad-grant removal"
    );
}
