use std::{
    fs,
    path::{Path, PathBuf},
};

const WINDOWS_IMMUTABLE_SOURCE_PATH: &str =
    "scripts/nxb-153-windows-immutable-source-inner.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

#[test]
fn windows_source_deny_acl_is_staged_explicitly_per_retained_source_directory() {
    let authority = source(WINDOWS_IMMUTABLE_SOURCE_PATH);

    for marker in [
        "$sourceDirectoryAcls = [Collections.Generic.List[object]]::new()",
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
