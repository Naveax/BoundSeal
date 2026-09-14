use std::{
    fs,
    path::{Path, PathBuf},
};

const DEPENDENCY_SOURCE_PATH: &str = "scripts/nxb-153-windows-dependency-source.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn windows_vendored_dependency_directories_receive_explicit_deny_acls() {
    let path = repository_root().join(DEPENDENCY_SOURCE_PATH);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()));

    for marker in [
        "$vendorDirectoryAcls = [Collections.Generic.List[object]]::new()",
        "$vendorDirectories = @(Get-ChildItem -LiteralPath $vendorRoot -Directory -Force -Recurse",
        "foreach ($directory in @($vendorRoot) + $vendorDirectories)",
        "Acl = Get-Acl -LiteralPath $directory",
        "Set-NxbDependencyWriteDeny -Path $directory",
        "for ($index = $vendorDirectoryAcls.Count - 1; $index -ge 0; $index--)",
        "Set-Acl -LiteralPath $snapshot.Path -AclObject $snapshot.Acl -ErrorAction Stop",
    ] {
        assert!(
            source.contains(marker),
            "{DEPENDENCY_SOURCE_PATH}: missing explicit vendored-directory ACL marker: {marker}"
        );
    }

    assert!(
        !source.contains("$vendorOriginalAcl = $null"),
        "{DEPENDENCY_SOURCE_PATH}: root-only vendor ACL snapshot must not remain selected"
    );
}
