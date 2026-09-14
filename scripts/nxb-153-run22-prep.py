from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement anchor, found {count}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


immutable = Path("scripts/nxb-153-windows-immutable-source-inner.ps1")
dependency = Path("scripts/nxb-153-windows-dependency-source.ps1")
contract = Path("crates/nxb-core/tests/nxb153_run20_windows_acl_source_contract.rs")

replace_once(
    immutable,
    "function Assert-NxbDirectoryCreateDenied {",
    r'''function Set-NxbSourceFileWriteDeny {
    param([Parameter(Mandatory = $true)][string]$Path)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $identity) {
        Fail-Nxb 'current Windows identity SID is unavailable'
    }
    $acl = Get-Acl -LiteralPath $Path
    $rights = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        $rights,
        [Security.AccessControl.InheritanceFlags]::None,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Deny
    )
    [void]$acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Assert-NxbDirectoryCreateDenied {''',
)
replace_once(
    immutable,
    "$sourceDirectoryAcls = [Collections.Generic.List[object]]::new()\n    $cleanupErrors",
    "$sourceDirectoryAcls = [Collections.Generic.List[object]]::new()\n    $sourceFileAcls = [Collections.Generic.List[object]]::new()\n    $cleanupErrors",
)
replace_once(
    immutable,
    "        Protect-NxbRuntimeDirectory -Path $runtime\n\n        foreach ($sourceDirectory in @($root, $nested)) {",
    "        Protect-NxbRuntimeDirectory -Path $runtime\n\n        $sourceFileAcls.Add([pscustomobject]@{\n            Path = $source\n            Acl = Get-Acl -LiteralPath $source\n        })\n        Set-NxbSourceFileWriteDeny -Path $source\n\n        foreach ($sourceDirectory in @($root, $nested)) {",
)
replace_once(
    immutable,
    "        for ($index = $sourceDirectoryAcls.Count - 1; $index -ge 0; $index--) {\n            $snapshot = $sourceDirectoryAcls[$index]\n            if (Test-Path -LiteralPath $snapshot.Path) {\n                try { Set-Acl -LiteralPath $snapshot.Path -AclObject $snapshot.Acl -ErrorAction Stop } catch { $cleanupErrors.Add(\"self-test source ACL restore: $($_.Exception.Message)\") }\n            }\n        }\n        if (Test-Path -LiteralPath $root) {",
    "        for ($index = $sourceDirectoryAcls.Count - 1; $index -ge 0; $index--) {\n            $snapshot = $sourceDirectoryAcls[$index]\n            if (Test-Path -LiteralPath $snapshot.Path) {\n                try { Set-Acl -LiteralPath $snapshot.Path -AclObject $snapshot.Acl -ErrorAction Stop } catch { $cleanupErrors.Add(\"self-test source directory ACL restore: $($_.Exception.Message)\") }\n            }\n        }\n        for ($index = $sourceFileAcls.Count - 1; $index -ge 0; $index--) {\n            $snapshot = $sourceFileAcls[$index]\n            if (Test-Path -LiteralPath $snapshot.Path) {\n                try { Set-Acl -LiteralPath $snapshot.Path -AclObject $snapshot.Acl -ErrorAction Stop } catch { $cleanupErrors.Add(\"self-test source file ACL restore: $($_.Exception.Message)\") }\n            }\n        }\n        if (Test-Path -LiteralPath $root) {",
)
replace_once(
    immutable,
    "$sourceDirectoryAcls = [Collections.Generic.List[object]]::new()\n$archiveStream",
    "$sourceDirectoryAcls = [Collections.Generic.List[object]]::new()\n$sourceFileAcls = [Collections.Generic.List[object]]::new()\n$archiveStream",
)
replace_once(
    immutable,
    "    foreach ($sourceDirectory in $sourceDirectories) {\n        $sourceDirectoryAcls.Add([pscustomobject]@{",
    "    foreach ($entry in $manifest) {\n        $sourceFile = $actualFiles[$entry.Path]\n        $sourceFileAcls.Add([pscustomobject]@{\n            Path = $sourceFile\n            Acl = Get-Acl -LiteralPath $sourceFile\n        })\n    }\n    foreach ($entry in $manifest) {\n        Set-NxbSourceFileWriteDeny -Path $actualFiles[$entry.Path]\n    }\n\n    foreach ($sourceDirectory in $sourceDirectories) {\n        $sourceDirectoryAcls.Add([pscustomobject]@{",
)
replace_once(
    immutable,
    "    for ($index = $sourceDirectoryAcls.Count - 1; $index -ge 0; $index--) {\n        $snapshot = $sourceDirectoryAcls[$index]\n        if (Test-Path -LiteralPath $snapshot.Path) {\n            try { Set-Acl -LiteralPath $snapshot.Path -AclObject $snapshot.Acl -ErrorAction Stop } catch { $cleanupErrors.Add(\"snapshot source ACL restore: $($_.Exception.Message)\") }\n        }\n    }\n    for ($index = $fileStreams.Count - 1; $index -ge 0; $index--) {",
    "    for ($index = $sourceDirectoryAcls.Count - 1; $index -ge 0; $index--) {\n        $snapshot = $sourceDirectoryAcls[$index]\n        if (Test-Path -LiteralPath $snapshot.Path) {\n            try { Set-Acl -LiteralPath $snapshot.Path -AclObject $snapshot.Acl -ErrorAction Stop } catch { $cleanupErrors.Add(\"snapshot source directory ACL restore: $($_.Exception.Message)\") }\n        }\n    }\n    for ($index = $sourceFileAcls.Count - 1; $index -ge 0; $index--) {\n        $snapshot = $sourceFileAcls[$index]\n        if (Test-Path -LiteralPath $snapshot.Path) {\n            try { Set-Acl -LiteralPath $snapshot.Path -AclObject $snapshot.Acl -ErrorAction Stop } catch { $cleanupErrors.Add(\"snapshot source file ACL restore: $($_.Exception.Message)\") }\n        }\n    }\n    for ($index = $fileStreams.Count - 1; $index -ge 0; $index--) {",
)

replace_once(
    dependency,
    "$vendorOriginalAcl = $null\n$primaryFailure",
    "$vendorDirectoryAcls = [Collections.Generic.List[object]]::new()\n$primaryFailure",
)
replace_once(
    dependency,
    "        $vendorOriginalAcl = Get-Acl -LiteralPath $vendorRoot\n        Set-NxbDependencyWriteDeny -Path $vendorRoot\n\n        [Int64]$pinnedBytes = 0\n        $pinnedFiles = 0\n        foreach ($directory in @(Get-ChildItem -LiteralPath $vendorRoot -Directory -Force -Recurse | Sort-Object { $_.FullName.Length } | ForEach-Object { $_.FullName })) {",
    "        $vendorDirectories = @(Get-ChildItem -LiteralPath $vendorRoot -Directory -Force -Recurse | Sort-Object { $_.FullName.Length } | ForEach-Object { $_.FullName })\n        foreach ($directory in @($vendorRoot) + $vendorDirectories) {\n            $vendorDirectoryAcls.Add([pscustomobject]@{\n                Path = $directory\n                Acl = Get-Acl -LiteralPath $directory\n            })\n        }\n        foreach ($directory in @($vendorRoot) + $vendorDirectories) {\n            Set-NxbDependencyWriteDeny -Path $directory\n        }\n\n        [Int64]$pinnedBytes = 0\n        $pinnedFiles = 0\n        foreach ($directory in $vendorDirectories) {",
)
replace_once(
    dependency,
    "    if ($null -ne $vendorOriginalAcl -and (Test-Path -LiteralPath $vendorRoot)) {\n        try { Set-Acl -LiteralPath $vendorRoot -AclObject $vendorOriginalAcl -ErrorAction Stop } catch { $cleanupErrors.Add(\"vendor ACL restore: $($_.Exception.Message)\") }\n    }",
    "    for ($index = $vendorDirectoryAcls.Count - 1; $index -ge 0; $index--) {\n        $snapshot = $vendorDirectoryAcls[$index]\n        if (Test-Path -LiteralPath $snapshot.Path) {\n            try { Set-Acl -LiteralPath $snapshot.Path -AclObject $snapshot.Acl -ErrorAction Stop } catch { $cleanupErrors.Add(\"vendor directory ACL restore: $($_.Exception.Message)\") }\n        }\n    }",
)

text = contract.read_text(encoding="utf-8")
text = text.replace(
    'fn windows_source_deny_acl_is_staged_explicitly_per_retained_source_directory()',
    'fn windows_source_deny_acl_is_staged_explicitly_per_retained_source_object()',
    1,
)
needle = '        "$sourceDirectoryAcls = [Collections.Generic.List[object]]::new()",\n'
if needle not in text:
    raise SystemExit("run20 contract marker insertion anchor missing")
text = text.replace(
    needle,
    needle
    + '        "$sourceFileAcls = [Collections.Generic.List[object]]::new()",\n'
    + '        "Set-NxbSourceFileWriteDeny -Path $source",\n'
    + '        "Set-NxbSourceFileWriteDeny -Path $actualFiles[$entry.Path]",\n'
    + '        "for ($index = $sourceFileAcls.Count - 1; $index -ge 0; $index--)",\n',
    1,
)
contract.write_text(text, encoding="utf-8")

new_contract = Path("crates/nxb-core/tests/nxb153_run22_windows_dependency_acl_source_contract.rs")
new_contract.write_text(r'''use std::{
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
''', encoding="utf-8")
