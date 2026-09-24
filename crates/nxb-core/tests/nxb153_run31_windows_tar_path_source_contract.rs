use std::{
    fs,
    path::{Path, PathBuf},
};

const WORKFLOW_PATH: &str = ".github/workflows/nxb-153-admission.yml";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source() -> String {
    let path = repository_root().join(WORKFLOW_PATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn required_offset(source: &str, marker: &str) -> usize {
    source
        .find(marker)
        .unwrap_or_else(|| panic!("{WORKFLOW_PATH}: missing source marker: {marker}"))
}

#[test]
fn hosted_windows_path_pins_tar_to_the_trusted_system32_application() {
    let text = source();

    for marker in [
        "$systemTarPath = [IO.Path]::GetFullPath((Join-Path ([Environment]::SystemDirectory) 'tar.exe'))",
        "$systemTarItem = Get-Item -LiteralPath $systemTarPath -Force -ErrorAction Stop",
        "[IO.FileAttributes]::ReparsePoint",
        "$tarNormalizedPath = [Collections.Generic.List[string]]::new()",
        "$systemTarDirectorySeen = $false",
        "$tarCandidate = Join-Path $pathEntry 'tar.exe'",
        "$candidateFull = [IO.Path]::GetFullPath($tarCandidate)",
        "[string]::Equals($candidateFull, $systemTarPath, [StringComparison]::OrdinalIgnoreCase)",
        "$env:PATH = $tarNormalizedPath -join [IO.Path]::PathSeparator",
        "$tarApplications = @(Get-Command tar -CommandType Application -ErrorAction Stop)",
        "$tarApplications.Count -ne 1",
        "[IO.Path]::GetFullPath([string]$tarApplications[0].Source)",
        "hosted Windows PATH did not normalize to the single trusted System32 tar application",
    ] {
        assert!(
            text.contains(marker),
            "{WORKFLOW_PATH}: hosted tar authority marker is missing: {marker}"
        );
    }

    for forbidden in [
        "Get-Command tar -CommandType Application -ErrorAction Stop | Select-Object -First 1",
        "(Get-Command tar -CommandType Application -ErrorAction Stop)[0]",
    ] {
        assert!(
            !text.contains(forbidden),
            "{WORKFLOW_PATH}: hosted tar authority must not silently select one ambiguous PATH result: {forbidden}"
        );
    }

    let python_commit = required_offset(
        &text,
        "$env:PATH = $pythonNormalizedPath -join [IO.Path]::PathSeparator",
    );
    let tar_system = required_offset(&text, "$systemTarPath = [IO.Path]::GetFullPath(");
    let tar_commit = required_offset(
        &text,
        "$env:PATH = $tarNormalizedPath -join [IO.Path]::PathSeparator",
    );
    let tar_assert = required_offset(
        &text,
        "$tarApplications = @(Get-Command tar -CommandType Application -ErrorAction Stop)",
    );
    let prepare = required_offset(
        &text,
        "& .\\scripts\\prepare-and-validate-nxb-153-windows.ps1 -RepoRoot .",
    );

    assert!(
        python_commit < tar_system
            && tar_system < tar_commit
            && tar_commit < tar_assert
            && tar_assert < prepare,
        "{WORKFLOW_PATH}: trusted tar normalization must complete after Python normalization and before Windows admission starts"
    );
}
