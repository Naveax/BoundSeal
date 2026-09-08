use std::{
    fs,
    path::{Path, PathBuf},
};

const VALIDATOR_PATH: &str = "scripts/validate-nxb-153-windows-inner.ps1";
const PREPARATION_PATH: &str = "scripts/prepare-and-validate-nxb-153-windows-inner.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_source(relative_path: &str) -> String {
    let path = repository_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn unique_index(text: &str, needle: &str) -> usize {
    let mut matches = text.match_indices(needle);
    let first = matches
        .next()
        .unwrap_or_else(|| panic!("{VALIDATOR_PATH}: missing required source pattern: {needle}"));
    assert!(
        matches.next().is_none(),
        "{VALIDATOR_PATH}: required source pattern must occur exactly once: {needle}"
    );
    first.0
}

fn first_index(text: &str, needle: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("{VALIDATOR_PATH}: missing required source pattern: {needle}"))
}

fn function_source<'a>(
    text: &'a str,
    relative_path: &str,
    function_marker: &str,
    next_function_marker: &str,
) -> &'a str {
    let start = text.find(function_marker).unwrap_or_else(|| {
        panic!("{relative_path}: missing function source marker: {function_marker}")
    });
    let tail = &text[start..];
    let end = tail.find(next_function_marker).unwrap_or_else(|| {
        panic!("{relative_path}: missing next function source marker: {next_function_marker}")
    });
    tail[..end].trim_end()
}

#[test]
fn windows_validator_version_output_is_bounded_before_h2_delegation() {
    let text = read_source(VALIDATOR_PATH);

    for marker in [
        "$fixedOutputByteLimit = 4096",
        "$fixedOutputReadTimeoutMilliseconds = 30000",
        "$fixedOutputExitTimeoutMilliseconds = 30000",
        "function Invoke-NxbBoundedFixedOutput",
        "$start.UseShellExecute = $false",
        "$start.RedirectStandardOutput = $true",
        "$start.RedirectStandardError = $false",
        "$start.CreateNoWindow = $true",
        "$process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)",
        "$total -gt $fixedOutputByteLimit",
        "$process.WaitForExit($fixedOutputExitTimeoutMilliseconds)",
        "$process.ExitCode -ne 0",
        "$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)",
        "$value.Length -gt 256",
        "$process.Kill($true)",
        "Get-Command rustup -CommandType Application -ErrorAction Stop",
        "Invoke-NxbBoundedFixedOutput -FilePath $Path -Arguments @('--version') -Label \"$Label version\"",
        "-Arguments @('run', $rustToolchain, 'rustc', '--version')",
        "-Arguments @('run', $rustToolchain, 'cargo', '--version')",
    ] {
        assert!(
            text.contains(marker),
            "{VALIDATOR_PATH}: missing fixed-output authority marker: {marker}"
        );
    }

    for forbidden in [
        "(& $Path --version | Out-String)",
        "(& rustup run $rustToolchain rustc --version | Out-String)",
        "(& rustup run $rustToolchain cargo --version | Out-String)",
        "ReadToEndAsync",
        "ReadLineAsync",
        "WaitForExit()",
    ] {
        assert!(
            !text.contains(forbidden),
            "{VALIDATOR_PATH}: forbidden unbounded/version-output source pattern is present: {forbidden}"
        );
    }

    assert!(
        !text.contains("Out-String"),
        "{VALIDATOR_PATH}: version/control output must not reintroduce post-hoc Out-String retention"
    );

    let helper_index = unique_index(&text, "function Invoke-NxbBoundedFixedOutput");
    let tool_version_index = unique_index(&text, "function Get-NxbToolVersion");
    let rustup_resolution_index = unique_index(
        &text,
        "$rustupCommand = Get-Command rustup -CommandType Application -ErrorAction Stop",
    );
    let first_h2_delegation = first_index(&text, "& $immutableSourcePath `");

    assert!(
        helper_index < tool_version_index,
        "{VALIDATOR_PATH}: bounded helper must be defined before tool-version inspection"
    );
    assert!(
        tool_version_index < rustup_resolution_index,
        "{VALIDATOR_PATH}: tool-version helper must be established before Rust toolchain version capture"
    );
    assert!(
        rustup_resolution_index < first_h2_delegation,
        "{VALIDATOR_PATH}: bounded Rust/tool version capture must complete before H2 delegation"
    );

    assert_eq!(
        text.matches("Invoke-NxbBoundedFixedOutput").count(),
        4,
        "{VALIDATOR_PATH}: expected one helper definition plus tool-version, rustc and cargo bounded call sites"
    );
}

#[test]
fn windows_validator_fixed_output_helper_matches_dynamically_probed_preparation_helper() {
    let validator = read_source(VALIDATOR_PATH);
    let preparation = read_source(PREPARATION_PATH);

    let validator_helper = function_source(
        &validator,
        VALIDATOR_PATH,
        "function Invoke-NxbBoundedFixedOutput {",
        "\nfunction Get-NxbToolVersion {",
    );
    let preparation_helper = function_source(
        &preparation,
        PREPARATION_PATH,
        "function Invoke-NxbBoundedFixedOutput {",
        "\nfunction Get-ToolVersion {",
    );

    assert_eq!(
        validator_helper, preparation_helper,
        "{VALIDATOR_PATH}: fixed-output helper must remain source-identical to the preparation helper exercised by the exact-head Windows dynamic tool-version probe"
    );

    for constant in [
        "$fixedOutputByteLimit = 4096",
        "$fixedOutputReadTimeoutMilliseconds = 30000",
        "$fixedOutputExitTimeoutMilliseconds = 30000",
    ] {
        assert!(
            validator.contains(constant),
            "{VALIDATOR_PATH}: missing shared fixed-output constant: {constant}"
        );
        assert!(
            preparation.contains(constant),
            "{PREPARATION_PATH}: missing shared fixed-output constant: {constant}"
        );
    }
}
