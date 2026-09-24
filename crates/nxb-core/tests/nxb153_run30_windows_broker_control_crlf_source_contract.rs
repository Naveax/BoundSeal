use std::{
    fs,
    path::{Path, PathBuf},
};

const LAUNCHER_PATH: &str = "scripts/nxb-153-windows-h2-destination-broker.py";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source() -> String {
    let path = repository_root().join(LAUNCHER_PATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn required_offset(source: &str, marker: &str) -> usize {
    source
        .find(marker)
        .unwrap_or_else(|| panic!("{LAUNCHER_PATH}: missing source marker: {marker}"))
}

#[test]
fn broker_control_reader_accepts_lf_and_crlf_without_weakening_the_envelope() {
    let text = source();
    let start = required_offset(&text, "def read_command() -> str | None:");
    let end = required_offset(&text[start..], "\n\ncore.read_command = read_command") + start;
    let body = &text[start..end];

    for marker in [
        "core.sys.stdin.buffer.readline(core.MAX_COMMAND_BYTES + 1)",
        "len(raw) > core.MAX_COMMAND_BYTES",
        "not raw.endswith(b\"\\n\")",
        "payload = raw[:-1]",
        "if payload.endswith(b\"\\r\"):",
        "payload = payload[:-1]",
        "payload.decode(\"ascii\", errors=\"strict\")",
        "core.fail(\"broker command is not strict ASCII\")",
    ] {
        assert!(
            body.contains(marker),
            "{LAUNCHER_PATH}: bounded CRLF command marker is missing: {marker}"
        );
    }

    let strip_lf = required_offset(body, "payload = raw[:-1]");
    let detect_cr = required_offset(body, "if payload.endswith(b\"\\r\"):");
    let strip_cr = required_offset(&body[detect_cr..], "payload = payload[:-1]") + detect_cr;
    let decode = required_offset(body, "payload.decode(\"ascii\", errors=\"strict\")");
    assert!(
        strip_lf < detect_cr && detect_cr < strip_cr && strip_cr < decode,
        "{LAUNCHER_PATH}: optional CR must be removed only after required LF framing and before strict ASCII decode"
    );
}

#[test]
fn patched_reader_is_installed_before_core_main_can_enter_broker_mode() {
    let text = source();
    let install = required_offset(&text, "core.read_command = read_command");
    let entry = required_offset(&text, "raise SystemExit(core.main())");
    assert!(
        install < entry,
        "{LAUNCHER_PATH}: CRLF-aware reader must replace the core reader before core.main executes"
    );
}
