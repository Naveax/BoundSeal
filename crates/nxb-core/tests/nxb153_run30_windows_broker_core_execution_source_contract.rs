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
fn verified_core_bytes_are_the_same_bytes_executed() {
    let text = source();
    let start = required_offset(&text, "def load_verified_core():");
    let end = required_offset(&text[start..], "\n\ncore = load_verified_core()") + start;
    let body = &text[start..end];

    for marker in [
        "raw = core_path.read_bytes()",
        "git_object = f\"blob {len(raw)}\\0\".encode(\"ascii\") + raw",
        "if digest != CORE_GIT_BLOB_SHA1:",
        "module = types.ModuleType(\"nxb153_h2_destination_broker_core\")",
        "module.__file__ = str(core_path)",
        "code = compile(raw, str(core_path), \"exec\")",
        "exec(code, module.__dict__)",
    ] {
        assert!(
            body.contains(marker),
            "{LAUNCHER_PATH}: verified-core execution marker is missing: {marker}"
        );
    }

    assert_eq!(
        body.matches("core_path.read_bytes()").count(),
        1,
        "{LAUNCHER_PATH}: core authority must be read exactly once before execution"
    );

    for forbidden in [
        "spec_from_file_location",
        "exec_module(",
        "open(core_path",
        "core_path.open(",
    ] {
        assert!(
            !body.contains(forbidden),
            "{LAUNCHER_PATH}: verified bytes are followed by a pathname reload: {forbidden}"
        );
    }

    let read = required_offset(body, "raw = core_path.read_bytes()");
    let verify = required_offset(body, "if digest != CORE_GIT_BLOB_SHA1:");
    let compile = required_offset(body, "code = compile(raw, str(core_path), \"exec\")");
    let execute = required_offset(body, "exec(code, module.__dict__)");
    assert!(
        read < verify && verify < compile && compile < execute,
        "{LAUNCHER_PATH}: exact Git-blob verification must linearize before compiling and executing the retained byte buffer"
    );
}

#[test]
fn broker_command_reader_accepts_exact_crlf_without_general_whitespace_normalization() {
    let text = source();
    let start = required_offset(&text, "def read_command() -> str | None:");
    let end = required_offset(&text[start..], "\n\ncore.read_command = read_command") + start;
    let body = &text[start..end];

    for marker in [
        "raw = core.sys.stdin.buffer.readline(core.MAX_COMMAND_BYTES + 1)",
        "not raw.endswith(b\"\\n\")",
        "payload = raw[:-1]",
        "if payload.endswith(b\"\\r\"):",
        "payload = payload[:-1]",
        "payload.decode(\"ascii\", errors=\"strict\")",
        "core.fail(\"broker command is not strict ASCII\")",
    ] {
        assert!(
            body.contains(marker),
            "{LAUNCHER_PATH}: bounded CRLF command-framing marker is missing: {marker}"
        );
    }

    for forbidden in [".strip(", ".rstrip(", ".lstrip("] {
        assert!(
            !body.contains(forbidden),
            "{LAUNCHER_PATH}: broker command framing must not normalize arbitrary whitespace: {forbidden}"
        );
    }

    let remove_lf = required_offset(body, "payload = raw[:-1]");
    let detect_cr = required_offset(body, "if payload.endswith(b\"\\r\"):");
    let remove_cr = required_offset(&body[detect_cr..], "payload = payload[:-1]") + detect_cr;
    let decode = required_offset(body, "payload.decode(\"ascii\", errors=\"strict\")");
    assert!(
        remove_lf < detect_cr && detect_cr < remove_cr && remove_cr < decode,
        "{LAUNCHER_PATH}: only one optional CR immediately before LF may be removed before strict ASCII decode"
    );
    assert!(
        text.contains("core.read_command = read_command"),
        "{LAUNCHER_PATH}: verified launcher must install the CRLF-aware command reader into the immutable core"
    );
}
