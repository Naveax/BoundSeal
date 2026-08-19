use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn bsl() -> &'static str {
    env!("CARGO_BIN_EXE_bsl")
}

fn temporary_directory(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bsl-release-cli-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn run(arguments: &[&str]) -> Output {
    Command::new(bsl())
        .args(arguments)
        .output()
        .expect("could not execute bsl")
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

struct Fixture {
    root: PathBuf,
    binary: PathBuf,
    sbom: PathBuf,
    checksums: PathBuf,
    document: PathBuf,
    public_key: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = temporary_directory("fixture");
        fs::create_dir_all(&root).unwrap();
        let binary = root.join(if cfg!(windows) { "bsl.exe" } else { "bsl" });
        let sbom = root.join("bsl.cdx.json");
        let checksums = root.join("SHA256SUMS");
        let document = root.join("bsl-release-manifest.json");
        let public_key = root.join("release-public-key.hex");
        fs::write(&binary, b"synthetic-bsl-release-binary").unwrap();
        fs::write(
            &sbom,
            b"{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[]}",
        )
        .unwrap();
        let binary_name = binary.file_name().unwrap().to_str().unwrap();
        fs::write(
            &checksums,
            format!(
                "{}  {}\n{}  bsl.cdx.json\n",
                sha256(&fs::read(&binary).unwrap()),
                binary_name,
                sha256(&fs::read(&sbom).unwrap())
            ),
        )
        .unwrap();
        Self {
            root,
            binary,
            sbom,
            checksums,
            document,
            public_key,
        }
    }

    fn template(&self, sequence: u64) -> Output {
        run(&[
            "release",
            "manifest-template",
            "--release-id",
            "v0.1.0-cli-test",
            "--release-sequence",
            &sequence.to_string(),
            "--source-commit",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--platform",
            if cfg!(windows) { "windows" } else { "linux" },
            "--architecture",
            "x86-64",
            "--binary",
            self.binary.to_str().unwrap(),
            "--sbom",
            self.sbom.to_str().unwrap(),
            "--checksums",
            self.checksums.to_str().unwrap(),
            "--generated-at",
            "2026-08-05T15:00:00Z",
            "--output",
            self.document.to_str().unwrap(),
            "--json",
        ])
    }

    fn sign(&self) -> Value {
        let template = self.template(9);
        assert!(
            template.status.success(),
            "template failed: {}",
            String::from_utf8_lossy(&template.stderr)
        );
        let mut value: Value = serde_json::from_slice(&fs::read(&self.document).unwrap()).unwrap();
        let payload_hex = value
            .get("signing_payload_hex")
            .and_then(Value::as_str)
            .unwrap();
        let mut payload = Vec::with_capacity(payload_hex.len() / 2);
        for pair in payload_hex.as_bytes().chunks_exact(2) {
            let text = std::str::from_utf8(pair).unwrap();
            payload.push(u8::from_str_radix(text, 16).unwrap());
        }
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[19_u8; 32]).unwrap();
        value["signature_hex"] = Value::String(lower_hex(key_pair.sign(&payload).as_ref()));
        fs::write(
            &self.document,
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
        )
        .unwrap();
        fs::write(&self.public_key, lower_hex(key_pair.public_key().as_ref())).unwrap();
        value
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn verify(fixture: &Fixture) -> Output {
    run(&[
        "release",
        "verify-manifest",
        "--document",
        fixture.document.to_str().unwrap(),
        "--public-key",
        fixture.public_key.to_str().unwrap(),
        "--binary",
        fixture.binary.to_str().unwrap(),
        "--sbom",
        fixture.sbom.to_str().unwrap(),
        "--checksums",
        fixture.checksums.to_str().unwrap(),
        "--json",
    ])
}

fn assert_json_error(output: &Output, exit_code: i32, code: &str) {
    assert_eq!(output.status.code(), Some(exit_code));
    let value: Value = serde_json::from_slice(&output.stderr).expect("stderr is not JSON");
    assert_eq!(value.get("schema_version").and_then(Value::as_u64), Some(1));
    assert_eq!(value.get("status").and_then(Value::as_str), Some("error"));
    assert_eq!(value.get("code").and_then(Value::as_str), Some(code));
    assert_eq!(
        value.get("exit_code").and_then(Value::as_i64),
        Some(i64::from(exit_code))
    );
}

#[test]
fn template_then_external_signature_verifies() {
    let fixture = Fixture::new();
    let value = fixture.sign();
    assert_eq!(
        value
            .pointer("/manifest/release_sequence")
            .and_then(Value::as_u64),
        Some(9)
    );
    let output = verify(&fixture);
    assert!(
        output.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result.get("status").and_then(Value::as_str), Some("valid"));
    assert_eq!(
        result.get("release_sequence").and_then(Value::as_u64),
        Some(9)
    );
    assert_eq!(
        result.get("network_activity").and_then(Value::as_str),
        Some("none")
    );
}

#[test]
fn tampered_signature_and_artifact_are_rejected_with_stable_diagnostics() {
    let fixture = Fixture::new();
    let mut value = fixture.sign();
    let original = value
        .get("signature_hex")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let mut bytes = original.into_bytes();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    value["signature_hex"] = Value::String(String::from_utf8(bytes).unwrap());
    fs::write(
        &fixture.document,
        format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
    )
    .unwrap();
    assert_json_error(
        &verify(&fixture),
        61,
        "BSL151-RELEASE-MANIFEST-VERIFY-FAILED",
    );

    fixture.sign();
    fs::write(&fixture.binary, b"tampered release binary").unwrap();
    assert_json_error(
        &verify(&fixture),
        61,
        "BSL151-RELEASE-MANIFEST-VERIFY-FAILED",
    );
}

#[test]
fn zero_sequence_is_rejected_with_template_diagnostic() {
    let fixture = Fixture::new();
    assert_json_error(
        &fixture.template(0),
        60,
        "BSL151-RELEASE-MANIFEST-TEMPLATE-FAILED",
    );
}
