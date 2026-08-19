use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SIGNATURE_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &str = "bsl-release-checksums-v1";
const MAX_CHECKSUM_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHECKSUM_LINES: usize = 10_000;
const MAX_PRIVATE_KEY_FILE_BYTES: u64 = 16 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "bsl-release-sign",
    version,
    about = "Offline Ed25519 signing and verification for BSL SHA256SUMS files"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Sign an exact SHA256SUMS file with an operator-provided PKCS#8 Ed25519 key.
    Sign {
        #[arg(long)]
        checksums: PathBuf,
        #[arg(long)]
        private_key_hex: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a signature certificate against an exact SHA256SUMS file.
    Verify {
        #[arg(long)]
        checksums: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SignaturePayload {
    version: u32,
    domain: String,
    algorithm: String,
    checksums_sha256: String,
    signer_key_id_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SignatureCertificate {
    payload: SignaturePayload,
    public_key_hex: String,
    signature_hex: String,
    certificate_sha256: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Sign {
            checksums,
            private_key_hex,
            output,
        } => {
            let certificate = sign_file(&checksums, &private_key_hex)?;
            write_json_atomic(&output, &certificate)?;
            println!("release_signature: created");
            println!("checksums_sha256: {}", certificate.payload.checksums_sha256);
            println!(
                "signer_key_id_sha256: {}",
                certificate.payload.signer_key_id_sha256
            );
            println!("certificate_sha256: {}", certificate.certificate_sha256);
            println!("output: {}", output.display());
            Ok(())
        }
        Command::Verify {
            checksums,
            certificate,
        } => {
            let certificate: SignatureCertificate = read_json_bounded(&certificate, 1024 * 1024)?;
            verify_file(&checksums, &certificate)?;
            println!("release_signature: valid");
            println!("checksums_sha256: {}", certificate.payload.checksums_sha256);
            println!(
                "signer_key_id_sha256: {}",
                certificate.payload.signer_key_id_sha256
            );
            println!("certificate_sha256: {}", certificate.certificate_sha256);
            Ok(())
        }
    }
}

fn sign_file(checksums: &Path, private_key_hex: &Path) -> Result<SignatureCertificate> {
    let checksum_bytes = read_checksum_file(checksums)?;
    enforce_private_key_permissions(private_key_hex)?;
    let private_key_text = read_text_bounded(private_key_hex, MAX_PRIVATE_KEY_FILE_BYTES)?;
    let private_key_bytes = decode_hex(private_key_text.trim())
        .context("private key file is not valid lowercase or uppercase hexadecimal")?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&private_key_bytes)
        .map_err(|_| anyhow::anyhow!("private key is not a valid Ed25519 PKCS#8 document"))?;
    let public_key = key_pair.public_key().as_ref();
    let payload = SignaturePayload {
        version: SIGNATURE_VERSION,
        domain: SIGNATURE_DOMAIN.into(),
        algorithm: "ed25519".into(),
        checksums_sha256: hash_bytes(&checksum_bytes),
        signer_key_id_sha256: hash_bytes(public_key),
    };
    validate_payload(&payload)?;
    let signing_bytes =
        serde_json::to_vec(&payload).context("could not serialize signature payload")?;
    let signature = key_pair.sign(&signing_bytes);
    let mut certificate = SignatureCertificate {
        payload,
        public_key_hex: lower_hex(public_key),
        signature_hex: lower_hex(signature.as_ref()),
        certificate_sha256: String::new(),
    };
    certificate.certificate_sha256 = certificate_digest(&certificate)?;
    verify_file(checksums, &certificate)?;
    Ok(certificate)
}

fn verify_file(checksums: &Path, certificate: &SignatureCertificate) -> Result<()> {
    let checksum_bytes = read_checksum_file(checksums)?;
    validate_payload(&certificate.payload)?;
    if hash_bytes(&checksum_bytes) != certificate.payload.checksums_sha256 {
        bail!("SHA256SUMS digest does not match the signature payload");
    }
    let public_key = decode_hex(&certificate.public_key_hex)
        .context("signature certificate public key is not valid hexadecimal")?;
    if public_key.len() != 32 {
        bail!("signature certificate public key must contain 32 Ed25519 bytes");
    }
    if hash_bytes(&public_key) != certificate.payload.signer_key_id_sha256 {
        bail!("signature certificate signer key identifier does not match the public key");
    }
    let signature = decode_hex(&certificate.signature_hex)
        .context("signature certificate signature is not valid hexadecimal")?;
    if signature.len() != 64 {
        bail!("signature certificate must contain a 64-byte Ed25519 signature");
    }
    let signing_bytes = serde_json::to_vec(&certificate.payload)
        .context("could not serialize signature payload")?;
    UnparsedPublicKey::new(&ED25519, &public_key)
        .verify(&signing_bytes, &signature)
        .map_err(|_| anyhow::anyhow!("Ed25519 signature verification failed"))?;
    if certificate.certificate_sha256 != certificate_digest(certificate)? {
        bail!("signature certificate digest mismatch");
    }
    Ok(())
}

fn validate_payload(payload: &SignaturePayload) -> Result<()> {
    if payload.version != SIGNATURE_VERSION
        || payload.domain != SIGNATURE_DOMAIN
        || payload.algorithm != "ed25519"
        || !is_sha256(&payload.checksums_sha256)
        || !is_sha256(&payload.signer_key_id_sha256)
    {
        bail!("signature payload is outside the BSL release-signing contract");
    }
    Ok(())
}

fn certificate_digest(certificate: &SignatureCertificate) -> Result<String> {
    let mut material = certificate.clone();
    material.certificate_sha256.clear();
    let bytes =
        serde_json::to_vec(&material).context("could not serialize certificate material")?;
    Ok(hash_bytes(&bytes))
}

fn read_checksum_file(path: &Path) -> Result<Vec<u8>> {
    let bytes = read_bytes_bounded(path, MAX_CHECKSUM_FILE_BYTES)?;
    let text = std::str::from_utf8(&bytes).context("SHA256SUMS file is not UTF-8")?;
    validate_checksum_lines(text)?;
    Ok(bytes)
}

fn validate_checksum_lines(text: &str) -> Result<()> {
    let mut count = 0_usize;
    let mut paths = BTreeSet::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        count = count.saturating_add(1);
        if count > MAX_CHECKSUM_LINES {
            bail!("SHA256SUMS contains too many entries");
        }
        let (digest, logical_path) = line
            .split_once("  ")
            .context("SHA256SUMS entry must use '<sha256><two spaces><path>'")?;
        if !is_sha256(digest) {
            bail!("SHA256SUMS contains an invalid lowercase SHA-256 value");
        }
        validate_logical_path(logical_path)?;
        if !paths.insert(logical_path.to_string()) {
            bail!("SHA256SUMS contains a duplicate logical path");
        }
    }
    if count == 0 {
        bail!("SHA256SUMS contains no entries");
    }
    Ok(())
}

fn validate_logical_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains('\\')
    {
        bail!("SHA256SUMS contains an invalid logical path");
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("SHA256SUMS contains an unsafe logical path");
    }
    Ok(())
}

fn read_json_bounded<T: for<'de> Deserialize<'de>>(path: &Path, maximum_bytes: u64) -> Result<T> {
    let bytes = read_bytes_bounded(path, maximum_bytes)?;
    serde_json::from_slice(&bytes).context("signature certificate JSON is invalid")
}

fn read_text_bounded(path: &Path, maximum_bytes: u64) -> Result<String> {
    let bytes = read_bytes_bounded(path, maximum_bytes)?;
    String::from_utf8(bytes).context("input file is not UTF-8")
}

fn read_bytes_bounded(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("could not inspect {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum_bytes {
        bail!("input file is empty, not regular, or exceeds its size limit");
    }
    fs::read(path).with_context(|| format!("could not read {}", path.display()))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes =
        serde_json::to_vec_pretty(value).context("could not serialize signature certificate")?;
    let parent = path
        .parent()
        .context("signature output path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("could not create {}", parent.display()))?;
    let temporary = parent.join(format!(
        ".bsl-release-sign-{}.tmp",
        &hash_bytes(&bytes)[..16]
    ));
    if temporary.exists() {
        fs::remove_file(&temporary)
            .with_context(|| format!("could not remove stale {}", temporary.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("could not create {}", temporary.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("could not write {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("could not sync {}", temporary.display()))?;
    drop(file);
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("could not replace {}", path.display()))?;
    }
    fs::rename(&temporary, path).with_context(|| {
        format!(
            "could not atomically move {} to {}",
            temporary.display(),
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(unix)]
fn enforce_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .with_context(|| format!("could not inspect {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!("private key file must not be readable or writable by group or others");
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_private_key_permissions(path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!("private key path is not a regular file");
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
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

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("hexadecimal input is invalid");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("hexadecimal input is invalid"),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ring::rand::SystemRandom;

    use super::*;

    #[test]
    fn signed_checksums_verify_and_tampering_fails() {
        let root =
            std::env::temp_dir().join(format!("bsl-release-sign-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let checksums = root.join("SHA256SUMS");
        fs::write(
            &checksums,
            format!("{}  bsl-linux-x86_64\n", "a".repeat(64)),
        )
        .unwrap();

        let key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key_path = root.join("release-key.hex");
        fs::write(&key_path, lower_hex(key_document.as_ref())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let certificate = sign_file(&checksums, &key_path).unwrap();
        verify_file(&checksums, &certificate).unwrap();

        fs::write(
            &checksums,
            format!("{}  bsl-linux-x86_64\n", "b".repeat(64)),
        )
        .unwrap();
        assert!(verify_file(&checksums, &certificate).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_checksum_paths_are_rejected() {
        assert!(validate_checksum_lines(&format!("{}  ../bsl\n", "a".repeat(64))).is_err());
        assert!(validate_checksum_lines(&format!("{}  /tmp/bsl\n", "a".repeat(64))).is_err());
        assert!(validate_checksum_lines(&format!("{}  bin\\bsl.exe\n", "a".repeat(64))).is_err());
    }
}
