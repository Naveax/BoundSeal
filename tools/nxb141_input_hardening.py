from pathlib import Path
import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"unexpected {label} count: {count}")
    return text.replace(old, new, 1)


library_path = Path("crates/nxb-unified-operator/src/lib.rs")
library = library_path.read_text(encoding="utf-8")
library = replace_once(
    library,
    "        || path.chars().any(char::is_control)\n",
    "        || path\n            .chars()\n            .any(|character| character.is_control() || character.is_whitespace())\n",
    "passive path control check",
)
marker = """    #[test]
    fn activation_tampering_is_rejected() {
"""
test = """    #[test]
    fn whitespace_path_scope_is_rejected() {
        let mut binding = binding();
        binding
            .allowed_path_prefixes
            .insert("/api/user data".into());
        assert_eq!(
            binding.validate().expect_err("whitespace path must fail"),
            UnifiedOperatorError::InvalidPathScope
        );
    }

    #[test]
    fn activation_tampering_is_rejected() {
"""
library = replace_once(library, marker, test, "whitespace path test marker")
library_path.write_text(library, encoding="utf-8", newline="\n")

cli_path = Path("crates/nxb-core/src/bin/nxb-unified-operator.rs")
cli = cli_path.read_text(encoding="utf-8")
cli = replace_once(cli, "    io::Write,\n", "    io::{Read, Write},\n", "CLI I/O import")
marker = "use sha2::{Digest, Sha256};\n"
constants = """use sha2::{Digest, Sha256};

const MAX_UNIFIED_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_UNIFIED_KEY_FILE_BYTES: u64 = 4 * 1024;
"""
cli = replace_once(cli, marker, constants, "CLI input constants")

read_json_pattern = re.compile(
    r"fn read_json<T: DeserializeOwned>\(path: &Path\) -> Result<T> \{.*?\n\}\n\n"
    r"(?=fn write_json)",
    re.DOTALL,
)
read_json_replacement = """fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = read_bounded_file(path, MAX_UNIFIED_ARTIFACT_BYTES)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("could not parse JSON {}", path.display()))
}

"""
cli, count = read_json_pattern.subn(read_json_replacement, cli, count=1)
if count != 1:
    raise SystemExit(f"unexpected read_json function count: {count}")

read_hex_pattern = re.compile(
    r"fn read_lower_hex_file\(path: &Path\) -> Result<Vec<u8>> \{.*?\n\}\n\n"
    r"(?=fn decode_lower_hex)",
    re.DOTALL,
)
read_hex_replacement = """fn read_lower_hex_file(path: &Path) -> Result<Vec<u8>> {
    let bytes = read_bounded_file(path, MAX_UNIFIED_KEY_FILE_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("hex file is not UTF-8: {}", path.display()))?;
    decode_lower_hex(text.trim())
}

fn read_bounded_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum_bytes {
        bail!("input file is not a bounded regular file: {}", path.display());
    }
    let expected_bytes = metadata.len();
    let capacity = usize::try_from(expected_bytes).context("input size does not fit memory index")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read {}", path.display()))?;
    if bytes.len() as u64 != expected_bytes {
        bail!("input file changed while being read: {}", path.display());
    }
    Ok(bytes)
}

"""
cli, count = read_hex_pattern.subn(read_hex_replacement, cli, count=1)
if count != 1:
    raise SystemExit(f"unexpected read_lower_hex_file function count: {count}")

cli = re.sub(
    'file\\.write_all\\(\\s*b"\\n"\\s*,?\\s*\\)',
    r'file.write_all(b"\\n")',
    cli,
    count=1,
)
cli = re.sub(
    'bytes\\.ends_with\\(\\s*b"\\n"\\s*\\)',
    r'bytes.ends_with(b"\\n")',
    cli,
    count=1,
)

cli = replace_once(
    cli,
    "        fs,\n        sync::atomic::{AtomicU64, Ordering},\n",
    "        fs::{self, OpenOptions},\n        sync::atomic::{AtomicU64, Ordering},\n",
    "CLI test imports",
)
cli = replace_once(
    cli,
    "    use super::{path_matches_prefix, write_json};\n",
    "    use super::{\n        path_matches_prefix, read_json, write_json, MAX_UNIFIED_ARTIFACT_BYTES,\n    };\n",
    "CLI test super imports",
)
marker = """    #[test]
    fn artifact_publication_is_complete_and_no_clobber() {
"""
test = """    #[test]
    fn oversized_artifact_is_rejected_before_parsing() {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let directory = std::env::temp_dir().join(format!(
            "nxb141-unified-input-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        let input = directory.join("oversized.json");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&input)
            .unwrap();
        file.set_len(MAX_UNIFIED_ARTIFACT_BYTES + 1).unwrap();
        assert!(read_json::<serde_json::Value>(&input).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn artifact_publication_is_complete_and_no_clobber() {
"""
cli = replace_once(cli, marker, test, "oversized artifact test marker")
cli_path.write_text(cli, encoding="utf-8", newline="\n")
