from pathlib import Path
import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"unexpected {label} count: {count}")
    return text.replace(old, new, 1)


library_path = Path("crates/nxb-unified-operator/src/lib.rs")
library = library_path.read_text(encoding="utf-8")
if not library.startswith("#![forbid(unsafe_code)]"):
    library = "#![forbid(unsafe_code)]\n\n" + library
library_path.write_text(library, encoding="utf-8", newline="\n")

cli_path = Path("crates/nxb-core/src/bin/nxb-unified-operator.rs")
cli = cli_path.read_text(encoding="utf-8")
if not cli.startswith("#![forbid(unsafe_code)]"):
    cli = "#![forbid(unsafe_code)]\n\n" + cli

cli = replace_once(
    cli,
    """use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
""",
    """use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
""",
    "CLI import block",
)
cli = replace_once(
    cli,
    'about = "Networkless NXB-140 unified operator artifact binder"',
    'about = "Networkless NXB-141 unified operator artifact binder"',
    "CLI milestone label",
)

write_pattern = re.compile(
    r"fn write_json<T: Serialize>\(path: &Path, value: &T\) -> Result<\(\)> \{.*?\n\}\n\n"
    r"(?=fn read_lower_hex_file)",
    re.DOTALL,
)
write_replacement = """fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("could not create {}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("output path must end in a UTF-8 file name")?;
    if path.exists() {
        bail!("refusing to overwrite existing output {}", path.display());
    }
    let bytes = serde_json::to_vec_pretty(value).context("could not serialize JSON output")?;
    let temporary_path = parent.join(format!(
        ".{file_name}.{}.nxb.tmp",
        std::process::id()
    ));
    let publication = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .with_context(|| format!("could not create {}", temporary_path.display()))?;
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .with_context(|| format!("could not synchronize {}", temporary_path.display()))?;
        fs::hard_link(&temporary_path, path)
            .with_context(|| format!("could not atomically publish {}", path.display()))?;
        Ok(())
    })();
    if let Err(error) = publication {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    let _ = fs::remove_file(&temporary_path);
    Ok(())
}

"""
cli, count = write_pattern.subn(write_replacement, cli, count=1)
if count != 1:
    raise SystemExit(f"unexpected write_json function count: {count}")

test_pattern = re.compile(r"#\[cfg\(test\)\]\nmod tests \{.*\}\n?\Z", re.DOTALL)
test_replacement = """#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::json;

    use super::{path_matches_prefix, write_json};

    #[test]
    fn authenticated_prefix_must_not_widen_discovery_scope() {
        assert!(path_matches_prefix("/app/admin", "/app"));
        assert!(path_matches_prefix("/app", "/app"));
        assert!(!path_matches_prefix("/application", "/app"));
        assert!(!path_matches_prefix("/", "/app"));
    }

    #[test]
    fn artifact_publication_is_complete_and_no_clobber() {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let directory = std::env::temp_dir().join(format!(
            "nxb141-unified-output-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        let output = directory.join("plan.json");
        write_json(&output, &json!({"version": 1, "state": "ready"})).unwrap();
        let bytes = fs::read(&output).unwrap();
        assert!(bytes.ends_with(b"\n"));
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["state"], "ready");
        assert!(write_json(&output, &json!({"state": "replaced"})).is_err());
        let unchanged: serde_json::Value =
            serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        assert_eq!(unchanged["state"], "ready");
        fs::remove_dir_all(directory).unwrap();
    }
}
"""
cli, count = test_pattern.subn(test_replacement, cli, count=1)
if count != 1:
    raise SystemExit(f"unexpected CLI test module count: {count}")
cli_path.write_text(cli, encoding="utf-8", newline="\n")
