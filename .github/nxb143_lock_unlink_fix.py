from pathlib import Path

path = Path(__file__).resolve().parents[1] / "crates/nxb-operator-runtime/src/lib.rs"
text = path.read_text(encoding="utf-8")

old = '''struct RuntimeLock {
    path: PathBuf,
    file: Option<File>,
}

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.unlock();
            drop(file);
        }
        let _ = fs::remove_file(&self.path);
    }
}
'''
new = '''struct RuntimeLock {
    file: Option<File>,
}

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.unlock();
            drop(file);
        }
    }
}
'''
if old not in text:
    raise SystemExit("runtime lock structure anchor not found")
text = text.replace(old, new, 1)

old = '''    Ok(RuntimeLock {
        path,
        file: Some(file),
    })
'''
new = '''    Ok(RuntimeLock { file: Some(file) })
'''
if old not in text:
    raise SystemExit("runtime lock constructor anchor not found")
text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")
