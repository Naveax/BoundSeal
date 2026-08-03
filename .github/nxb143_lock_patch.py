from pathlib import Path

path = Path(__file__).resolve().parents[1] / "crates/nxb-operator-runtime/src/lib.rs"
text = path.read_text(encoding="utf-8")

text = text.replace(
    "    fs::{self, OpenOptions},\n",
    "    fs::{self, File, OpenOptions, TryLockError},\n",
    1,
)

struct_anchor = "pub struct CheckpointBoundRuntime {\n"
lock_struct = '''struct RuntimeLock {
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
if "struct RuntimeLock {" not in text:
    if text.count(struct_anchor) != 1:
        raise SystemExit("runtime struct anchor not found")
    text = text.replace(struct_anchor, lock_struct + struct_anchor, 1)

text = text.replace("    lock_path: PathBuf,\n", "    lock: RuntimeLock,\n", 1)

empty_check = '''        if fs::read_dir(&journal_directory)
            .map_err(io_error)?
            .next()
            .is_some()
        {
            return Err(RuntimeError::JournalDirectoryNotEmpty);
        }
'''
empty_replacement = '''        for entry in fs::read_dir(&journal_directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if entry.file_name() != RUNTIME_LOCK_FILE {
                return Err(RuntimeError::JournalDirectoryNotEmpty);
            }
        }
'''
if empty_check not in text:
    raise SystemExit("journal empty check anchor not found")
text = text.replace(empty_check, empty_replacement, 1)

text = text.replace(
    "        let lock_path = acquire_lock(&journal_directory, clock)?;\n",
    "        let lock = acquire_lock(&journal_directory, clock)?;\n",
)

text = text.replace(
    '''            Err(error) => {
                let _ = fs::remove_file(&lock_path);
                return Err(error.into());
            }
''',
    '''            Err(error) => return Err(error.into()),
''',
)
text = text.replace(
    '''            Err(error) => {
                let _ = fs::remove_file(&lock_path);
                return Err(error);
            }
''',
    '''            Err(error) => return Err(error),
''',
)
text = text.replace("                let _ = fs::remove_file(&lock_path);\n", "")
text = text.replace("            let _ = fs::remove_file(&lock_path);\n", "")
text = text.replace("            lock_path,\n", "            lock,\n")

runtime_drop = '''impl Drop for CheckpointBoundRuntime {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

'''
if runtime_drop not in text:
    raise SystemExit("runtime drop anchor not found")
text = text.replace(runtime_drop, "", 1)

acquire_start = text.find("fn acquire_lock(")
acquire_end = text.find("\nfn publish_record(", acquire_start)
if acquire_start < 0 or acquire_end < 0:
    raise SystemExit("acquire lock function anchors not found")
new_acquire = '''fn acquire_lock(
    journal_directory: &Path,
    clock: RuntimeClock,
) -> Result<RuntimeLock, RuntimeError> {
    let path = journal_directory.join(RUNTIME_LOCK_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(io_error)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(RuntimeError::RuntimeLocked),
        Err(TryLockError::Error(error)) => return Err(io_error(error)),
    }
    if let Err(error) = file.set_len(0) {
        let _ = file.unlock();
        return Err(io_error(error));
    }
    let bytes = format!(
        "pid={}\\nepoch_seconds={}\\n",
        std::process::id(),
        clock.epoch_seconds
    );
    if let Err(error) = file
        .write_all(bytes.as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _ = file.unlock();
        return Err(io_error(error));
    }
    Ok(RuntimeLock {
        path,
        file: Some(file),
    })
}
'''
text = text[:acquire_start] + new_acquire + text[acquire_end:]

if "fn os_lock_rejects_concurrent_owner_and_recovers_stale_path()" not in text:
    anchor = "    #[test]\n    fn completion_requires_teardown_pending_state() {\n"
    if text.count(anchor) != 1:
        raise SystemExit("lock test insertion anchor not found")
    test = '''    #[test]
    fn os_lock_rejects_concurrent_owner_and_recovers_stale_path() {
        let (root, runtime_plan, consumed) = setup("os-lock");
        let clock = RuntimeClock {
            epoch_seconds: 1_101,
            epoch_milliseconds: 1_101_000,
        };
        let state_directory = root.join("state");
        let journal_directory = root.join("journal");
        let (runtime, _) = CheckpointBoundRuntime::initialize(
            &state_directory,
            &journal_directory,
            runtime_plan.clone(),
            &consumed,
            clock,
        )
        .expect("initialize");
        assert!(matches!(
            CheckpointBoundRuntime::open(
                &state_directory,
                &journal_directory,
                runtime_plan.clone(),
                consumed.activation_certificate_sha256(),
                consumed.marker_path(),
                clock,
            ),
            Err(RuntimeError::RuntimeLocked)
        ));
        drop(runtime);
        fs::write(journal_directory.join(RUNTIME_LOCK_FILE), b"stale owner\\n")
            .expect("write stale lock path");
        let (reopened, recovery) = CheckpointBoundRuntime::open(
            state_directory,
            journal_directory,
            runtime_plan,
            consumed.activation_certificate_sha256(),
            consumed.marker_path(),
            RuntimeClock {
                epoch_seconds: 1_102,
                epoch_milliseconds: 1_102_000,
            },
        )
        .expect("OS lock must recover a stale path");
        assert!(recovery.continuation_allowed);
        drop(reopened);
        fs::remove_dir_all(root).expect("cleanup");
    }

'''
    text = text.replace(anchor, test + anchor, 1)

path.write_text(text, encoding="utf-8", newline="\n")
