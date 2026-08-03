from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def materialize_workspace() -> None:
    path = ROOT / "Cargo.toml"
    text = path.read_text(encoding="utf-8")
    member = '    "crates/nxb-operator-runtime",\n'
    if member not in text:
        anchor = '    "crates/nxb-operator",\n'
        if text.count(anchor) != 1:
            raise SystemExit("unexpected workspace anchor")
        text = text.replace(anchor, anchor + member, 1)
    path.write_text(text, encoding="utf-8", newline="\n")


def harden_state() -> None:
    path = ROOT / "crates/nxb-operator-state/src/lib.rs"
    text = path.read_text(encoding="utf-8")

    if "NonCanonicalCheckpoint" not in text:
        pattern = re.compile(
            r"(let checkpoint: OperatorCheckpoint = serde_json::from_slice\(&bytes\)\n"
            r"\s*\.map_err\(\|error\| OperatorStateError::Serialization\(error\.to_string\(\)\)\)\?;\n)"
            r"(\s*if checkpoint\.sequence != sequence \{)"
        )
        replacement = (
            r"\1"
            "            if bytes != checkpoint_bytes(&checkpoint)? {\n"
            "                return Err(OperatorStateError::NonCanonicalCheckpoint);\n"
            "            }\n"
            r"\2"
        )
        text, count = pattern.subn(replacement, text, count=1)
        if count != 1:
            raise SystemExit("checkpoint parse anchor not found")

    text = re.sub(
        r"\n\s*\| \(OperatorRunStatus::Running, OperatorRunStatus::Completed\)",
        "",
        text,
        count=1,
    )

    if "checkpoint bytes are not in canonical serialized form" not in text:
        anchor = (
            '    #[error("checkpoint SHA-256 does not match its contents")]\n'
            "    CheckpointDigestMismatch,\n"
        )
        if text.count(anchor) != 1:
            raise SystemExit("checkpoint error anchor not found")
        text = text.replace(
            anchor,
            anchor
            + '    #[error("checkpoint bytes are not in canonical serialized form")]\n'
            + "    NonCanonicalCheckpoint,\n",
            1,
        )

    if "fn noncanonical_checkpoint_bytes_are_rejected()" not in text:
        anchor = "    #[test]\n    fn interrupted_publication_is_rejected() {\n"
        if text.count(anchor) != 1:
            raise SystemExit("state test anchor not found")
        tests = '''    #[test]
    fn noncanonical_checkpoint_bytes_are_rejected() {
        let (root, store) = initialized_store("noncanonical", 1024 * 1024);
        let path = store.directory().join(checkpoint_file_name(0));
        let mut bytes = fs::read(&path).expect("read checkpoint");
        bytes.push(b'\\n');
        fs::write(&path, bytes).expect("rewrite checkpoint");
        assert!(matches!(
            store.recover(1_200).expect_err("noncanonical bytes must fail"),
            OperatorStateError::NonCanonicalCheckpoint
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn completion_requires_teardown_checkpoint() {
        let (root, store) = initialized_store("teardown-order", 1024 * 1024);
        store
            .append(
                CheckpointUpdate {
                    status: OperatorRunStatus::Running,
                    counters: OperatorCounters::default(),
                    stop_reason: None,
                },
                1_150,
            )
            .expect("enter running state");
        assert!(matches!(
            store
                .append(
                    CheckpointUpdate {
                        status: OperatorRunStatus::Completed,
                        counters: OperatorCounters::default(),
                        stop_reason: Some("completed".into()),
                    },
                    1_160,
                )
                .expect_err("direct completion must fail"),
            OperatorStateError::InvalidStatusTransition
        ));
        store
            .append(
                CheckpointUpdate {
                    status: OperatorRunStatus::TeardownPending,
                    counters: OperatorCounters::default(),
                    stop_reason: Some("teardown started".into()),
                },
                1_170,
            )
            .expect("enter teardown");
        store
            .append(
                CheckpointUpdate {
                    status: OperatorRunStatus::Completed,
                    counters: OperatorCounters::default(),
                    stop_reason: Some("teardown completed".into()),
                },
                1_180,
            )
            .expect("complete after teardown");
        fs::remove_dir_all(root).expect("cleanup");
    }

'''
        text = text.replace(anchor, tests + anchor, 1)

    path.write_text(text, encoding="utf-8", newline="\n")


def harden_runtime() -> None:
    path = ROOT / "crates/nxb-operator-runtime/src/lib.rs"
    text = path.read_text(encoding="utf-8")
    loop_anchor = (
        "    let mut unresolved = None;\n"
        "    let mut reconcile = None;\n"
        "    for (expected, (index, paths)) in records.into_iter().enumerate() {\n"
    )
    if "let mut incomplete_seen = false;" not in text:
        if text.count(loop_anchor) != 1:
            raise SystemExit("runtime journal loop anchor not found")
        text = text.replace(
            loop_anchor,
            "    let mut unresolved = None;\n"
            "    let mut reconcile = None;\n"
            "    let mut incomplete_seen = false;\n"
            "    for (expected, (index, paths)) in records.into_iter().enumerate() {\n"
            "        if incomplete_seen {\n"
            "            return Err(RuntimeError::StateJournalMismatch);\n"
            "        }\n",
            1,
        )

    if "incomplete_seen = unresolved.is_some() || reconcile.is_some();" not in text:
        start = text.find("        if unresolved.is_some() || reconcile.is_some() {")
        if start < 0:
            raise SystemExit("runtime incomplete block start not found")
        end_marker = "        }\n    }\n    if reconcile.is_none()"
        end = text.find(end_marker, start)
        if end < 0:
            raise SystemExit("runtime incomplete block end not found")
        replacement = (
            "        incomplete_seen = unresolved.is_some() || reconcile.is_some();\n"
            "    }\n"
            "    if reconcile.is_none()"
        )
        text = text[:start] + replacement + text[end + len(end_marker) :]

    helper_start = text.find("\nfn records_len_hint(")
    if helper_start >= 0:
        helper_end = text.find(
            "\n#[derive(Debug, Clone, Copy)]\nenum RecordKind", helper_start
        )
        if helper_end < 0:
            raise SystemExit("runtime helper end not found")
        text = text[:helper_start] + "\n" + text[helper_end:]

    path.write_text(text, encoding="utf-8", newline="\n")


materialize_workspace()
harden_state()
harden_runtime()
