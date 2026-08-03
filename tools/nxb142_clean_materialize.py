from pathlib import Path
import re

root = Path("Cargo.toml")
workspace = root.read_text(encoding="utf-8")
member = '    "crates/nxb-operator-state",\n'
if member not in workspace:
    anchor = '    "crates/nxb-operator",\n'
    if workspace.count(anchor) != 1:
        raise SystemExit("unexpected workspace member anchor")
    workspace = workspace.replace(anchor, anchor + member, 1)
root.write_text(workspace, encoding="utf-8", newline="\n")

path = Path("crates/nxb-operator-state/src/lib.rs")
text = path.read_text(encoding="utf-8")


def sub_once(pattern, replacement, label):
    global text
    text, count = re.subn(pattern, replacement, text, count=1, flags=re.DOTALL)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")


if "checkpoint bytes are not in canonical serialized form" not in text:
    sub_once(
        r"(let checkpoint: OperatorCheckpoint = serde_json::from_slice\(&bytes\)\s*\.map_err\(\|error\| OperatorStateError::Serialization\(error\.to_string\(\)\)\)\?;)(\s*if checkpoint\.sequence != sequence \{)",
        lambda match: match.group(1)
        + """
            if bytes != checkpoint_bytes(&checkpoint)? {
                return Err(OperatorStateError::NonCanonicalCheckpoint);
            }"""
        + match.group(2),
        "checkpoint parse block",
    )
    sub_once(
        r"(#\[error\(\"checkpoint SHA-256 does not match its contents\"\)\]\s*CheckpointDigestMismatch,)",
        lambda match: match.group(1)
        + """
    #[error("checkpoint bytes are not in canonical serialized form")]
    NonCanonicalCheckpoint,""",
        "checkpoint error block",
    )

text, direct_count = re.subn(
    r"\s*\| \(OperatorRunStatus::Running, OperatorRunStatus::Completed\)",
    "",
    text,
    count=1,
)
if direct_count != 1 and "completion_requires_teardown_checkpoint" not in text:
    raise SystemExit("direct completion transition not found")

if "fn noncanonical_checkpoint_bytes_are_rejected()" not in text:
    tests = """
    #[test]
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

"""
    sub_once(
        r"(\s*#\[test\]\s*fn interrupted_publication_is_rejected\(\) \{)",
        lambda match: tests + match.group(1),
        "state test insertion point",
    )

path.write_text(text, encoding="utf-8", newline="\n")
