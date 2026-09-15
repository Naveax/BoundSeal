use std::{
    fs,
    path::{Path, PathBuf},
};

const BROKER_PATH: &str = "scripts/nxb-153-windows-h2-destination-broker.py";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source() -> String {
    let path = repository_root().join(BROKER_PATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn required_offset(source: &str, marker: &str) -> usize {
    source
        .find(marker)
        .unwrap_or_else(|| panic!("{BROKER_PATH}: missing source marker: {marker}"))
}

#[test]
fn creator_handles_suppress_their_own_delayed_file_time_notifications() {
    let text = source();

    for marker in [
        "self.SetFileTime = self.kernel32.SetFileTime",
        "self.SetFileTime.argtypes = [",
        "def suppress_automatic_file_times(self, handle: int) -> None:",
        "preserve = FILETIME(0xFFFFFFFF, 0xFFFFFFFF)",
        "if not self.SetFileTime(",
        "self.winerror(\"SetFileTime suppress automatic file times\")",
        "if not directory:\n            self.suppress_automatic_file_times(handle)",
    ] {
        assert!(
            text.contains(marker),
            "{BROKER_PATH}: creator-handle time suppression marker is missing: {marker}"
        );
    }

    let create = required_offset(&text, "def create_relative(");
    let suppress = required_offset(&text[create..], "self.suppress_automatic_file_times(handle)") + create;
    let returned = required_offset(&text[suppress..], "return handle") + suppress;
    assert!(
        create < suppress && suppress < returned,
        "{BROKER_PATH}: automatic file-time suppression must occur before a newly created file handle escapes create_relative"
    );
}

#[test]
fn transitioned_read_guards_withhold_write_and_delete_sharing() {
    let text = source();
    let start = required_offset(&text, "def open_guard_file(self, path: str) -> int:");
    let end = required_offset(&text[start..], "\n    def create_relative(") + start;
    let body = &text[start..end];

    assert!(
        body.contains("FILE_SHARE_READ,\n            None,"),
        "{BROKER_PATH}: final read guard must share reads only"
    );
    assert!(
        !body.contains("FILE_SHARE_READ | FILE_SHARE_WRITE"),
        "{BROKER_PATH}: final read guard must not admit external write sharing"
    );
}

#[test]
fn watcher_still_covers_the_close_reopen_transition_and_post_freeze_lifetime() {
    let text = source();
    let arm = required_offset(&text, "self._arm_watcher()");
    let transition = required_offset(&text, "self._transition_writers_to_read_guards()");
    assert!(
        arm < transition,
        "{BROKER_PATH}: subtree watcher must be armed before creator handles are released"
    );

    let transition_start = required_offset(&text, "def _transition_writers_to_read_guards(self) -> None:");
    let transition_end = required_offset(&text[transition_start..], "\n    def copy_and_freeze(") + transition_start;
    let body = &text[transition_start..transition_end];
    for marker in [
        "self.native.close(writer)",
        "guard = self.native.open_guard_file(str(path))",
        "if actual_identity != expected_identity:",
        "if self.violated.is_set():",
    ] {
        assert!(
            body.contains(marker),
            "{BROKER_PATH}: fail-closed writer-to-guard transition marker is missing: {marker}"
        );
    }
}

#[test]
fn self_test_proves_read_guard_rejects_post_freeze_file_writes() {
    let text = source();
    for marker in [
        "write_succeeded = False",
        "with copied.open(\"r+b\") as stream:",
        "fail(\"self-test retained destination read guard allowed write\")",
    ] {
        assert!(
            text.contains(marker),
            "{BROKER_PATH}: post-freeze write-sharing self-test marker is missing: {marker}"
        );
    }
}
